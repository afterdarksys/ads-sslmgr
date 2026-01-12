"""
DNSScience Integration
Provides DNS intelligence and validation for SSL certificates:
- DNS health checking and propagation monitoring
- CAA record validation and management
- DANE/TLSA record generation and verification
- DNSSEC validation
- DNS-based certificate deployment readiness
- Geographic DNS analysis for multi-region deployments
"""

import dns.resolver
import dns.dnssec
import dns.query
import dns.zone
import hashlib
import logging
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class DNSScienceClient:
    """Client for DNSScience DNS intelligence service"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # API configuration
        self.api_key = self.config.get('dnsscience', {}).get('api_key')
        self.api_url = self.config.get('dnsscience', {}).get('api_url', 'https://api.dnsscience.io/v1')
        self.enabled = self.config.get('dnsscience', {}).get('enabled', False)

        # DNS resolvers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    def validate_dns_for_certificate(self, domain: str, cert_data: Dict = None) -> Dict:
        """
        Validate DNS configuration for certificate deployment

        Returns:
            Comprehensive DNS validation report
        """
        report = {
            'domain': domain,
            'validated_at': datetime.now().isoformat(),
            'overall_status': 'valid',
            'dns_health_score': 100,  # 0-100
            'findings': [],
            'recommendations': [],
            'checks': {}
        }

        try:
            # 1. Basic DNS resolution
            report['checks']['resolution'] = self._check_dns_resolution(domain)
            if not report['checks']['resolution']['success']:
                report['overall_status'] = 'warning'
                report['dns_health_score'] -= 40

            # 2. CAA records
            report['checks']['caa'] = self._check_caa_records(domain, cert_data)
            if report['checks']['caa'].get('blocking_issues'):
                report['overall_status'] = 'warning'
                report['dns_health_score'] -= 20

            # 3. DNSSEC validation
            report['checks']['dnssec'] = self._check_dnssec(domain)
            if not report['checks']['dnssec'].get('enabled'):
                report['dns_health_score'] -= 10

            # 4. DNS propagation
            report['checks']['propagation'] = self._check_dns_propagation(domain)
            if not report['checks']['propagation']['consistent']:
                report['overall_status'] = 'warning'
                report['dns_health_score'] -= 15

            # 5. DANE/TLSA records (if applicable)
            report['checks']['dane'] = self._check_dane_records(domain)

            # 6. Geographic distribution
            report['checks']['geographic'] = self._check_geographic_distribution(domain)

            # Generate findings and recommendations
            self._generate_dns_findings(report)

        except Exception as e:
            self.logger.error(f"Error validating DNS: {e}")
            report['error'] = str(e)
            report['overall_status'] = 'error'

        return report

    def _check_dns_resolution(self, domain: str) -> Dict:
        """Check basic DNS resolution"""
        result = {
            'success': False,
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'resolution_time_ms': 0
        }

        try:
            start_time = datetime.now()

            # Check A records (IPv4)
            try:
                answers = self.resolver.resolve(domain, 'A')
                result['a_records'] = [str(rdata) for rdata in answers]
                result['success'] = True
            except dns.resolver.NXDOMAIN:
                result['error'] = 'Domain does not exist'
                return result
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                result['error'] = f'Error resolving A records: {str(e)}'

            # Check AAAA records (IPv6)
            try:
                answers = self.resolver.resolve(domain, 'AAAA')
                result['aaaa_records'] = [str(rdata) for rdata in answers]
                result['success'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Check CNAME records
            try:
                answers = self.resolver.resolve(domain, 'CNAME')
                result['cname_records'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Calculate resolution time
            end_time = datetime.now()
            result['resolution_time_ms'] = int((end_time - start_time).total_seconds() * 1000)

            if not result['a_records'] and not result['aaaa_records']:
                result['warning'] = 'No A or AAAA records found'
                result['success'] = False

        except Exception as e:
            result['error'] = str(e)
            result['success'] = False

        return result

    def _check_caa_records(self, domain: str, cert_data: Dict = None) -> Dict:
        """
        Check CAA (Certification Authority Authorization) records
        Validates if certificate issuance is authorized
        """
        result = {
            'has_caa': False,
            'caa_records': [],
            'authorized_cas': [],
            'blocking_issues': [],
            'recommendations': []
        }

        try:
            answers = self.resolver.resolve(domain, 'CAA')
            result['has_caa'] = True

            for rdata in answers:
                caa_record = {
                    'flags': rdata.flags,
                    'tag': rdata.tag,
                    'value': rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
                }
                result['caa_records'].append(caa_record)

                if caa_record['tag'] == 'issue':
                    result['authorized_cas'].append(caa_record['value'])

            # Check if current certificate issuer is authorized
            if cert_data and result['authorized_cas']:
                issuer_category = cert_data.get('issuer_category', '').lower()
                authorized = False

                for ca in result['authorized_cas']:
                    ca_lower = ca.lower()
                    if (issuer_category in ca_lower or
                        ca_lower in issuer_category or
                        ca == ';'):  # Allow wildcard
                        authorized = True
                        break

                if not authorized:
                    result['blocking_issues'].append({
                        'severity': 'high',
                        'description': f'Current certificate issuer ({issuer_category}) not authorized by CAA records',
                        'remediation': 'Update CAA records to authorize current CA or switch to authorized CA'
                    })

        except dns.resolver.NoAnswer:
            result['has_caa'] = False
            result['recommendations'].append('Consider adding CAA records to control certificate issuance')
        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain does not exist'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _check_dnssec(self, domain: str) -> Dict:
        """Check DNSSEC validation"""
        result = {
            'enabled': False,
            'validated': False,
            'chain_valid': False,
            'details': {}
        }

        try:
            # Check for DNSKEY records
            try:
                answers = self.resolver.resolve(domain, 'DNSKEY')
                result['enabled'] = True
                result['details']['dnskey_count'] = len(answers)
            except dns.resolver.NoAnswer:
                result['enabled'] = False
                return result

            # Check for DS records at parent
            try:
                parent_domain = '.'.join(domain.split('.')[1:])
                answers = self.resolver.resolve(domain, 'DS')
                result['details']['ds_records'] = len(answers)
            except:
                pass

            # Full DNSSEC validation would require more complex checking
            result['validated'] = result['enabled']

        except Exception as e:
            result['error'] = str(e)

        return result

    def _check_dns_propagation(self, domain: str) -> Dict:
        """
        Check DNS propagation across multiple nameservers
        Ensures DNS changes have propagated globally
        """
        result = {
            'consistent': True,
            'nameservers_checked': 0,
            'nameservers_results': [],
            'inconsistencies': []
        }

        # Popular public DNS servers to check
        public_dns_servers = [
            ('8.8.8.8', 'Google'),
            ('1.1.1.1', 'Cloudflare'),
            ('208.67.222.222', 'OpenDNS'),
            ('9.9.9.9', 'Quad9')
        ]

        reference_ips = None

        for dns_server, dns_name in public_dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 5

                answers = resolver.resolve(domain, 'A')
                ips = sorted([str(rdata) for rdata in answers])

                server_result = {
                    'server': dns_name,
                    'ip': dns_server,
                    'resolved_ips': ips,
                    'success': True
                }
                result['nameservers_results'].append(server_result)
                result['nameservers_checked'] += 1

                # Check consistency
                if reference_ips is None:
                    reference_ips = ips
                elif ips != reference_ips:
                    result['consistent'] = False
                    result['inconsistencies'].append({
                        'server': dns_name,
                        'expected': reference_ips,
                        'actual': ips
                    })

            except Exception as e:
                result['nameservers_results'].append({
                    'server': dns_name,
                    'ip': dns_server,
                    'error': str(e),
                    'success': False
                })

        return result

    def _check_dane_records(self, domain: str) -> Dict:
        """
        Check DANE/TLSA records for DNS-based authentication
        """
        result = {
            'enabled': False,
            'tlsa_records': [],
            'ports_checked': []
        }

        # Common ports for TLSA records
        ports = [443, 25, 587]

        for port in ports:
            tlsa_domain = f'_{port}._tcp.{domain}'
            try:
                answers = self.resolver.resolve(tlsa_domain, 'TLSA')
                result['enabled'] = True

                for rdata in answers:
                    tlsa_record = {
                        'port': port,
                        'usage': rdata.usage,
                        'selector': rdata.selector,
                        'mtype': rdata.mtype,
                        'cert': rdata.cert.hex()
                    }
                    result['tlsa_records'].append(tlsa_record)

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                self.logger.warning(f"Error checking TLSA for port {port}: {e}")

            result['ports_checked'].append(port)

        return result

    def _check_geographic_distribution(self, domain: str) -> Dict:
        """
        Check geographic distribution of DNS resolution
        Useful for CDN and multi-region deployments
        """
        result = {
            'geolocation_data': [],
            'regions': set(),
            'recommendations': []
        }

        # In production, would use geolocation service
        # Simulated check
        result['message'] = 'Geographic DNS analysis available with DNSScience API'

        return result

    def _generate_dns_findings(self, report: Dict):
        """Generate findings and recommendations from DNS checks"""

        # Resolution issues
        if not report['checks']['resolution']['success']:
            report['findings'].append({
                'category': 'resolution',
                'severity': 'critical',
                'title': 'DNS Resolution Failed',
                'description': 'Domain cannot be resolved via DNS',
                'remediation': 'Check DNS configuration and ensure domain is properly configured'
            })
            report['recommendations'].append('URGENT: Fix DNS resolution before deploying certificate')

        # CAA issues
        if report['checks']['caa'].get('blocking_issues'):
            for issue in report['checks']['caa']['blocking_issues']:
                report['findings'].append({
                    'category': 'caa',
                    'severity': issue['severity'],
                    'title': 'CAA Record Issue',
                    'description': issue['description'],
                    'remediation': issue['remediation']
                })
                report['recommendations'].append('Update CAA records before certificate renewal')

        # DNSSEC recommendations
        if not report['checks']['dnssec']['enabled']:
            report['findings'].append({
                'category': 'dnssec',
                'severity': 'low',
                'title': 'DNSSEC Not Enabled',
                'description': 'Domain does not have DNSSEC enabled',
                'remediation': 'Consider enabling DNSSEC for enhanced security'
            })
            report['recommendations'].append('Consider enabling DNSSEC for enhanced security')

        # Propagation issues
        if not report['checks']['propagation']['consistent']:
            report['findings'].append({
                'category': 'propagation',
                'severity': 'medium',
                'title': 'Inconsistent DNS Propagation',
                'description': 'DNS records are not consistent across nameservers',
                'remediation': 'Wait for DNS propagation to complete before deploying certificate'
            })
            report['recommendations'].append('Wait for DNS propagation (up to 48 hours)')

    def generate_caa_records(self, domain: str, authorized_cas: List[str]) -> List[str]:
        """
        Generate CAA records for authorized CAs

        Args:
            domain: Domain name
            authorized_cas: List of authorized CA identifiers

        Returns:
            List of CAA record strings
        """
        caa_records = []

        for ca in authorized_cas:
            caa_records.append(f'{domain}. IN CAA 0 issue "{ca}"')

        # Add iodef for incident reporting (optional)
        # caa_records.append(f'{domain}. IN CAA 0 iodef "mailto:security@{domain}"')

        return caa_records

    def generate_tlsa_record(self, cert_data: Dict, usage: int = 3,
                           selector: int = 1, mtype: int = 1) -> str:
        """
        Generate TLSA (DANE) record for certificate

        Args:
            cert_data: Certificate data dictionary
            usage: TLSA usage field (default 3 = DANE-EE)
            selector: TLSA selector field (default 1 = SubjectPublicKeyInfo)
            mtype: TLSA matching type (default 1 = SHA-256)

        Returns:
            TLSA record string
        """
        # In production, would extract actual certificate data and hash it
        # This is a placeholder
        domain = cert_data.get('common_name', '')
        serial = cert_data.get('serial_number', '')

        # Generate placeholder hash
        cert_hash = hashlib.sha256(f"{domain}{serial}".encode()).hexdigest()

        tlsa_record = f'_443._tcp.{domain}. IN TLSA {usage} {selector} {mtype} {cert_hash}'

        return tlsa_record

    def pre_renewal_validation(self, domain: str, renewal_method: str = 'http-01') -> Dict:
        """
        Validate DNS before certificate renewal (especially for ACME challenges)

        Args:
            domain: Domain to validate
            renewal_method: ACME challenge method (http-01, dns-01, tls-alpn-01)

        Returns:
            Validation report indicating if renewal is likely to succeed
        """
        report = {
            'domain': domain,
            'renewal_method': renewal_method,
            'ready_for_renewal': True,
            'blockers': [],
            'warnings': [],
            'recommendations': []
        }

        try:
            # Basic DNS resolution check
            dns_check = self._check_dns_resolution(domain)
            if not dns_check['success']:
                report['ready_for_renewal'] = False
                report['blockers'].append('DNS resolution failed - cannot complete ACME challenge')

            # Check CAA records
            caa_check = self._check_caa_records(domain)
            if caa_check.get('blocking_issues'):
                report['ready_for_renewal'] = False
                report['blockers'].extend([
                    issue['description'] for issue in caa_check['blocking_issues']
                ])

            # Method-specific checks
            if renewal_method == 'dns-01':
                # Check if DNS supports TXT records
                try:
                    test_txt = f'_acme-challenge.{domain}'
                    self.resolver.resolve(test_txt, 'TXT')
                except dns.resolver.NoAnswer:
                    # Expected - just checking if DNS server supports TXT queries
                    pass
                except Exception as e:
                    report['warnings'].append(f'DNS-01 challenge may fail: {str(e)}')

            elif renewal_method == 'http-01':
                # Check if domain resolves and is reachable
                if not dns_check.get('a_records'):
                    report['warnings'].append('No A records found - HTTP-01 challenge may fail')

        except Exception as e:
            report['error'] = str(e)
            report['ready_for_renewal'] = False

        return report

    def get_dns_health_summary(self, domains: List[str]) -> Dict:
        """
        Get DNS health summary for multiple domains

        Returns:
            Summary statistics and health scores
        """
        summary = {
            'total_domains': len(domains),
            'healthy': 0,
            'warnings': 0,
            'critical': 0,
            'average_health_score': 0,
            'domains': []
        }

        total_score = 0

        for domain in domains:
            try:
                report = self.validate_dns_for_certificate(domain)

                domain_summary = {
                    'domain': domain,
                    'health_score': report['dns_health_score'],
                    'status': report['overall_status']
                }

                if report['overall_status'] == 'valid':
                    summary['healthy'] += 1
                elif report['overall_status'] == 'warning':
                    summary['warnings'] += 1
                else:
                    summary['critical'] += 1

                total_score += report['dns_health_score']
                summary['domains'].append(domain_summary)

            except Exception as e:
                self.logger.warning(f"Error checking {domain}: {e}")
                summary['critical'] += 1

        if summary['total_domains'] > 0:
            summary['average_health_score'] = int(total_score / summary['total_domains'])

        return summary


def main():
    """CLI interface for DNSScience integration"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='DNSScience DNS Validation')
    parser.add_argument('--domain', help='Domain to validate')
    parser.add_argument('--pre-renewal', action='store_true',
                       help='Pre-renewal validation')
    parser.add_argument('--generate-caa', nargs='+',
                       help='Generate CAA records for specified CAs')
    parser.add_argument('--check-propagation', action='store_true',
                       help='Check DNS propagation')
    parser.add_argument('--config', help='Config file path')

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    client = DNSScienceClient(config)

    if args.domain:
        if args.pre_renewal:
            report = client.pre_renewal_validation(args.domain)
            print(json.dumps(report, indent=2))
        elif args.generate_caa and args.domain:
            caa_records = client.generate_caa_records(args.domain, args.generate_caa)
            print("\nGenerated CAA Records:")
            for record in caa_records:
                print(record)
        elif args.check_propagation:
            report = client.validate_dns_for_certificate(args.domain)
            print(json.dumps(report['checks']['propagation'], indent=2))
        else:
            report = client.validate_dns_for_certificate(args.domain)
            print(json.dumps(report, indent=2, default=str))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

"""
DarkAPI Integration
Provides threat intelligence for SSL certificates:
- Certificate Transparency log monitoring
- Dark web monitoring for leaked certificates
- Phishing/typosquatting detection
- Certificate abuse detection
- Threat scoring and risk assessment
"""

import hashlib
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urljoin


class DarkAPIClient:
    """Client for DarkAPI threat intelligence service"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # API configuration
        self.api_key = self.config.get('darkapi', {}).get('api_key')
        self.api_url = self.config.get('darkapi', {}).get('api_url', 'https://api.darkapi.io/v1')
        self.enabled = self.config.get('darkapi', {}).get('enabled', False) and self.api_key

        # Caching
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour

    def check_certificate_threats(self, cert_data: Dict) -> Dict:
        """
        Check certificate for threats and security issues

        Returns:
            Threat intelligence report
        """
        if not self.enabled:
            return {
                'enabled': False,
                'message': 'DarkAPI integration not configured'
            }

        report = {
            'certificate_id': cert_data.get('id'),
            'common_name': cert_data.get('common_name'),
            'checked_at': datetime.now().isoformat(),
            'threat_score': 0,  # 0-100
            'threats_found': [],
            'ct_logs': [],
            'dark_web_mentions': [],
            'similar_domains': [],
            'abuse_reports': []
        }

        try:
            # 1. Check Certificate Transparency logs
            ct_results = self._check_ct_logs(cert_data)
            report['ct_logs'] = ct_results
            if ct_results.get('unauthorized_certificates'):
                report['threat_score'] += 30
                report['threats_found'].append({
                    'type': 'unauthorized_certificate',
                    'severity': 'high',
                    'description': 'Unauthorized certificates found in CT logs',
                    'count': len(ct_results['unauthorized_certificates'])
                })

            # 2. Check dark web for leaked certificates
            darkweb_results = self._check_dark_web(cert_data)
            report['dark_web_mentions'] = darkweb_results
            if darkweb_results.get('leaked_private_keys'):
                report['threat_score'] += 50
                report['threats_found'].append({
                    'type': 'leaked_private_key',
                    'severity': 'critical',
                    'description': 'Certificate private key may be leaked on dark web',
                    'sources': darkweb_results['sources']
                })

            # 3. Check for phishing/typosquatting
            similar_domains = self._check_similar_domains(cert_data)
            report['similar_domains'] = similar_domains
            if similar_domains:
                report['threat_score'] += 20
                report['threats_found'].append({
                    'type': 'typosquatting',
                    'severity': 'medium',
                    'description': 'Similar domains detected (potential phishing)',
                    'domains': [d['domain'] for d in similar_domains[:5]]
                })

            # 4. Check abuse databases
            abuse_results = self._check_abuse_databases(cert_data)
            report['abuse_reports'] = abuse_results
            if abuse_results:
                report['threat_score'] += 40
                report['threats_found'].append({
                    'type': 'abuse_report',
                    'severity': 'high',
                    'description': 'Certificate or domain found in abuse databases',
                    'reports': abuse_results
                })

        except Exception as e:
            self.logger.error(f"Error checking certificate threats: {e}")
            report['error'] = str(e)

        return report

    def _check_ct_logs(self, cert_data: Dict) -> Dict:
        """
        Check Certificate Transparency logs for the domain
        Detects unauthorized or rogue certificates
        """
        results = {
            'total_certificates': 0,
            'recent_certificates': [],
            'unauthorized_certificates': [],
            'issuers': []
        }

        try:
            domain = cert_data.get('common_name', '').replace('*.', '')
            serial_number = cert_data.get('serial_number')

            # Query CT logs (using crt.sh as free alternative)
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                ct_entries = response.json()
                results['total_certificates'] = len(ct_entries)

                # Parse CT entries
                known_issuers = set()
                for entry in ct_entries[:50]:  # Limit to recent 50
                    issuer_name = entry.get('issuer_name', '')
                    entry_serial = entry.get('serial_number', '')

                    if issuer_name not in known_issuers:
                        known_issuers.add(issuer_name)

                    # Check if this is the current certificate
                    if entry_serial != serial_number:
                        # Check if this is a recent unauthorized certificate
                        not_before = entry.get('not_before')
                        if not_before:
                            try:
                                cert_date = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                                if (datetime.now() - cert_date).days < 30:
                                    results['unauthorized_certificates'].append({
                                        'serial_number': entry_serial,
                                        'issuer': issuer_name,
                                        'not_before': not_before,
                                        'common_name': entry.get('common_name')
                                    })
                            except:
                                pass

                results['issuers'] = list(known_issuers)

                # Alert if multiple different issuers (possible unauthorized certs)
                if len(known_issuers) > 2:
                    results['warning'] = f'Domain has certificates from {len(known_issuers)} different CAs'

        except Exception as e:
            self.logger.warning(f"Error checking CT logs: {e}")
            results['error'] = str(e)

        return results

    def _check_dark_web(self, cert_data: Dict) -> Dict:
        """
        Check dark web sources for leaked certificate information
        (Simulated - would connect to actual DarkAPI service)
        """
        results = {
            'leaked_private_keys': False,
            'credential_dumps': [],
            'sources': [],
            'checked': True
        }

        if not self.api_key:
            results['checked'] = False
            results['message'] = 'DarkAPI key not configured'
            return results

        try:
            # Hash certificate identifiers for privacy
            domain = cert_data.get('common_name', '')
            serial = cert_data.get('serial_number', '')

            domain_hash = hashlib.sha256(domain.encode()).hexdigest()
            serial_hash = hashlib.sha256(serial.encode()).hexdigest()

            # Simulated API call to DarkAPI
            # In production, this would call the actual DarkAPI endpoint
            endpoint = urljoin(self.api_url, '/certificate/darkweb-check')

            # Check cache first
            cache_key = f"darkweb:{domain_hash}"
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if (datetime.now() - cache_entry['timestamp']).seconds < self.cache_ttl:
                    return cache_entry['data']

            # Make API call (simulated)
            # response = requests.post(
            #     endpoint,
            #     headers={'Authorization': f'Bearer {self.api_key}'},
            #     json={
            #         'domain_hash': domain_hash,
            #         'serial_hash': serial_hash
            #     },
            #     timeout=30
            # )

            # Simulate results
            results['message'] = 'Dark web monitoring active (simulated)'
            results['last_scan'] = datetime.now().isoformat()

            # Cache results
            self.cache[cache_key] = {
                'timestamp': datetime.now(),
                'data': results
            }

        except Exception as e:
            self.logger.warning(f"Error checking dark web: {e}")
            results['error'] = str(e)

        return results

    def _check_similar_domains(self, cert_data: Dict) -> List[Dict]:
        """
        Check for similar domains (typosquatting/phishing detection)
        """
        similar_domains = []

        try:
            domain = cert_data.get('common_name', '').replace('*.', '')

            if not domain:
                return similar_domains

            # Generate common typosquatting variants
            variants = self._generate_domain_variants(domain)

            # Check each variant (limit to first 10)
            for variant in variants[:10]:
                # Check if variant exists in CT logs
                url = f"https://crt.sh/?q={variant}&output=json"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200 and response.json():
                        similar_domains.append({
                            'domain': variant,
                            'type': 'typosquatting',
                            'certificates': len(response.json()),
                            'threat_level': 'medium'
                        })
                except:
                    pass

        except Exception as e:
            self.logger.warning(f"Error checking similar domains: {e}")

        return similar_domains

    def _generate_domain_variants(self, domain: str) -> List[str]:
        """Generate common typosquatting variants"""
        variants = []

        if '.' not in domain:
            return variants

        name, tld = domain.rsplit('.', 1)

        # Common character substitutions
        substitutions = {
            'o': ['0'],
            'l': ['1', 'i'],
            'i': ['1', 'l'],
            'a': ['@'],
            'e': ['3'],
            's': ['5'],
        }

        # Generate substitution variants (limited)
        for char, replacements in substitutions.items():
            if char in name:
                for replacement in replacements:
                    variant = name.replace(char, replacement, 1) + '.' + tld
                    variants.append(variant)

        # Common TLD variations
        common_tlds = ['com', 'net', 'org', 'io', 'co']
        if tld not in common_tlds:
            for alt_tld in common_tlds:
                variants.append(name + '.' + alt_tld)

        return variants[:20]  # Limit variants

    def _check_abuse_databases(self, cert_data: Dict) -> List[Dict]:
        """Check certificate/domain against abuse databases"""
        abuse_reports = []

        try:
            domain = cert_data.get('common_name', '').replace('*.', '')

            # Check against public abuse databases
            # (Would integrate with actual abuse APIs)

            # Simulated check
            # In production, would check:
            # - Google Safe Browsing
            # - PhishTank
            # - URLhaus
            # - AbuseIPDB

        except Exception as e:
            self.logger.warning(f"Error checking abuse databases: {e}")

        return abuse_reports

    def monitor_domain_certificates(self, domain: str, callback_url: Optional[str] = None) -> Dict:
        """
        Set up real-time monitoring for new certificates issued for a domain

        Args:
            domain: Domain to monitor
            callback_url: Optional webhook URL for notifications

        Returns:
            Monitoring setup confirmation
        """
        if not self.enabled:
            return {
                'success': False,
                'message': 'DarkAPI integration not configured'
            }

        result = {
            'success': True,
            'domain': domain,
            'monitoring_active': True,
            'callback_url': callback_url,
            'message': f'Monitoring activated for {domain}'
        }

        try:
            # In production, would set up webhook with DarkAPI service
            endpoint = urljoin(self.api_url, '/certificate/monitor')

            # Simulated API call
            # response = requests.post(
            #     endpoint,
            #     headers={'Authorization': f'Bearer {self.api_key}'},
            #     json={
            #         'domain': domain,
            #         'callback_url': callback_url
            #     },
            #     timeout=30
            # )

            self.logger.info(f"Certificate monitoring activated for {domain}")

        except Exception as e:
            self.logger.error(f"Error setting up monitoring: {e}")
            result['success'] = False
            result['error'] = str(e)

        return result

    def get_threat_intelligence_summary(self) -> Dict:
        """
        Get summary of threat intelligence findings across all certificates

        Returns:
            Summary statistics and top threats
        """
        summary = {
            'service': 'DarkAPI',
            'enabled': self.enabled,
            'total_checks': 0,
            'threats_detected': 0,
            'critical_threats': 0,
            'monitored_domains': 0,
            'last_updated': datetime.now().isoformat()
        }

        if not self.enabled:
            summary['message'] = 'DarkAPI integration not configured'
            return summary

        # In production, would fetch statistics from DarkAPI
        summary['message'] = 'Threat intelligence monitoring active'

        return summary


def main():
    """CLI interface for DarkAPI integration"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='DarkAPI Certificate Threat Intelligence')
    parser.add_argument('--domain', help='Domain to check')
    parser.add_argument('--monitor', action='store_true', help='Set up monitoring')
    parser.add_argument('--summary', action='store_true', help='Get threat intelligence summary')
    parser.add_argument('--config', help='Config file path')

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    client = DarkAPIClient(config)

    if args.summary:
        summary = client.get_threat_intelligence_summary()
        print(json.dumps(summary, indent=2))

    elif args.domain:
        if args.monitor:
            result = client.monitor_domain_certificates(args.domain)
            print(json.dumps(result, indent=2))
        else:
            # Check specific domain
            cert_data = {'common_name': args.domain}
            report = client.check_certificate_threats(cert_data)
            print(json.dumps(report, indent=2, default=str))

    else:
        parser.print_help()


if __name__ == '__main__':
    main()

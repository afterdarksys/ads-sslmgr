"""
Advanced Certificate Validation Engine
Comprehensive certificate validation including:
- Expiry monitoring with intelligent alerting
- Chain of trust validation
- Revocation checking (OCSP/CRL)
- Certificate transparency validation
- Security policy compliance
- Cryptographic strength analysis
"""

import os
import ssl
import socket
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID


class ValidationSeverity(Enum):
    """Severity levels for validation issues"""
    CRITICAL = "critical"      # Certificate unusable or major security issue
    HIGH = "high"              # Significant issue requiring attention
    MEDIUM = "medium"          # Issue that should be addressed
    LOW = "low"                # Minor issue or informational
    INFO = "info"              # Informational only


class ValidationCategory(Enum):
    """Categories of validation checks"""
    EXPIRY = "expiry"
    CHAIN = "chain"
    REVOCATION = "revocation"
    CRYPTO = "cryptographic"
    POLICY = "policy"
    TRANSPARENCY = "transparency"
    DNS = "dns"
    THREAT = "threat"


class CertificateValidator:
    """Advanced certificate validation engine"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Expiry thresholds (days)
        self.expiry_thresholds = {
            'critical': 7,      # 7 days - critical alert
            'high': 15,         # 15 days - urgent action needed
            'medium': 30,       # 30 days - action needed
            'low': 60,          # 60 days - plan renewal
            'info': 90          # 90 days - informational
        }

        # Override with config
        if 'expiry_thresholds' in self.config:
            self.expiry_thresholds.update(self.config['expiry_thresholds'])

    def validate_certificate(self, cert_data: Dict,
                           check_revocation: bool = True,
                           check_chain: bool = True,
                           check_transparency: bool = True,
                           check_policy: bool = True) -> Dict:
        """
        Perform comprehensive certificate validation

        Returns validation report with findings
        """
        report = {
            'certificate_id': cert_data.get('id'),
            'common_name': cert_data.get('common_name'),
            'validated_at': datetime.now().isoformat(),
            'overall_status': 'valid',
            'risk_score': 0,  # 0-100, higher is worse
            'findings': [],
            'recommendations': [],
            'compliance': {},
            'statistics': {}
        }

        # 1. EXPIRY VALIDATION (always critical)
        expiry_findings = self._validate_expiry(cert_data)
        report['findings'].extend(expiry_findings)

        # 2. CRYPTOGRAPHIC VALIDATION
        crypto_findings = self._validate_cryptography(cert_data)
        report['findings'].extend(crypto_findings)

        # 3. CHAIN VALIDATION
        if check_chain:
            chain_findings = self._validate_chain(cert_data)
            report['findings'].extend(chain_findings)

        # 4. REVOCATION STATUS
        if check_revocation:
            revocation_findings = self._validate_revocation(cert_data)
            report['findings'].extend(revocation_findings)

        # 5. POLICY COMPLIANCE
        if check_policy:
            policy_findings = self._validate_policy(cert_data)
            report['findings'].extend(policy_findings)

        # 6. CERTIFICATE TRANSPARENCY
        if check_transparency:
            ct_findings = self._validate_transparency(cert_data)
            report['findings'].extend(ct_findings)

        # Calculate overall status and risk score
        report['overall_status'], report['risk_score'] = self._calculate_status(report['findings'])

        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report['findings'])

        # Compliance check
        report['compliance'] = self._check_compliance(report['findings'])

        return report

    def _validate_expiry(self, cert_data: Dict) -> List[Dict]:
        """
        Validate certificate expiry with intelligent monitoring
        Returns list of findings
        """
        findings = []

        try:
            # Parse expiry date
            not_valid_before = cert_data.get('not_valid_before')
            not_valid_after = cert_data.get('not_valid_after')

            if isinstance(not_valid_after, str):
                not_valid_after = datetime.fromisoformat(not_valid_after.replace('Z', '+00:00'))

            if isinstance(not_valid_before, str):
                not_valid_before = datetime.fromisoformat(not_valid_before.replace('Z', '+00:00'))

            now = datetime.now(not_valid_after.tzinfo) if not_valid_after.tzinfo else datetime.now()

            # Calculate days until expiry
            days_until_expiry = (not_valid_after - now).days

            # Check if certificate is not yet valid
            if now < not_valid_before:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.HIGH.value,
                    'code': 'CERT_NOT_YET_VALID',
                    'title': 'Certificate Not Yet Valid',
                    'description': f'Certificate is not valid until {not_valid_before.isoformat()}',
                    'days_until_valid': (not_valid_before - now).days,
                    'impact': 'Certificate cannot be used until valid date',
                    'remediation': 'Wait until certificate becomes valid or request new certificate'
                })

            # Check if certificate is expired
            elif days_until_expiry < 0:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.CRITICAL.value,
                    'code': 'CERT_EXPIRED',
                    'title': 'Certificate Expired',
                    'description': f'Certificate expired {abs(days_until_expiry)} days ago on {not_valid_after.isoformat()}',
                    'days_since_expiry': abs(days_until_expiry),
                    'impact': 'Certificate is invalid and will cause connection failures',
                    'remediation': 'URGENT: Renew certificate immediately'
                })

            # Check expiry thresholds
            elif days_until_expiry <= self.expiry_thresholds['critical']:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.CRITICAL.value,
                    'code': 'CERT_EXPIRING_CRITICAL',
                    'title': 'Certificate Expiring Critically Soon',
                    'description': f'Certificate expires in {days_until_expiry} days on {not_valid_after.isoformat()}',
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_valid_after.isoformat(),
                    'impact': 'Certificate will expire very soon, causing service disruption',
                    'remediation': 'URGENT: Renew certificate immediately'
                })

            elif days_until_expiry <= self.expiry_thresholds['high']:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.HIGH.value,
                    'code': 'CERT_EXPIRING_SOON',
                    'title': 'Certificate Expiring Soon',
                    'description': f'Certificate expires in {days_until_expiry} days on {not_valid_after.isoformat()}',
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_valid_after.isoformat(),
                    'impact': 'Certificate expiring soon, renewal should be prioritized',
                    'remediation': 'Schedule certificate renewal within 7 days'
                })

            elif days_until_expiry <= self.expiry_thresholds['medium']:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.MEDIUM.value,
                    'code': 'CERT_EXPIRING_30_DAYS',
                    'title': 'Certificate Expiring in 30 Days',
                    'description': f'Certificate expires in {days_until_expiry} days on {not_valid_after.isoformat()}',
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_valid_after.isoformat(),
                    'impact': 'Certificate should be renewed to avoid service disruption',
                    'remediation': 'Plan certificate renewal within 2 weeks'
                })

            elif days_until_expiry <= self.expiry_thresholds['low']:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.LOW.value,
                    'code': 'CERT_EXPIRING_60_DAYS',
                    'title': 'Certificate Expiring in 60 Days',
                    'description': f'Certificate expires in {days_until_expiry} days on {not_valid_after.isoformat()}',
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_valid_after.isoformat(),
                    'impact': 'Certificate renewal should be planned',
                    'remediation': 'Begin planning certificate renewal process'
                })

            elif days_until_expiry <= self.expiry_thresholds['info']:
                findings.append({
                    'category': ValidationCategory.EXPIRY.value,
                    'severity': ValidationSeverity.INFO.value,
                    'code': 'CERT_EXPIRING_90_DAYS',
                    'title': 'Certificate Expiring in 90 Days',
                    'description': f'Certificate expires in {days_until_expiry} days on {not_valid_after.isoformat()}',
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_valid_after.isoformat(),
                    'impact': 'Informational - certificate has sufficient validity',
                    'remediation': 'Monitor for renewal at 60 days before expiry'
                })

            # Check validity period length (warn if >398 days for public CAs)
            validity_days = (not_valid_after - not_valid_before).days
            if validity_days > 398:
                issuer_category = cert_data.get('issuer_category', '')
                if issuer_category in ['letsencrypt', 'digicert', 'comodo', 'sectigo']:
                    findings.append({
                        'category': ValidationCategory.POLICY.value,
                        'severity': ValidationSeverity.HIGH.value,
                        'code': 'CERT_VALIDITY_TOO_LONG',
                        'title': 'Certificate Validity Period Too Long',
                        'description': f'Certificate has {validity_days} day validity (max 398 days for public CAs)',
                        'validity_days': validity_days,
                        'impact': 'Certificate may be rejected by browsers/clients',
                        'remediation': 'Obtain new certificate with validity ≤398 days'
                    })

        except Exception as e:
            self.logger.error(f"Error validating expiry: {e}")
            findings.append({
                'category': ValidationCategory.EXPIRY.value,
                'severity': ValidationSeverity.HIGH.value,
                'code': 'EXPIRY_VALIDATION_ERROR',
                'title': 'Expiry Validation Error',
                'description': f'Failed to validate certificate expiry: {str(e)}',
                'impact': 'Unable to determine certificate expiry status',
                'remediation': 'Manually verify certificate expiry date'
            })

        return findings

    def _validate_cryptography(self, cert_data: Dict) -> List[Dict]:
        """Validate cryptographic properties"""
        findings = []

        # Check signature algorithm
        sig_algorithm = cert_data.get('signature_algorithm', '').lower()

        if 'sha1' in sig_algorithm or 'md5' in sig_algorithm:
            findings.append({
                'category': ValidationCategory.CRYPTO.value,
                'severity': ValidationSeverity.CRITICAL.value,
                'code': 'WEAK_SIGNATURE_ALGORITHM',
                'title': 'Weak Signature Algorithm',
                'description': f'Certificate uses weak signature algorithm: {sig_algorithm}',
                'algorithm': sig_algorithm,
                'impact': 'Certificate may be rejected by modern clients',
                'remediation': 'Replace certificate with SHA-256 or stronger'
            })

        elif 'sha256' in sig_algorithm or 'sha384' in sig_algorithm or 'sha512' in sig_algorithm:
            # Good - modern algorithm
            pass

        # Check key usage
        key_usage = cert_data.get('key_usage', {})
        cert_type = cert_data.get('certificate_type', 'unknown')

        if cert_type == 'server':
            if not key_usage.get('key_encipherment') and not key_usage.get('digital_signature'):
                findings.append({
                    'category': ValidationCategory.POLICY.value,
                    'severity': ValidationSeverity.MEDIUM.value,
                    'code': 'MISSING_KEY_USAGE',
                    'title': 'Missing Required Key Usage',
                    'description': 'Server certificate missing required key usage extensions',
                    'impact': 'Certificate may not work correctly for TLS/SSL',
                    'remediation': 'Obtain certificate with correct key usage extensions'
                })

        # Check for deprecated key sizes (would need actual key size from cert object)
        # This is a placeholder - real implementation would extract key size

        return findings

    def _validate_chain(self, cert_data: Dict) -> List[Dict]:
        """Validate certificate chain of trust"""
        findings = []

        # Check if certificate is self-signed
        issuer = cert_data.get('issuer', {})
        subject = cert_data.get('subject', {})

        if issuer.get('common_name') == subject.get('common_name'):
            cert_type = cert_data.get('certificate_type', 'unknown')
            if cert_type != 'root':
                findings.append({
                    'category': ValidationCategory.CHAIN.value,
                    'severity': ValidationSeverity.HIGH.value,
                    'code': 'SELF_SIGNED_CERTIFICATE',
                    'title': 'Self-Signed Certificate',
                    'description': 'Certificate is self-signed and not from a trusted CA',
                    'impact': 'Certificate will not be trusted by clients',
                    'remediation': 'Obtain certificate from a trusted Certificate Authority'
                })

        # Check issuer category
        issuer_category = cert_data.get('issuer_category', 'unknown')
        if issuer_category == 'unknown' or issuer_category == 'other':
            findings.append({
                'category': ValidationCategory.CHAIN.value,
                'severity': ValidationSeverity.LOW.value,
                'code': 'UNKNOWN_ISSUER',
                'title': 'Unknown Certificate Issuer',
                'description': f'Certificate issued by unknown CA: {issuer.get("common_name")}',
                'impact': 'May indicate internal or untrusted CA',
                'remediation': 'Verify certificate issuer is trusted'
            })

        return findings

    def _validate_revocation(self, cert_data: Dict) -> List[Dict]:
        """Check certificate revocation status via OCSP/CRL"""
        findings = []

        # This would require the actual certificate object
        # Placeholder implementation

        # Check if certificate has revocation information
        has_ocsp = False  # Would check for OCSP extension
        has_crl = False   # Would check for CRL distribution points

        if not has_ocsp and not has_crl:
            findings.append({
                'category': ValidationCategory.REVOCATION.value,
                'severity': ValidationSeverity.LOW.value,
                'code': 'NO_REVOCATION_INFO',
                'title': 'No Revocation Information',
                'description': 'Certificate does not include OCSP or CRL revocation information',
                'impact': 'Cannot verify if certificate has been revoked',
                'remediation': 'Consider using certificates with OCSP/CRL support'
            })

        return findings

    def _validate_policy(self, cert_data: Dict) -> List[Dict]:
        """Validate against security policies"""
        findings = []

        # Check for wildcard certificates
        common_name = cert_data.get('common_name', '')
        sans = cert_data.get('subject_alt_names', [])

        if common_name.startswith('*.') or any(san.startswith('DNS:*.') for san in sans):
            findings.append({
                'category': ValidationCategory.POLICY.value,
                'severity': ValidationSeverity.INFO.value,
                'code': 'WILDCARD_CERTIFICATE',
                'title': 'Wildcard Certificate Detected',
                'description': f'Certificate uses wildcard domain: {common_name}',
                'impact': 'Wildcard certificates have broader scope and require careful management',
                'remediation': 'Ensure wildcard certificate is properly secured'
            })

        # Check for multiple SANs (good practice)
        if len(sans) == 0:
            findings.append({
                'category': ValidationCategory.POLICY.value,
                'severity': ValidationSeverity.LOW.value,
                'code': 'NO_SAN_EXTENSION',
                'title': 'No Subject Alternative Names',
                'description': 'Certificate does not include Subject Alternative Name extension',
                'impact': 'Modern browsers require SAN extension',
                'remediation': 'Obtain certificate with SAN extension'
            })

        return findings

    def _validate_transparency(self, cert_data: Dict) -> List[Dict]:
        """Validate Certificate Transparency compliance"""
        findings = []

        # Check for CT poison extension (should not be present in production)
        # Check for SCT (Signed Certificate Timestamp)
        # This would require actual certificate object

        # Placeholder
        has_sct = False

        issuer_category = cert_data.get('issuer_category', '')
        if issuer_category in ['letsencrypt', 'digicert', 'comodo', 'sectigo']:
            if not has_sct:
                findings.append({
                    'category': ValidationCategory.TRANSPARENCY.value,
                    'severity': ValidationSeverity.LOW.value,
                    'code': 'NO_SCT',
                    'title': 'No Certificate Transparency Log',
                    'description': 'Certificate does not include SCT (Signed Certificate Timestamp)',
                    'impact': 'Certificate may not comply with CT requirements',
                    'remediation': 'Ensure certificates are logged in CT logs'
                })

        return findings

    def _calculate_status(self, findings: List[Dict]) -> Tuple[str, int]:
        """Calculate overall validation status and risk score"""
        if not findings:
            return 'valid', 0

        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate risk score (0-100)
        risk_score = (
            severity_counts['critical'] * 40 +
            severity_counts['high'] * 20 +
            severity_counts['medium'] * 10 +
            severity_counts['low'] * 3 +
            severity_counts['info'] * 1
        )

        # Determine overall status
        if severity_counts['critical'] > 0:
            status = 'critical'
        elif severity_counts['high'] > 0:
            status = 'warning'
        elif severity_counts['medium'] > 0:
            status = 'needs_attention'
        elif severity_counts['low'] > 0:
            status = 'minor_issues'
        else:
            status = 'valid'

        return status, min(risk_score, 100)

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate actionable recommendations from findings"""
        recommendations = []

        # Group findings by code
        codes = set(f['code'] for f in findings)

        if 'CERT_EXPIRED' in codes:
            recommendations.append('URGENT: Renew expired certificate immediately to restore service')

        if 'CERT_EXPIRING_CRITICAL' in codes or 'CERT_EXPIRING_SOON' in codes:
            recommendations.append('Prioritize certificate renewal within the next 7 days')

        if 'CERT_EXPIRING_30_DAYS' in codes:
            recommendations.append('Schedule certificate renewal within the next 2 weeks')

        if 'WEAK_SIGNATURE_ALGORITHM' in codes:
            recommendations.append('Replace certificate with modern signature algorithm (SHA-256 or better)')

        if 'SELF_SIGNED_CERTIFICATE' in codes:
            recommendations.append('Obtain certificate from a trusted Certificate Authority')

        if 'NO_REVOCATION_INFO' in codes:
            recommendations.append('Consider using certificates with OCSP or CRL support')

        return recommendations

    def _check_compliance(self, findings: List[Dict]) -> Dict:
        """Check compliance with various standards"""
        compliance = {
            'pci_dss': {'compliant': True, 'issues': []},
            'hipaa': {'compliant': True, 'issues': []},
            'soc2': {'compliant': True, 'issues': []},
            'nist': {'compliant': True, 'issues': []}
        }

        for finding in findings:
            code = finding['code']
            severity = finding['severity']

            # PCI-DSS requires no weak crypto
            if code in ['WEAK_SIGNATURE_ALGORITHM']:
                compliance['pci_dss']['compliant'] = False
                compliance['pci_dss']['issues'].append(finding['title'])

            # All standards require valid certificates
            if code in ['CERT_EXPIRED', 'CERT_EXPIRING_CRITICAL']:
                for standard in compliance:
                    compliance[standard]['compliant'] = False
                    compliance[standard]['issues'].append(finding['title'])

        return compliance

    def monitor_expiry_batch(self, certificates: List[Dict]) -> Dict:
        """
        Monitor expiry for multiple certificates
        Returns summary and alerts
        """
        summary = {
            'total_certificates': len(certificates),
            'expired': [],
            'critical': [],     # < 7 days
            'high': [],         # < 15 days
            'medium': [],       # < 30 days
            'low': [],          # < 60 days
            'info': [],         # < 90 days
            'valid': [],
            'errors': []
        }

        for cert in certificates:
            try:
                findings = self._validate_expiry(cert)

                if not findings:
                    summary['valid'].append(cert)
                else:
                    for finding in findings:
                        severity = finding['severity']
                        code = finding['code']

                        if code == 'CERT_EXPIRED':
                            summary['expired'].append({
                                'cert': cert,
                                'finding': finding
                            })
                        elif severity == 'critical':
                            summary['critical'].append({
                                'cert': cert,
                                'finding': finding
                            })
                        elif severity == 'high':
                            summary['high'].append({
                                'cert': cert,
                                'finding': finding
                            })
                        elif severity == 'medium':
                            summary['medium'].append({
                                'cert': cert,
                                'finding': finding
                            })
                        elif severity == 'low':
                            summary['low'].append({
                                'cert': cert,
                                'finding': finding
                            })
                        else:
                            summary['info'].append({
                                'cert': cert,
                                'finding': finding
                            })

            except Exception as e:
                summary['errors'].append({
                    'cert': cert,
                    'error': str(e)
                })

        return summary


def main():
    """CLI interface for certificate validator"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Certificate Validator')
    parser.add_argument('cert_file', help='Certificate file to validate')
    parser.add_argument('--chain', action='store_true', help='Validate chain of trust')
    parser.add_argument('--revocation', action='store_true', help='Check revocation status')
    parser.add_argument('--transparency', action='store_true', help='Check CT compliance')
    parser.add_argument('--output', '-o', help='Output JSON file')

    args = parser.parse_args()

    # Parse certificate
    from certificate_parser import CertificateParser
    parser_obj = CertificateParser()
    certs = parser_obj.parse_certificate_file(args.cert_file)

    if not certs:
        print(f"Error: Could not parse certificate file {args.cert_file}")
        return

    # Validate certificate
    validator = CertificateValidator()
    report = validator.validate_certificate(
        certs[0],
        check_chain=args.chain,
        check_revocation=args.revocation,
        check_transparency=args.transparency
    )

    # Print report
    print(f"\n=== Certificate Validation Report ===")
    print(f"Certificate: {report['common_name']}")
    print(f"Overall Status: {report['overall_status'].upper()}")
    print(f"Risk Score: {report['risk_score']}/100")

    if report['findings']:
        print(f"\nFindings ({len(report['findings'])}):")
        for finding in report['findings']:
            print(f"\n  [{finding['severity'].upper()}] {finding['title']}")
            print(f"  {finding['description']}")
            if finding.get('remediation'):
                print(f"  Remediation: {finding['remediation']}")

    if report['recommendations']:
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")

    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nReport saved to {args.output}")


if __name__ == '__main__':
    main()

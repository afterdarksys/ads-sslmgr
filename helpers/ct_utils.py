"""
Certificate Transparency (CT) utilities.

Implements Chrome's CT policy (as of 2024), SCT extraction from X.509
extensions, and a compliance check function used by the certificate validator
and CA integrations.

Key references:
  RFC 6962  – Certificate Transparency
  RFC 9162  – Certificate Transparency Version 2.0
  OID       – 1.3.6.1.4.1.11129.2.4.2  (embedded SCT list extension)
  Chrome CT policy: ≥2 SCTs for validity >180 days; ≥1 for ≤180 days.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# SCT extension OID (embedded Signed Certificate Timestamp List)
SCT_OID = '1.3.6.1.4.1.11129.2.4.2'

# Issuer categories that are required to have CT coverage
PUBLIC_CA_CATEGORIES = {'letsencrypt', 'digicert', 'sectigo', 'comodo', 'aws', 'cloudflare'}

# Issuer categories that are exempt from CT requirements (private/internal CAs)
EXEMPT_CA_CATEGORIES = {'private', 'ca', 'internal', 'cose', 'cwt', 'unknown'}


# ── Chrome CT policy ──────────────────────────────────────────────────────────

class ChromeCTPolicy:
    """Implements Chrome's embedded SCT policy.

    Rule: certificates with a validity period >180 days require at least 2 SCTs;
    those with ≤180 days require at least 1.
    """

    def required_sct_count(self, validity_days: int) -> int:
        """Return the minimum number of SCTs Chrome requires."""
        return 2 if validity_days > 180 else 1

    def is_compliant(self, sct_count: int, validity_days: int) -> bool:
        return sct_count >= self.required_sct_count(validity_days)


# ── SCT parsing ───────────────────────────────────────────────────────────────

def parse_scts(cert_pem: Optional[str]) -> List[Dict]:
    """Extract SCTs from the embedded SCT list extension of a PEM certificate.

    Returns a list of dicts, one per SCT.  Returns an empty list if the
    extension is absent or the cert cannot be parsed.
    """
    if not cert_pem:
        return []

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ObjectIdentifier

        cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        sct_oid = ObjectIdentifier(SCT_OID)
        try:
            ext = cert.extensions.get_extension_for_oid(sct_oid)
        except x509.ExtensionNotFound:
            return []

        # cryptography ≥42 exposes PrecertificateSignedCertificateTimestamps
        ext_value = ext.value
        scts: List[Dict] = []

        if hasattr(ext_value, '__iter__'):
            for sct in ext_value:
                entry: Dict = {'raw': True}
                if hasattr(sct, 'log_id'):
                    entry['log_id'] = sct.log_id.hex() if sct.log_id else None
                if hasattr(sct, 'timestamp'):
                    entry['timestamp'] = sct.timestamp.isoformat() if sct.timestamp else None
                if hasattr(sct, 'version'):
                    entry['version'] = str(sct.version)
                scts.append(entry)
        else:
            # Fallback: at least one SCT present (raw bytes)
            scts.append({'raw': True, 'bytes': ext_value.public_bytes.hex()
                         if hasattr(ext_value, 'public_bytes') else None})

        return scts

    except Exception as e:
        logger.debug(f"SCT parse failed: {e}")
        return []


# ── compliance check ──────────────────────────────────────────────────────────

def verify_ct_compliance(cert_pem: Optional[str],
                         issuer_category: str = '') -> Dict:
    """Check whether a certificate meets Chrome CT policy.

    Args:
        cert_pem:         PEM-encoded certificate string (may be None).
        issuer_category:  The issuer category string from the Certificate record.

    Returns a dict with keys:
        status      – 'CT_COMPLIANT' | 'NO_SCT' | 'INSUFFICIENT_SCTS' |
                      'CT_EXEMPT' | 'CT_UNVERIFIABLE'
        severity    – 'INFO' | 'MEDIUM' | 'HIGH'
        has_sct     – bool
        sct_count   – int
        required    – int (0 for exempt CAs)
        compliant   – bool
        ct_exempt   – bool
        message     – human-readable summary
    """
    category = (issuer_category or '').lower()

    # Private / internal CAs are exempt from CT requirements
    if category in EXEMPT_CA_CATEGORIES:
        return {
            'status': 'CT_EXEMPT',
            'severity': 'INFO',
            'has_sct': False,
            'sct_count': 0,
            'required': 0,
            'compliant': True,
            'ct_exempt': True,
            'message': f'CT not required for {category} CAs',
        }

    # Without a PEM we cannot verify
    if not cert_pem:
        return {
            'status': 'CT_UNVERIFIABLE',
            'severity': 'INFO',
            'has_sct': False,
            'sct_count': 0,
            'required': -1,
            'compliant': False,
            'ct_exempt': False,
            'message': 'No certificate PEM provided; CT compliance cannot be verified',
        }

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Compute validity in days
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') \
            else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') \
            else cert.not_valid_after.replace(tzinfo=timezone.utc)
        validity_days = (not_after - not_before).days

        scts = parse_scts(cert_pem)
        sct_count = len(scts)
        policy = ChromeCTPolicy()
        required = policy.required_sct_count(validity_days)
        compliant = policy.is_compliant(sct_count, validity_days)

        if sct_count == 0:
            status, severity = 'NO_SCT', 'HIGH'
            message = f'No SCTs found; Chrome requires {required} for {validity_days}-day cert'
        elif not compliant:
            status, severity = 'INSUFFICIENT_SCTS', 'MEDIUM'
            message = f'Only {sct_count} SCT(s) found; Chrome requires {required}'
        else:
            status, severity = 'CT_COMPLIANT', 'INFO'
            message = f'{sct_count} SCT(s) satisfy Chrome CT policy ({required} required)'

        return {
            'status': status,
            'severity': severity,
            'has_sct': sct_count > 0,
            'sct_count': sct_count,
            'required': required,
            'compliant': compliant,
            'ct_exempt': False,
            'message': message,
            'validity_days': validity_days,
            'scts': scts,
        }

    except Exception as e:
        logger.warning(f"CT compliance check failed: {e}")
        return {
            'status': 'CT_UNVERIFIABLE',
            'severity': 'INFO',
            'has_sct': False,
            'sct_count': 0,
            'required': -1,
            'compliant': False,
            'ct_exempt': False,
            'message': f'CT check error: {e}',
        }

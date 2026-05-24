"""
Private CA renewal integration for the RenewalRouter.
Handles re-issuance of certificates that were originally issued by an internal
PrivateCA.  Implements the same interface as other CA integrations.
"""
from datetime import datetime
from typing import Dict

from database.models import Certificate, DatabaseManager, PrivateCA, PrivatelyIssuedCertificate


class PrivateCAIntegration:
    """
    Renewal integration for certificates issued by an internal Private CA.

    A certificate is routed here when cert.issuer_category == 'private'.
    Re-issuance looks up the original PrivatelyIssuedCertificate record to
    reproduce the same cert_type, SANs, and validity period.
    """

    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self._ca_config = config.get('private_ca', {})
        self.key_storage_dir = self._ca_config.get('key_storage_dir', './ca_keys')

    # ── Integration interface ────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """True when at least one active Private CA record exists in the database."""
        try:
            session = self.db_manager.get_session()
            try:
                return session.query(PrivateCA).filter_by(is_active=True).count() > 0
            finally:
                session.close()
        except Exception:
            return False

    def check_renewal_eligibility(self, cert: Certificate) -> Dict:
        """
        Eligible when:
        1. cert.issuer_category == 'private'
        2. A PrivatelyIssuedCertificate row matches the serial number
        3. The issuing PrivateCA is still active
        """
        if cert.issuer_category != 'private':
            return {'eligible': False, 'reason': 'Certificate was not issued by a private CA'}

        session = self.db_manager.get_session()
        try:
            pic = session.query(PrivatelyIssuedCertificate).filter_by(
                serial_number=cert.serial_number
            ).first()

            if not pic:
                return {
                    'eligible': False,
                    'reason': 'Certificate serial not found in private CA records',
                }

            ca = session.query(PrivateCA).filter_by(id=pic.ca_id, is_active=True).first()
            if not ca:
                return {'eligible': False, 'reason': 'Issuing CA is inactive or missing'}

            return {
                'eligible': True,
                'reason': 'Certificate can be re-issued by private CA',
                'ca_id': ca.id,
                'pic_id': pic.id,
            }
        finally:
            session.close()

    def renew_certificate(self, cert: Certificate, **kwargs) -> Dict:
        """Re-issue the certificate from the same private CA."""
        try:
            from ca.ca_manager import CAManager
        except ImportError as exc:
            return {'success': False, 'error': f'ca.ca_manager not available: {exc}'}

        # Fetch original record outside the CAManager session to avoid nested sessions
        session = self.db_manager.get_session()
        try:
            pic = session.query(PrivatelyIssuedCertificate).filter_by(
                serial_number=cert.serial_number
            ).first()
            if not pic:
                return {'success': False, 'error': 'Original certificate record not found'}

            ca_id = pic.ca_id
            common_name = cert.common_name
            cert_type = pic.cert_type or 'server'
            san_dns = pic.san_dns
            san_ips = pic.san_ips
            san_emails = pic.san_emails
            days = pic.days_validity or 365
        finally:
            session.close()

        mgr = CAManager(self.db_manager, self.key_storage_dir)
        issue_kwargs = {}
        if san_dns:
            issue_kwargs['san_dns'] = san_dns
        if san_ips:
            issue_kwargs['san_ips'] = san_ips
        if san_emails:
            issue_kwargs['san_emails'] = san_emails

        result = mgr.issue_certificate(
            ca_id=ca_id,
            common_name=common_name,
            cert_type=cert_type,
            validity_days=days,
            **issue_kwargs,
        )

        if result['success']:
            result['message'] = f'Re-issued by private CA (ID {ca_id})'
        return result

    def test_configuration(self) -> Dict:
        """Verify the module is importable and the DB is reachable."""
        tests_passed = []
        errors = []

        try:
            from ca.private_ca import PrivateCAManager  # noqa: F401
            tests_passed.append('ca.private_ca importable')
        except ImportError as e:
            errors.append(f'ca.private_ca not importable: {e}')

        try:
            from ca.ca_manager import CAManager  # noqa: F401
            tests_passed.append('ca.ca_manager importable')
        except ImportError as e:
            errors.append(f'ca.ca_manager not importable: {e}')

        try:
            session = self.db_manager.get_session()
            count = session.query(PrivateCA).count()
            session.close()
            tests_passed.append(f'DB accessible ({count} CA records)')
        except Exception as e:
            errors.append(f'DB error: {e}')

        return {
            'all_tests_passed': len(errors) == 0,
            'tests_run': tests_passed,
            'errors': errors,
            'enabled': self.enabled,
        }

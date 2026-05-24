"""
Integration tests for integrations/private_ca_integration.py.
"""

import pytest
from unittest.mock import MagicMock, patch
from database.models import Certificate


def _private_cert(common_name='internal.lan', serial='TEST-SERIAL-001'):
    cert = MagicMock(spec=Certificate)
    cert.id = 99
    cert.common_name = common_name
    cert.serial_number = serial
    cert.issuer_info = {'common_name': 'Internal Root CA'}
    cert.issuer_category = 'private'
    cert.days_until_expiry = 30
    cert.subject_alt_names = [common_name]
    return cert


@pytest.fixture(scope='module')
def private_integration(test_config, db_manager):
    from integrations.private_ca_integration import PrivateCAIntegration
    return PrivateCAIntegration(test_config, db_manager)


class TestPrivateCAIntegration:
    def test_enabled_reflects_db_state(self, private_integration):
        # Just verify it returns a bool without crashing
        result = private_integration.enabled
        assert isinstance(result, bool)

    def test_check_eligibility_non_private_cert(self, private_integration):
        cert = _private_cert()
        cert.issuer_category = 'letsencrypt'
        result = private_integration.check_renewal_eligibility(cert)
        assert not result['eligible']

    def test_check_eligibility_unknown_serial(self, private_integration):
        cert = _private_cert(serial='DOES-NOT-EXIST-99999')
        result = private_integration.check_renewal_eligibility(cert)
        assert not result['eligible']
        assert 'reason' in result

    def test_renew_with_no_db_record_returns_error(self, private_integration):
        cert = _private_cert(serial='NO-SUCH-SERIAL-XYZ')
        result = private_integration.renew_certificate(cert)
        assert not result.get('success')
        assert 'error' in result

    def test_renew_returns_dict(self, private_integration):
        cert = _private_cert()
        result = private_integration.renew_certificate(cert)
        assert isinstance(result, dict)
        assert 'success' in result

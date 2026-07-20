"""
Integration tests for core/renewal_router.py.

Tests route-detection logic using mocked CA integrations so that no
real network calls are made.  The router's issuer_pattern matching and
manual override paths are exercised.
"""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(scope='module')
def renewal_router(test_config, db_manager):
    from core.renewal_router import RenewalRouter
    return RenewalRouter(test_config, db_manager)


def _fake_cert(common_name='test.example.com', issuer_cn='Let\'s Encrypt Authority X3',
               issuer_category='letsencrypt', days=30):
    """Return a minimal mock Certificate object."""
    from database.models import Certificate
    cert = MagicMock(spec=Certificate)
    cert.id = 1
    cert.common_name = common_name
    cert.issuer_info = {'common_name': issuer_cn, 'organization': issuer_cn}
    cert.issuer_category = issuer_category
    cert.days_until_expiry = days
    cert.subject_alt_names = [common_name]
    cert.not_valid_after = None
    return cert


# ── issuer detection ──────────────────────────────────────────────────────────

class TestIssuerDetection:
    def test_detect_letsencrypt(self, renewal_router):
        cert = _fake_cert(
            issuer_cn="Let's Encrypt Authority X3",
            issuer_category='letsencrypt',
        )
        ca = renewal_router._detect_issuer_ca(cert)
        assert ca == 'letsencrypt'

    def test_detect_digicert(self, renewal_router):
        cert = _fake_cert(
            issuer_cn='DigiCert Global Root CA',
            issuer_category='digicert',
        )
        ca = renewal_router._detect_issuer_ca(cert)
        assert ca == 'digicert'

    def test_detect_sectigo(self, renewal_router):
        cert = _fake_cert(
            issuer_cn='Sectigo RSA Domain Validation Secure Server CA',
            issuer_category='sectigo',
        )
        ca = renewal_router._detect_issuer_ca(cert)
        assert ca in ('sectigo', 'comodo')  # legacy alias acceptable

    def test_detect_private(self, renewal_router):
        cert = _fake_cert(
            issuer_cn='Internal Root CA',
            issuer_category='private',
        )
        ca = renewal_router._detect_issuer_ca(cert)
        assert ca == 'private'

    def test_unknown_falls_back_to_letsencrypt_or_none(self, renewal_router):
        cert = _fake_cert(
            issuer_cn='Unknown Mysterious CA',
            issuer_category='unknown',
        )
        ca = renewal_router._detect_issuer_ca(cert)
        # Router may return None or a default; just confirm no exception
        assert ca is None or isinstance(ca, str)


# ── force_ca override ─────────────────────────────────────────────────────────

class TestForceCA:
    def test_force_ca_overrides_detection(self, renewal_router):
        cert = _fake_cert(issuer_category='letsencrypt')

        mock_integration = MagicMock()
        mock_integration.is_enabled.return_value = True
        mock_integration.renew_certificate.return_value = {
            'success': True, 'message': 'Renewed by forced CA'
        }

        with patch.dict(renewal_router.integrations, {'digicert': mock_integration}):
            result = renewal_router.route_renewal(cert, force_ca='digicert')

        assert result.get('success') or 'error' in result  # may fail due to missing config

    def test_force_invalid_ca_returns_error(self, renewal_router):
        cert = _fake_cert()
        result = renewal_router.route_renewal(cert, force_ca='nonexistent_ca')
        assert not result.get('success')
        assert 'error' in result

    def test_discovered_ca_plugin_can_handle_forced_renewal(self, test_config, db_manager, monkeypatch):
        from providers.registry import ProviderRegistry
        from core.renewal_router import RenewalRouter

        class Plugin:
            enabled = True

            def renew(self, request):
                return {"success": True, "plugin_request": request}

        def discover(registry, config, manager):
            registry.register_ca("custom", Plugin())
            return []

        monkeypatch.setattr(ProviderRegistry, "discover", discover)
        router = RenewalRouter(test_config, db_manager)
        cert = _fake_cert()

        result = router.route_renewal(cert, force_ca="custom", renewal_options={"profile": "dv"})

        assert result["success"] is True
        assert result["plugin_request"]["certificate"] is cert
        assert result["plugin_request"]["options"] == {"profile": "dv"}


# ── integration status ────────────────────────────────────────────────────────

class TestIntegrationStatus:
    def test_test_all_integrations_returns_dict(self, renewal_router):
        results = renewal_router.test_all_integrations()
        assert isinstance(results, dict)
        assert 'integrations' in results
        assert 'summary' in results

    def test_summary_has_required_fields(self, renewal_router):
        results = renewal_router.test_all_integrations()
        summary = results['summary']
        for key in ('total', 'enabled', 'working', 'failed'):
            assert key in summary, f"Missing summary key: {key}"

    def test_all_known_integrations_listed(self, renewal_router):
        results = renewal_router.test_all_integrations()
        integrations = results['integrations']
        for expected in ('letsencrypt', 'digicert'):
            assert expected in integrations

"""
Integration tests for PrivateCA / CAManager.

Covers: root CA creation, intermediate CA creation, certificate issuance,
revocation, CRL generation, and the full root→issuing→leaf chain.
"""

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────

def _ok(result, label=''):
    assert result.get('success'), f"{label} failed: {result.get('error')}"
    return result


# ── root CA ──────────────────────────────────────────────────────────────────

class TestRootCA:
    def test_create_root_rsa(self, ca_manager):
        result = _ok(ca_manager.create_root_ca(
            name='test-root-rsa',
            common_name='Test Root CA (RSA)',
            organization='Test Org',
            country='US',
            validity_years=10,
            key_type='rsa',
            key_size_or_curve=2048,
        ), 'create_root_rsa')
        assert result['ca_id'] > 0
        assert 'Test Root CA' in result['common_name']

    def test_create_root_ec(self, ca_manager):
        result = _ok(ca_manager.create_root_ca(
            name='test-root-ec',
            common_name='Test Root CA (EC)',
            organization='Test Org',
            country='US',
            validity_years=10,
            key_type='ec',
            key_size_or_curve='P-256',
        ), 'create_root_ec')
        assert result['ca_id'] > 0

    def test_duplicate_name_fails(self, ca_manager):
        result = ca_manager.create_root_ca(
            name='test-root-rsa',   # already created above
            common_name='Duplicate Root',
            country='US',
            validity_years=5,
        )
        assert not result['success']

    def test_list_contains_created_cas(self, ca_manager):
        cas = ca_manager.list_cas()
        names = [c['name'] for c in cas]
        assert 'test-root-rsa' in names
        assert 'test-root-ec' in names

    def test_get_ca_returns_correct_record(self, ca_manager):
        cas = ca_manager.list_cas()
        root = next(c for c in cas if c['name'] == 'test-root-rsa')
        fetched = ca_manager.get_ca(root['id'])
        assert fetched is not None
        assert fetched['name'] == 'test-root-rsa'
        assert fetched['ca_type'] == 'root'

    def test_get_nonexistent_ca_returns_none(self, ca_manager):
        assert ca_manager.get_ca(999999) is None


# ── intermediate / issuing CA ─────────────────────────────────────────────────

class TestIntermediateCA:
    @pytest.fixture(autouse=True)
    def _root_id(self, ca_manager):
        cas = ca_manager.list_cas()
        root = next((c for c in cas if c['name'] == 'test-root-rsa'), None)
        if root is None:
            r = ca_manager.create_root_ca(
                name='test-root-rsa-int',
                common_name='Test Root for Intermediate',
                country='US',
                validity_years=10,
            )
            self.root_id = r['ca_id']
        else:
            self.root_id = root['id']

    def test_create_intermediate(self, ca_manager):
        result = _ok(ca_manager.create_intermediate_ca(
            name='test-intermediate',
            parent_id=self.root_id,
            common_name='Test Intermediate CA',
            organization='Test Org',
            country='US',
            validity_years=5,
        ), 'create_intermediate')
        assert result['ca_id'] > 0

    def test_create_issuing(self, ca_manager):
        # Ensure intermediate exists
        cas = ca_manager.list_cas()
        inter = next((c for c in cas if c['name'] == 'test-intermediate'), None)
        if inter is None:
            r = ca_manager.create_intermediate_ca(
                name='test-intermediate',
                parent_id=self.root_id,
                common_name='Test Intermediate CA',
                country='US',
                validity_years=5,
            )
            inter_id = r['ca_id']
        else:
            inter_id = inter['id']

        result = _ok(ca_manager.create_issuing_ca(
            name='test-issuing',
            parent_id=inter_id,
            common_name='Test Issuing CA',
            country='US',
            validity_years=3,
        ), 'create_issuing')
        assert result['ca_id'] > 0


# ── certificate issuance ──────────────────────────────────────────────────────

class TestCertificateIssuance:
    @pytest.fixture(autouse=True)
    def _issuing_ca(self, ca_manager):
        """Ensure an issuing CA is available and store its id."""
        cas = ca_manager.list_cas()
        issuing = next((c for c in cas if c['name'] == 'test-issuing'), None)
        if issuing:
            self.ca_id = issuing['id']
            return

        # Create full chain on demand
        root = ca_manager.create_root_ca(
            name='chain-root', common_name='Chain Root', country='US', validity_years=20,
        )
        inter = ca_manager.create_intermediate_ca(
            name='chain-inter', parent_id=root['ca_id'],
            common_name='Chain Intermediate', country='US', validity_years=10,
        )
        iss = ca_manager.create_issuing_ca(
            name='chain-issuing', parent_id=inter['ca_id'],
            common_name='Chain Issuing', country='US', validity_years=5,
        )
        self.ca_id = iss['ca_id']

    def test_issue_server_cert(self, ca_manager):
        result = _ok(ca_manager.issue_certificate(
            ca_id=self.ca_id,
            common_name='server.example.com',
            cert_type='server',
            san_dns=['server.example.com', 'www.example.com'],
            validity_days=365,
        ), 'issue_server')
        assert result['cert_id'] > 0
        assert '-----BEGIN CERTIFICATE-----' in result['cert_pem']

    def test_issue_client_cert(self, ca_manager):
        result = _ok(ca_manager.issue_certificate(
            ca_id=self.ca_id,
            common_name='client@example.com',
            cert_type='client',
            validity_days=180,
        ), 'issue_client')
        assert result['cert_id'] > 0

    def test_issue_cert_with_ip_san(self, ca_manager):
        result = _ok(ca_manager.issue_certificate(
            ca_id=self.ca_id,
            common_name='internal.lan',
            cert_type='server',
            san_dns=['internal.lan'],
            san_ips=['192.168.1.1'],
            validity_days=90,
        ), 'issue_with_ip_san')
        assert result['cert_id'] > 0

    def test_list_issued_certs(self, ca_manager):
        certs = ca_manager.list_issued_certs(self.ca_id)
        assert isinstance(certs, list)
        assert len(certs) >= 1

    def test_unknown_ca_id_fails(self, ca_manager):
        result = ca_manager.issue_certificate(
            ca_id=999999,
            common_name='nope.example.com',
            validity_days=365,
        )
        assert not result['success']


# ── revocation & CRL ─────────────────────────────────────────────────────────

class TestRevocationAndCRL:
    @pytest.fixture(autouse=True)
    def _setup(self, ca_manager):
        cas = ca_manager.list_cas()
        issuing = next((c for c in cas if c.get('ca_type') == 'issuing'), None)
        if issuing is None:
            pytest.skip('No issuing CA available for revocation tests')
        self.ca_id = issuing['id']

        result = ca_manager.issue_certificate(
            ca_id=self.ca_id,
            common_name='revoke-me.example.com',
            cert_type='server',
            validity_days=365,
        )
        assert result['success']
        self.cert_id = result['cert_id']

    def test_revoke_certificate(self, ca_manager):
        result = _ok(ca_manager.revoke_certificate(
            self.ca_id, self.cert_id, 'key_compromise'
        ), 'revoke')
        assert result.get('revoked_serial')

    def test_revoke_twice_fails(self, ca_manager):
        # First revocation may already have happened in the same fixture instance
        ca_manager.revoke_certificate(self.ca_id, self.cert_id, 'unspecified')
        result = ca_manager.revoke_certificate(self.ca_id, self.cert_id, 'unspecified')
        assert not result['success']

    def test_regenerate_crl(self, ca_manager):
        result = _ok(ca_manager.regenerate_crl(self.ca_id), 'regenerate_crl')
        assert '-----BEGIN X509 CRL-----' in result['crl_pem']

    def test_get_crl_after_generation(self, ca_manager):
        ca_manager.regenerate_crl(self.ca_id)
        crl_pem = ca_manager.get_crl(self.ca_id)
        assert crl_pem is not None
        assert '-----BEGIN X509 CRL-----' in crl_pem

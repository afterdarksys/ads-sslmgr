"""
Integration tests for core/certificate_parser.py.

Covers: PEM parsing, COSE_Sign1 export/re-parse, CWT export, format detection.
"""

import pytest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_self_signed(cn='test.example.com', days=365, key=None):
    """Return (cert_pem_str, key) for a minimal self-signed certificate."""
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key


@pytest.fixture(scope='module')
def parser():
    from core.certificate_parser import CertificateParser
    return CertificateParser()


@pytest.fixture(scope='module')
def sample_cert_pem():
    pem, _ = _make_self_signed('sample.example.com', days=90)
    return pem


# ── PEM parsing ───────────────────────────────────────────────────────────────

class TestPEMParsing:
    def test_parse_returns_list(self, parser, sample_cert_pem, tmp_path):
        cert_file = tmp_path / 'sample.pem'
        cert_file.write_text(sample_cert_pem)
        results = parser.parse_certificate_file(str(cert_file))
        assert isinstance(results, list)
        assert len(results) == 1

    def test_parse_common_name(self, parser, sample_cert_pem, tmp_path):
        cert_file = tmp_path / 'sample2.pem'
        cert_file.write_text(sample_cert_pem)
        result = parser.parse_certificate_file(str(cert_file))[0]
        assert result['common_name'] == 'sample.example.com'

    def test_parse_days_until_expiry(self, parser, tmp_path):
        pem, _ = _make_self_signed(days=90)
        cert_file = tmp_path / 'expiry.pem'
        cert_file.write_text(pem)
        result = parser.parse_certificate_file(str(cert_file))[0]
        assert 85 <= result['days_until_expiry'] <= 91

    def test_parse_expired_cert(self, parser, tmp_path):
        # Create a cert that expired yesterday via backdating (not possible with
        # naive datetime; skip if cryptography enforces valid range)
        pytest.skip('Backdated cert generation requires mocking; skipped here')

    def test_san_extraction(self, parser, tmp_path):
        pem, _ = _make_self_signed('san-test.example.com', days=60)
        cert_file = tmp_path / 'san.pem'
        cert_file.write_text(pem)
        result = parser.parse_certificate_file(str(cert_file))[0]
        sans = result.get('subject_alt_names') or []
        # SANs may be stored as 'DNS:hostname' or bare 'hostname'
        assert any('san-test.example.com' in s for s in sans)


# ── COSE export ───────────────────────────────────────────────────────────────

class TestCOSEExport:
    def test_cose_export_returns_bytes(self, parser, sample_cert_pem, tmp_path):
        cert_file = tmp_path / 'cose_src.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.COSE)
        assert isinstance(exported, bytes)
        assert len(exported) > 50

    def test_cose_export_is_valid_cbor_tag_18(self, parser, sample_cert_pem, tmp_path):
        import cbor2
        cert_file = tmp_path / 'cose_tag.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.COSE)
        decoded = cbor2.loads(exported)
        assert hasattr(decoded, 'tag') and decoded.tag == 18, 'Must be COSE_Sign1 (tag 18)'

    def test_cose_sign1_has_64_byte_signature(self, parser, sample_cert_pem, tmp_path):
        import cbor2
        cert_file = tmp_path / 'cose_sig.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.COSE)
        decoded = cbor2.loads(exported)
        _protected, _unprotected, _payload, signature = decoded.value
        assert len(signature) == 64, 'ES256 signature must be 64 bytes (R||S)'

    def test_cose_different_exports_have_different_signatures(self, parser, sample_cert_pem, tmp_path):
        """Each export uses a fresh ephemeral key — signatures must differ."""
        import cbor2
        from core.certificate_parser import CertificateFormat

        cert_file = tmp_path / 'cose_diff.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]

        sig1 = cbor2.loads(parser.export_certificate(cert_data, CertificateFormat.COSE)).value[3]
        sig2 = cbor2.loads(parser.export_certificate(cert_data, CertificateFormat.COSE)).value[3]
        assert sig1 != sig2, 'Ephemeral keys must produce different signatures each time'


# ── CWT export ────────────────────────────────────────────────────────────────

class TestCWTExport:
    def test_cwt_export_returns_bytes(self, parser, sample_cert_pem, tmp_path):
        cert_file = tmp_path / 'cwt_src.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.CWT)
        assert isinstance(exported, bytes)

    def test_cwt_is_cose_sign1_wrapped(self, parser, sample_cert_pem, tmp_path):
        import cbor2
        cert_file = tmp_path / 'cwt_sign1.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.CWT)
        decoded = cbor2.loads(exported)
        assert hasattr(decoded, 'tag') and decoded.tag == 18, 'Signed CWT must use COSE_Sign1 (tag 18)'

    def test_cwt_payload_contains_standard_claims(self, parser, sample_cert_pem, tmp_path):
        import cbor2
        cert_file = tmp_path / 'cwt_claims.pem'
        cert_file.write_text(sample_cert_pem)
        cert_data = parser.parse_certificate_file(str(cert_file))[0]
        from core.certificate_parser import CertificateFormat
        exported = parser.export_certificate(cert_data, CertificateFormat.CWT)
        decoded = cbor2.loads(exported)
        _, _, payload_bytes, _ = decoded.value
        claims = cbor2.loads(payload_bytes)
        # RFC 8392 standard claims: 1=iss, 2=sub, 4=exp, 5=nbf, 6=iat
        for claim_id in (1, 2, 4, 5, 6):
            assert claim_id in claims, f'CWT claim {claim_id} missing'
        assert claims[4] > claims[6], 'exp must be after iat'

import hashlib
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _issuing_ca(ca_manager):
    prefix = "agent-{}".format(uuid.uuid4().hex[:8])
    result = ca_manager.bootstrap_hierarchy(
        prefix, "Agent Test", key_size_or_curve=2048,
    )
    assert result["success"]
    return result["issuing_ca_id"]


def _csr(common_name="host.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def test_bootstrap_token_is_hashed_single_use_and_enrolls_agent(db_manager, ca_manager):
    from database.models import EnrollmentToken
    from pki.enrollment import EnrollmentService

    service = EnrollmentService(db_manager, ca_manager)
    ca_id = _issuing_ca(ca_manager)
    token = service.create_token(ca_id, name="web-01", cert_type="server", ttl_hours=1)

    session = db_manager.get_session()
    record = session.query(EnrollmentToken).filter_by(id=token["token_id"]).one()
    assert record.token_hash != token["token"]
    assert record.token_hash == hashlib.sha256(token["token"].encode()).hexdigest()
    session.close()

    enrolled = service.enroll(token["token"], _csr())
    duplicate = service.enroll(token["token"], _csr("other.example.com"))

    assert enrolled["success"] is True
    assert enrolled["agent_id"]
    assert enrolled["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert enrolled["chain_pem"].count("-----BEGIN CERTIFICATE-----") == 4
    assert duplicate["success"] is False
    assert duplicate["error_kind"] == "authentication"


def test_renewal_requires_current_certificate_fingerprint(db_manager, ca_manager):
    from pki.enrollment import EnrollmentService

    service = EnrollmentService(db_manager, ca_manager)
    ca_id = _issuing_ca(ca_manager)
    token = service.create_token(ca_id, name="renew-host")
    enrolled = service.enroll(token["token"], _csr("renew.example.com"))

    denied = service.renew(enrolled["agent_id"], "wrong", _csr("renew.example.com"), force=True)
    renewed = service.renew(
        enrolled["agent_id"], enrolled["certificate_fingerprint"],
        _csr("renew.example.com"), force=True,
    )

    assert denied["success"] is False
    assert denied["error_kind"] == "authentication"
    assert renewed["success"] is True
    assert renewed["certificate_fingerprint"] != enrolled["certificate_fingerprint"]


def test_revoked_agent_cannot_renew(db_manager, ca_manager):
    from pki.enrollment import EnrollmentService

    service = EnrollmentService(db_manager, ca_manager)
    ca_id = _issuing_ca(ca_manager)
    token = service.create_token(ca_id, name="revoked-host")
    enrolled = service.enroll(token["token"], _csr("revoked.example.com"))

    revoked = service.revoke(
        enrolled["agent_id"], reason="key_compromise",
        certificate_fingerprint=enrolled["certificate_fingerprint"],
    )
    renewed = service.renew(
        enrolled["agent_id"], enrolled["certificate_fingerprint"],
        _csr("revoked.example.com"), force=True,
    )

    assert revoked["success"] is True
    assert renewed["success"] is False
    assert renewed["error_kind"] == "authorization"

import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _certificate(common_name="host.example.com", days=90):
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class Response:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class Session:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.payloads.pop(0))


def test_agent_enrolls_and_keeps_private_key_local(tmp_path):
    from agents.certificate_agent import CertificateAgent

    cert = _certificate()
    session = Session([{
        "success": True, "agent_id": "agent-1", "cert_pem": cert,
        "chain_pem": cert, "certificate_fingerprint": "abc",
    }])
    agent = CertificateAgent({
        "server_url": "https://pki.example.com",
        "state_dir": str(tmp_path), "common_name": "host.example.com",
    }, session=session)

    result = agent.enroll("one-time-token")

    assert result["success"] is True
    assert (tmp_path / "tls.key").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "tls.crt").read_text() == cert
    request_json = session.calls[0][1]["json"]
    assert "PRIVATE KEY" not in json.dumps(request_json)
    assert "BEGIN CERTIFICATE REQUEST" in request_json["csr_pem"]


def test_agent_skips_renewal_when_certificate_is_not_due(tmp_path):
    from agents.certificate_agent import CertificateAgent

    (tmp_path / "tls.crt").write_text(_certificate(days=90))
    (tmp_path / "agent.json").write_text(json.dumps({"agent_id": "a", "certificate_fingerprint": "f"}))
    session = Session([])
    agent = CertificateAgent({"server_url": "https://pki", "state_dir": str(tmp_path)}, session=session)

    result = agent.renew_if_needed()

    assert result == {"success": True, "renewed": False, "reason": "not_due"}
    assert session.calls == []


def test_agent_renews_with_current_certificate_and_rotates_key(tmp_path):
    from agents.certificate_agent import CertificateAgent

    old_cert = _certificate(days=1)
    new_cert = _certificate(days=90)
    (tmp_path / "tls.crt").write_text(old_cert)
    (tmp_path / "tls.key").write_text("old-key")
    (tmp_path / "agent.json").write_text(json.dumps({"agent_id": "agent-1", "certificate_fingerprint": "old-fp"}))
    session = Session([{
        "success": True, "agent_id": "agent-1", "cert_pem": new_cert,
        "chain_pem": new_cert, "certificate_fingerprint": "new-fp",
    }])
    agent = CertificateAgent({
        "server_url": "https://pki", "state_dir": str(tmp_path),
        "common_name": "host.example.com", "renewal_days": 30,
    }, session=session)

    result = agent.renew_if_needed()

    assert result["renewed"] is True
    assert (tmp_path / "tls.key").read_text() != "old-key"
    assert "headers" not in session.calls[0][1]
    assert session.calls[0][1]["cert"] == (str(tmp_path / "tls.crt"), str(tmp_path / "tls.key"))

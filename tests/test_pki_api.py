import json
from functools import wraps

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _allow_auth(self, required_role=None):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            return function(*args, **kwargs)
        return wrapped
    return decorator


def _csr():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api-host.example.com")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api-host.example.com")]), False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM).decode()
    )


def test_api_exposes_providers_and_private_pki_enrollment(tmp_path, monkeypatch):
    from auth.oauth2_handler import OAuth2Handler
    monkeypatch.setattr(OAuth2Handler, "require_auth", _allow_auth)

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "database": {"type": "sqlite", "name": str(tmp_path / "api.db")},
        "directories": {"certificates": str(tmp_path / "certs")},
        "private_ca": {"key_storage_dir": str(tmp_path / "keys")},
        "certificate_authorities": {
            "letsencrypt": {"enabled": False},
            "digicert": {"enabled": False},
            "sectigo": {"enabled": False},
        },
        "dns_providers": {"cloudflare": {}, "bunny": {}},
    }))

    from web.api import SSLManagerAPI
    api = SSLManagerAPI(str(config_path))
    api.cert_manager.db_manager.create_tables()
    client = api.app.test_client()

    providers = client.get("/api/providers")
    hierarchy = client.post("/api/pki/hierarchies", json={
        "name_prefix": "api", "common_name_prefix": "API Test", "key_size": 2048,
    })
    issuing_ca_id = hierarchy.get_json()["issuing_ca_id"]
    token = client.post("/api/pki/enrollment-tokens", json={
        "ca_id": issuing_ca_id, "name": "api-host",
    }).get_json()
    enrolled = client.post("/api/pki/enroll", json={
        "token": token["token"], "csr_pem": _csr(),
    })
    spoofed_renewal = client.post(
        "/api/pki/agents/{}/renew".format(enrolled.get_json()["agent_id"]),
        json={"csr_pem": _csr(), "force": True},
        headers={"X-Client-Certificate-Fingerprint": enrolled.get_json()["certificate_fingerprint"]},
    )

    assert providers.status_code == 200
    assert set(providers.get_json()["certificate_authorities"]) >= {"letsencrypt", "digicert", "sectigo"}
    assert set(providers.get_json()["dns_providers"]) >= {"cloudflare", "bunny"}
    assert hierarchy.status_code == 201
    assert enrolled.status_code == 201
    assert enrolled.get_json()["agent_id"]
    assert spoofed_renewal.status_code == 401

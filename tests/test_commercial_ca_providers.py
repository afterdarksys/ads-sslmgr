from unittest.mock import patch


class Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self.payload = payload
        self.text = text
        self.headers = {}

    def json(self):
        if self.payload is None:
            raise ValueError("not json")
        return self.payload


def _leaf_pem(tmp_path):
    from ca.private_ca import PrivateCAManager

    manager = PrivateCAManager(tmp_path / "keys")
    root = manager.create_root_ca("Commercial Test Root", key_size_or_curve=2048)
    leaf = manager.issue_certificate(
        "example.com", root["cert_pem"], root["key_pem"], san_dns=["example.com"]
    )
    return leaf["cert_pem"]


def test_digicert_download_validates_and_atomically_writes(tmp_path, db_manager):
    from integrations.digicert import DigiCertIntegration

    cert_pem = _leaf_pem(tmp_path)
    config = {
        "directories": {"certificates": str(tmp_path / "certs")},
        "certificate_authorities": {"digicert": {"enabled": True, "api_key": "secret"}},
    }
    provider = DigiCertIntegration(config, db_manager)
    with patch.object(provider, "_request", return_value={"success": True, "data": cert_pem}):
        result = provider._download_certificate("123")

    path = tmp_path / "certs" / "digicert_123.pem"
    assert result["success"] is True
    assert path.read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(path.parent.glob("*.tmp"))


def test_digicert_rejects_malformed_download_without_replacing_file(tmp_path, db_manager):
    from integrations.digicert import DigiCertIntegration

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    target = cert_dir / "digicert_123.pem"
    target.write_text("working certificate")
    config = {
        "directories": {"certificates": str(cert_dir)},
        "certificate_authorities": {"digicert": {"enabled": True, "api_key": "secret"}},
    }
    provider = DigiCertIntegration(config, db_manager)
    with patch.object(provider, "_request", return_value={"success": True, "data": "not a certificate"}):
        result = provider._download_certificate("123")

    assert result["success"] is False
    assert result["error_kind"] == "validation"
    assert target.read_text() == "working certificate"


def test_sectigo_collection_validates_and_atomically_writes(tmp_path, db_manager):
    from integrations.comodo import ComodoIntegration

    cert_pem = _leaf_pem(tmp_path)
    config = {
        "directories": {"certificates": str(tmp_path / "certs")},
        "certificate_authorities": {
            "sectigo": {"enabled": True, "login": "u", "password": "secret", "customer_uri": "c"}
        },
    }
    provider = ComodoIntegration(config, db_manager)
    with patch.object(provider, "_request", return_value={"success": True, "data": cert_pem}):
        result = provider.collect_certificate(77)

    path = tmp_path / "certs" / "sectigo_77.pem"
    assert result["success"] is True
    assert path.stat().st_mode & 0o777 == 0o600


def test_commercial_provider_auth_errors_do_not_echo_secrets(tmp_path, db_manager):
    from integrations.digicert import DigiCertIntegration

    config = {
        "directories": {"certificates": str(tmp_path)},
        "certificate_authorities": {"digicert": {"enabled": True, "api_key": "top-secret"}},
    }
    provider = DigiCertIntegration(config, db_manager)
    response = Response(status_code=403, text="rejected top-secret")
    with patch("integrations.digicert.requests.request", return_value=response):
        result = provider._request("GET", "/user/me")

    assert result["error_kind"] == "authentication"
    assert "top-secret" not in result["error"]


def test_digicert_retries_rate_limit_then_succeeds(tmp_path, db_manager):
    from integrations.digicert import DigiCertIntegration

    config = {
        "directories": {"certificates": str(tmp_path)},
        "certificate_authorities": {"digicert": {"enabled": True, "api_key": "key"}},
    }
    provider = DigiCertIntegration(config, db_manager)
    responses = [Response(status_code=429), Response(payload={"id": 1})]
    with patch("integrations.digicert.requests.request", side_effect=responses), patch("integrations.digicert.time.sleep"):
        result = provider._request("GET", "/user/me")

    assert result == {"success": True, "data": {"id": 1}, "status_code": 200}

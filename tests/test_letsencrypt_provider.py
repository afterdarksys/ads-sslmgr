from pathlib import Path


def _integration(tmp_path, db_manager, **overrides):
    from integrations.letsencrypt import LetsEncryptIntegration

    le = {
        "enabled": True,
        "staging": True,
        "email": "admin@example.com",
        "certbot_cmd": "/usr/bin/certbot",
        "config_dir": str(tmp_path / "config"),
        "work_dir": str(tmp_path / "work"),
        "logs_dir": str(tmp_path / "logs"),
    }
    le.update(overrides)
    config = {
        "certificate_authorities": {"letsencrypt": le},
        "dns_providers": {
            "cloudflare": {"enabled": True, "api_token": "secret-token", "zone_id": "z1"}
        },
    }
    return LetsEncryptIntegration(config, db_manager)


def test_http_command_is_noninteractive_and_uses_configured_paths(tmp_path, db_manager):
    integration = _integration(tmp_path, db_manager)

    command = integration._build_certbot_command(["example.com"], "http")

    assert command[:3] == ["/usr/bin/certbot", "certonly", "--standalone"]
    assert "--non-interactive" in command
    assert "--staging" in command
    assert command[-2:] == ["-d", "example.com"]


def test_builtin_dns_command_uses_python_hooks_and_protected_config(tmp_path, db_manager):
    integration = _integration(tmp_path, db_manager, dns_provider="cloudflare")

    command = integration._build_certbot_command(["*.example.com"], "dns")
    config_path = integration.config_dir / "dns_provider.json"

    assert "--manual" in command
    assert "--manual-auth-hook" in command
    assert "providers.dns.hook present" in command[command.index("--manual-auth-hook") + 1]
    assert "providers.dns.hook cleanup" in command[command.index("--manual-cleanup-hook") + 1]
    assert config_path.exists()
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert "secret-token" in config_path.read_text()


def test_native_certbot_dns_plugin_can_be_selected(tmp_path, db_manager):
    integration = _integration(
        tmp_path,
        db_manager,
        certbot_plugin="dns-route53",
        certbot_plugin_options={"dns-route53-propagation-seconds": 45},
    )

    command = integration._build_certbot_command(["example.com"], "dns")

    assert command[2:4] == ["--authenticator", "dns-route53"]
    assert "--dns-route53-propagation-seconds" in command
    assert "45" in command
    assert "--manual-auth-hook" not in command


def test_health_reports_missing_email_and_binary(tmp_path, db_manager, monkeypatch):
    integration = _integration(tmp_path, db_manager, email="", certbot_cmd="missing-certbot")
    monkeypatch.setattr("integrations.letsencrypt.shutil.which", lambda value: None)

    result = integration.test_configuration()

    assert result["all_tests_passed"] is False
    assert "email not configured" in result["errors"]
    assert "certbot executable not found" in result["errors"]


def test_domain_extraction_accepts_plain_and_prefixed_sans(tmp_path, db_manager):
    integration = _integration(tmp_path, db_manager)

    class Cert:
        common_name = "example.com"
        subject_alt_names = ["DNS:www.example.com", "api.example.com", "example.com"]

    assert integration._extract_domains_from_cert(Cert()) == [
        "example.com", "www.example.com", "api.example.com"
    ]

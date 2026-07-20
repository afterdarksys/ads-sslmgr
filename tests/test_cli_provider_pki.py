import json

from click.testing import CliRunner


def _config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "database": {"type": "sqlite", "name": str(tmp_path / "cli.db")},
        "directories": {"certificates": str(tmp_path / "certs")},
        "private_ca": {"key_storage_dir": str(tmp_path / "keys")},
        "certificate_authorities": {},
        "dns_providers": {},
    }))
    return path


def test_cli_lists_builtin_provider_types(tmp_path):
    from cli.ssl_manager import cli

    result = CliRunner().invoke(cli, ["--config", str(_config(tmp_path)), "providers", "list", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert set(payload["certificate_authorities"]) >= {"letsencrypt", "digicert", "sectigo"}
    assert set(payload["dns_providers"]) >= {"cloudflare", "bunny"}


def test_cli_bootstraps_hierarchy_and_creates_enrollment_token(tmp_path):
    from cli.ssl_manager import cli

    runner = CliRunner()
    config = _config(tmp_path)
    bootstrap = runner.invoke(cli, [
        "--config", str(config), "ca", "bootstrap", "corp",
        "--common-name-prefix", "Corp", "--key-size", "2048", "--format", "json",
    ])
    assert bootstrap.exit_code == 0, bootstrap.output
    hierarchy = json.loads(bootstrap.output)

    token = runner.invoke(cli, [
        "--config", str(config), "ca", "create-token",
        str(hierarchy["issuing_ca_id"]), "web-01", "--format", "json",
    ])

    assert token.exit_code == 0, token.output
    assert json.loads(token.output)["token"]

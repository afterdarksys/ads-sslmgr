"""Certbot manual auth/cleanup hook runner for typed DNS providers."""

import hashlib
import argparse
import json
import os
from pathlib import Path

from providers.config import ProviderConfig


def _state_file(state_dir: Path, domain: str, validation: str) -> Path:
    digest = hashlib.sha256("{}\0{}".format(domain, validation).encode()).hexdigest()
    return state_dir / "{}.json".format(digest)


def run(action: str, provider, state_dir) -> dict:
    domain = os.environ.get("CERTBOT_DOMAIN", "")
    validation = os.environ.get("CERTBOT_VALIDATION", "")
    if not domain or not validation:
        raise RuntimeError("CERTBOT_DOMAIN and CERTBOT_VALIDATION are required")
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_file = _state_file(state_dir, domain, validation)
    if action == "present":
        result = provider.present(domain, validation)
        state_file.write_text(json.dumps(result))
        state_file.chmod(0o600)
        return result
    if action == "cleanup":
        if not state_file.exists():
            return {"success": True, "skipped": True}
        state = json.loads(state_file.read_text())
        result = provider.cleanup(domain, str(state["record_id"]))
        state_file.unlink()
        return result
    raise ValueError("Unknown hook action: {}".format(action))


def _build_provider(name: str, config: dict):
    resolved = ProviderConfig(config)
    keys = ("enabled", "api_token", "api_key", "zone_id", "zone_name", "ttl", "timeout", "base_url")
    provider_config = {key: resolved.dns(name, key) for key in keys if resolved.dns(name, key) is not None}
    if name == "cloudflare":
        from providers.dns.cloudflare import CloudflareDNSProvider
        return CloudflareDNSProvider(provider_config)
    if name == "bunny":
        from providers.dns.bunny import BunnyDNSProvider
        return BunnyDNSProvider(provider_config)
    raise ValueError("Unknown built-in DNS provider: {}".format(name))


def main(argv=None):
    parser = argparse.ArgumentParser(description="SSL Manager certbot DNS hook")
    parser.add_argument("action", choices=("present", "cleanup"))
    parser.add_argument("--provider", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--state-dir", required=True)
    args = parser.parse_args(argv)
    config = json.loads(Path(args.config).read_text())
    run(args.action, _build_provider(args.provider, config), args.state_dir)


if __name__ == "__main__":
    main()

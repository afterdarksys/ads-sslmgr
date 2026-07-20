"""Certbot manual auth/cleanup hook runner for typed DNS providers."""

import hashlib
import json
import os
from pathlib import Path


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

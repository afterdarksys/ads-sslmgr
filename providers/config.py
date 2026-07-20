"""Provider configuration with backwards-compatible environment overrides."""

import json
import os
from typing import Any, Dict


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


class ProviderConfig:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    def ca(self, provider: str, key: str, default: Any = None) -> Any:
        return self._get("CA", "certificate_authorities", provider, key, default)

    def dns(self, provider: str, key: str, default: Any = None) -> Any:
        # New dns_providers section wins; cloud_providers remains compatible.
        env_name = self._env_name("DNS", provider, key)
        if env_name in os.environ:
            return _coerce(os.environ[env_name])
        section = self.config.get("dns_providers", {}).get(provider, {})
        if key in section:
            return section[key]
        return self.config.get("cloud_providers", {}).get(provider, {}).get(key, default)

    def _get(self, prefix, section, provider, key, default):
        env_name = self._env_name(prefix, provider, key)
        if env_name in os.environ:
            return _coerce(os.environ[env_name])
        return self.config.get(section, {}).get(provider, {}).get(key, default)

    @staticmethod
    def _env_name(kind: str, provider: str, key: str) -> str:
        clean = lambda value: "".join(c if c.isalnum() else "_" for c in value.upper())
        return "SSLMGR_{}_{}_{}".format(clean(kind), clean(provider), clean(key))

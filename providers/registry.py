"""Provider registry and installed-package discovery."""

from importlib import metadata
from typing import Any, Dict, Iterable, List, Optional


class DuplicateProviderError(ValueError):
    pass


def _entry_points_for(group: str) -> Iterable[Any]:
    points = metadata.entry_points()
    if hasattr(points, "select"):
        return points.select(group=group)
    return points.get(group, ())


class ProviderRegistry:
    CA_GROUP = "sslmgr.ca_providers"
    DNS_GROUP = "sslmgr.dns_providers"

    def __init__(self):
        self._ca: Dict[str, Any] = {}
        self._dns: Dict[str, Any] = {}
        self._ca_aliases: Dict[str, str] = {}
        self._dns_aliases: Dict[str, str] = {}

    def register_ca(self, name: str, provider: Any, aliases=()):
        self._register(self._ca, self._ca_aliases, name, provider, aliases)

    def register_dns(self, name: str, provider: Any, aliases=()):
        self._register(self._dns, self._dns_aliases, name, provider, aliases)

    def get_ca(self, name: str) -> Any:
        return self._get(self._ca, self._ca_aliases, name)

    def get_dns(self, name: str) -> Any:
        return self._get(self._dns, self._dns_aliases, name)

    def list_ca(self) -> List[str]:
        return sorted(self._ca)

    def list_dns(self) -> List[str]:
        return sorted(self._dns)

    def discover(self, config: dict, db_manager=None) -> List[dict]:
        failures = []
        for group, register in (
            (self.CA_GROUP, self.register_ca),
            (self.DNS_GROUP, self.register_dns),
        ):
            for point in _entry_points_for(group):
                try:
                    factory = point.load()
                    register(point.name, factory(config, db_manager))
                except Exception as exc:
                    failures.append({"provider": point.name, "group": group, "error": str(exc)})
        return failures

    @staticmethod
    def _register(store, aliases_store, name, provider, aliases):
        key = name.lower()
        if key in store or key in aliases_store:
            raise DuplicateProviderError("Provider {!r} is already registered".format(name))
        store[key] = provider
        for alias in aliases:
            alias_key = alias.lower()
            if alias_key in store or alias_key in aliases_store:
                raise DuplicateProviderError("Provider alias {!r} is already registered".format(alias))
            aliases_store[alias_key] = key

    @staticmethod
    def _get(store, aliases_store, name):
        key = name.lower()
        canonical = aliases_store.get(key, key)
        if canonical not in store:
            raise KeyError("Unknown provider: {}".format(name))
        return store[canonical]

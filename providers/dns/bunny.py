"""bunny.net DNS-01 provider."""

from typing import Any, Dict

import requests

from providers.base import DNSChallengeProvider, ErrorKind, ProviderError


class BunnyDNSProvider(DNSChallengeProvider):
    name = "bunny"

    def __init__(self, config: Dict[str, Any], session=None):
        self.config = config or {}
        self.api_key = self.config.get("api_key", "")
        self.zone_id = self.config.get("zone_id")
        self.zone_name = self.config.get("zone_name", "").rstrip(".")
        self.base_url = self.config.get("base_url", "https://api.bunny.net")
        self.ttl = int(self.config.get("ttl", 60))
        self.timeout = float(self.config.get("timeout", 15))
        self.session = session or requests.Session()

    def present(self, domain: str, validation: str) -> Dict[str, Any]:
        self._require_config()
        name = self._relative_name(domain)
        data = self._request(
            "PUT", "/dnszone/{}/records".format(self.zone_id),
            json={"Type": 3, "Ttl": self.ttl, "Value": validation, "Name": name},
        )
        record_id = data.get("Id") if isinstance(data, dict) else None
        if record_id is None:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Bunny did not return a DNS record id", provider=self.name)
        return {"success": True, "record_id": str(record_id), "record_name": name, "zone_id": str(self.zone_id)}

    def cleanup(self, domain: str, record_id: str) -> Dict[str, Any]:
        self._require_config()
        self._request("DELETE", "/dnszone/{}/records/{}".format(self.zone_id, record_id))
        return {"success": True, "record_id": str(record_id)}

    def health(self) -> Dict[str, Any]:
        missing = [name for name, value in (("api_key", self.api_key), ("zone_id", self.zone_id)) if not value]
        return {"provider": self.name, "healthy": not missing, "missing": missing}

    def _relative_name(self, domain: str) -> str:
        fqdn = "_acme-challenge." + domain.lstrip("*.").rstrip(".")
        if self.zone_name and fqdn.endswith("." + self.zone_name):
            return fqdn[: -(len(self.zone_name) + 1)]
        return fqdn

    def _require_config(self):
        missing = self.health()["missing"]
        if missing:
            raise ProviderError(ErrorKind.CONFIGURATION, "Bunny DNS is missing: {}".format(", ".join(missing)), provider=self.name)

    def _request(self, method: str, path: str, **kwargs):
        headers = {"AccessKey": self.api_key, "Content-Type": "application/json"}
        try:
            response = self.session.request(
                method, self.base_url.rstrip("/") + path, headers=headers,
                timeout=self.timeout, **kwargs
            )
        except requests.Timeout:
            raise ProviderError(ErrorKind.TIMEOUT, "Bunny DNS request timed out", retryable=True, provider=self.name)
        except requests.RequestException as exc:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Bunny DNS request failed: {}".format(exc), retryable=True, provider=self.name)
        if response.status_code in (401, 403):
            raise ProviderError(ErrorKind.AUTHENTICATION, "Bunny rejected the configured API key", provider=self.name)
        if response.status_code == 429:
            raise ProviderError(ErrorKind.RATE_LIMIT, "Bunny DNS API rate limit reached", retryable=True, provider=self.name)
        if response.status_code >= 400:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Bunny DNS API returned HTTP {}".format(response.status_code), retryable=response.status_code >= 500, provider=self.name)
        if response.status_code == 204:
            return {}
        try:
            return response.json()
        except ValueError:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Bunny returned an invalid response", provider=self.name)

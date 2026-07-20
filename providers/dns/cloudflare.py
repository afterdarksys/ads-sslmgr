"""Cloudflare DNS-01 provider using scoped API tokens."""

from typing import Any, Dict, Optional

import requests

from providers.base import DNSChallengeProvider, ErrorKind, ProviderError


class CloudflareDNSProvider(DNSChallengeProvider):
    name = "cloudflare"

    def __init__(self, config: Dict[str, Any], session=None):
        self.config = config or {}
        self.api_token = self.config.get("api_token", "")
        self.zone_id = self.config.get("zone_id", "")
        self.base_url = self.config.get("base_url", "https://api.cloudflare.com/client/v4")
        self.ttl = int(self.config.get("ttl", 60))
        self.timeout = float(self.config.get("timeout", 15))
        self.session = session or requests.Session()
        self._zones: Dict[str, str] = {}

    def present(self, domain: str, validation: str) -> Dict[str, Any]:
        zone_id = self._zone_for(domain)
        name = "_acme-challenge." + domain.lstrip("*.").rstrip(".")
        data = self._request(
            "POST",
            "/zones/{}/dns_records".format(zone_id),
            json={"type": "TXT", "name": name, "content": validation, "ttl": self.ttl},
        )
        record_id = data.get("id")
        if not record_id:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Cloudflare did not return a DNS record id", provider=self.name)
        return {"success": True, "record_id": record_id, "record_name": name, "zone_id": zone_id}

    def cleanup(self, domain: str, record_id: str) -> Dict[str, Any]:
        zone_id = self._zone_for(domain)
        self._request("DELETE", "/zones/{}/dns_records/{}".format(zone_id, record_id))
        return {"success": True, "record_id": record_id}

    def health(self) -> Dict[str, Any]:
        missing = [] if self.api_token else ["api_token"]
        return {"provider": self.name, "healthy": not missing, "missing": missing}

    def _zone_for(self, domain: str) -> str:
        if self.zone_id:
            return str(self.zone_id)
        domain = domain.lstrip("*.").rstrip(".")
        if domain in self._zones:
            return self._zones[domain]
        labels = domain.split(".")
        for index in range(max(0, len(labels) - 2)):
            candidate = ".".join(labels[index:])
            result = self._request("GET", "/zones", params={"name": candidate, "status": "active"})
            if result:
                zone_id = result[0].get("id")
                if zone_id:
                    self._zones[domain] = zone_id
                    return zone_id
        raise ProviderError(ErrorKind.CONFIGURATION, "No Cloudflare zone found for {}".format(domain), provider=self.name)

    def _request(self, method: str, path: str, **kwargs):
        if not self.api_token:
            raise ProviderError(ErrorKind.CONFIGURATION, "Cloudflare api_token is not configured", provider=self.name)
        headers = {"Authorization": "Bearer {}".format(self.api_token), "Content-Type": "application/json"}
        try:
            response = self.session.request(
                method, self.base_url.rstrip("/") + path, headers=headers,
                timeout=self.timeout, **kwargs
            )
        except requests.Timeout:
            raise ProviderError(ErrorKind.TIMEOUT, "Cloudflare DNS request timed out", retryable=True, provider=self.name)
        except requests.RequestException as exc:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Cloudflare DNS request failed: {}".format(exc), retryable=True, provider=self.name)
        if response.status_code in (401, 403):
            raise ProviderError(ErrorKind.AUTHENTICATION, "Cloudflare rejected the configured API token", provider=self.name)
        if response.status_code == 429:
            raise ProviderError(ErrorKind.RATE_LIMIT, "Cloudflare DNS API rate limit reached", retryable=True, provider=self.name)
        if response.status_code >= 400:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Cloudflare DNS API returned HTTP {}".format(response.status_code), retryable=response.status_code >= 500, provider=self.name)
        try:
            payload = response.json()
        except ValueError:
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Cloudflare returned an invalid response", provider=self.name)
        if not payload.get("success", False):
            raise ProviderError(ErrorKind.REMOTE_SERVICE, "Cloudflare DNS operation failed", provider=self.name)
        return payload.get("result")

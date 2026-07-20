import json

import pytest


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_cloudflare_creates_and_deletes_only_created_record():
    from providers.dns.cloudflare import CloudflareDNSProvider

    session = FakeSession([
        FakeResponse(payload={"success": True, "result": [{"id": "zone-1"}]}),
        FakeResponse(payload={"success": True, "result": {"id": "record-7"}}),
        FakeResponse(payload={"success": True, "result": {"id": "record-7"}}),
    ])
    provider = CloudflareDNSProvider({"api_token": "secret"}, session=session)

    created = provider.present("*.www.example.com", "txt-value")
    deleted = provider.cleanup("*.www.example.com", created["record_id"])

    assert created["record_id"] == "record-7"
    assert created["record_name"] == "_acme-challenge.www.example.com"
    assert deleted["success"] is True
    assert session.calls[1][2]["json"]["type"] == "TXT"
    assert session.calls[2][1].endswith("/zones/zone-1/dns_records/record-7")
    assert session.calls[0][2]["headers"]["Authorization"] == "Bearer secret"


def test_cloudflare_returns_normalized_authentication_error():
    from providers.dns.cloudflare import CloudflareDNSProvider
    from providers.base import ProviderError

    session = FakeSession([FakeResponse(status_code=403, payload={"errors": [{"message": "bad token"}]})])
    provider = CloudflareDNSProvider({"api_token": "secret", "zone_id": "z"}, session=session)

    with pytest.raises(ProviderError) as raised:
        provider.present("example.com", "value")

    result = raised.value.to_dict()
    assert result["error_kind"] == "authentication"
    assert "secret" not in result["error"]


def test_bunny_creates_txt_and_deletes_by_record_id():
    from providers.dns.bunny import BunnyDNSProvider

    session = FakeSession([
        FakeResponse(status_code=201, payload={"Id": 42}),
        FakeResponse(status_code=204, payload={}),
    ])
    provider = BunnyDNSProvider(
        {"api_key": "bunny-secret", "zone_id": 99, "zone_name": "example.com"},
        session=session,
    )

    created = provider.present("host.example.com", "proof")
    provider.cleanup("host.example.com", created["record_id"])

    body = session.calls[0][2]["json"]
    assert body == {"Type": 3, "Ttl": 60, "Value": "proof", "Name": "_acme-challenge.host"}
    assert session.calls[0][2]["headers"]["AccessKey"] == "bunny-secret"
    assert session.calls[1][1].endswith("/dnszone/99/records/42")


def test_bunny_requires_zone_id_and_key():
    from providers.dns.bunny import BunnyDNSProvider

    health = BunnyDNSProvider({}).health()

    assert health["healthy"] is False
    assert set(health["missing"]) == {"api_key", "zone_id"}


def test_hook_persists_record_id_for_cleanup(tmp_path, monkeypatch):
    from providers.dns import hook

    calls = []

    class Provider:
        def present(self, domain, validation):
            calls.append(("present", domain, validation))
            return {"success": True, "record_id": "remote-1", "zone_id": "zone"}

        def cleanup(self, domain, record_id):
            calls.append(("cleanup", domain, record_id))
            return {"success": True}

    monkeypatch.setenv("CERTBOT_DOMAIN", "example.com")
    monkeypatch.setenv("CERTBOT_VALIDATION", "proof")
    state = tmp_path / "state"

    hook.run("present", Provider(), state)
    assert json.loads(next(state.iterdir()).read_text())["record_id"] == "remote-1"
    hook.run("cleanup", Provider(), state)

    assert calls == [
        ("present", "example.com", "proof"),
        ("cleanup", "example.com", "remote-1"),
    ]
    assert list(state.iterdir()) == []

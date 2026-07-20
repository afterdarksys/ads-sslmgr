import pytest


def test_registry_registers_alias_without_duplicate_instance():
    from providers.registry import ProviderRegistry

    provider = object()
    registry = ProviderRegistry()
    registry.register_ca("sectigo", provider, aliases=("comodo",))

    assert registry.get_ca("sectigo") is provider
    assert registry.get_ca("COMODO") is provider
    assert registry.list_ca() == ["sectigo"]


def test_registry_rejects_duplicate_names():
    from providers.registry import ProviderRegistry, DuplicateProviderError

    registry = ProviderRegistry()
    registry.register_dns("cloudflare", object())

    with pytest.raises(DuplicateProviderError):
        registry.register_dns("cloudflare", object())


def test_config_environment_overrides_json(monkeypatch):
    from providers.config import ProviderConfig

    monkeypatch.setenv("SSLMGR_CA_DIGICERT_API_KEY", "from-env")
    config = ProviderConfig({
        "certificate_authorities": {"digicert": {"api_key": "from-json"}}
    })

    assert config.ca("digicert", "api_key") == "from-env"
    assert config.ca("digicert", "enabled", False) is False


def test_config_coerces_environment_values(monkeypatch):
    from providers.config import ProviderConfig

    monkeypatch.setenv("SSLMGR_DNS_BUNNY_ENABLED", "true")
    monkeypatch.setenv("SSLMGR_DNS_BUNNY_TTL", "60")
    config = ProviderConfig({})

    assert config.dns("bunny", "enabled") is True
    assert config.dns("bunny", "ttl") == 60


def test_provider_error_is_safe_and_structured():
    from providers.base import ErrorKind, ProviderError

    error = ProviderError(
        ErrorKind.AUTHENTICATION,
        "authentication failed",
        retryable=False,
        provider="digicert",
        metadata={"request_id": "abc"},
    )

    assert error.to_dict() == {
        "success": False,
        "error": "authentication failed",
        "error_kind": "authentication",
        "retryable": False,
        "provider": "digicert",
        "metadata": {"request_id": "abc"},
    }


def test_discover_loads_entry_point_provider(monkeypatch):
    from providers.registry import ProviderRegistry

    plugin = object()

    class FakeEntryPoint:
        name = "example"

        def load(self):
            return lambda config, db_manager=None: plugin

    monkeypatch.setattr(
        "providers.registry._entry_points_for",
        lambda group: [FakeEntryPoint()] if group == "sslmgr.ca_providers" else [],
    )
    registry = ProviderRegistry()
    failures = registry.discover({}, None)

    assert failures == []
    assert registry.get_ca("example") is plugin


def test_broken_plugin_does_not_break_discovery(monkeypatch):
    from providers.registry import ProviderRegistry

    class BrokenEntryPoint:
        name = "broken"

        def load(self):
            raise RuntimeError("cannot import")

    monkeypatch.setattr(
        "providers.registry._entry_points_for", lambda group: [BrokenEntryPoint()]
    )
    failures = ProviderRegistry().discover({}, None)

    assert len(failures) == 2
    assert all(item["provider"] == "broken" for item in failures)
    assert all("cannot import" in item["error"] for item in failures)

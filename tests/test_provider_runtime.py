from time import monotonic, sleep

from backend.src.config import Settings
from backend.src.providers.composite_provider import CompositeThreatIntelProvider
from backend.src.providers.models import ProviderRecord


class CountingProvider:
    def __init__(self) -> None:
        self.calls = 0

    def lookup_ioc(self, entity_type: str, value: str):
        self.calls += 1
        sleep(0.08)
        return ProviderRecord(entity_type=entity_type, indicator=value, verdict="undetected")


class Registry:
    def __init__(self) -> None:
        self.virustotal = CountingProvider()
        self.otx = CountingProvider()
        self.abuseipdb = CountingProvider()


def test_ioc_providers_execute_concurrently_and_result_is_cached() -> None:
    registry = Registry()
    provider = CompositeThreatIntelProvider(Settings(provider_cache_ttl_seconds=60), registry=registry)  # type: ignore[arg-type]
    started = monotonic()
    first = provider.lookup_ioc("ip", "192.0.2.199")
    elapsed = monotonic() - started
    second = provider.lookup_ioc("ip", "192.0.2.199")

    assert isinstance(first, ProviderRecord) and isinstance(second, ProviderRecord)
    assert elapsed < 0.20
    assert registry.virustotal.calls == registry.otx.calls == registry.abuseipdb.calls == 1
    assert first is not second

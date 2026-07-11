"""Thin facade over provider selection and aggregation."""

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable

from backend.src.config import Settings, get_settings
from backend.src.providers.aggregator import ProviderAggregator
from backend.src.providers.cache import CACHE_MISS, ProviderCache, shared_provider_cache
from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderCall, ProviderResult
from backend.src.providers.registry import ProviderRegistry


class CompositeThreatIntelProvider(ThreatIntelProvider):
    """Select providers for a capability and delegate all merging."""

    AUTHORITY = {"VirusTotal": 0.90, "AlienVault OTX": 0.70, "AbuseIPDB": 0.90, "NVD": 1.00, "MITRE ATT&CK": 1.00}

    def __init__(self, settings: Settings | None = None, registry: ProviderRegistry | None = None, aggregator: ProviderAggregator | None = None) -> None:
        settings = settings or get_settings()
        self.providers = registry or ProviderRegistry.from_settings(settings)
        self.aggregator = aggregator or ProviderAggregator()
        self.cache: ProviderCache = shared_provider_cache(settings.provider_cache_ttl_seconds, settings.provider_cache_max_entries)
        self.max_workers = settings.provider_max_workers

    def _cached(self, key: tuple[str, ...], loader: Callable[[], ProviderResult]) -> ProviderResult:
        cached = self.cache.get(key)
        if cached is not CACHE_MISS:
            return cached  # type: ignore[return-value]
        result = loader()
        self.cache.put(key, result)
        return result

    def _parallel(self, jobs: list[tuple[str, str, Callable[[], ProviderResult]]]) -> list[ProviderCall]:
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(jobs)), thread_name_prefix="intel-provider") as executor:
            futures = [(provider, role, executor.submit(loader)) for provider, role, loader in jobs]
            return [self._call(provider, role, future.result()) for provider, role, future in futures]

    def _call(self, provider: str, role: str, result: ProviderResult) -> ProviderCall:
        return ProviderCall(provider=provider, role=role, authority=self.AUTHORITY[provider], result=result)

    def lookup_ioc(self, entity_type: str, entity_value: str) -> ProviderResult:
        def load() -> ProviderResult:
            jobs = [("VirusTotal", "primary", lambda: self.providers.virustotal.lookup_ioc(entity_type, entity_value)), ("AlienVault OTX", "supporting", lambda: self.providers.otx.lookup_ioc(entity_type, entity_value))]
            if entity_type == "ip":
                jobs.append(("AbuseIPDB", "primary", lambda: self.providers.abuseipdb.lookup_ioc(entity_type, entity_value)))
            return self.aggregator.merge_ioc(self._parallel(jobs), entity_type, entity_value)
        return self._cached(("ioc", entity_type, entity_value.casefold()), load)

    def lookup_actor(self, actor_name: str) -> ProviderResult:
        return self._cached(("actor", actor_name.casefold()), lambda: self.aggregator.merge_actor(self._parallel([("MITRE ATT&CK", "primary", lambda: self.providers.mitre.lookup_actor(actor_name)), ("AlienVault OTX", "supporting", lambda: self.providers.otx.lookup_actor(actor_name))]), actor_name))

    def lookup_exposure(self, product: str, version: str) -> ProviderResult:
        return self._cached(("exposure", product.casefold(), version.casefold()), lambda: self.aggregator.annotate_single(self._call("NVD", "primary", self.providers.nvd.lookup_exposure(product, version))))

    def lookup_relationships(self, entity_type: str, entity_value: str) -> ProviderResult:
        return self._cached(("relationships", entity_type, entity_value.casefold()), lambda: self.aggregator.annotate_single(self._call("VirusTotal", "primary", self.providers.virustotal.lookup_relationships(entity_type, entity_value))))

    def lookup_asn(self, ip: str) -> ProviderResult:
        return self._cached(("asn", ip), lambda: self.aggregator.annotate_single(self._call("VirusTotal", "primary", self.providers.virustotal.lookup_asn(ip))))

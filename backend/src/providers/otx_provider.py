"""AlienVault OTX indicator and pulse enrichment provider."""

from urllib.parse import quote
from backend.src.config import Settings, get_settings
from backend.src.providers.api_helpers import error, get_json
from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult
from backend.src.tools.schemas import EvidenceItem, SourceReference


class OTXProvider:
    TYPES = {"ip": "IPv4", "domain": "domain", "hash": "file"}

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def lookup_ioc(self, entity_type: str, value: str) -> ProviderResult:
        indicator_type = self.TYPES.get(entity_type)
        if not indicator_type:
            return None
        if not self.settings.alien_vault_api_key:
            return error("AlienVault OTX", "configuration", "ALIEN_VAULT_API_KEY is not configured.")
        payload = get_json(provider="AlienVault OTX", url=f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{quote(value, safe='')}/general", timeout=self.settings.api_timeout_seconds, headers={"X-OTX-API-KEY": self.settings.alien_vault_api_key})
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        pulse_info = payload.get("pulse_info", {})
        count = int(pulse_info.get("count", 0))
        pulses = pulse_info.get("pulses", [])
        names = [str(item.get("name")) for item in pulses[:5] if isinstance(item, dict) and item.get("name")]
        evidence = [EvidenceItem(claim=f"AlienVault OTX links this indicator to {count} threat pulses; pulse count is context, not a risk score.", source="AlienVault OTX", source_type="community_threat_intelligence", observed_value=str(count), reliability="medium")]
        if names:
            evidence.append(EvidenceItem(claim=f"Recent pulse names include: {', '.join(names)}.", source="AlienVault OTX", source_type="threat_pulse", observed_value=", ".join(names), reliability="medium"))
        return ProviderRecord(verdict="suspicious" if count else "undetected", summary=f"AlienVault OTX links the indicator to {count} pulses.", evidence=evidence, sources=[SourceReference(name="AlienVault OTX", url=f"https://otx.alienvault.com/indicator/{indicator_type}/{value}", source_type="community_threat_intelligence")], attributes=payload)

    def lookup_actor(self, actor: str) -> ProviderResult:
        if not self.settings.alien_vault_api_key:
            return error("AlienVault OTX", "configuration", "ALIEN_VAULT_API_KEY is not configured.")
        payload = get_json(provider="AlienVault OTX", url="https://otx.alienvault.com/api/v1/search/pulses", timeout=self.settings.api_timeout_seconds, headers={"X-OTX-API-KEY": self.settings.alien_vault_api_key}, params={"q": actor, "limit": 10})
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        results = payload.get("results", [])
        evidence = [EvidenceItem(claim=f"OTX pulse: {pulse.get('name', 'unnamed pulse')}", source="AlienVault OTX", source_type="threat_pulse", observed_value=str(pulse.get("id", "")), reliability="medium") for pulse in results[:10] if isinstance(pulse, dict)]
        return ProviderRecord(actor=actor, summary=f"AlienVault OTX returned {len(results)} pulses matching {actor}.", evidence=evidence, sources=[SourceReference(name="AlienVault OTX", url=f"https://otx.alienvault.com/browse/global/pulses?q={quote(actor)}", source_type="threat_pulse")])

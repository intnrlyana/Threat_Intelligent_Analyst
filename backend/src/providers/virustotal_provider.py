"""VirusTotal API v3 threat-intelligence provider."""

from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from backend.src.config import Settings, get_settings
from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult
from backend.src.tools.schemas import EvidenceItem, RelatedEntity, SourceReference, ToolError


class VirusTotalProvider(ThreatIntelProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None) -> None:
        self.settings = settings or get_settings()
        self.api_key = self.settings.virustotal_api_key
        self._client = client

    def _error(self, error_type: str, message: str, retryable: bool = False) -> ProviderFailure:
        return ProviderFailure(error=ToolError(provider="VirusTotal", error_type=error_type, message=message, retryable=retryable))

    def _get(self, path: str) -> dict[str, object] | ProviderFailure | None:
        if not self.api_key:
            return self._error("configuration", "VIRUSTOTAL_API_KEY is not configured.")
        try:
            if self._client is not None:
                response = self._client.get(path, headers={"x-apikey": self.api_key})
            else:
                with httpx.Client(base_url=self.BASE_URL, timeout=self.settings.api_timeout_seconds) as client:
                    response = client.get(path, headers={"x-apikey": self.api_key})
        except httpx.TimeoutException:
            return self._error("timeout", "VirusTotal did not respond before the configured timeout.", True)
        except httpx.HTTPError as exc:
            return self._error("provider_error", f"VirusTotal request failed: {exc}", True)
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            return self._error("rate_limit", "VirusTotal API quota or rate limit was reached.", True)
        if response.status_code in {401, 403}:
            return self._error("authentication", "VirusTotal rejected the API key or account permissions.")
        if response.is_error:
            return self._error("provider_error", f"VirusTotal returned HTTP {response.status_code}.", response.status_code >= 500)
        payload = response.json()
        return payload if isinstance(payload, dict) else self._error("invalid_response", "VirusTotal returned an unexpected response.")

    @staticmethod
    def _collection(entity_type: str) -> str | None:
        return {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(entity_type)

    @staticmethod
    def _source(entity_type: str, value: str) -> SourceReference:
        collection = {"ip": "ip-address", "domain": "domain", "hash": "file"}[entity_type]
        return SourceReference(name="VirusTotal", url=f"https://www.virustotal.com/gui/{collection}/{value}", source_type="live_threat_intelligence")

    def lookup_ioc(self, entity_type: str, entity_value: str) -> ProviderResult:
        collection = self._collection(entity_type)
        if collection is None:
            return self._error("unsupported_entity", f"VirusTotal lookup does not support entity type {entity_type}.")
        payload = self._get(f"/{collection}/{quote(entity_value, safe='')}")
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        data = payload.get("data", {})
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = sum(int(value) for value in stats.values() if isinstance(value, int))
        detections = malicious + suspicious
        score = round(100 * detections / total) if total else 0
        verdict = "malicious" if malicious else "suspicious" if suspicious else "undetected"
        source = self._source(entity_type, entity_value)
        evidence = [EvidenceItem(claim=f"VirusTotal engines reported {malicious} malicious and {suspicious} suspicious detections out of {total} results.", source="VirusTotal", source_type="multi_engine_analysis", observed_value=f"{detections}/{total}", reliability="high"), EvidenceItem(claim=f"VirusTotal recorded {harmless} harmless and {undetected} undetected results.", source="VirusTotal", source_type="multi_engine_analysis", observed_value=f"{harmless} harmless; {undetected} undetected", reliability="medium")]
        return ProviderRecord(entity_type=entity_type, indicator=entity_value, verdict=verdict, risk_score=score, summary=f"Live VirusTotal report: {detections} engines flagged {entity_value}.", evidence=evidence, sources=[source], attributes=attributes, retrieved_at=datetime.now(timezone.utc))

    def lookup_relationships(self, entity_type: str, entity_value: str) -> ProviderResult:
        collection = self._collection(entity_type)
        if collection is None:
            return self._error("unsupported_entity", f"VirusTotal relationships do not support {entity_type}.")
        relationships = ["resolutions", "communicating_files"] if entity_type in {"ip", "domain"} else ["contacted_domains", "contacted_ips"]
        related: list[dict[str, str]] = []
        for relationship in relationships:
            payload = self._get(f"/{collection}/{quote(entity_value, safe='')}/relationships/{relationship}?limit=10")
            if payload is None:
                continue
            if isinstance(payload, ProviderFailure):
                return payload
            for item in payload.get("data", []):
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                vt_type = str(item.get("type", "unknown"))
                value = str(item["id"])
                related_type = {"ip_address": "ip", "file": "hash"}.get(vt_type, vt_type)
                # VirusTotal's IP ``resolutions`` relationship IDs concatenate
                # the source IP and hostname (for example ``1.2.3.4example.com``).
                if vt_type == "resolution" and entity_type == "ip" and value.startswith(entity_value):
                    value = value[len(entity_value):]
                    related_type = "domain"
                related.append(RelatedEntity(entity_type=related_type, value=value, relationship=relationship, source="VirusTotal"))
        return ProviderRecord(entity_type=entity_type, indicator=entity_value, related_entities=related, sources=[self._source(entity_type, entity_value)])

    def lookup_asn(self, ip: str) -> ProviderResult:
        payload = self._get(f"/ip_addresses/{quote(ip, safe='')}")
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        attributes = payload.get("data", {}).get("attributes", {})
        return ProviderRecord(indicator=ip, asn=f"AS{attributes.get('asn', 'unknown')}", organization=str(attributes.get("as_owner", "unknown")), country=str(attributes.get("country", "unknown")), sources=[self._source("ip", ip)], attributes=attributes)

    def lookup_actor(self, actor_name: str) -> ProviderResult:
        return self._error("unsupported_capability", "VirusTotal is not configured as an authoritative actor/TTP catalog in this application.")

    def lookup_exposure(self, product: str, version: str) -> ProviderResult:
        return self._error("unsupported_capability", "VirusTotal does not provide product-version vulnerability exposure assessment.")

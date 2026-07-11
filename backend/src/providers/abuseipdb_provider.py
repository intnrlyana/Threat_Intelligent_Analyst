"""AbuseIPDB API v2 enrichment provider."""

from backend.src.config import Settings, get_settings
from backend.src.providers.api_helpers import error, get_json
from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult
from backend.src.tools.schemas import EvidenceItem, SourceReference


class AbuseIPDBProvider:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def lookup_ioc(self, entity_type: str, value: str) -> ProviderResult:
        if entity_type != "ip":
            return None
        if not self.settings.abuseipdb_api_key:
            return error("AbuseIPDB", "configuration", "ABUSEIPDB_API_KEY is not configured.")
        payload = get_json(provider="AbuseIPDB", url="https://api.abuseipdb.com/api/v2/check", timeout=self.settings.api_timeout_seconds, headers={"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}, params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""})
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        return ProviderRecord(
            verdict="malicious" if score >= 75 else "suspicious" if score >= 25 else "undetected",
            risk_score=score,
            summary=f"AbuseIPDB confidence {score}% from {reports} reports.",
            evidence=[EvidenceItem(claim=f"AbuseIPDB reports an abuse confidence score of {score}% with {reports} reports.", source="AbuseIPDB", source_type="abuse_reputation", observed_value=f"{score}%", reliability="high")],
            sources=[SourceReference(name="AbuseIPDB", url=f"https://www.abuseipdb.com/check/{value}", source_type="abuse_reputation")],
            attributes=data,
        )

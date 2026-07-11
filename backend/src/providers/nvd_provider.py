"""NVD CVE API 2.0 product exposure provider."""

from backend.src.config import Settings, get_settings
from backend.src.providers.api_helpers import error, get_json
from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult, VulnerabilityRecord
from backend.src.tools.schemas import SourceReference


class NVDProvider:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @staticmethod
    def _metric(cve: dict[str, object]) -> tuple[str, str]:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, []) if isinstance(metrics, dict) else []
            if entries:
                data = entries[0].get("cvssData", {})
                return str(data.get("baseSeverity", entries[0].get("baseSeverity", "unknown"))).lower(), str(data.get("baseScore", "unknown"))
        return "unknown", "unknown"

    def lookup_exposure(self, product: str, version: str) -> ProviderResult:
        if not self.settings.nvd_api_key:
            return error("NVD", "configuration", "NVD_API_KEY is not configured.")
        payload = get_json(provider="NVD", url="https://services.nvd.nist.gov/rest/json/cves/2.0", timeout=self.settings.api_timeout_seconds, headers={"apiKey": self.settings.nvd_api_key}, params={"keywordSearch": f"{product} {version}", "resultsPerPage": 10})
        if payload is None or isinstance(payload, ProviderFailure):
            return payload
        vulnerabilities = []
        for wrapper in payload.get("vulnerabilities", [])[:10]:
            cve = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            descriptions = cve.get("descriptions", [])
            description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
            severity, score = self._metric(cve)
            references = cve.get("references", [])
            vulnerabilities.append(VulnerabilityRecord(cve_id=str(cve.get("id", "unknown")), severity=severity, affected_versions=f"NVD keyword match for {product} {version}; verify CPE applicability", summary=str(description), remediation="Review vendor advisory and apply the vendor-supported fixed release.", cvss_score=score, reference=str(references[0].get("url")) if references else None))
        return ProviderRecord(product=product, version=version, exposure_status="potentially_exposed" if vulnerabilities else "unknown", summary=f"NVD returned {len(vulnerabilities)} CVE candidates for {product} {version}.", vulnerabilities=vulnerabilities, sources=[SourceReference(name="NVD", url=f"https://nvd.nist.gov/vuln/search/results?query={product}%20{version}", source_type="vulnerability_catalog")], applicability_note="Keyword matches are candidates, not proof that the deployed build is affected.")

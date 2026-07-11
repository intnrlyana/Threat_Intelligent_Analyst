"""NVD-backed product exposure reasoning tool."""

from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderRecord
from backend.src.tools.helpers import provider_failure, public_raw_record
from backend.src.tools.schemas import EvidenceItem, ToolRequest, ToolResult

TOOL_NAME = "exposure_check"
MAX_EXPOSURE_EVIDENCE = 5


def exposure_check(request: ToolRequest, provider: ThreatIntelProvider) -> ToolResult:
    product, version = request.product or request.entity_value, request.version or ""
    record = provider.lookup_exposure(product, version)
    failure = provider_failure(record, TOOL_NAME, f"NVD returned no exposure evidence for {product} {version}.".strip())
    if failure:
        return failure
    assert isinstance(record, ProviderRecord)
    displayed = record.vulnerabilities[:MAX_EXPOSURE_EVIDENCE]
    evidence = [EvidenceItem(claim=f"{item.cve_id} ({item.severity}): {item.summary} Affected versions: {item.affected_versions}. Remediation: {item.remediation}", source="NVD", source_type="vulnerability_catalog", observed_value=item.cve_id, reliability="high") for item in displayed]
    summary = record.summary or f"NVD returned {len(record.vulnerabilities)} CVE candidates for {product} {version}."
    if record.exposure_status == "potentially_exposed":
        summary = f"potentially exposed based on NVD candidate matches. {summary}"
    if len(record.vulnerabilities) > len(displayed):
        summary += f" Showing {len(displayed)} of {len(record.vulnerabilities)} candidates, prioritised by NVD result order."
    return ToolResult(tool_name=TOOL_NAME, success=True, verdict=record.exposure_status or "unknown", summary=summary, evidence=evidence, sources=record.sources, provider_findings=record.provider_findings, raw_record=public_raw_record(record))

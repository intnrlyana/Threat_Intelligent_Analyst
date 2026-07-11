"""Actor and ATT&CK technique lookup tool."""

from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderRecord
from backend.src.tools.helpers import provider_failure, public_raw_record
from backend.src.tools.schemas import EvidenceItem, ToolRequest, ToolResult

TOOL_NAME = "actor_ttp_lookup"
MAX_TTP_EVIDENCE = 5


def actor_ttp_lookup(request: ToolRequest, provider: ThreatIntelProvider) -> ToolResult:
    """Return a concise, evidence-grounded ATT&CK profile for an actor."""
    record = provider.lookup_actor(request.entity_value)
    failure = provider_failure(record, TOOL_NAME, f"No actor profile was found for {request.entity_value}.")
    if failure:
        return failure
    assert isinstance(record, ProviderRecord)

    displayed_ttps = record.known_ttps[:MAX_TTP_EVIDENCE]
    technique_evidence = [
        EvidenceItem(
            claim=f"{ttp.technique_id} - {ttp.technique_name}: {ttp.description}",
            source="MITRE ATT&CK",
            source_type="authoritative_ttp_catalog",
            observed_value=ttp.technique_id,
            reliability="high",
        )
        for ttp in displayed_ttps
    ]
    total = record.total_known_ttps or len(record.known_ttps)
    summary = record.summary
    if total > len(displayed_ttps):
        summary = f"{summary} Showing {len(displayed_ttps)} representative techniques of {total} documented relationships."
    return ToolResult(
        tool_name=TOOL_NAME,
        success=True,
        summary=summary,
        evidence=record.evidence + technique_evidence,
        sources=record.sources,
        provider_findings=record.provider_findings,
        raw_record=public_raw_record(record),
        errors=record.provider_errors,
        degraded=bool(record.provider_errors),
    )

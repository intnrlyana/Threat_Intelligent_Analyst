"""VirusTotal relationship pivot tool."""

from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderRecord
from backend.src.tools.helpers import provider_failure, public_raw_record
from backend.src.tools.schemas import EvidenceItem, ToolRequest, ToolResult

TOOL_NAME = "pivot_related_entities"


def pivot_related_entities(request: ToolRequest, provider: ThreatIntelProvider) -> ToolResult:
    record = provider.lookup_relationships(request.entity_type, request.entity_value)
    failure = provider_failure(record, TOOL_NAME, f"VirusTotal returned no relationships for {request.entity_value}.")
    if failure:
        return failure
    assert isinstance(record, ProviderRecord)
    evidence = [EvidenceItem(claim=f"{item.value} is related to {request.entity_value} through {item.relationship}.", source=item.source, source_type="relationship_graph", observed_value=item.value, reliability="medium") for item in record.related_entities]
    summary = f"Found {len(record.related_entities)} VirusTotal relationships for {request.entity_value}." if record.related_entities else f"VirusTotal returned no accessible relationships for {request.entity_value}."
    return ToolResult(tool_name=TOOL_NAME, success=bool(record.related_entities), summary=summary, evidence=evidence, sources=record.sources, provider_findings=record.provider_findings, related_entities=record.related_entities, raw_record=public_raw_record(record))

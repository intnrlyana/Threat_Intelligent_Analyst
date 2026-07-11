"""VirusTotal ASN enrichment tool."""

from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderRecord
from backend.src.tools.helpers import provider_failure, public_raw_record
from backend.src.tools.schemas import EvidenceItem, ToolRequest, ToolResult

TOOL_NAME = "asn_lookup"


def asn_lookup(request: ToolRequest, provider: ThreatIntelProvider) -> ToolResult:
    record = provider.lookup_asn(request.entity_value)
    failure = provider_failure(record, TOOL_NAME, f"VirusTotal returned no network information for {request.entity_value}.")
    if failure:
        return failure
    assert isinstance(record, ProviderRecord)
    asn, organization, country = record.asn or "unknown", record.organization or "unknown", record.country or "unknown"
    return ToolResult(tool_name=TOOL_NAME, success=True, summary=f"{request.entity_value} maps to {asn}, {organization}, country {country}.", evidence=[EvidenceItem(claim=f"IP maps to {asn}.", source="VirusTotal", source_type="asn_database", observed_value=asn, reliability="high"), EvidenceItem(claim=f"ASN organization is {organization} in country {country}.", source="VirusTotal", source_type="asn_database", observed_value=organization, reliability="medium")], sources=record.sources, provider_findings=record.provider_findings, raw_record=public_raw_record(record))

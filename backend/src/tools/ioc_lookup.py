"""IOC reputation tool over the normalized provider contract."""

import ipaddress

from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.models import ProviderRecord
from backend.src.security.retrieved_data_guard import detect_indirect_prompt_injection
from backend.src.tools.helpers import provider_failure, public_raw_record
from backend.src.tools.schemas import ToolError, ToolRequest, ToolResult

TOOL_NAME = "ioc_reputation_lookup"
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _is_documentation_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in DOCUMENTATION_NETWORKS)


def ioc_reputation_lookup(request: ToolRequest, provider: ThreatIntelProvider) -> ToolResult:
    if request.entity_type == "ip" and _is_documentation_ip(request.entity_value):
        return ToolResult(
            tool_name=TOOL_NAME,
            success=False,
            summary=f"{request.entity_value} is a reserved documentation/test IP address; an external reputation lookup is not actionable.",
            errors=[ToolError(provider="input_validation", error_type="reserved_indicator", message="Documentation/test IP ranges are excluded from external reputation verdicts.")],
        )
    record = provider.lookup_ioc(request.entity_type, request.entity_value)
    failure = provider_failure(record, TOOL_NAME, f"No provider report was found for {request.entity_value}.")
    if failure:
        return failure
    assert isinstance(record, ProviderRecord)
    guardrail = detect_indirect_prompt_injection(public_raw_record(record))
    return ToolResult(tool_name=TOOL_NAME, success=True, verdict=record.verdict, risk_score=record.risk_score, summary=record.summary or None, evidence=record.evidence, sources=record.sources, related_entities=record.related_entities, safety_flags=guardrail.flags, provider_findings=record.provider_findings, raw_record=public_raw_record(record), errors=record.provider_errors, degraded=bool(record.provider_errors))

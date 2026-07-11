"""Conversions from typed provider results to public tool results."""

from backend.src.providers.models import ProviderFailure, ProviderRecord, ProviderResult
from backend.src.tools.schemas import ToolResult


def provider_failure(result: ProviderResult, tool_name: str, missing_summary: str) -> ToolResult | None:
    if result is None:
        return ToolResult(tool_name=tool_name, success=False, summary=missing_summary)
    if isinstance(result, ProviderFailure):
        return ToolResult(tool_name=tool_name, success=False, summary=result.error.message, errors=[result.error], degraded=True)
    return None


def public_raw_record(record: ProviderRecord) -> dict[str, object]:
    return record.model_dump(mode="json", exclude={"attributes"})

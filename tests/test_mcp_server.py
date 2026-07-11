import asyncio

import pytest

from backend.mcp_server import _public_result, _validate_indicator, capabilities, mcp
from backend.src.tools.schemas import EvidenceItem, ToolResult


def test_mcp_exposes_bounded_tools_and_capability_resource() -> None:
    tools = asyncio.run(mcp.list_tools())
    resources = asyncio.run(mcp.list_resources())

    assert {tool.name for tool in tools} == {
        "investigate_ioc",
        "pivot_related_entities",
        "enrich_ip_network",
        "search_actor_intelligence",
        "assess_product_exposure",
    }
    assert {str(resource.uri) for resource in resources} == {"threat-intel://capabilities"}
    assert set(capabilities()["providers"]) == {"VirusTotal", "AlienVault OTX", "AbuseIPDB", "NVD", "MITRE ATT&CK"}


def test_mcp_result_omits_raw_provider_payload() -> None:
    result = ToolResult(
        tool_name="ioc_reputation_lookup",
        success=True,
        verdict="suspicious",
        evidence=[EvidenceItem(claim="Test evidence", source="Test", source_type="test")],
        raw_record={"secret_provider_payload": "not exposed"},
    )

    payload = _public_result(result)

    assert "raw_record" not in payload
    assert payload["provider_status"] == "ok"


@pytest.mark.parametrize("entity_type,value", [("ip", "not-an-ip"), ("domain", "invalid"), ("hash", "abcd")])
def test_mcp_rejects_invalid_indicators(entity_type: str, value: str) -> None:
    with pytest.raises(ValueError):
        _validate_indicator(entity_type, value)

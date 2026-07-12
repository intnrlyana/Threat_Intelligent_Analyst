from backend.src.evidence.response_builder import build_response
from tests.fake_provider import FakeThreatIntelProvider
from backend.src.tools.ioc_lookup import ioc_reputation_lookup
from backend.src.tools.schemas import EvidenceItem, SourceReference, ToolError, ToolRequest, ToolResult


def test_response_has_all_required_sections() -> None:
    result = ioc_reputation_lookup(ToolRequest(entity_type="ip", entity_value="45.83.122.10"), FakeThreatIntelProvider())
    response, confidence = build_response(result, "45.83.122.10")

    for section in ("Finding", "Evidence", "Impact / Risk", "NIST CSF-Aligned Actions", "Sources", "Limitations"):
        assert section in response
    assert "\n\nConfidence\n" not in response
    for prefix in ("- Detect:", "- Respond:", "- Protect:"):
        assert prefix in response
    assert confidence.label == "High"


def test_partial_provider_failure_retains_verdict_and_medium_confidence() -> None:
    result = ioc_reputation_lookup(ToolRequest(entity_type="ip", entity_value="45.83.122.10"), FakeThreatIntelProvider())
    result.errors = [ToolError(provider="Optional provider", error_type="authentication", message="Permission denied")]
    result.sources.append(SourceReference(name="Second source", source_type="test"))
    result.degraded = True

    response, confidence = build_response(result, "45.83.122.10")

    assert "assessed as malicious" in response
    assert "optional providers failed" in response
    assert confidence.label == "Medium"


def test_authoritative_evidence_remains_medium_when_optional_enrichment_fails() -> None:
    result = ToolResult(
        tool_name="actor_ttp_lookup",
        success=True,
        evidence=[
            EvidenceItem(claim="T1003.002 — Security Account Manager", source="MITRE ATT&CK", source_type="authoritative_ttp_catalog", reliability="high"),
            EvidenceItem(claim="T1059.001 — PowerShell", source="MITRE ATT&CK", source_type="authoritative_ttp_catalog", reliability="high"),
        ],
        sources=[SourceReference(name="MITRE ATT&CK — APT29 (G0016)", source_type="authoritative_ttp_catalog")],
        errors=[ToolError(provider="AlienVault OTX", error_type="rate_limit", message="Optional enrichment unavailable")],
        degraded=True,
    )

    _, confidence = build_response(result, "APT29")

    assert confidence.label == "Medium"


def test_missing_data_and_provider_error_responses_are_cautious() -> None:
    provider = FakeThreatIntelProvider()
    missing = ioc_reputation_lookup(ToolRequest(entity_type="ip", entity_value="8.8.8.7"), provider)
    degraded = ioc_reputation_lookup(ToolRequest(entity_type="ip", entity_value="8.8.4.4"), provider)

    missing_response, _ = build_response(missing, "8.8.8.7")
    degraded_response, _ = build_response(degraded, "8.8.4.4")

    assert "Unknown is not safe" in missing_response
    assert "incomplete/degraded" in degraded_response


def test_reserved_documentation_indicator_has_no_reputation_confidence() -> None:
    result = ioc_reputation_lookup(ToolRequest(entity_type="ip", entity_value="192.0.2.1"), FakeThreatIntelProvider())

    response, confidence = build_response(result, "192.0.2.1")

    assert confidence.label == "Not applicable"
    assert confidence.score is None
    assert "reserved documentation/test IP" in response

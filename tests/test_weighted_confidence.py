from datetime import datetime, timezone

from backend.src.evidence.confidence import score_confidence
from backend.src.tools.schemas import EvidenceItem, ProviderFinding, SourceReference, ToolResult


def _finding(provider: str, verdict: str, authority: float = 0.9) -> ProviderFinding:
    return ProviderFinding(provider=provider, role="primary", authority=authority, verdict=verdict, retrieved_at=datetime.now(timezone.utc), evidence_count=1)


def _result(findings: list[ProviderFinding]) -> ToolResult:
    return ToolResult(
        tool_name="ioc_reputation_lookup",
        success=True,
        verdict="suspicious",
        evidence=[EvidenceItem(claim="Provider evidence", source=item.provider, source_type="reputation") for item in findings],
        sources=[SourceReference(name=item.provider, source_type="reputation") for item in findings],
        provider_findings=findings,
    )


def test_agreeing_independent_providers_score_higher_than_one_provider() -> None:
    one = score_confidence(_result([_finding("VirusTotal", "malicious")]))
    three = score_confidence(_result([_finding("VirusTotal", "malicious"), _finding("AbuseIPDB", "malicious"), _finding("OTX", "malicious", 0.7)]))

    assert one.score is not None and three.score is not None
    assert three.score > one.score
    assert three.factors["coverage"] == 1.0


def test_provider_disagreement_is_reported_and_reduces_agreement() -> None:
    assessment = score_confidence(_result([_finding("VirusTotal", "malicious"), _finding("AbuseIPDB", "undetected")]))

    assert assessment.factors["agreement"] < 1.0
    assert assessment.contradictions
    assert "VirusTotal reported malicious" in assessment.contradictions[0]


def test_threat_risk_does_not_control_confidence() -> None:
    result = _result([_finding("VirusTotal", "undetected"), _finding("AbuseIPDB", "undetected"), _finding("OTX", "undetected", 0.7)])
    result.risk_score = 0

    assessment = score_confidence(result)

    assert assessment.score is not None and assessment.score >= 75
    assert assessment.label == "High"

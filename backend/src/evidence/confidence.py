"""Explainable confidence scoring independent from threat risk."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from backend.src.tools.schemas import ProviderFinding, ToolResult


class ConfidenceAssessment(BaseModel):
    label: str
    score: int | None = Field(default=None, ge=0, le=100)
    reason: str
    factors: dict[str, float] = Field(default_factory=dict)
    contradictions: list[str] = Field(default_factory=list)


VERDICT_VALUE = {"benign": -1.0, "harmless": -1.0, "undetected": 0.0, "unknown": 0.0, "suspicious": 0.5, "malicious": 1.0, "potentially_exposed": 1.0}
ROLE_WEIGHT = {"primary": 1.0, "supporting": 0.6, "contextual": 0.3}


def _legacy_score(result: ToolResult) -> ConfidenceAssessment:
    """Keep deterministic behavior for injected test providers lacking findings."""
    if not result.success and not result.evidence:
        if result.degraded or result.errors:
            return ConfidenceAssessment(label="Low", score=10, reason="The provider returned an error without usable evidence.")
        return ConfidenceAssessment(label="Unknown", reason="No available evidence was returned by the configured providers.")
    if result.degraded or result.errors:
        if len(result.evidence) >= 2 and result.sources:
            return ConfidenceAssessment(label="Medium", score=60, reason="Substantial sourced evidence was returned, but an optional provider failed.")
        return ConfidenceAssessment(label="Low", score=30, reason="Some evidence is present, but coverage is limited by provider errors.")
    if len(result.evidence) >= 2 and result.sources:
        return ConfidenceAssessment(label="High", score=80, reason="Multiple evidence items and source coverage support the finding.")
    if result.evidence:
        return ConfidenceAssessment(label="Medium", score=55, reason="At least one evidence item supports the finding, with limited coverage.")
    return ConfidenceAssessment(label="Unknown", reason="No evidence is available to support a conclusion.")


def _freshness(finding: ProviderFinding) -> float:
    timestamp = finding.observed_at or finding.retrieved_at
    age_days = max(0, (datetime.now(timezone.utc) - timestamp).days)
    if finding.observed_at is None:
        return 0.7  # Retrieval is current, but observation age is not supplied.
    if age_days <= 7:
        return 1.0
    if age_days <= 30:
        return 0.8
    if age_days <= 90:
        return 0.6
    if age_days <= 365:
        return 0.3
    return 0.1


def _agreement(findings: list[ProviderFinding]) -> tuple[float, list[str]]:
    usable = [item for item in findings if item.success and item.role != "contextual" and item.verdict in VERDICT_VALUE]
    if not usable:
        return 0.7, []  # Actor/TTP and ASN evidence may not have a verdict.
    if len(usable) == 1:
        return 0.6, []
    values = [VERDICT_VALUE[str(item.verdict)] for item in usable]
    spread = max(values) - min(values)
    score = max(0.0, 1.0 - spread / 2.0)
    contradictions = []
    for left_index, left in enumerate(usable):
        for right in usable[left_index + 1:]:
            if abs(VERDICT_VALUE[str(left.verdict)] - VERDICT_VALUE[str(right.verdict)]) >= 0.5:
                contradictions.append(f"{left.provider} reported {left.verdict}, while {right.provider} reported {right.verdict}.")
    return score, contradictions


def _completeness(result: ToolResult) -> float:
    checks = [bool(result.evidence), bool(result.sources), all(item.claim and item.source for item in result.evidence)]
    if result.tool_name == "ioc_reputation_lookup":
        checks.append(result.verdict is not None)
    elif result.tool_name == "actor_ttp_lookup":
        checks.append(any(item.observed_value and item.observed_value.startswith("T") for item in result.evidence))
    elif result.tool_name == "exposure_check":
        checks.append(any(item.observed_value and item.observed_value.startswith("CVE-") for item in result.evidence))
    return sum(bool(value) for value in checks) / len(checks)


def score_confidence(result: ToolResult) -> ConfidenceAssessment:
    """Calculate confidence from authority, coverage, agreement, freshness and health."""
    if any(error.error_type == "reserved_indicator" for error in result.errors):
        return ConfidenceAssessment(
            label="Not applicable",
            reason="The indicator is a reserved documentation/test address, so no reputation confidence is applicable.",
        )
    if not result.provider_findings:
        return _legacy_score(result)
    successful = [item for item in result.provider_findings if item.success]
    if not successful or not result.evidence:
        if result.errors or any(item.error_type for item in result.provider_findings):
            return ConfidenceAssessment(label="Low", score=10, reason="No usable evidence was returned and one or more providers failed.")
        return ConfidenceAssessment(label="Unknown", reason="No usable evidence was returned.")

    authority_weights = [ROLE_WEIGHT.get(item.role, 0.6) for item in successful]
    authority = sum(item.authority * weight for item, weight in zip(successful, authority_weights)) / sum(authority_weights)
    coverage = min(len({item.provider for item in successful}) / 3.0, 1.0)
    agreement, contradictions = _agreement(result.provider_findings)
    freshness = sum(_freshness(item) for item in successful) / len(successful)
    completeness = _completeness(result)
    health_weights = [ROLE_WEIGHT.get(item.role, 0.6) for item in result.provider_findings]
    provider_health = sum(weight for item, weight in zip(result.provider_findings, health_weights) if item.success) / sum(health_weights)
    factors = {
        "authority": round(authority, 3),
        "coverage": round(coverage, 3),
        "agreement": round(agreement, 3),
        "freshness": round(freshness, 3),
        "completeness": round(completeness, 3),
        "provider_health": round(provider_health, 3),
    }
    score = round(100 * (authority * 0.25 + coverage * 0.20 + agreement * 0.25 + freshness * 0.15 + completeness * 0.10 + provider_health * 0.05))
    label = "High" if score >= 75 else "Medium" if score >= 50 else "Low"
    reason = f"Weighted evidence confidence is {score}/100 based on authority, independent coverage, agreement, freshness, completeness, and provider health."
    if contradictions:
        reason += f" {len(contradictions)} provider contradiction{'s were' if len(contradictions) != 1 else ' was'} detected."
    return ConfidenceAssessment(label=label, score=score, reason=reason, factors=factors, contradictions=contradictions)

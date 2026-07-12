"""Build plain-text SOC responses exclusively from typed tool results."""

from backend.src.evidence.confidence import ConfidenceAssessment, score_confidence
from backend.src.evidence.ledger import EvidenceLedger
from backend.src.evidence.response_policy import ACTION_CATALOGUE, DEFAULT_ACTION_IDS
from backend.src.tools.schemas import ToolResult


def _bullet_list(values: list[str], empty_text: str) -> str:
    return "\n".join(f"- {value}" for value in values) if values else f"- {empty_text}"


def _finding(result: ToolResult, entity_value: str) -> str:
    if any(error.error_type == "reserved_indicator" for error in result.errors):
        return result.summary or f"{entity_value} is a reserved documentation/test indicator and is not actionable for external reputation analysis."
    if result.degraded and result.evidence:
        if result.tool_name == "ioc_reputation_lookup":
            score = f" (normalized reputation score: {result.risk_score}/100)" if result.risk_score is not None else ""
            return f"{entity_value} is assessed as {result.verdict or 'unknown'} from the available evidence{score}; one or more optional providers failed."
        return (result.summary or f"Evidence was found for {entity_value}.") + " One or more optional providers failed."
    if result.degraded:
        return f"The result for {entity_value} is inconclusive because the configured providers could not complete the lookup."
    if not result.success:
        return f"No available evidence was found for {entity_value}."
    if result.tool_name == "ioc_reputation_lookup":
        score = f" (normalized reputation score: {result.risk_score}/100)" if result.risk_score is not None else ""
        return f"{entity_value} is assessed as {result.verdict or 'unknown'} based on correlated live provider evidence{score}."
    if result.tool_name == "exposure_check":
        return result.summary or f"{entity_value} is potentially exposed based on local evidence."
    return result.summary or f"Live provider evidence was found for {entity_value}."


def _limitations(result: ToolResult) -> list[str]:
    if any(error.error_type == "reserved_indicator" for error in result.errors):
        return ["Documentation/test address ranges do not represent operational threat indicators.", "No external reputation verdict was requested or inferred for this address."]
    if result.degraded and result.evidence:
        if result.tool_name == "actor_ttp_lookup":
            return ["One or more optional providers failed, but authoritative ATT&CK evidence from successful providers is retained.", "Map the documented techniques against internal detections and hunting coverage before drawing operational conclusions."]
        if result.tool_name == "exposure_check":
            return ["One or more optional providers failed, but successful vulnerability evidence is retained.", "Verify exact build, patch level, CPE applicability, and deployment exposure before concluding vulnerability."]
        return ["One or more optional providers failed, but evidence from successful providers is retained.", "Correlate the available reputation evidence with internal telemetry before taking action."]
    if result.degraded:
        return ["The result is incomplete/degraded due to provider failure.", "Unknown is not safe; use another source or retry before making a decision."]
    if not result.success:
        return ["No available evidence was found.", "Unknown is not safe; absence from external providers is not a clean verdict."]
    limitations = ["This result reflects external provider data available at retrieval time and may change."]
    if result.tool_name == "ioc_reputation_lookup":
        limitations.append("Reputation evidence does not prove internal compromise.")
        if result.verdict in {"undetected", "harmless", "unknown"}:
            limitations.append("An undetected or harmless external reputation is not a clean verdict; check relevant internal telemetry before treating the indicator as safe.")
    elif result.tool_name == "exposure_check":
        limitations.append("NVD keyword matches are candidates; verify CPE applicability, exact build, patch level, and deployment exposure before concluding vulnerability.")
    elif result.tool_name == "asn_lookup":
        limitations.append("ASN enrichment should not be used as the sole blocking decision.")
    elif result.tool_name == "pivot_related_entities":
        limitations.append("Relationship records can be historical and do not establish that a related entity is malicious or currently active.")
    if "indirect_prompt_injection" in result.safety_flags:
        limitations.append("A retrieved record contained instruction-like text. It was treated as untrusted data and ignored for control flow.")
    return limitations


def _fallback_impact(result: ToolResult) -> str:
    return {
        "ioc_reputation_lookup": "External reputation can prioritize investigation, but it does not establish the target's relevance to the organization or prove internal compromise.",
        "pivot_related_entities": "The returned entities share infrastructure relationships with the target; those relationships do not establish maliciousness or current activity.",
        "asn_lookup": "Network ownership context can support correlation and scoping, but it does not establish malicious intent or justify blocking the ASN.",
        "actor_ttp_lookup": "The documented techniques describe historical actor behavior and can inform detection coverage; they do not establish current activity in the organization.",
        "exposure_check": "Candidate vulnerabilities may create operational risk only when the exact product build, affected range, configuration, and deployment exposure are applicable.",
    }.get(result.tool_name, "The available evidence requires internal context before operational impact can be concluded.")


def _fallback_actions(result: ToolResult) -> str:
    catalogue = ACTION_CATALOGUE.get(result.tool_name)
    identifiers = DEFAULT_ACTION_IDS.get(result.tool_name)
    if not catalogue or not identifiers:
        return "- Detect: Review relevant internal telemetry.\n- Respond: Escalate only when evidence is corroborated.\n- Protect: Apply proportionate controls after validating impact."
    return "\n".join(f"- {catalogue[action_id][0]}: {catalogue[action_id][1]}" for action_id in identifiers)


def build_response(result: ToolResult, entity_value: str) -> tuple[str, ConfidenceAssessment]:
    """Create a fixed-format analyst response without inventing evidence."""
    ledger = EvidenceLedger.from_tool_result(result)
    confidence = score_confidence(result)
    evidence = _bullet_list([item.claim for item in ledger.items()], "No available evidence was found.")
    sources = _bullet_list([source.name for source in ledger.sources(result)], "No source records were returned.")
    errors = [f"{error.provider} ({error.error_type}): {error.message}" for error in result.errors]
    if errors:
        evidence = f"{evidence}\n" + _bullet_list(errors, "")
    response = "\n\n".join(
        [
            f"Finding\n{_finding(result, entity_value)}",
            f"Evidence\n{evidence}",
            f"Impact / Risk\n{_fallback_impact(result)}",
            f"NIST CSF-Aligned Actions\n{_fallback_actions(result)}",
            f"Sources\n{sources}",
            f"Limitations\n{_bullet_list(_limitations(result), 'No additional limitations recorded.')}",
        ]
    )
    return response, confidence

"""Build plain-text SOC responses exclusively from typed tool results."""

from backend.src.evidence.confidence import ConfidenceAssessment, score_confidence
from backend.src.evidence.ledger import EvidenceLedger
from backend.src.tools.schemas import ToolResult


def _bullet_list(values: list[str], empty_text: str) -> str:
    return "\n".join(f"- {value}" for value in values) if values else f"- {empty_text}"


def _finding(result: ToolResult, entity_value: str) -> str:
    if any(error.error_type == "reserved_indicator" for error in result.errors):
        return result.summary or f"{entity_value} is a reserved documentation/test indicator and is not actionable for external reputation analysis."
    if result.degraded and result.evidence:
        if result.tool_name == "ioc_reputation_lookup":
            score = f" (provider detection ratio: {result.risk_score}/100)" if result.risk_score is not None else ""
            return f"{entity_value} is assessed as {result.verdict or 'unknown'} from the available evidence{score}; one or more optional providers failed."
        return (result.summary or f"Evidence was found for {entity_value}.") + " One or more optional providers failed."
    if result.degraded:
        return f"The result for {entity_value} is inconclusive because the configured providers could not complete the lookup."
    if not result.success:
        return f"No available evidence was found for {entity_value}."
    if result.tool_name == "ioc_reputation_lookup":
        score = f" (provider detection ratio: {result.risk_score}/100)" if result.risk_score is not None else ""
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


def _next_step(result: ToolResult) -> str:
    if any(error.error_type == "reserved_indicator" for error in result.errors):
        return "Use an observed production indicator or relevant internal telemetry for investigation."
    if result.degraded and result.evidence:
        if result.tool_name == "actor_ttp_lookup":
            return "Map successful ATT&CK evidence to internal detections; separately retry or repair the failed optional provider."
        if result.tool_name == "exposure_check":
            return "Validate the exact deployed build and patch level; separately retry or repair the failed optional provider."
        return "Review the successful provider evidence and internal telemetry; separately repair or retry the failed provider."
    if result.degraded:
        return "Retry later or check alternate threat-intelligence sources."
    if not result.success:
        return "Check additional sources and relevant internal telemetry before treating the indicator as safe."
    if result.tool_name == "actor_ttp_lookup":
        return "Map these techniques against internal detections and hunting coverage."
    if result.tool_name == "exposure_check":
        return "Verify the exact build and patch level, then apply the listed remediation where applicable."
    if result.tool_name == "pivot_related_entities":
        return "Check DNS, proxy, and endpoint telemetry for the related entities."
    if result.tool_name == "asn_lookup":
        return "Use this ASN information as enrichment alongside other evidence."
    return "Review relevant internal telemetry and scope any related activity."


def build_response(result: ToolResult, entity_value: str) -> tuple[str, ConfidenceAssessment]:
    """Create a fixed-format analyst response without inventing evidence."""
    ledger = EvidenceLedger.from_tool_result(result)
    confidence = score_confidence(result)
    evidence = _bullet_list([item.claim for item in ledger.items()], "No available evidence was found.")
    sources = _bullet_list([source.name for source in ledger.sources(result)], "No source records were returned.")
    errors = [f"{error.provider} ({error.error_type}): {error.message}" for error in result.errors]
    if errors:
        evidence = f"{evidence}\n" + _bullet_list(errors, "")
    confidence_details = confidence.label
    if confidence.score is not None:
        confidence_details += f" ({confidence.score}/100)"
    confidence_details += f" - {confidence.reason}"
    if confidence.factors:
        confidence_details += "\nFactors:\n" + _bullet_list(
            [f"{name.replace('_', ' ').title()}: {value:.2f}" for name, value in confidence.factors.items()],
            "No factor details available.",
        )
    if confidence.contradictions:
        confidence_details += "\nContradictions:\n" + _bullet_list(confidence.contradictions, "No contradictions detected.")
    response = "\n\n".join(
        [
            f"Finding\n{_finding(result, entity_value)}",
            f"Evidence\n{evidence}",
            f"Sources\n{sources}",
            f"Confidence\n{confidence_details}",
            f"Limitations\n{_bullet_list(_limitations(result), 'No additional limitations recorded.')}",
            f"Recommended Next Step\n{_next_step(result)}",
        ]
    )
    return response, confidence

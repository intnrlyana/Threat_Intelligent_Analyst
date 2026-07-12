"""Validated, evidence-bounded LLM routing and response composition."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.config import Settings
from backend.src.evidence.confidence import score_confidence
from backend.src.evidence.response_policy import (
    ACTION_CATALOGUE,
    DEFAULT_ACTION_IDS,
    DEFAULT_LIMITATION_IDS,
    LIMITATION_CATALOGUE,
    UNSUPPORTED_ANALYSIS_TERMS,
)
from backend.src.llm.groq_provider import GroqLLMProvider
from backend.src.llm.prompts import GROUNDED_RESPONSE_PROMPT, INVESTIGATION_PLAN_PROMPT, ROUTING_PROMPT
from backend.src.tools.schemas import ToolResult


class GroqRoutingResult(BaseModel):
    """The only classifier contract accepted from the remote model."""

    model_config = ConfigDict(extra="forbid")

    intent: Literal["ioc_lookup", "actor_ttp", "exposure_reasoning", "pivot", "asn_lookup", "unknown"]
    entity_type: Literal["ip", "domain", "hash", "actor", "product", "version", "asn", "unknown"]
    entity_value: str | None = None
    product: str | None = None
    version: str | None = None
    requires_context: bool
    confidence: float = Field(ge=0, le=1)
    rationale_summary: str = Field(default="", max_length=280)

    @model_validator(mode="after")
    def reject_placeholder_entities(self) -> "GroqRoutingResult":
        values = (self.entity_value, self.product, self.version)
        if any(value and value.strip().lower() == "unknown" for value in values):
            raise ValueError("placeholder values are not valid entities")
        if self.entity_type == "unknown" and self.entity_value is not None:
            raise ValueError("unknown entity types cannot have an entity value")
        return self

    def to_decision(self) -> RoutingDecision:
        payload = self.model_dump()
        payload["intent"] = Intent(payload["intent"])
        payload["entity_type"] = EntityType(payload["entity_type"])
        return RoutingDecision(**payload)


class EvidenceBoundStatement(BaseModel):
    """One analytical statement with explicit evidence provenance."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(min_length=1, max_length=5)
    certainty: Literal["supported", "hypothesis", "unknown"]


class IOCAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: list[EvidenceBoundStatement] = Field(min_length=1, max_length=3)
    action_ids: list[Literal["IOC-DE-01", "IOC-RS-01", "IOC-PR-01"]] = Field(min_length=1, max_length=3)
    limitation_ids: list[Literal["IOC-LIM-TIME", "IOC-LIM-COMPROMISE", "IOC-LIM-UNKNOWN"]] = Field(min_length=1, max_length=3)


class PivotAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: list[EvidenceBoundStatement] = Field(min_length=1, max_length=3)
    action_ids: list[Literal["PIVOT-DE-01", "PIVOT-RS-01", "PIVOT-PR-01"]] = Field(min_length=1, max_length=3)
    limitation_ids: list[Literal["PIVOT-LIM-RELATIONSHIP", "PIVOT-LIM-CONTEXT"]] = Field(min_length=1, max_length=2)


class ASNAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: list[EvidenceBoundStatement] = Field(min_length=1, max_length=3)
    action_ids: list[Literal["ASN-DE-01", "ASN-RS-01", "ASN-PR-01"]] = Field(min_length=1, max_length=3)
    limitation_ids: list[Literal["ASN-LIM-ENRICHMENT", "ASN-LIM-LOCATION"]] = Field(min_length=1, max_length=2)


class ActorAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: list[EvidenceBoundStatement] = Field(min_length=1, max_length=3)
    action_ids: list[Literal["ACTOR-DE-01", "ACTOR-RS-01", "ACTOR-PR-01"]] = Field(min_length=1, max_length=3)
    limitation_ids: list[Literal["ACTOR-LIM-HISTORICAL", "ACTOR-LIM-COVERAGE"]] = Field(min_length=1, max_length=2)


class ExposureAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: list[EvidenceBoundStatement] = Field(min_length=1, max_length=3)
    action_ids: list[Literal["EXPOSURE-DE-01", "EXPOSURE-RS-01", "EXPOSURE-PR-01"]] = Field(min_length=1, max_length=3)
    limitation_ids: list[Literal["EXPOSURE-LIM-CANDIDATE", "EXPOSURE-LIM-PATCH"]] = Field(min_length=1, max_length=2)


GroundedAnalysis = IOCAnalysis | PivotAnalysis | ASNAnalysis | ActorAnalysis | ExposureAnalysis

ANALYSIS_SCHEMAS: dict[str, type[BaseModel]] = {
    "ioc_reputation_lookup": IOCAnalysis,
    "pivot_related_entities": PivotAnalysis,
    "asn_lookup": ASNAnalysis,
    "actor_ttp_lookup": ActorAnalysis,
    "exposure_check": ExposureAnalysis,
}


class GroqPlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: Literal["ioc_lookup", "actor_ttp", "exposure_reasoning", "pivot", "asn_lookup"]
    entity_type: Literal["ip", "domain", "hash", "actor", "product"]
    entity_value: str
    product: str | None = None
    version: str | None = None


class GroqInvestigationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: list[GroqPlanStep] = Field(min_length=1, max_length=3)


def get_groq_provider(settings: Settings) -> GroqLLMProvider:
    if settings.llm_provider.lower() != "groq":
        raise RuntimeError(f"Unsupported LLM provider: {settings.llm_provider}")
    return GroqLLMProvider(settings)


def classify_with_groq(message: str, settings: Settings) -> RoutingDecision:
    """Classify a query using a LangChain prompt and Pydantic output contract."""
    try:
        prompt = ROUTING_PROMPT.invoke({"analyst_query": message})
        result = get_groq_provider(settings).invoke_structured(prompt, GroqRoutingResult)
        return GroqRoutingResult.model_validate(result).to_decision()
    except ValidationError as exc:
        raise RuntimeError("Groq router returned invalid schema") from exc
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Groq router failed: {exc}") from exc


def plan_with_groq(message: str, primary: RoutingDecision, allowed_entities: set[str], settings: Settings) -> list[GroqPlanStep]:
    try:
        prompt = INVESTIGATION_PLAN_PROMPT.invoke({"analyst_query": message, "allowed_entities": sorted(allowed_entities), "primary_intent": primary.intent.value, "max_steps": 3})
        result = get_groq_provider(settings).invoke_structured(prompt, GroqInvestigationPlan)
        plan = GroqInvestigationPlan.model_validate(result)
    except (ValidationError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Groq investigation planner failed: {exc}") from exc
    normalized = {value.casefold() for value in allowed_entities}
    supplied_values = [value for step in plan.steps for value in (step.entity_value, step.product, step.version) if value]
    if any(value.casefold() not in normalized for value in supplied_values):
        raise RuntimeError("Groq investigation plan introduced an untrusted entity")
    compatible = {"ioc_lookup": {"ip", "domain", "hash"}, "pivot": {"ip", "domain"}, "asn_lookup": {"ip"}, "actor_ttp": {"actor"}, "exposure_reasoning": {"product"}}
    if any(step.entity_type not in compatible[step.intent] for step in plan.steps):
        raise RuntimeError("Groq investigation plan selected an incompatible entity type")
    if not any(step.intent == primary.intent.value for step in plan.steps):
        raise RuntimeError("Groq investigation plan omitted the routed primary task")
    return plan.steps


def _sections(plan: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for section in plan.split("\n\n"):
        heading, _, body = section.partition("\n")
        values[heading] = body
    return values


def _fact_tokens(value: str) -> set[str]:
    import re
    patterns = (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        r"\bCVE-\d{4}-\d+\b", r"\bT\d{4}(?:\.\d{3})?\b", r"\bAS\d+\b", r"\b\d+(?:\.\d+)?%?\b",
    )
    return {match.group(0).casefold() for pattern in patterns for match in re.finditer(pattern, value, re.IGNORECASE)}


def _render_grounded(plan: str, result: ToolResult, generated: GroundedAnalysis) -> str:
    generated_text = " ".join(statement.text for statement in generated.analysis)
    if not _fact_tokens(generated_text) <= _fact_tokens(plan):
        raise RuntimeError("Groq response introduced a fact token absent from grounded evidence")
    protected_terms = ("virustotal", "alienvault", "abuseipdb", "shodan", "nvd", "mitre att&ck", "safe", "clean")
    generated_lower, plan_lower = generated_text.casefold(), plan.casefold()
    if any(term in generated_lower and term not in plan_lower for term in protected_terms):
        raise RuntimeError("Groq response introduced a protected term or provider absent from grounded evidence")
    security_claims = ("ransomware", "malware", "phishing", "botnet", "exploit", "backdoor", "apt", "campaign", "compromised", "breach")
    if any(term in generated_lower and term not in plan_lower for term in security_claims):
        raise RuntimeError("Groq response introduced an unsupported security claim")
    valid_evidence_ids = {f"EV-{index:03d}" for index in range(1, len(result.evidence) + 1)}
    referenced_ids = {evidence_id for statement in generated.analysis for evidence_id in statement.evidence_ids}
    if not referenced_ids <= valid_evidence_ids:
        raise RuntimeError("Groq response cited an evidence ID absent from the structured case")
    if any(term in generated_lower for term in UNSUPPORTED_ANALYSIS_TERMS.get(result.tool_name, ())):
        raise RuntimeError(f"Groq analysis exceeded the capability of {result.tool_name} evidence")
    policy_actions = ACTION_CATALOGUE[result.tool_name]
    policy_limitations = LIMITATION_CATALOGUE[result.tool_name]
    sections = _sections(plan)
    impact = "\n".join(
        f"- {'Hypothesis: ' if statement.certainty == 'hypothesis' else ''}{statement.text} [Evidence: {', '.join(statement.evidence_ids)}]"
        for statement in generated.analysis
    )
    selected_actions = list(dict.fromkeys([*generated.action_ids, *DEFAULT_ACTION_IDS[result.tool_name]]))
    actions = "\n".join(f"- {policy_actions[action_id][0]}: {policy_actions[action_id][1]}" for action_id in selected_actions)
    selected_limitations = list(dict.fromkeys([*generated.limitation_ids, *DEFAULT_LIMITATION_IDS[result.tool_name]]))
    limitations = "\n".join(f"- {policy_limitations[limitation_id]}" for limitation_id in selected_limitations)
    return "\n\n".join([
        f"Finding\n{sections['Finding']}",
        f"Evidence\n{sections['Evidence']}",
        f"Impact / Risk\n{impact}",
        f"NIST CSF-Aligned Actions\n{actions}",
        f"Sources\n{sections['Sources']}",
        f"Limitations\n{limitations}",
    ])


def _grounded_case(result: ToolResult, entity_value: str) -> str:
    """Serialize observations for analysis without seeding generic conclusions."""
    confidence = score_confidence(result)
    case = {
        "investigation_type": result.tool_name,
        "target": entity_value,
        "provider_derived_verdict": result.verdict or "unknown",
        "provider_detection_ratio": result.risk_score,
        "evidence": [
            {
                "id": f"EV-{index:03d}",
                "source": item.source,
                "claim": item.claim,
                "observed_value": item.observed_value,
                "reliability": item.reliability,
            }
            for index, item in enumerate(result.evidence, start=1)
        ],
        "sources": [source.model_dump(mode="json") for source in result.sources],
        "provider_findings": [finding.model_dump(mode="json") for finding in result.provider_findings],
        "provider_errors": [error.model_dump(mode="json") for error in result.errors],
        "confidence": confidence.model_dump(mode="json"),
        "degraded": result.degraded,
    }
    return json.dumps(case, ensure_ascii=False, indent=2)


def compose_with_groq(deterministic_plan: str, result: ToolResult, entity_value: str, settings: Settings) -> str:
    """Analyze a structured case and preserve immutable locally rendered sections."""
    try:
        schema = ANALYSIS_SCHEMAS.get(result.tool_name)
        if schema is None:
            raise RuntimeError(f"No grounded analysis schema exists for {result.tool_name}")
        grounded_case = _grounded_case(result, entity_value)
        generated = get_groq_provider(settings).invoke_structured(GROUNDED_RESPONSE_PROMPT.invoke({"grounded_case": grounded_case}), schema)
        parsed = schema.model_validate(generated)
        return _render_grounded(deterministic_plan, result, parsed)  # type: ignore[arg-type]
    except ValidationError as exc:
        raise RuntimeError("Groq response composer returned invalid schema") from exc
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Groq response composer failed: {exc}") from exc

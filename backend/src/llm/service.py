"""Validated, evidence-bounded LLM routing and response composition."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.config import Settings
from backend.src.llm.groq_provider import GroqLLMProvider
from backend.src.llm.prompts import COREFERENCE_PROMPT, GROUNDED_RESPONSE_PROMPT, INVESTIGATION_PLAN_PROMPT, ROUTING_PROMPT


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
    rationale_summary: str = Field(min_length=1, max_length=280)

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


class GroqGroundedResponse(BaseModel):
    """Bounded narrative fields; immutable evidence sections are rendered locally."""

    model_config = ConfigDict(extra="forbid")

    finding: str = Field(min_length=1, max_length=700)
    limitations: list[str] = Field(min_length=1, max_length=4)
    recommended_next_step: str = Field(min_length=1, max_length=500)


class GroqCoreferenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected_memory_key: Literal["last_ip", "last_domain", "last_hash", "last_actor", "last_product", "last_version", "none"]
    confidence: float = Field(ge=0, le=1)


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


def resolve_coreference_with_groq(message: str, intent: Intent, memory: dict[str, str], settings: Settings) -> tuple[str, str] | None:
    allowed = {"last_ip"} if intent == Intent.ASN_LOOKUP else {"last_ip", "last_domain"} if intent == Intent.PIVOT else set(memory)
    available = {key: value for key, value in memory.items() if key in allowed and value}
    if not available:
        return None
    try:
        result = get_groq_provider(settings).invoke_structured(COREFERENCE_PROMPT.invoke({"analyst_query": message, "intent": intent.value, "available_memory": available}), GroqCoreferenceResult)
        parsed = GroqCoreferenceResult.model_validate(result)
    except (ValidationError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Groq coreference resolver failed: {exc}") from exc
    if parsed.selected_memory_key == "none" or parsed.confidence < 0.70 or parsed.selected_memory_key not in available:
        return None
    return parsed.selected_memory_key, available[parsed.selected_memory_key]


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


def _render_grounded(plan: str, generated: GroqGroundedResponse) -> str:
    generated_text = " ".join([generated.finding, *generated.limitations, generated.recommended_next_step])
    if not _fact_tokens(generated_text) <= _fact_tokens(plan):
        raise RuntimeError("Groq response introduced a fact token absent from grounded evidence")
    protected_terms = ("virustotal", "alienvault", "abuseipdb", "shodan", "nvd", "mitre att&ck", "malicious", "suspicious", "harmless", "undetected", "safe", "clean", "potentially exposed")
    generated_lower, plan_lower = generated_text.casefold(), plan.casefold()
    if any(term in generated_lower and term not in plan_lower for term in protected_terms):
        raise RuntimeError("Groq response introduced a protected verdict or provider absent from grounded evidence")
    # Ordinary explanatory language is allowed. Only security-relevant claims
    # that would materially change an analyst decision must already appear in
    # the grounded plan.
    security_claims = ("ransomware", "malware", "phishing", "botnet", "exploit", "backdoor", "apt", "campaign", "compromised", "breach")
    if any(term in generated_lower and term not in plan_lower for term in security_claims):
        raise RuntimeError("Groq response introduced an unsupported security claim")
    sections = _sections(plan)
    limitations = "\n".join(f"- {item}" for item in generated.limitations)
    return "\n\n".join([
        f"Finding\n{generated.finding}", f"Evidence\n{sections['Evidence']}", f"Sources\n{sections['Sources']}",
        f"Confidence\n{sections['Confidence']}", f"Limitations\n{limitations}", f"Recommended Next Step\n{generated.recommended_next_step}",
    ])


def compose_with_groq(deterministic_plan: str, settings: Settings) -> str:
    """Generate bounded narrative while preserving immutable evidence and confidence."""
    try:
        result = get_groq_provider(settings).invoke_structured(GROUNDED_RESPONSE_PROMPT.invoke({"grounded_plan": deterministic_plan}), GroqGroundedResponse)
        return _render_grounded(deterministic_plan, GroqGroundedResponse.model_validate(result))
    except ValidationError as exc:
        raise RuntimeError("Groq response composer returned invalid schema") from exc
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Groq response composer failed: {exc}") from exc

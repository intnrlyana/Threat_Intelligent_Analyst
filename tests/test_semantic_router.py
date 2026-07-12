from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.agents.semantic_router import SemanticRouteResult
from backend.src.config import get_settings
from backend.src.graph.workflow import run_agent_workflow
from backend.src.llm.groq_provider import GroqLLMProvider


def test_confident_qdrant_route_skips_router_llm(monkeypatch) -> None:
    monkeypatch.setenv("ROUTER_MODE", "semantic")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("RESPONSE_MODE", "deterministic")
    get_settings.cache_clear()
    result = SemanticRouteResult(
        RoutingDecision(intent=Intent.IOC_LOOKUP, entity_type=EntityType.IP, entity_value="45.83.122.10", confidence=0.91),
        True,
        0.91,
        0.14,
        (("ioc_lookup", 0.91), ("pivot", 0.77)),
    )
    monkeypatch.setattr("backend.src.graph.workflow.route_semantically", lambda message, entity, settings: result)

    def fail_if_called(self, prompt, schema):  # pragma: no cover - assertion path
        raise AssertionError("Groq router must not run for a confident Qdrant route")

    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", fail_if_called)
    state = run_agent_workflow("Is 45.83.122.10 malicious?")

    assert state.intent == "ioc_lookup"
    assert state.router_used == "qdrant_semantic"
    assert state.router_llm_status == "skipped_semantic_confident"


def test_ambiguous_qdrant_route_uses_groq(monkeypatch) -> None:
    monkeypatch.setenv("ROUTER_MODE", "semantic")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("RESPONSE_MODE", "deterministic")
    get_settings.cache_clear()
    result = SemanticRouteResult(
        RoutingDecision(intent=Intent.PIVOT, confidence=0.81),
        False,
        0.81,
        0.01,
        (("pivot", 0.81), ("asn_lookup", 0.80)),
    )
    monkeypatch.setattr("backend.src.graph.workflow.route_semantically", lambda message, entity, settings: result)
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {
        "intent": "pivot",
        "entity_type": "unknown",
        "entity_value": None,
        "product": None,
        "version": None,
        "requires_context": True,
        "confidence": 0.82,
        "rationale_summary": "The request asks for related infrastructure.",
    })

    state = run_agent_workflow("Map that infrastructure further.")

    assert state.intent == "pivot"
    assert state.router_used == "groq_after_semantic"
    assert state.llm_calls_made >= 1

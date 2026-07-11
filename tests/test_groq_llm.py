from backend.src.config import get_settings
from backend.src.graph.workflow import run_agent_workflow
from backend.src.graph.state import AgentMemory
from backend.src.llm.groq_provider import GroqLLMProvider


def _configure_groq(monkeypatch, *, router_mode: str = "hybrid", response_mode: str = "deterministic", max_llm_calls: int = 2) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("ROUTER_MODE", router_mode)
    monkeypatch.setenv("RESPONSE_MODE", response_mode)
    monkeypatch.setenv("MAX_LLM_CALLS_PER_QUERY", str(max_llm_calls))
    get_settings.cache_clear()


def test_high_confidence_ioc_skips_groq_router(monkeypatch) -> None:
    _configure_groq(monkeypatch)

    def should_not_be_called(self, prompt: object, schema: object) -> object:  # pragma: no cover - assertion path
        raise AssertionError("high-confidence rule route should not call Groq")

    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", should_not_be_called)
    state = run_agent_workflow("I received an alert about 45.83.122.10 — can you tell me whether it looks malicious and what I should do next?")

    assert state.trace is not None
    assert state.intent == "ioc_lookup"
    assert state.entity_value == "45.83.122.10"
    assert state.trace.router_used == "rule_based"
    assert state.trace.llm_called is False
    assert state.trace.router_llm_status == "skipped_high_confidence"
    assert state.trace.response_composer_llm_status == "skipped_deterministic_mode"


def test_ambiguous_query_uses_mocked_groq_router(monkeypatch) -> None:
    _configure_groq(monkeypatch)
    router_json = {
        "intent": "pivot", "entity_type": "unknown", "entity_value": None,
        "product": None, "version": None, "requires_context": True,
        "confidence": 0.61, "rationale_summary": "The request asks to follow related infrastructure.",
    }
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: router_json)

    state = run_agent_workflow("Can you investigate that further?")

    assert state.intent == "pivot"
    assert state.trace is not None
    assert state.trace.router_used == "groq"
    assert state.trace.llm_called is True


def test_llm_response_composer_uses_mocked_grounded_plan(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {
        "finding": "The available provider evidence assesses 45.83.122.10 as malicious.",
        "limitations": ["External reputation does not prove internal compromise."],
        "recommended_next_step": "Review internal telemetry for 45.83.122.10.",
    })
    state = run_agent_workflow("Is 45.83.122.10 malicious?")

    assert state.trace is not None
    assert state.trace.response_composer_used == "groq"
    assert "Finding" in state.response and "Sources" in state.response
    assert "The indicator was detected." in state.response


def test_semantic_coreference_selects_only_existing_memory(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="deterministic")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {"selected_memory_key": "last_ip", "confidence": 0.91})
    state = run_agent_workflow("Pivot further from the infrastructure we investigated.", AgentMemory(last_ip="45.83.122.10"))
    assert state.entity_value == "45.83.122.10"
    assert state.resolved_from_memory is True
    assert state.context_resolver_used == "groq"


def test_compound_query_uses_validated_multi_tool_plan(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="deterministic")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {"steps": [
        {"intent": "asn_lookup", "entity_type": "ip", "entity_value": "45.83.122.10"},
        {"intent": "ioc_lookup", "entity_type": "ip", "entity_value": "45.83.122.10"},
    ]})
    state = run_agent_workflow("Investigate 45.83.122.10 and get its ASN.")
    assert state.planner_used == "groq"
    assert state.tools_called == ["asn_lookup", "ioc_reputation_lookup"]
    assert state.tool_calls_made == 2


def test_planner_rejects_invented_entity_and_falls_back(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="deterministic")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {"steps": [
        {"intent": "asn_lookup", "entity_type": "ip", "entity_value": "203.0.113.250"}
    ]})
    state = run_agent_workflow("Investigate 45.83.122.10 and get its ASN.")
    assert state.planner_used == "deterministic_fallback"
    assert state.tools_called == ["asn_lookup"]
    assert state.llm_error is not None


def test_grounded_composer_rejects_new_fact_token(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {
        "finding": "The evidence also identifies CVE-2099-99999.",
        "limitations": ["External evidence may change."],
        "recommended_next_step": "Review CVE-2099-99999.",
    })
    state = run_agent_workflow("Is 45.83.122.10 malicious?")
    assert state.response_composer_used == "deterministic"
    assert "CVE-2099-99999" not in state.response


def test_grounded_composer_rejects_unsupported_qualitative_claim(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {
        "finding": "The indicator operates ransomware infrastructure.",
        "limitations": ["External evidence may change."],
        "recommended_next_step": "Review internal telemetry.",
    })
    state = run_agent_workflow("Is 45.83.122.10 malicious?")
    assert state.response_composer_used == "deterministic"
    assert "ransomware" not in state.response


def test_grounded_composer_allows_normal_explanatory_language(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {
        "finding": "The available provider evidence supports further review, including vulnerability context where relevant.",
        "limitations": ["External evidence may change over time."],
        "recommended_next_step": "Review relevant internal telemetry.",
    })
    state = run_agent_workflow("Is 45.83.122.10 malicious?")
    assert state.response_composer_used == "groq"


def test_llm_response_composer_rejects_claim_bearing_model_output(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {"response": "invented threat analysis"})
    state = run_agent_workflow("Is 45.83.122.10 malicious?")

    assert state.trace is not None
    assert state.trace.response_composer_used == "deterministic"
    assert state.trace.llm_error is not None


def test_invalid_llm_response_falls_back_to_deterministic_plan(monkeypatch) -> None:
    _configure_groq(monkeypatch, router_mode="rule_based", response_mode="llm")
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: {"response": "untrusted rewrite"})

    state = run_agent_workflow("Is 45.83.122.10 malicious?")

    assert state.trace is not None
    assert state.trace.response_composer_used == "deterministic"
    assert state.trace.llm_error is not None
    assert "Finding" in state.response and "assessed as malicious" in state.response


def test_invalid_groq_router_output_falls_back_safely(monkeypatch) -> None:
    _configure_groq(monkeypatch)
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: "not-json")

    state = run_agent_workflow("Can you investigate that further?")

    assert state.intent == "unknown"
    assert state.trace is not None
    assert state.trace.router_used == "rule_based_fallback"
    assert state.trace.llm_error is not None


def test_llm_call_budget_skips_response_composer_after_llm_routing(monkeypatch) -> None:
    _configure_groq(monkeypatch, response_mode="llm", max_llm_calls=1)
    router_json = {
        "intent": "ioc_lookup", "entity_type": "ip", "entity_value": "45.83.122.10",
        "product": None, "version": None, "requires_context": False,
        "confidence": 0.9, "rationale_summary": "An IP reputation lookup is appropriate.",
    }
    monkeypatch.setattr(GroqLLMProvider, "invoke_structured", lambda self, prompt, schema: router_json)

    state = run_agent_workflow("Could you help determine what this alert needs?")

    assert state.trace is not None
    assert state.trace.llm_calls_made == 1
    assert state.trace.response_composer_used == "deterministic"
    assert state.trace.response_composer_llm_status == "skipped_budget"

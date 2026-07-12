from backend.src.graph.state import AgentMemory
from backend.src.graph.workflow import run_agent_workflow
from backend.src.agent_harness.context import resolve_context
from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision


def test_asn_follow_up_resolves_last_ip() -> None:
    state = run_agent_workflow("and what's its ASN?", AgentMemory(last_ip="45.83.122.10"))

    assert state.intent == "asn_lookup"
    assert state.entity_type == "ip"
    assert state.entity_value == "45.83.122.10"
    assert state.resolved_from_memory is True
    assert state.context_used == {"last_ip": "45.83.122.10"}


def test_pivot_from_that_ip_resolves_last_ip() -> None:
    state = run_agent_workflow("Pivot from that IP to related domains.", AgentMemory(last_ip="45.83.122.10"))

    assert state.intent == "pivot"
    assert state.entity_value == "45.83.122.10"
    assert state.resolved_from_memory is True


def test_pivot_without_context_requests_indicator() -> None:
    state = run_agent_workflow("Pivot from that IP to related domains.")

    assert state.requires_context is True
    assert "Please provide an indicator" in state.response


def test_generic_pivot_uses_only_compatible_memory_entity() -> None:
    state = run_agent_workflow("Pivot further from the infrastructure we investigated.", AgentMemory(last_ip="45.83.122.10"))

    assert state.entity_value == "45.83.122.10"
    assert state.resolved_from_memory is True
    assert state.context_resolver_used == "deterministic"


def test_generic_pivot_does_not_guess_between_ip_and_domain() -> None:
    state = run_agent_workflow(
        "Pivot further from the infrastructure we investigated.",
        AgentMemory(last_ip="45.83.122.10", last_domain="example.com"),
    )

    assert state.requires_context is True
    assert "Please provide an indicator" in state.response


def test_llm_ip_placeholder_does_not_override_session_ip() -> None:
    decision = RoutingDecision(intent=Intent.PIVOT, entity_type=EntityType.IP, entity_value="IP address")

    resolution = resolve_context("Pivot from that IP to related domains.", decision, AgentMemory(last_ip="45.83.122.10"))

    assert resolution.entity_value == "45.83.122.10"
    assert resolution.resolved_from_memory is True


def test_version_follow_up_resolves_last_product() -> None:
    decision = RoutingDecision(
        intent=Intent.EXPOSURE_REASONING,
        entity_type=EntityType.VERSION,
        entity_value="7.13.8",
        version="7.13.8",
    )

    resolution = resolve_context("7.13.8", decision, AgentMemory(last_product="Confluence", last_version="7.13"))

    assert resolution.entity_type == EntityType.PRODUCT
    assert resolution.entity_value == "Confluence"
    assert resolution.resolved_from_memory is True
    assert resolution.context_used == {"last_product": "Confluence"}


def test_version_only_follow_up_runs_exposure_for_remembered_product() -> None:
    state = run_agent_workflow("7.13.8", AgentMemory(last_product="Confluence", last_version="7.13"))

    assert state.intent == "exposure_reasoning"
    assert state.product == "Confluence"
    assert state.version == "7.13.8"
    assert state.entity_type == "product"
    assert state.entity_value == "Confluence"
    assert state.resolved_from_memory is True
    assert state.tools_called == ["exposure_check"]

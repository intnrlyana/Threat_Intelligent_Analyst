"""Explicit deterministic LangGraph orchestration for local analyst workflows."""

from datetime import UTC, datetime
from time import perf_counter
from typing import Callable, TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from backend.src.agent_harness.context import ContextResolution, resolve_context, update_memory
from backend.src.agent_harness.execution import execute_task, next_action_for
from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.agents.coordinator import create_agent_task, extract_entities, is_high_confidence_rule_decision, route_message, select_specialist
from backend.src.agents.semantic_router import COMPATIBLE_ENTITY_TYPES, route_semantically
from backend.src.config import get_settings
from backend.src.evidence.confidence import score_confidence
from backend.src.evidence.response_builder import build_response
from backend.src.graph.state import AgentMemory, AgentState, ToolTrace
from backend.src.llm.service import classify_with_groq, compose_with_groq, plan_with_groq
from backend.src.observability.trace import NodeTrace
from backend.src.security.input_guard import detect_direct_prompt_injection, validate_input
from backend.src.security.prompt_guard import classify_with_prompt_guard
from backend.src.tools.schemas import ToolError, ToolResult

INJECTION_REFUSAL = (
    "I can help with threat intelligence analysis, but I cannot follow instructions that "
    "attempt to override system rules or expose internal prompts."
)


def _fixed_report(finding: str, limitation: str, next_step: str) -> str:
    """Render non-investigation outcomes with the same stable report contract."""
    return "\n\n".join([
        f"Finding\n{finding}",
        "Evidence\n- No investigation evidence was collected.",
        "Impact / Risk\nNo evidence-based operational impact can be assessed for this request.",
        "NIST CSF-Aligned Actions\n"
        f"- Detect: {next_step}\n"
        "- Respond: Do not initiate containment without corroborating evidence.\n"
        "- Protect: Maintain existing controls while the request is clarified.",
        "Sources\n- No source records were returned.",
        f"Limitations\n- {limitation}",
    ])


class WorkflowGraphState(TypedDict):
    agent_state: AgentState


def initialize_state(message: str, memory: AgentMemory | None = None) -> AgentState:
    """Create a fresh operational state without exposing internal reasoning."""
    return AgentState(
        message=validate_input(message),
        memory=memory or AgentMemory(),
        trace_id=str(uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
    )


def _decision_from_state(state: AgentState) -> RoutingDecision:
    return RoutingDecision(
        intent=Intent(state.intent),
        entity_type=EntityType(state.entity_type or "unknown"),
        entity_value=state.entity_value,
        product=state.product,
        version=state.version,
    )


def _missing_context_response(intent: Intent) -> str:
    if intent == Intent.PIVOT:
        return _fixed_report("The pivot target could not be resolved.", "No IP address or domain was available for the pivot.", "Please provide an indicator such as an IP address or domain.")
    if intent == Intent.EXPOSURE_REASONING:
        return _fixed_report("The software product could not be resolved for this version.", "A version alone is insufficient for exposure assessment.", "Provide the product and version, such as Confluence 7.13.")
    return _fixed_report("The ASN lookup target could not be resolved.", "No IP address was available for enrichment.", "Provide the IP address to enrich.")


def _unknown_response() -> str:
    return _fixed_report("The request could not be classified into a supported investigation.", "The request did not contain enough supported threat-intelligence context.", "Provide a threat indicator, actor name, software version, or pivot target.")


def _refresh_trace(state: AgentState) -> None:
    settings = get_settings()
    result = state.tool_result
    provider_errors = [] if result is None else [f"{error.provider} ({error.error_type}): {error.message}" for error in result.errors]
    state.trace = ToolTrace(
        trace_id=state.trace_id,
        timestamp=state.timestamp,
        total_latency_ms=round(sum(item.latency_ms for item in state.node_timings), 2),
        workflow_nodes_executed=state.workflow_nodes_executed,
        node_timings=state.node_timings,
        intent=state.intent,
        selected_agent=state.selected_agent,
        delegated_task_id=state.delegated_task_id,
        entity_type=state.entity_type,
        entity_value=state.entity_value,
        product=state.product,
        version=state.version,
        resolved_from_memory=state.resolved_from_memory,
        context_used=state.context_used,
        context_resolver_used=state.context_resolver_used,
        safety_flags=state.safety_flags,
        tools_called=state.tools_called,
        source_count=state.source_count,
        evidence_count=state.evidence_count,
        confidence=state.confidence,
        confidence_reason=state.confidence_reason,
        confidence_score=state.confidence_score,
        confidence_factors=state.confidence_factors,
        confidence_contradictions=state.confidence_contradictions,
        degraded=state.degraded,
        provider_errors=provider_errors,
        mode=settings.data_mode,
        router_mode=settings.router_mode,
        router_used=state.router_used,
        llm_called=state.llm_called,
        router_llm_status=state.router_llm_status,
        planner_llm_status=state.planner_llm_status,
        response_composer_llm_status=state.response_composer_llm_status,
        llm_calls_made=state.llm_calls_made,
        tool_calls_made=state.tool_calls_made,
        semantic_guard_called=state.semantic_guard_called,
        semantic_guard_risk=state.semantic_guard_risk,
        semantic_guard_label=state.semantic_guard_label,
        semantic_guard_confidence=state.semantic_guard_confidence,
        semantic_guard_error=state.semantic_guard_error,
        llm_provider=settings.llm_provider,
        llm_model=settings.llm_model,
        llm_error=state.llm_error,
        llm_skipped_reason=state.llm_skipped_reason,
        response_mode=settings.response_mode,
        response_composer_used=state.response_composer_used,
        planner_used=state.planner_used,
        next_action=next_action_for(Intent(state.intent), state.requires_context, result),
    )


def _timed_node(name: str, operation: Callable[[AgentState], None]):
    def node(graph_state: WorkflowGraphState) -> WorkflowGraphState:
        state = graph_state["agent_state"]
        started = perf_counter()
        operation(state)
        state.workflow_nodes_executed.append(name)
        state.node_timings.append(NodeTrace(node_name=name, status="completed", latency_ms=round((perf_counter() - started) * 1000, 2)))
        _refresh_trace(state)
        return {"agent_state": state}

    return node


def _input_guard(state: AgentState) -> None:
    guardrail = detect_direct_prompt_injection(state.message)
    if guardrail.is_blocked:
        state.intent = Intent.BLOCKED_PROMPT_INJECTION.value
        state.selected_agent = "none"
        state.safety_flags = guardrail.flags


def _semantic_guard(state: AgentState) -> None:
    settings = get_settings()
    if not settings.prompt_guard_enabled:
        state.semantic_guard_risk = "disabled"
        return
    state.semantic_guard_called = True
    try:
        assessment = classify_with_prompt_guard(state.message, settings)
    except RuntimeError as exc:
        state.semantic_guard_risk = "unknown"
        state.semantic_guard_error = str(exc)
        return
    state.semantic_guard_risk = assessment.risk
    state.semantic_guard_label = assessment.label
    state.semantic_guard_confidence = assessment.confidence
    if assessment.risk == "high":
        state.intent = Intent.BLOCKED_PROMPT_INJECTION.value
        state.selected_agent = "none"
        state.safety_flags.append("semantic_prompt_injection")


def _reserve_llm_call(state: AgentState, purpose: str) -> bool:
    if state.llm_calls_made >= get_settings().max_llm_calls_per_query:
        setattr(state, f"{purpose}_llm_status", "skipped_budget")
        state.llm_skipped_reason = "llm_call_budget_exhausted"
        return False
    state.llm_calls_made += 1
    state.llm_called = True
    setattr(state, f"{purpose}_llm_status", "called")
    return True


def _validated_groq_route(decision: RoutingDecision, entity: RoutingDecision) -> RoutingDecision:
    """Overlay deterministic entities and reject incompatible Groq intents."""
    if entity.entity_type != EntityType.UNKNOWN:
        decision = decision.model_copy(update={
            "entity_type": entity.entity_type,
            "entity_value": entity.entity_value,
            "product": entity.product,
            "version": entity.version,
        })
    if decision.entity_type not in COMPATIBLE_ENTITY_TYPES.get(decision.intent, set()):
        return RoutingDecision(intent=Intent.UNKNOWN, rationale_summary="Groq intent was incompatible with the extracted entity type.")
    return decision


def _route_intent(state: AgentState) -> None:
    settings = get_settings()
    router_mode = settings.router_mode.lower()
    if router_mode == "semantic":
        entity = extract_entities(state.message)
        decision = RoutingDecision(intent=Intent.UNKNOWN)
        try:
            semantic = route_semantically(state.message, entity, settings)
            if semantic.accepted:
                decision = semantic.decision
                state.router_used = "qdrant_semantic"
                state.router_llm_status = "skipped_semantic_confident"
            elif settings.groq_api_key and _reserve_llm_call(state, "router"):
                groq_decision = _validated_groq_route(classify_with_groq(state.message, settings), entity)
                if groq_decision.intent == Intent.UNKNOWN and entity.entity_type != EntityType.UNKNOWN:
                    decision = groq_decision
                    state.router_used = "groq_incompatible"
                else:
                    decision = groq_decision
                    state.router_used = "groq_after_semantic"
            else:
                state.router_used = "semantic_unknown"
                state.router_llm_status = "skipped_missing_key" if not settings.groq_api_key else state.router_llm_status
        except RuntimeError as exc:
            state.llm_error = str(exc)
            if settings.groq_api_key and _reserve_llm_call(state, "router"):
                try:
                    decision = _validated_groq_route(classify_with_groq(state.message, settings), entity)
                    state.router_used = "groq_semantic_fallback" if decision.intent != Intent.UNKNOWN else "groq_incompatible"
                except RuntimeError as groq_exc:
                    state.llm_error = f"{exc}; {groq_exc}"
                    state.router_used = "semantic_failed"
                    state.router_llm_status = "failed"
            else:
                state.router_used = "semantic_failed"
        state.intent = decision.intent.value
        state.selected_agent = select_specialist(state.intent)
        state.entity_type = None if decision.entity_type == EntityType.UNKNOWN else decision.entity_type.value
        state.entity_value = decision.entity_value
        state.product = decision.product
        state.version = decision.version
        return

    rule_decision = route_message(state.message)
    decision = rule_decision
    should_use_groq = router_mode == "llm" or (router_mode == "hybrid" and not is_high_confidence_rule_decision(rule_decision))
    if should_use_groq:
        if not settings.groq_api_key:
            state.router_llm_status = "skipped_missing_key"
            state.router_used = "rule_based_fallback"
        elif _reserve_llm_call(state, "router"):
            try:
                groq_decision = classify_with_groq(state.message, settings)
                if rule_decision.intent != Intent.UNKNOWN and groq_decision.intent == Intent.UNKNOWN:
                    state.router_used = "rule_based_fallback"
                    state.router_llm_status = "fallback_unknown"
                else:
                    decision = groq_decision
                    state.router_used = "groq"
            except RuntimeError as exc:
                state.llm_error = str(exc)
                state.router_used = "rule_based_fallback"
                state.router_llm_status = "failed"
    else:
        state.router_used = "rule_based"
        state.router_llm_status = "skipped_high_confidence" if router_mode == "hybrid" else "skipped_rule_mode"
    state.intent = decision.intent.value
    state.selected_agent = select_specialist(state.intent)
    state.entity_type = None if decision.entity_type == EntityType.UNKNOWN else decision.entity_type.value
    state.entity_value = decision.entity_value
    state.product = decision.product
    state.version = decision.version


def _resolve_context(state: AgentState) -> None:
    resolution = resolve_context(state.message, _decision_from_state(state), state.memory)
    state.entity_type = None if resolution.entity_type == EntityType.UNKNOWN else resolution.entity_type.value
    state.entity_value = resolution.entity_value
    state.requires_context = resolution.requires_context
    state.resolved_from_memory = resolution.resolved_from_memory
    state.context_used = resolution.context_used
    if state.intent == Intent.EXPOSURE_REASONING.value and resolution.context_used.get("last_product"):
        state.product = resolution.context_used["last_product"]


def _delegate_agent(state: AgentState) -> None:
    state.selected_agent = select_specialist(state.intent)
    task = create_agent_task(
        intent=state.intent,
        selected_agent=state.selected_agent,
        entity_type=state.entity_type,
        entity_value=state.entity_value,
        product=state.product,
        version=state.version,
        shared_context={"memory": state.memory.model_dump(), "context_used": state.context_used},
        query=state.message,
    )
    state.delegated_task_id = task.task_id
    state.agent_task = task
    state.agent_tasks = [task]
    settings = get_settings()
    compound = " and " in state.message.lower() and any(word in state.message.lower() for word in ("pivot", "related", "asn", "autonomous system", "ttp", "exposed"))
    if compound and not settings.groq_api_key:
        state.planner_llm_status = "skipped_missing_key"
    if compound and settings.groq_api_key and _reserve_llm_call(state, "planner"):
        allowed = {value for value in [state.entity_value, state.product, state.version, state.memory.last_ip, state.memory.last_domain, state.memory.last_actor] if value}
        try:
            steps = plan_with_groq(state.message, _decision_from_state(state), allowed, settings)
            planned_tasks = [create_agent_task(intent=step.intent, selected_agent=select_specialist(step.intent), entity_type=step.entity_type, entity_value=step.entity_value, product=step.product, version=step.version, shared_context={"memory": state.memory.model_dump()}, query=state.message) for step in steps]
            state.agent_tasks = planned_tasks
            state.agent_task = planned_tasks[0]
            state.planner_used = "groq"
        except RuntimeError as exc:
            state.llm_error = str(exc)
            state.planner_used = "deterministic_fallback"
            state.planner_llm_status = "failed"


def _execute_tool(state: AgentState) -> None:
    if state.agent_task is None:
        return
    if state.tool_calls_made >= get_settings().max_tool_calls_per_query:
        state.tool_result = ToolResult(
            tool_name="none",
            success=False,
            summary="Tool-call budget exhausted before executing the requested lookup.",
            errors=[ToolError(provider="orchestrator", error_type="tool_call_budget_exhausted", message="Maximum tool calls per query reached.")],
            degraded=True,
        )
        state.degraded = True
        return
    results: list[ToolResult] = []
    for task in state.agent_tasks or [state.agent_task]:
        if state.tool_calls_made >= get_settings().max_tool_calls_per_query:
            break
        state.tool_calls_made += 1
        state.agent_result = execute_task(task)
        if state.agent_result.tool_result:
            results.append(state.agent_result.tool_result)
    state.tool_results = results
    if not results:
        return
    state.tools_called = [result.tool_name for result in results]
    if len(results) == 1:
        state.tool_result = results[0]
    else:
        state.tool_result = ToolResult(
            tool_name="multi_tool_investigation", success=any(result.success for result in results),
            verdict=max((result.verdict for result in results if result.verdict), default=None),
            risk_score=max((result.risk_score for result in results if result.risk_score is not None), default=None),
            summary=" ".join(result.summary or "" for result in results).strip(),
            evidence=[item for result in results for item in result.evidence], sources=[item for result in results for item in result.sources],
            related_entities=[item for result in results for item in result.related_entities], errors=[item for result in results for item in result.errors],
            safety_flags=list(dict.fromkeys(item for result in results for item in result.safety_flags)),
            provider_findings=[item for result in results for item in result.provider_findings], degraded=any(result.degraded for result in results),
        )
    state.degraded = state.tool_result.degraded


def _build_evidence(state: AgentState) -> None:
    if state.tool_result:
        state.source_count = len(state.tool_result.sources)
        state.evidence_count = len(state.tool_result.evidence)
        state.safety_flags.extend(flag for flag in state.tool_result.safety_flags if flag not in state.safety_flags)


def _score_confidence(state: AgentState) -> None:
    if state.tool_result:
        assessment = score_confidence(state.tool_result)
        state.confidence = assessment.label
        state.confidence_reason = assessment.reason
        state.confidence_score = assessment.score
        state.confidence_factors = assessment.factors
        state.confidence_contradictions = assessment.contradictions


def _build_response(state: AgentState) -> None:
    if state.intent == Intent.BLOCKED_PROMPT_INJECTION.value:
        state.response = _fixed_report(INJECTION_REFUSAL, "The request triggered prompt-injection controls and was not investigated.", "Submit a threat-intelligence question without instructions to override or reveal protected prompts.")
    elif state.intent == Intent.UNKNOWN.value:
        state.response = _unknown_response()
    elif state.requires_context:
        state.response = _missing_context_response(Intent(state.intent))
    elif state.tool_result:
        deterministic_response, assessment = build_response(state.tool_result, state.entity_value or state.product or "unknown")
        settings = get_settings()
        reserved = any(error.error_type == "reserved_indicator" for error in state.tool_result.errors)
        llm_analysis_tools = {"ioc_reputation_lookup", "actor_ttp_lookup", "exposure_check"}
        analysis_is_useful = state.tool_result.tool_name in llm_analysis_tools
        if settings.response_mode.lower() == "llm" and settings.groq_api_key and state.tool_result.evidence and not reserved and analysis_is_useful:
            if _reserve_llm_call(state, "response_composer"):
                try:
                    state.response = compose_with_groq(
                        deterministic_response,
                        state.tool_result,
                        state.entity_value or state.product or "unknown",
                        settings,
                    )
                    state.response_composer_used = "groq"
                    state.response_composer_llm_status = "generated"
                except RuntimeError as exc:
                    state.llm_error = str(exc)
                    state.response = deterministic_response
                    state.response_composer_llm_status = "failed_fallback"
            else:
                state.response = deterministic_response
        else:
            state.response = deterministic_response
            if not analysis_is_useful:
                state.response_composer_llm_status = "skipped_not_needed"
            elif reserved or not state.tool_result.evidence:
                state.response_composer_llm_status = "skipped_no_actionable_evidence"
            elif settings.response_mode.lower() != "llm":
                state.response_composer_llm_status = "skipped_deterministic_mode"
            else:
                state.response_composer_llm_status = "skipped_missing_key"
        state.confidence = assessment.label
        state.confidence_reason = assessment.reason
        state.confidence_score = assessment.score
        state.confidence_factors = assessment.factors
        state.confidence_contradictions = assessment.contradictions
    else:
        state.response = _fixed_report("No tool result was available.", "Unknown is not safe and no provider result was available.", "Check another source or retry the investigation.")


def _update_memory(state: AgentState) -> None:
    resolution = ContextResolution(
        entity_type=EntityType(state.entity_type or "unknown"),
        entity_value=state.entity_value,
        requires_context=state.requires_context,
        resolved_from_memory=state.resolved_from_memory,
        context_used=state.context_used,
    )
    state.memory = update_memory(state.memory, _decision_from_state(state), resolution)
    if state.intent == Intent.ASN_LOOKUP.value and state.tool_result and state.tool_result.raw_record:
        asn = state.tool_result.raw_record.get("asn")
        if asn:
            state.memory.last_asn = str(asn)


def _after_input_guard(graph_state: WorkflowGraphState) -> str:
    return "build_response_node" if graph_state["agent_state"].intent == Intent.BLOCKED_PROMPT_INJECTION.value else "semantic_guard_node"


def _after_semantic_guard(graph_state: WorkflowGraphState) -> str:
    return "build_response_node" if graph_state["agent_state"].intent == Intent.BLOCKED_PROMPT_INJECTION.value else "route_intent_node"


def _after_route(graph_state: WorkflowGraphState) -> str:
    return "build_response_node" if graph_state["agent_state"].intent == Intent.UNKNOWN.value else "resolve_context_node"


def _after_context(graph_state: WorkflowGraphState) -> str:
    return "build_response_node" if graph_state["agent_state"].requires_context else "delegate_agent_node"


def _after_response(graph_state: WorkflowGraphState) -> str:
    state = graph_state["agent_state"]
    if state.intent in {Intent.BLOCKED_PROMPT_INJECTION.value, Intent.UNKNOWN.value} or state.requires_context:
        return END
    return "update_memory_node"


def build_agent_graph():
    """Compile the deterministic production-shaped LangGraph workflow."""
    graph = StateGraph(WorkflowGraphState)
    graph.add_node("input_guard_node", _timed_node("input_guard_node", _input_guard))
    graph.add_node("semantic_guard_node", _timed_node("semantic_guard_node", _semantic_guard))
    graph.add_node("route_intent_node", _timed_node("route_intent_node", _route_intent))
    graph.add_node("resolve_context_node", _timed_node("resolve_context_node", _resolve_context))
    graph.add_node("delegate_agent_node", _timed_node("delegate_agent_node", _delegate_agent))
    graph.add_node("execute_tool_node", _timed_node("execute_tool_node", _execute_tool))
    graph.add_node("build_evidence_node", _timed_node("build_evidence_node", _build_evidence))
    graph.add_node("score_confidence_node", _timed_node("score_confidence_node", _score_confidence))
    graph.add_node("build_response_node", _timed_node("build_response_node", _build_response))
    graph.add_node("update_memory_node", _timed_node("update_memory_node", _update_memory))
    graph.add_edge(START, "input_guard_node")
    graph.add_conditional_edges("input_guard_node", _after_input_guard)
    graph.add_conditional_edges("semantic_guard_node", _after_semantic_guard)
    graph.add_conditional_edges("route_intent_node", _after_route)
    graph.add_conditional_edges("resolve_context_node", _after_context)
    graph.add_edge("delegate_agent_node", "execute_tool_node")
    graph.add_edge("execute_tool_node", "build_evidence_node")
    graph.add_edge("build_evidence_node", "score_confidence_node")
    graph.add_edge("score_confidence_node", "build_response_node")
    graph.add_conditional_edges("build_response_node", _after_response)
    graph.add_edge("update_memory_node", END)
    return graph.compile()


_COMPILED_GRAPH = build_agent_graph()


def run_agent_workflow(message: str, memory: AgentMemory | None = None) -> AgentState:
    """Run the explicit local LangGraph workflow and return operational state."""
    result = _COMPILED_GRAPH.invoke({"agent_state": initialize_state(message, memory)})
    return result["agent_state"]

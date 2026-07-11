"""Execution helpers for deterministic local agent routing."""

from backend.src.agent_harness.guardrails import task_is_allowed_for_agent
from backend.src.agent_harness.schemas import AgentResult, AgentTask, Intent
from backend.src.providers.base import ThreatIntelProvider
from backend.src.providers.composite_provider import CompositeThreatIntelProvider
from backend.src.security.retrieved_data_guard import guard_tool_result
from backend.src.tools.registry import INTENT_TO_TOOL_NAME, build_default_registry
from backend.src.tools.schemas import ToolRequest, ToolResult


def execute_task(task: AgentTask, provider: ThreatIntelProvider | None = None) -> AgentResult:
    """Execute one allowlisted local tool on behalf of a delegated specialist."""
    tool_name = INTENT_TO_TOOL_NAME.get(task.intent)
    if tool_name is None or not task_is_allowed_for_agent(task, tool_name):
        return AgentResult(task_id=task.task_id, agent_name=task.to_agent, status="blocked", notes=["The requested tool is not allowlisted for this specialist agent."])
    request = ToolRequest(
        entity_type=task.entity_type or "unknown",
        entity_value=task.entity_value or task.product or "unknown",
        product=task.product,
        version=task.version,
        context={key: str(value) for key, value in task.shared_context.items()},
    )
    result = execute_routed_tool(task.intent, request, provider)
    return AgentResult(task_id=task.task_id, agent_name=task.to_agent, tool_result=result, status="completed" if result.success else "degraded" if result.degraded else "no_data")


def execute_routed_tool(intent: str, request: ToolRequest, provider: ThreatIntelProvider | None = None) -> ToolResult:
    """Select and execute the one bounded local tool allowed for a routed intent."""
    tool_name = INTENT_TO_TOOL_NAME.get(intent)
    if tool_name is None:
        return ToolResult(tool_name="none", success=False, summary="No tool is registered for this intent.")
    handler = build_default_registry().get(tool_name)
    if handler is None:
        return ToolResult(tool_name=tool_name, success=False, summary="The requested local tool is unavailable.")
    return guard_tool_result(handler(request, provider or CompositeThreatIntelProvider()))


def next_action_for(intent: Intent, requires_context: bool, result: ToolResult | None = None) -> str:
    """Describe the next bounded action without invoking intelligence tools."""
    if requires_context:
        return "Await an IP address or domain from the analyst."
    if intent == Intent.UNKNOWN:
        return "Await a clearer threat-intelligence request."
    if result is not None and any(error.error_type == "rate_limit" for error in result.errors):
        return "Provider rate limit reached; retry later or use an alternate source."
    if result is not None and result.degraded:
        return "Retry the lookup or check alternate sources before making a decision."
    if result is not None and not result.success:
        return "Check additional sources and internal telemetry; unknown is not safe."
    return "Review the evidence and perform the recommended validation step."

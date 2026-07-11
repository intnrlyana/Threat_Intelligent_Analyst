"""Shared agent-harness admission and delegation guardrails."""

from backend.src.agent_harness.agents import get_agent
from backend.src.agent_harness.schemas import AgentTask


def task_is_allowed_for_agent(task: AgentTask, tool_name: str) -> bool:
    agent = get_agent(task.to_agent)
    return bool(agent and tool_name in agent.allowed_tools)

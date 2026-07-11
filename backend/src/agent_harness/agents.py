"""Structured local agent definitions and allowed tool boundaries."""

from pydantic import BaseModel, Field

from backend.src.agent_harness.schemas import AgentRole


class AgentDefinition(BaseModel):
    name: str
    role: AgentRole
    allowed_tools: list[str] = Field(default_factory=list)

AGENTS = {
    "coordinator": AgentDefinition(name="Coordinator Agent", role=AgentRole.COORDINATOR),
    "ioc_analyst": AgentDefinition(name="IOC Analyst Agent", role=AgentRole.IOC_ANALYST, allowed_tools=["ioc_reputation_lookup", "asn_lookup", "pivot_related_entities"]),
    "actor_ttp_analyst": AgentDefinition(name="Actor/TTP Analyst Agent", role=AgentRole.ACTOR_TTP_ANALYST, allowed_tools=["actor_ttp_lookup"]),
    "exposure_analyst": AgentDefinition(name="Exposure Analyst Agent", role=AgentRole.EXPOSURE_ANALYST, allowed_tools=["exposure_check"]),
    "pivot_analyst": AgentDefinition(name="Pivot Analyst Agent", role=AgentRole.PIVOT_ANALYST, allowed_tools=["pivot_related_entities", "asn_lookup"]),
}

def get_agent(name: str) -> AgentDefinition | None:
    return AGENTS.get(name)

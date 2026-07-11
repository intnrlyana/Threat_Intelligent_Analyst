"""Typed contracts for deterministic routing and agent delegation."""

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from backend.src.tools.schemas import ToolResult


class AgentRole(StrEnum):
    COORDINATOR = "coordinator"
    IOC_ANALYST = "ioc_analyst"
    ACTOR_TTP_ANALYST = "actor_ttp_analyst"
    EXPOSURE_ANALYST = "exposure_analyst"
    PIVOT_ANALYST = "pivot_analyst"


class Intent(StrEnum):
    IOC_LOOKUP = "ioc_lookup"
    ACTOR_TTP = "actor_ttp"
    EXPOSURE_REASONING = "exposure_reasoning"
    PIVOT = "pivot"
    ASN_LOOKUP = "asn_lookup"
    UNKNOWN = "unknown"
    BLOCKED_PROMPT_INJECTION = "blocked_prompt_injection"


class EntityType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    ACTOR = "actor"
    PRODUCT = "product"
    VERSION = "version"
    ASN = "asn"
    UNKNOWN = "unknown"


class RoutingDecision(BaseModel):
    intent: Intent
    entity_type: EntityType = EntityType.UNKNOWN
    entity_value: str | None = None
    product: str | None = None
    version: str | None = None
    requires_context: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale_summary: str = ""


class AgentTask(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    from_agent: str = "coordinator"
    to_agent: str
    intent: str
    entity_type: str | None = None
    entity_value: str | None = None
    product: str | None = None
    version: str | None = None
    shared_context: dict[str, object] = Field(default_factory=dict)
    query: str = ""


class AgentResult(BaseModel):
    task_id: str
    agent_name: str
    tool_result: ToolResult | None = None
    status: str = "completed"
    notes: list[str] = Field(default_factory=list)

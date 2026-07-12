"""State and operational trace models shared by LangGraph nodes."""

from pydantic import BaseModel, Field

from backend.src.agent_harness.schemas import AgentResult, AgentTask
from backend.src.observability.trace import NodeTrace
from backend.src.tools.schemas import ToolResult


class AgentMemory(BaseModel):
    last_ip: str | None = None
    last_domain: str | None = None
    last_hash: str | None = None
    last_actor: str | None = None
    last_product: str | None = None
    last_version: str | None = None
    last_asn: str | None = None


class ToolTrace(BaseModel):
    trace_id: str
    timestamp: str = ""
    total_latency_ms: float = 0
    workflow_nodes_executed: list[str] = Field(default_factory=list)
    node_timings: list[NodeTrace] = Field(default_factory=list)
    intent: str
    selected_agent: str
    delegated_task_id: str | None = None
    entity_type: str | None = None
    entity_value: str | None = None
    product: str | None = None
    version: str | None = None
    resolved_from_memory: bool = False
    context_used: dict[str, str] = Field(default_factory=dict)
    context_resolver_used: str = "deterministic"
    safety_flags: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)
    source_count: int = 0
    evidence_count: int = 0
    confidence: str | None = None
    confidence_reason: str | None = None
    confidence_score: int | None = None
    confidence_factors: dict[str, float] = Field(default_factory=dict)
    confidence_contradictions: list[str] = Field(default_factory=list)
    degraded: bool = False
    provider_errors: list[str] = Field(default_factory=list)
    mode: str = "multi_provider"
    router_mode: str = "hybrid"
    router_used: str = "rule_based"
    llm_called: bool = False
    router_llm_status: str = "not_run"
    planner_llm_status: str = "not_needed"
    response_composer_llm_status: str = "not_run"
    llm_calls_made: int = 0
    tool_calls_made: int = 0
    semantic_guard_called: bool = False
    semantic_guard_risk: str = "not_run"
    semantic_guard_label: str | None = None
    semantic_guard_confidence: float | None = None
    semantic_guard_error: str | None = None
    llm_provider: str = "groq"
    llm_model: str = "llama-3.1-8b-instant"
    llm_error: str | None = None
    llm_skipped_reason: str | None = None
    response_mode: str = "llm"
    response_composer_used: str = "deterministic"
    planner_used: str = "not_used"
    next_action: str = ""


class AgentState(BaseModel):
    message: str
    intent: str = "unknown"
    selected_agent: str = "coordinator"
    entity_type: str | None = None
    entity_value: str | None = None
    product: str | None = None
    version: str | None = None
    requires_context: bool = False
    resolved_from_memory: bool = False
    context_used: dict[str, str] = Field(default_factory=dict)
    context_resolver_used: str = "deterministic"
    safety_flags: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)
    source_count: int = 0
    evidence_count: int = 0
    confidence: str | None = None
    confidence_reason: str | None = None
    confidence_score: int | None = None
    confidence_factors: dict[str, float] = Field(default_factory=dict)
    confidence_contradictions: list[str] = Field(default_factory=list)
    degraded: bool = False
    router_used: str = "rule_based"
    llm_called: bool = False
    router_llm_status: str = "not_run"
    planner_llm_status: str = "not_needed"
    response_composer_llm_status: str = "not_run"
    llm_calls_made: int = 0
    tool_calls_made: int = 0
    semantic_guard_called: bool = False
    semantic_guard_risk: str = "not_run"
    semantic_guard_label: str | None = None
    semantic_guard_confidence: float | None = None
    semantic_guard_error: str | None = None
    llm_error: str | None = None
    llm_skipped_reason: str | None = None
    response_composer_used: str = "deterministic"
    response: str = ""
    memory: AgentMemory = Field(default_factory=AgentMemory)
    trace_id: str
    timestamp: str = ""
    workflow_nodes_executed: list[str] = Field(default_factory=list)
    node_timings: list[NodeTrace] = Field(default_factory=list)
    delegated_task_id: str | None = None
    tool_result: ToolResult | None = None
    agent_task: AgentTask | None = None
    agent_result: AgentResult | None = None
    agent_tasks: list[AgentTask] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    planner_used: str = "not_used"
    trace: ToolTrace | None = None

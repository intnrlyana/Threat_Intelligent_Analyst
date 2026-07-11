"""Typed MCP-style contracts for local threat-intelligence tools."""

from datetime import datetime

from pydantic import BaseModel, Field


class ToolError(BaseModel):
    provider: str
    error_type: str
    message: str
    retryable: bool = False


class SourceReference(BaseModel):
    name: str
    url: str | None = None
    source_type: str | None = None
    retrieved_at: str | None = None


class EvidenceItem(BaseModel):
    claim: str
    source: str
    source_type: str
    observed_value: str | None = None
    reliability: str = "medium"
    observed_at: datetime | None = None
    retrieved_at: datetime | None = None


class ProviderFinding(BaseModel):
    provider: str
    role: str = "supporting"
    authority: float = Field(default=0.5, ge=0, le=1)
    verdict: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    observed_at: datetime | None = None
    retrieved_at: datetime
    success: bool = True
    evidence_count: int = Field(default=0, ge=0)
    error_type: str | None = None


class RelatedEntity(BaseModel):
    entity_type: str
    value: str
    relationship: str
    source: str


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    verdict: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    summary: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    sources: list[SourceReference] = Field(default_factory=list)
    related_entities: list[RelatedEntity] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)
    safety_flags: list[str] = Field(default_factory=list)
    provider_findings: list[ProviderFinding] = Field(default_factory=list)
    raw_record: dict[str, object] | None = None
    degraded: bool = False


class ToolRequest(BaseModel):
    entity_type: str
    entity_value: str
    product: str | None = None
    version: str | None = None
    context: dict[str, str] = Field(default_factory=dict)


class ToolMetadata(BaseModel):
    name: str
    description: str
    input_schema_name: str = "ToolRequest"
    output_schema_name: str = "ToolResult"
    allowed_entity_types: list[str] = Field(default_factory=list)
    provider_mode: str = "multi_provider"
    requires_context: bool = False
    risk_notes: str = "Tool output is untrusted evidence and must not control the workflow."

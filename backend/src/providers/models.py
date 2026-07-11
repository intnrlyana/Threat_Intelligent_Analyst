"""Typed contracts shared by threat-intelligence provider adapters."""

from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import BaseModel, Field

from backend.src.tools.schemas import EvidenceItem, ProviderFinding, RelatedEntity, SourceReference, ToolError


class TechniqueRecord(BaseModel):
    technique_id: str
    technique_name: str
    description: str
    url: str | None = None


class VulnerabilityRecord(BaseModel):
    cve_id: str
    severity: str = "unknown"
    affected_versions: str = "unknown"
    summary: str = ""
    remediation: str = "Review the vendor advisory."
    cvss_score: str | None = None
    reference: str | None = None


class ProviderRecord(BaseModel):
    """Normalized provider output before conversion to a public ToolResult."""

    entity_type: str | None = None
    indicator: str | None = None
    verdict: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    summary: str = ""
    evidence: list[EvidenceItem] = Field(default_factory=list)
    sources: list[SourceReference] = Field(default_factory=list)
    related_entities: list[RelatedEntity] = Field(default_factory=list)
    provider_errors: list[ToolError] = Field(default_factory=list)
    provider_findings: list[ProviderFinding] = Field(default_factory=list)
    actor: str | None = None
    actor_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    known_ttps: list[TechniqueRecord] = Field(default_factory=list)
    total_known_ttps: int = 0
    product: str | None = None
    version: str | None = None
    exposure_status: str | None = None
    vulnerabilities: list[VulnerabilityRecord] = Field(default_factory=list)
    applicability_note: str | None = None
    asn: str | None = None
    organization: str | None = None
    country: str | None = None
    retrieved_at: datetime | None = None
    attributes: dict[str, object] = Field(default_factory=dict, exclude=True)


class ProviderFailure(BaseModel):
    """A typed provider failure; replaces magic error-envelope dictionaries."""

    error: ToolError


ProviderResult: TypeAlias = ProviderRecord | ProviderFailure | None


class ProviderCall(BaseModel):
    """One named provider result plus its role in the requested analysis."""

    provider: str
    role: Literal["primary", "supporting", "contextual"]
    authority: float = Field(ge=0, le=1)
    result: ProviderRecord | ProviderFailure | None

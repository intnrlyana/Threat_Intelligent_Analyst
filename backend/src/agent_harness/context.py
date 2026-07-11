"""Context resolution and memory updates for local conversations."""

import ipaddress
import re

from pydantic import BaseModel, Field

from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.graph.state import AgentMemory


class ContextResolution(BaseModel):
    entity_type: EntityType = EntityType.UNKNOWN
    entity_value: str | None = None
    requires_context: bool = False
    resolved_from_memory: bool = False
    context_used: dict[str, str] = Field(default_factory=dict)


def _valid_explicit_entity(decision: RoutingDecision) -> bool:
    """Reject LLM placeholders so follow-up references can resolve from memory."""
    if not decision.entity_value:
        return False
    if decision.entity_type == EntityType.IP:
        try:
            ipaddress.ip_address(decision.entity_value)
            return True
        except ValueError:
            return False
    if decision.entity_type == EntityType.DOMAIN:
        return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", decision.entity_value, re.IGNORECASE))
    return decision.entity_value.lower() not in {"ip", "ip address", "domain", "domain name", "unknown", "it", "that ip", "that domain"}


def resolve_context(message: str, decision: RoutingDecision, memory: AgentMemory) -> ContextResolution:
    """Resolve constrained follow-up references from the current session memory."""
    if _valid_explicit_entity(decision):
        return ContextResolution(entity_type=decision.entity_type, entity_value=decision.entity_value)

    normalized = message.lower()
    needs_follow_up = decision.intent in {Intent.PIVOT, Intent.ASN_LOOKUP}
    references_ip = "that ip" in normalized or " it" in f" {normalized}" or "its" in normalized
    references_domain = "that domain" in normalized

    if decision.intent == Intent.ASN_LOOKUP and memory.last_ip:
        return ContextResolution(
            entity_type=EntityType.IP,
            entity_value=memory.last_ip,
            resolved_from_memory=True,
            context_used={"last_ip": memory.last_ip},
        )
    if decision.intent == Intent.PIVOT:
        if references_domain and memory.last_domain:
            return ContextResolution(
                entity_type=EntityType.DOMAIN,
                entity_value=memory.last_domain,
                resolved_from_memory=True,
                context_used={"last_domain": memory.last_domain},
            )
        if references_ip and memory.last_ip:
            return ContextResolution(
                entity_type=EntityType.IP,
                entity_value=memory.last_ip,
                resolved_from_memory=True,
                context_used={"last_ip": memory.last_ip},
            )
        if references_domain and memory.last_domain:
            return ContextResolution(
                entity_type=EntityType.DOMAIN,
                entity_value=memory.last_domain,
                resolved_from_memory=True,
                context_used={"last_domain": memory.last_domain},
            )
    if needs_follow_up:
        return ContextResolution(requires_context=True)
    return ContextResolution(entity_type=decision.entity_type, entity_value=decision.entity_value)


def update_memory(memory: AgentMemory, decision: RoutingDecision, resolution: ContextResolution) -> AgentMemory:
    """Return a copied memory object updated only with resolved analyst entities."""
    updated = memory.model_copy(deep=True)
    entity_type = resolution.entity_type
    if entity_type == EntityType.IP and resolution.entity_value:
        updated.last_ip = resolution.entity_value
    elif entity_type == EntityType.DOMAIN and resolution.entity_value:
        updated.last_domain = resolution.entity_value
    elif entity_type == EntityType.HASH and resolution.entity_value:
        updated.last_hash = resolution.entity_value
    elif entity_type == EntityType.ACTOR and resolution.entity_value:
        updated.last_actor = resolution.entity_value
    elif entity_type == EntityType.ASN and resolution.entity_value:
        updated.last_asn = resolution.entity_value
    if decision.product:
        updated.last_product = decision.product
    if decision.version:
        updated.last_version = decision.version
    return updated

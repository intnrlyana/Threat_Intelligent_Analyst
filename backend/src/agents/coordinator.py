"""Deterministic coordinator for local Stage 2 routing."""

import ipaddress
import re

from backend.src.agent_harness.schemas import AgentTask, EntityType, Intent, RoutingDecision

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
ACTOR_PATTERN = re.compile(r"\bAPT\s?(\d{1,4})\b", re.IGNORECASE)
ASN_PATTERN = re.compile(r"\bAS\d{1,10}\b", re.IGNORECASE)
PRODUCT_VERSION_PATTERN = re.compile(r"\b([A-Za-z][A-Za-z0-9_-]*)\s+(\d+(?:\.\d+){1,3})\b")

IOC_WORDS = ("malicious", "suspicious", "reputation", "check", "investigate")
ACTOR_WORDS = ("ttp", "ttps", "technique", "techniques")
EXPOSURE_WORDS = ("we run", "version", "are we exposed", "vulnerable", "cve")
PIVOT_WORDS = ("pivot", "related domain", "related domains", "related ip", "passive dns")
ASN_WORDS = ("asn", "autonomous system", "what's its asn", "what is its asn")

SPECIALIST_BY_INTENT = {
    Intent.IOC_LOOKUP: "ioc_analyst",
    Intent.ACTOR_TTP: "actor_ttp_analyst",
    Intent.EXPOSURE_REASONING: "exposure_analyst",
    Intent.PIVOT: "pivot_analyst",
    Intent.ASN_LOOKUP: "pivot_analyst",
    Intent.UNKNOWN: "coordinator",
    Intent.BLOCKED_PROMPT_INJECTION: "none",
}


def _first_ip(message: str) -> str | None:
    for candidate in IP_PATTERN.findall(message):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _first_domain(message: str) -> str | None:
    for candidate in DOMAIN_PATTERN.findall(message):
        if _first_ip(candidate) is None:
            return candidate.lower()
    return None


def _product_and_version(message: str) -> tuple[str | None, str | None]:
    for match in PRODUCT_VERSION_PATTERN.finditer(message):
        product, version = match.group(1), match.group(2)
        try:
            ipaddress.ip_address(version)
        except ValueError:
            return product, version
    return None, None


def route_message(message: str) -> RoutingDecision:
    """Classify an analyst message with transparent local rules."""
    normalized = message.lower()
    ip = _first_ip(message)
    domain = _first_domain(message)
    hash_value = HASH_PATTERN.search(message)
    actor = ACTOR_PATTERN.search(message)
    asn = ASN_PATTERN.search(message)
    product, version = _product_and_version(message)

    if any(word in normalized for word in ASN_WORDS):
        return RoutingDecision(
            intent=Intent.ASN_LOOKUP,
            entity_type=EntityType.IP if ip else (EntityType.ASN if asn else EntityType.UNKNOWN),
            entity_value=ip or (asn.group(0).upper() if asn else None),
        )
    if any(word in normalized for word in PIVOT_WORDS):
        if ip:
            return RoutingDecision(intent=Intent.PIVOT, entity_type=EntityType.IP, entity_value=ip)
        if domain:
            return RoutingDecision(intent=Intent.PIVOT, entity_type=EntityType.DOMAIN, entity_value=domain)
        return RoutingDecision(intent=Intent.PIVOT)
    product_version_request = bool(product and version and product.lower() not in {"is", "are", "and", "the", "this"})
    if any(word in normalized for word in EXPOSURE_WORDS) or product_version_request:
        return RoutingDecision(
            intent=Intent.EXPOSURE_REASONING,
            entity_type=EntityType.PRODUCT,
            entity_value=product,
            product=product,
            version=version,
        )
    if actor or any(word in normalized for word in ACTOR_WORDS):
        return RoutingDecision(
            intent=Intent.ACTOR_TTP,
            entity_type=EntityType.ACTOR if actor else EntityType.UNKNOWN,
            entity_value=f"APT{actor.group(1)}" if actor else None,
        )
    if hash_value:
        return RoutingDecision(intent=Intent.IOC_LOOKUP, entity_type=EntityType.HASH, entity_value=hash_value.group(0).lower())
    if ip and (any(word in normalized for word in IOC_WORDS) or ip):
        return RoutingDecision(intent=Intent.IOC_LOOKUP, entity_type=EntityType.IP, entity_value=ip)
    if domain and (any(word in normalized for word in IOC_WORDS) or domain):
        return RoutingDecision(intent=Intent.IOC_LOOKUP, entity_type=EntityType.DOMAIN, entity_value=domain)
    return RoutingDecision(intent=Intent.UNKNOWN)


def is_high_confidence_rule_decision(decision: RoutingDecision) -> bool:
    """Identify rule results that are precise enough to avoid remote routing."""
    if decision.intent == Intent.IOC_LOOKUP:
        return decision.entity_type in {EntityType.IP, EntityType.DOMAIN, EntityType.HASH} and bool(decision.entity_value)
    if decision.intent == Intent.ACTOR_TTP:
        return decision.entity_type == EntityType.ACTOR and bool(decision.entity_value)
    if decision.intent == Intent.EXPOSURE_REASONING:
        return bool(decision.product and decision.version)
    if decision.intent in {Intent.PIVOT, Intent.ASN_LOOKUP}:
        return decision.entity_type != EntityType.UNKNOWN and bool(decision.entity_value)
    return False


def select_specialist(intent: str) -> str:
    return SPECIALIST_BY_INTENT.get(Intent(intent), "coordinator")


def create_agent_task(
    *, intent: str, selected_agent: str, entity_type: str | None, entity_value: str | None,
    product: str | None, version: str | None, shared_context: dict[str, object], query: str,
) -> AgentTask:
    """Create an observable coordinator-to-specialist delegation task."""
    return AgentTask(
        from_agent="coordinator", to_agent=selected_agent, intent=intent,
        entity_type=entity_type, entity_value=entity_value, product=product, version=version,
        shared_context=shared_context, query=query,
    )

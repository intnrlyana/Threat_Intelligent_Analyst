"""MCP-style local tool registry with operational metadata."""

from collections.abc import Callable

from backend.src.tools.schemas import ToolMetadata

ToolHandler = Callable[..., object]

INTENT_TO_TOOL_NAME = {
    "ioc_lookup": "ioc_reputation_lookup",
    "actor_ttp": "actor_ttp_lookup",
    "exposure_reasoning": "exposure_check",
    "pivot": "pivot_related_entities",
    "asn_lookup": "asn_lookup",
}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolHandler] = {}
        self._metadata: dict[str, ToolMetadata] = {}

    def register(self, name: str, handler: ToolHandler, metadata: ToolMetadata) -> None:
        self._tools[name] = handler
        self._metadata[name] = metadata

    def get(self, name: str | None) -> ToolHandler | None:
        return self._tools.get(name) if name else None

    def metadata(self) -> list[ToolMetadata]:
        return list(self._metadata.values())


def build_default_registry() -> ToolRegistry:
    from backend.src.tools.actor_ttp import TOOL_NAME as actor_name, actor_ttp_lookup
    from backend.src.tools.asn import TOOL_NAME as asn_name, asn_lookup
    from backend.src.tools.exposure import TOOL_NAME as exposure_name, exposure_check
    from backend.src.tools.ioc_lookup import TOOL_NAME as ioc_name, ioc_reputation_lookup
    from backend.src.tools.pivot import TOOL_NAME as pivot_name, pivot_related_entities

    registry = ToolRegistry()
    registry.register(ioc_name, ioc_reputation_lookup, ToolMetadata(name=ioc_name, description="Retrieves live VirusTotal reputation evidence for an IP, domain, or hash.", allowed_entity_types=["ip", "domain", "hash"], risk_notes="Reputation does not prove internal compromise."))
    registry.register(actor_name, actor_ttp_lookup, ToolMetadata(name=actor_name, description="Retrieves authoritative MITRE ATT&CK actor-to-technique mappings with optional OTX pulse context.", allowed_entity_types=["actor"], risk_notes="ATT&CK documents publicly reported behavior and is not exhaustive."))
    registry.register(exposure_name, exposure_check, ToolMetadata(name=exposure_name, description="Reports that product-version exposure is outside the VirusTotal provider scope.", allowed_entity_types=["product"], risk_notes="Use an authoritative vulnerability catalog for this capability."))
    registry.register(pivot_name, pivot_related_entities, ToolMetadata(name=pivot_name, description="Pivots from an indicator through VirusTotal relationships.", allowed_entity_types=["ip", "domain"], requires_context=True, risk_notes="Relationship availability depends on the VirusTotal plan."))
    registry.register(asn_name, asn_lookup, ToolMetadata(name=asn_name, description="Retrieves live VirusTotal network and ASN enrichment for an IP address.", allowed_entity_types=["ip"], requires_context=True, risk_notes="ASN data must not be the sole blocking decision."))
    return registry


def list_registered_tools() -> list[ToolMetadata]:
    return build_default_registry().metadata()


def get_tool_for_intent(intent: str) -> ToolHandler | None:
    return build_default_registry().get(INTENT_TO_TOOL_NAME.get(intent))

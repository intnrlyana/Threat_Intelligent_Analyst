"""Qdrant Cloud-first semantic routing over curated approved examples."""

from dataclasses import dataclass
from functools import lru_cache

from backend.src.agent_harness.schemas import EntityType, Intent, RoutingDecision
from backend.src.agents.routing_dataset import load_approved_examples
from backend.src.config import Settings

COMPATIBLE_ENTITY_TYPES: dict[Intent, set[EntityType]] = {
    Intent.IOC_LOOKUP: {EntityType.IP, EntityType.DOMAIN, EntityType.HASH},
    Intent.PIVOT: {EntityType.IP, EntityType.DOMAIN, EntityType.UNKNOWN},
    Intent.ASN_LOOKUP: {EntityType.IP, EntityType.ASN, EntityType.UNKNOWN},
    Intent.ACTOR_TTP: {EntityType.ACTOR, EntityType.UNKNOWN},
    Intent.EXPOSURE_REASONING: {EntityType.PRODUCT, EntityType.VERSION, EntityType.UNKNOWN},
    Intent.UNKNOWN: set(EntityType),
}


@dataclass(frozen=True)
class SemanticRouteResult:
    decision: RoutingDecision
    accepted: bool
    score: float
    margin: float
    candidates: tuple[tuple[str, float], ...]


def _decision(intent: Intent, entity: RoutingDecision, confidence: float, rationale: str) -> RoutingDecision:
    if entity.entity_type not in COMPATIBLE_ENTITY_TYPES[intent]:
        return RoutingDecision(intent=Intent.UNKNOWN, confidence=confidence, rationale_summary="Semantic intent was incompatible with the extracted entity type.")
    return RoutingDecision(
        intent=intent,
        entity_type=entity.entity_type,
        entity_value=entity.entity_value,
        product=entity.product,
        version=entity.version,
        requires_context=intent in {Intent.PIVOT, Intent.ASN_LOOKUP} and entity.entity_type == EntityType.UNKNOWN,
        confidence=confidence,
        rationale_summary=rationale,
    )


class QdrantSemanticRouter:
    """Managed-Qdrant collection with client-side FastEmbed inference."""

    def __init__(self, settings: Settings) -> None:
        if not settings.qdrant_url:
            raise RuntimeError("QDRANT_URL is not configured")
        if not settings.qdrant_api_key:
            raise RuntimeError("QDRANT_API_KEY is not configured")
        try:
            from qdrant_client import QdrantClient, models
        except ImportError as exc:  # pragma: no cover - deployment configuration
            raise RuntimeError("Semantic routing requires qdrant-client[fastembed]") from exc
        self.settings = settings
        self.models = models
        self.client = QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key, timeout=settings.api_timeout_seconds)
        self.client.set_model(settings.semantic_embedding_model)
        self.vector_name = next(iter(self.client.get_fastembed_vector_params()))
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        name = self.settings.semantic_collection_name
        if self.client.collection_exists(name):
            return
        approved = load_approved_examples()
        self.client.create_collection(name, vectors_config=self.client.get_fastembed_vector_params())
        self.client.upsert(
            collection_name=name,
            wait=True,
            points=[
                self.models.PointStruct(
                    id=index,
                    vector={self.vector_name: self.models.Document(text=item.text, model=self.settings.semantic_embedding_model)},
                    payload={
                        "document": item.text,
                        "intent": item.intent.value,
                        "approved": item.approved,
                        "dataset_version": item.dataset_version,
                        "family": item.family,
                        "style": item.style,
                        "entity_types": [value.value for value in item.entity_types],
                    },
                )
                for index, item in enumerate(approved, start=1)
            ],
        )

    def route(self, message: str, entity: RoutingDecision) -> SemanticRouteResult:
        response = self.client.query_points(
            collection_name=self.settings.semantic_collection_name,
            query=self.models.Document(text=message, model=self.settings.semantic_embedding_model),
            using=self.vector_name,
            limit=self.settings.semantic_top_k,
        )
        best_by_intent: dict[Intent, float] = {}
        for match in response.points:
            payload = match.payload or {}
            if not payload.get("approved"):
                continue
            try:
                intent = Intent(str(payload["intent"]))
            except (KeyError, ValueError):
                continue
            if entity.entity_type not in COMPATIBLE_ENTITY_TYPES[intent]:
                continue
            best_by_intent[intent] = max(best_by_intent.get(intent, 0.0), float(match.score))
        ranked = sorted(best_by_intent.items(), key=lambda item: item[1], reverse=True)
        if not ranked:
            return SemanticRouteResult(RoutingDecision(intent=Intent.UNKNOWN), False, 0.0, 0.0, ())
        top_intent, top_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        margin = top_score - second_score
        entity_threshold = 0.62 if entity.entity_type in {EntityType.ACTOR, EntityType.PRODUCT, EntityType.VERSION} else self.settings.semantic_score_threshold
        accepted = top_score >= entity_threshold and margin >= self.settings.semantic_margin_threshold
        decision = _decision(top_intent, entity, top_score, f"Qdrant semantic score={top_score:.3f}, margin={margin:.3f}.")
        if decision.intent == Intent.UNKNOWN and top_intent != Intent.UNKNOWN:
            accepted = False
        return SemanticRouteResult(decision, accepted, top_score, margin, tuple((intent.value, score) for intent, score in ranked))


@lru_cache(maxsize=1)
def _cached_router(url: str, api_key: str, collection: str, model: str, score: float, margin: float, top_k: int, timeout: int) -> QdrantSemanticRouter:
    return QdrantSemanticRouter(Settings(
        qdrant_url=url,
        qdrant_api_key=api_key,
        semantic_collection_name=collection,
        semantic_embedding_model=model,
        semantic_score_threshold=score,
        semantic_margin_threshold=margin,
        semantic_top_k=top_k,
        api_timeout_seconds=timeout,
    ))


def route_semantically(message: str, entity: RoutingDecision, settings: Settings) -> SemanticRouteResult:
    try:
        router = _cached_router(
            settings.qdrant_url,
            settings.qdrant_api_key,
            settings.semantic_collection_name,
            settings.semantic_embedding_model,
            settings.semantic_score_threshold,
            settings.semantic_margin_threshold,
            settings.semantic_top_k,
            settings.api_timeout_seconds,
        )
        return router.route(message, entity)
    except Exception as exc:
        raise RuntimeError(f"Qdrant semantic router failed: {exc}") from exc

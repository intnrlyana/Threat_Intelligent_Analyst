"""Create or refresh the approved semantic-routing collection in Qdrant Cloud."""

from backend.src.agents.semantic_router import _cached_router
from backend.src.config import get_settings


def main() -> None:
    settings = get_settings()
    if not settings.qdrant_url or not settings.qdrant_api_key:
        raise SystemExit("QDRANT_URL and QDRANT_API_KEY are required")
    _cached_router.cache_clear()
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
    info = router.client.get_collection(settings.semantic_collection_name)
    print(f"synced collection={settings.semantic_collection_name} points={info.points_count}")


if __name__ == "__main__":
    main()

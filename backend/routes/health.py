"""Health check endpoint."""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.src.config import get_settings
from backend.src.providers.cache import shared_provider_cache

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    """Return service liveness and operating mode."""
    settings = get_settings()
    return {"status": "ok", "service": "threat-intelligent-analyst", "mode": settings.data_mode}


@router.get("/ready")
def readiness() -> JSONResponse:
    """Report whether required local components and useful providers are configured."""
    settings = get_settings()
    model_path = Path(settings.prompt_guard_model)
    guard_ready = not settings.prompt_guard_enabled or model_path.exists() or bool(settings.huggingface_token)
    providers = {
        "virustotal": bool(settings.virustotal_api_key),
        "alienvault_otx": bool(settings.alien_vault_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "nvd": True,  # NVD supports unauthenticated, lower-rate access.
        "mitre_attack": True,
    }
    ready = guard_ready and any(providers.values())
    payload = {
        "status": "ready" if ready else "not_ready",
        "service": "threat-intelligent-analyst",
        "checks": {"prompt_guard": guard_ready, "providers": providers},
        "cache": shared_provider_cache(settings.provider_cache_ttl_seconds, settings.provider_cache_max_entries).status(),
    }
    return JSONResponse(payload, status_code=200 if ready else 503)

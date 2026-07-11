"""Application settings loaded from the environment."""

import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class Settings(BaseModel):
    data_mode: str = Field(default="multi_provider")
    llm_provider: str = Field(default="groq")
    router_mode: str = Field(default="hybrid")
    response_mode: str = Field(default="llm")
    groq_api_key: str = Field(default="", repr=False)
    llm_model: str = Field(default="llama-3.1-8b-instant")
    llm_max_tokens: int = Field(default=600, ge=64, le=4096)
    max_llm_calls_per_query: int = Field(default=2, ge=1)
    prompt_guard_enabled: bool = Field(default=True)
    prompt_guard_model: str = Field(default="meta-llama/Llama-Prompt-Guard-2-86M")
    prompt_guard_max_tokens: int = Field(default=512, ge=64, le=2048)
    prompt_guard_threshold: float = Field(default=0.957909, ge=0, le=1)
    retrieved_semantic_guard_enabled: bool = Field(default=True)
    retrieved_guard_max_chars: int = Field(default=4000, ge=256, le=20000)
    huggingface_token: str = Field(default="", repr=False)
    virustotal_api_key: str = Field(default="", repr=False)
    alien_vault_api_key: str = Field(default="", repr=False)
    nvd_api_key: str = Field(default="", repr=False)
    abuseipdb_api_key: str = Field(default="", repr=False)
    max_tool_calls_per_query: int = Field(default=3, ge=1)
    api_timeout_seconds: int = Field(default=10, ge=1)
    provider_cache_ttl_seconds: int = Field(default=300, ge=1)
    provider_cache_max_entries: int = Field(default=256, ge=1)
    provider_max_workers: int = Field(default=3, ge=1, le=10)


@lru_cache
def get_settings() -> Settings:
    """Build cached settings for the current process."""
    return Settings(
        data_mode=os.getenv("DATA_MODE", "multi_provider"),
        llm_provider=os.getenv("LLM_PROVIDER", "groq"),
        router_mode=os.getenv("ROUTER_MODE", "hybrid"),
        response_mode=os.getenv("RESPONSE_MODE", "llm"),
        groq_api_key=os.getenv("GROQ_API_KEY", ""),
        llm_model=os.getenv("LLM_MODEL", "llama-3.1-8b-instant"),
        llm_max_tokens=int(os.getenv("LLM_MAX_TOKENS", "600")),
        max_llm_calls_per_query=int(os.getenv("MAX_LLM_CALLS_PER_QUERY", "2")),
        prompt_guard_enabled=os.getenv("PROMPT_GUARD_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"},
        prompt_guard_model=os.getenv("PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M"),
        prompt_guard_max_tokens=int(os.getenv("PROMPT_GUARD_MAX_TOKENS", "512")),
        prompt_guard_threshold=float(os.getenv("PROMPT_GUARD_THRESHOLD", "0.957909")),
        retrieved_semantic_guard_enabled=os.getenv("RETRIEVED_SEMANTIC_GUARD_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"},
        retrieved_guard_max_chars=int(os.getenv("RETRIEVED_GUARD_MAX_CHARS", "4000")),
        huggingface_token=os.getenv("HUGGINGFACE_TOKEN", ""),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", os.getenv("VIRUS_TOTAL_API_KEY", "")),
        alien_vault_api_key=os.getenv("ALIEN_VAULT_API_KEY", os.getenv("OTX_API_KEY", "")),
        nvd_api_key=os.getenv("NVD_API_KEY", ""),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        max_tool_calls_per_query=int(os.getenv("MAX_TOOL_CALLS_PER_QUERY", "3")),
        api_timeout_seconds=int(os.getenv("API_TIMEOUT_SECONDS", "10")),
        provider_cache_ttl_seconds=int(os.getenv("PROVIDER_CACHE_TTL_SECONDS", "300")),
        provider_cache_max_entries=int(os.getenv("PROVIDER_CACHE_MAX_ENTRIES", "256")),
        provider_max_workers=int(os.getenv("PROVIDER_MAX_WORKERS", "3")),
    )

from backend.src.config import get_settings


def test_default_settings_use_multi_provider(monkeypatch) -> None:
    for name in (
        "DATA_MODE", "LLM_PROVIDER", "ROUTER_MODE", "RESPONSE_MODE", "GROQ_API_KEY", "LLM_MODEL", "LLM_MAX_TOKENS", "MAX_LLM_CALLS_PER_QUERY", "PROMPT_GUARD_ENABLED", "PROMPT_GUARD_MODEL", "PROMPT_GUARD_MAX_TOKENS", "HUGGINGFACE_TOKEN", "VIRUSTOTAL_API_KEY", "VIRUS_TOTAL_API_KEY",
        "PROMPT_GUARD_THRESHOLD", "MAX_TOOL_CALLS_PER_QUERY", "API_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.data_mode == "multi_provider"
    assert settings.virustotal_api_key == ""
    assert settings.llm_provider == "groq"
    assert settings.router_mode == "semantic"
    assert settings.response_mode == "llm"
    assert settings.groq_api_key == ""
    assert settings.llm_model == "llama-3.1-8b-instant"
    assert settings.llm_max_tokens == 600
    assert settings.max_llm_calls_per_query == 2
    assert settings.prompt_guard_enabled is True
    assert settings.prompt_guard_model == "meta-llama/Llama-Prompt-Guard-2-86M"
    assert settings.prompt_guard_max_tokens == 512
    assert settings.prompt_guard_threshold == 0.957909
    assert settings.max_tool_calls_per_query == 3
    assert settings.api_timeout_seconds == 10
    get_settings.cache_clear()

"""Keep the suite offline even when a developer has configured local credentials."""

import pytest

from backend.src.config import get_settings
from tests.fake_provider import FakeThreatIntelProvider


@pytest.fixture(autouse=True)
def disable_live_groq(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("ROUTER_MODE", "hybrid")
    monkeypatch.setenv("RESPONSE_MODE", "llm")
    monkeypatch.setenv("PROMPT_GUARD_ENABLED", "false")
    monkeypatch.setenv("RETRIEVED_SEMANTIC_GUARD_ENABLED", "false")
    monkeypatch.setattr("backend.src.agent_harness.execution.CompositeThreatIntelProvider", FakeThreatIntelProvider)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()

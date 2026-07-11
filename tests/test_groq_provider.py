from backend.src.config import Settings
from backend.src.llm.groq_provider import GroqLLMProvider
from backend.src.llm.prompts import ROUTING_PROMPT
from backend.src.llm.service import GroqRoutingResult


def test_groq_provider_configures_langchain_chat_model_and_validates_output(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeStructuredModel:
        def invoke(self, prompt: object) -> dict[str, object]:
            captured["prompt"] = prompt
            return {
                "intent": "ioc_lookup",
                "entity_type": "ip",
                "entity_value": "45.83.122.10",
                "product": None,
                "version": None,
                "requires_context": False,
                "confidence": 0.9,
                "rationale_summary": "An IP reputation lookup is appropriate.",
            }

    class FakeChatGroq:
        def __init__(self, **kwargs: object) -> None:
            captured["constructor"] = kwargs

        def with_structured_output(self, schema: type[GroqRoutingResult]) -> FakeStructuredModel:
            captured["schema"] = schema
            return FakeStructuredModel()

    monkeypatch.setattr("backend.src.llm.groq_provider.ChatGroq", FakeChatGroq)
    provider = GroqLLMProvider(Settings(groq_api_key="test-key", llm_max_tokens=256))

    result = provider.invoke_structured(ROUTING_PROMPT.invoke({"analyst_query": "Is 45.83.122.10 malicious?"}), GroqRoutingResult)

    assert captured["constructor"]["model"] == "llama-3.1-8b-instant"
    assert captured["constructor"]["temperature"] == 0
    assert captured["constructor"]["max_tokens"] == 256
    assert captured["schema"] is GroqRoutingResult
    assert result.intent == "ioc_lookup"

"""LangChain-backed Groq client used by controlled LLM features."""

from typing import TypeVar

from langchain_core.prompt_values import PromptValue
from langchain_groq import ChatGroq
from pydantic import BaseModel

from backend.src.config import Settings

StructuredResult = TypeVar("StructuredResult", bound=BaseModel)


class GroqLLMProvider:
    """Expose a narrow, schema-bound LangChain interface to Groq."""

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.groq_api_key
        self.model = settings.llm_model
        self.timeout_seconds = settings.api_timeout_seconds
        self.max_tokens = settings.llm_max_tokens
        self._chat_model = ChatGroq(
            model=self.model,
            api_key=self.api_key,
            temperature=0,
            max_tokens=self.max_tokens,
            timeout=self.timeout_seconds,
            max_retries=0,
        )

    def invoke_structured(self, prompt: PromptValue, schema: type[StructuredResult]) -> StructuredResult:
        """Invoke Groq through LangChain and validate its typed response contract."""
        if not self.api_key:
            raise RuntimeError("Groq API key is not configured")
        try:
            response = self._chat_model.with_structured_output(schema).invoke(prompt)
            return response if isinstance(response, schema) else schema.model_validate(response)
        except Exception as exc:
            raise RuntimeError(f"Groq LangChain invocation failed: {exc}") from exc

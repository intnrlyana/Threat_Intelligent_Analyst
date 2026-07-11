"""Local Prompt Guard classifier for semantic prompt-injection detection."""

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field

from backend.src.config import Settings


class PromptGuardAssessment(BaseModel):
    risk: Literal["low", "high", "unknown"]
    label: str
    confidence: float = Field(ge=0, le=1)


@lru_cache
def _load_classifier(model: str, token: str) -> object:
    try:
        from transformers import pipeline
    except ImportError as exc:
        raise RuntimeError("Prompt Guard dependencies are not installed") from exc
    try:
        return pipeline("text-classification", model=model, token=token or None)
    except Exception as exc:
        raise RuntimeError(
            "Prompt Guard model is unavailable; confirm Hugging Face model access and authentication."
        ) from exc


def _is_injection_label(label: str) -> bool:
    normalized = label.strip().lower()
    return any(value in normalized for value in ("malicious", "injection", "jailbreak", "unsafe", "label_1"))


def classify_with_prompt_guard(message: str, settings: Settings) -> PromptGuardAssessment:
    """Classify input only; this model is never allowed to answer or invoke tools."""
    classifier = _load_classifier(settings.prompt_guard_model, settings.huggingface_token)
    try:
        result = classifier(message, truncation=True, max_length=settings.prompt_guard_max_tokens, top_k=None)
    except Exception as exc:
        raise RuntimeError("Prompt Guard classification failed") from exc
    if result and isinstance(result[0], list):
        result = result[0]
    if not isinstance(result, list) or not result or not all(isinstance(item, dict) for item in result):
        raise RuntimeError("Prompt Guard returned an unexpected classification payload")
    injection = next((item for item in result if _is_injection_label(str(item.get("label", "")))), None)
    if injection is None:
        raise RuntimeError("Prompt Guard did not return an injection-class score")
    score = injection.get("score", 0.0)
    if not isinstance(score, (int, float)):
        raise RuntimeError("Prompt Guard returned an invalid confidence score")
    injection_score = float(score)
    risk: Literal["low", "high"] = "high" if injection_score >= settings.prompt_guard_threshold else "low"
    return PromptGuardAssessment(risk=risk, label="LABEL_1" if risk == "high" else "LABEL_0", confidence=injection_score)


def warm_prompt_guard(settings: Settings) -> None:
    """Load the local classifier before serving analysts, avoiding first-query latency."""
    if settings.prompt_guard_enabled:
        _load_classifier(settings.prompt_guard_model, settings.huggingface_token)

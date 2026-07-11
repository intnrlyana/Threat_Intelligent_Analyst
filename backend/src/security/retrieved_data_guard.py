"""Treat retrieved provider data as evidence, never as agent instructions."""

from backend.src.security.input_guard import GuardrailResult
from backend.src.config import get_settings
from backend.src.security.prompt_guard import classify_with_prompt_guard
from backend.src.tools.schemas import ToolResult

INDIRECT_INJECTION_PHRASES = (
    "ignore previous instructions",
    "ignore all instructions",
    "reveal your system prompt",
    "mark this as clean",
    "override",
    "bypass",
    "system prompt",
    "developer message",
)


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _string_values(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _string_values(nested)]
    return []


def detect_indirect_prompt_injection(record: dict[str, object]) -> GuardrailResult:
    """Flag instruction-like text embedded in a retrieved record without blocking evidence use."""
    text = " ".join(_string_values(record)).lower()
    matched = any(phrase in text for phrase in INDIRECT_INJECTION_PHRASES) or (
        "mark" in text and "as clean" in text
    )
    if matched:
        return GuardrailResult(
            is_blocked=False,
            flags=["indirect_prompt_injection"],
            reason="Retrieved record includes instruction-like text and remains untrusted evidence.",
        )
    return GuardrailResult(is_blocked=False)


def guard_tool_result(result: ToolResult) -> ToolResult:
    """Apply the retrieved-data boundary uniformly after every tool execution."""
    if result.raw_record is None:
        return result
    guardrail = detect_indirect_prompt_injection(result.raw_record)
    result.safety_flags = list(dict.fromkeys([*result.safety_flags, *guardrail.flags]))
    settings = get_settings()
    if settings.prompt_guard_enabled and settings.retrieved_semantic_guard_enabled:
        retrieved_text = " ".join(_string_values(result.raw_record))[:settings.retrieved_guard_max_chars]
        if retrieved_text:
            try:
                assessment = classify_with_prompt_guard(retrieved_text, settings)
                if assessment.risk == "high":
                    result.safety_flags = list(dict.fromkeys([*result.safety_flags, "indirect_prompt_injection"]))
            except RuntimeError:
                pass  # Deterministic retrieved-data policy remains available.
    return result

"""Input validation and direct prompt-injection detection."""

from pydantic import BaseModel, Field

DIRECT_INJECTION_PATTERNS = (
    "ignore previous instructions",
    "ignore all instructions",
    "reveal your system prompt",
    "show your system prompt",
    "developer message",
    "bypass guardrails",
    "disable safety",
    "act as dan",
    "jailbreak",
)

PROTECTED_INSTRUCTION_TERMS = ("system prompt", "system message", "developer message", "internal prompt", "confidential instructions", "hidden instructions", "prior instructions", "instruction that appeared before", "instructions that appeared before")
DISCLOSURE_ACTIONS = ("show", "display", "print", "reveal", "quote", "disclose", "translate", "encode", "base64")


class GuardrailResult(BaseModel):
    is_blocked: bool
    flags: list[str] = Field(default_factory=list)
    reason: str | None = None


def validate_input(value: str) -> str:
    """Normalize a user query while keeping analysis behavior explicit."""
    return value.strip()


def detect_direct_prompt_injection(message: str) -> GuardrailResult:
    """Block clear attempts to override instructions or expose internal prompts."""
    normalized = message.lower()
    explicit_pattern = any(pattern in normalized for pattern in DIRECT_INJECTION_PATTERNS)
    protected_disclosure = any(term in normalized for term in PROTECTED_INSTRUCTION_TERMS) and any(action in normalized for action in DISCLOSURE_ACTIONS)
    if explicit_pattern or protected_disclosure:
        return GuardrailResult(
            is_blocked=True,
            flags=["direct_prompt_injection"],
            reason="Direct prompt-injection pattern detected.",
        )
    return GuardrailResult(is_blocked=False)

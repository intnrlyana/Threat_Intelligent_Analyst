"""Server-rendered chat endpoints."""

from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from backend.src.config import get_settings
from backend.src.graph.state import AgentMemory, AgentState
from backend.src.graph.workflow import run_agent_workflow

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))

# Local-only session storage. Production deployments should use Redis or a database-backed store.
_session_memories: dict[str, AgentMemory] = {}


def _investigation_summary(state: AgentState) -> dict[str, object] | None:
    """Build a deterministic analyst-facing summary from typed workflow state."""
    result = state.tool_result
    if result is None:
        return None

    if result.degraded and result.evidence:
        verdict = (result.verdict or "Partial evidence").replace("_", " ").title()
        tone = "danger" if result.verdict == "malicious" else "warning"
        provider_status = f"Partial evidence - {len(result.errors)} provider{'s' if len(result.errors) != 1 else ''} unavailable"
    elif result.degraded:
        verdict, tone = "Inconclusive", "warning"
        provider_status = "Provider rate-limited" if any(error.error_type == "rate_limit" for error in result.errors) else "Provider unavailable"
    elif not result.success:
        verdict, tone, provider_status = "Unknown", "neutral", "No usable evidence returned"
    else:
        verdict = (result.verdict or "Evidence found").replace("_", " ").title()
        tone, provider_status = ("danger" if result.verdict in {"malicious", "potentially_exposed"} else "neutral"), "Evidence retrieved"

    entity = state.entity_value or state.product or "Unknown entity"
    risk_label = "provider detection ratio" if result.tool_name == "ioc_reputation_lookup" else "risk score"
    related_entities = [f"{item.value} / {item.relationship.replace('_', ' ')}" for item in result.related_entities]
    return {
        "entity": entity,
        "entity_type": state.entity_type or "unknown",
        "verdict": verdict,
        "tone": tone,
        "confidence": f"{state.confidence} ({state.confidence_score}/100)" if state.confidence_score is not None else state.confidence or "Unknown",
        "risk_score": result.risk_score,
        "risk_label": risk_label,
        "provider_status": provider_status,
        "source_coverage": f"{len(result.sources)} source{'s' if len(result.sources) != 1 else ''}" if result.sources else "No sources returned",
        "related_entities": related_entities,
    }


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"mode": get_settings().data_mode})


@router.post("/chat", response_class=HTMLResponse)
def chat(request: Request, message: str = Form(...)) -> HTMLResponse:
    """Run the analyst workflow and return chat, trace, and context partials."""
    session_id = request.cookies.get("tia_session_id")
    is_new_session = session_id is None
    if is_new_session:
        session_id = str(uuid4())

    state = run_agent_workflow(message, _session_memories.get(session_id))
    _session_memories[session_id] = state.memory
    response = templates.get_template("partials/chat_message.html").render(
        message=state.response,
        user_message=state.message,
        summary=_investigation_summary(state),
    )
    trace_panel = templates.get_template("partials/trace_panel.html").render(
        trace=state.trace.model_dump() if state.trace else {},
        oob=True,
    )
    context_panel = templates.get_template("partials/context_panel.html").render(memory=state.memory.model_dump(), oob=True)
    result = HTMLResponse(response + trace_panel + context_panel)
    if is_new_session:
        result.set_cookie("tia_session_id", session_id, httponly=True, samesite="lax")
    return result

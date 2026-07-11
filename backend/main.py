"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.routes.chat import router as chat_router
from backend.routes.health import router as health_router
from backend.src.config import get_settings
from backend.src.security.prompt_guard import warm_prompt_guard

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Warm the local safety model during startup, not on an analyst's first request."""
    try:
        warm_prompt_guard(get_settings())
    except RuntimeError as exc:
        # The deterministic guard remains active and /ready exposes the degraded state.
        logger.warning("Prompt Guard warm-up failed: %s", exc)
    yield


app = FastAPI(title="Threat Intelligent Analyst", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(health_router)
app.include_router(chat_router)

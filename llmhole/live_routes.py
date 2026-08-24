"""Live Mode HTTP surface, mounted under /api/live.

Targets a local Ollama server - there is no API key anywhere. Kept in its own
router so the offline lab has zero dependency on it.
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Response
from pydantic import BaseModel, Field

from .flags import flag_for, level_key, points_for
from .levels import Level
from .live_engine import (
    DEFAULT_ENDPOINT,
    SUGGESTED_MODELS,
    LiveError,
    endpoint_allowed,
    list_models,
    list_scenarios,
    normalise_endpoint,
    run_live,
)
from .live_state import check_budget, clear_conn, get_conn, record_usage, set_conn
from .state import SESSION_COOKIE, get_or_create

router = APIRouter(prefix="/api/live", tags=["live"])


class ConnectIn(BaseModel):
    endpoint: str = DEFAULT_ENDPOINT
    model: str = ""


class LiveAttemptIn(BaseModel):
    level: str = "low"
    fields: dict[str, str] = Field(default_factory=dict)


def _cookie(response: Response, session) -> None:
    response.set_cookie(
        SESSION_COOKIE, session.id, httponly=True, samesite="lax", max_age=86400
    )


@router.get("/providers")
def providers() -> dict:
    return {
        "provider": "ollama",
        "label": "Ollama (Local - no internet required)",
        "default_endpoint": DEFAULT_ENDPOINT,
        "suggested_models": SUGGESTED_MODELS,
    }


@router.get("/models")
def models(endpoint: str = DEFAULT_ENDPOINT) -> dict:
    """List the models actually installed in the user's Ollama server."""
    try:
        return {"models": list_models(endpoint), "endpoint": normalise_endpoint(endpoint)}
    except LiveError as exc:
        return {"error": {"kind": exc.kind, "message": exc.message}}


@router.get("/scenarios")
def scenarios() -> dict:
    items = list_scenarios()
    # Unbounded Consumption is demonstration-only in Live Mode: it is never sent
    # to a real model (that is exactly the resource-exhaustion we refuse to run on
    # the user's own machine). It runs against the offline engine instead.
    from .challenges import get as _get

    unbounded = _get("unbounded-consumption")
    if unbounded is not None:
        pub = unbounded.public()
        items.append(
            {
                "id": "unbounded-consumption",
                "title": pub["title"],
                "owasp": pub["owasp"],
                "goal": pub["goal"],
                "fields": pub["fields"],
                "theme": pub.get("theme", {}),
                "needs_tools": False,
                "demo_only": True,
                "demo_reason": (
                    "Not run against a real model on purpose: forcing a live model to "
                    "generate a huge response is the very resource-exhaustion attack "
                    "this challenge is about, and it would tie up your own machine. It "
                    "runs against the deterministic offline engine here instead."
                ),
            }
        )
    return {"scenarios": items}


@router.get("/status")
def status(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)
    conn = get_conn(session.id)
    if conn is None:
        return {"connected": False}
    return {
        "connected": True,
        "endpoint": conn.endpoint,
        "model": conn.model,
        "requests_made": conn.requests_made,
        "remaining_requests": conn.remaining_requests(),
    }


@router.post("/connect")
def connect(
    payload: ConnectIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)

    model = payload.model.strip()
    if not model:
        return {"ok": False, "error": {"kind": "no_model", "message": "Pick a model name."}}

    if not endpoint_allowed(payload.endpoint):
        return {
            "ok": False,
            "error": {
                "kind": "endpoint_not_allowed",
                "message": "That endpoint host is not allow-listed. Set "
                "LLMHOLE_ALLOWED_LLM_HOSTS to permit it.",
            },
        }

    endpoint = normalise_endpoint(payload.endpoint)
    conn = set_conn(session.id, endpoint, model)
    return {"ok": True, "endpoint": conn.endpoint, "model": conn.model}


@router.delete("/connect")
def disconnect(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)
    clear_conn(session.id)
    return {"ok": True}


@router.post("/demo/{challenge_id}/attempt")
def demo_attempt(
    challenge_id: str,
    payload: LiveAttemptIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    """Run a demonstration-only challenge on the OFFLINE engine - no model, no
    scoring. Used for Unbounded Consumption in Live Mode.
    """
    from .challenges import get as _get
    from .challenges.base import Attempt

    challenge = _get(challenge_id)
    if challenge is None:
        return {"error": {"kind": "unknown_scenario", "message": "Unknown challenge."}}

    session = get_or_create(session_id)
    _cookie(response, session)
    result = challenge.handler(
        Attempt(level=Level.parse(payload.level), fields=payload.fields), session
    )
    return {
        "response": result.response,
        "solved": result.solved,
        "refused": result.refused,
        "refusal_reason": result.refusal_reason,
        "notes": result.notes,
        "meta": result.meta,
        "demo": True,  # deliberately no flag and no points in Live Mode
    }


@router.post("/challenges/{scenario_id}/attempt")
def live_attempt(
    scenario_id: str,
    payload: LiveAttemptIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)

    conn = get_conn(session.id)
    if conn is None:
        return {"error": {"kind": "not_connected", "message": "Connect a local model first."}}

    ok, reason = check_budget(conn)
    if not ok:
        return {"error": {"kind": "rate_limited", "message": reason}}

    level = Level.parse(payload.level)
    try:
        result = run_live(scenario_id, level, payload.fields, conn)
    except LiveError as exc:
        return {"error": {"kind": exc.kind, "message": exc.message}}

    if not result.refused_by_guard:
        record_usage(conn)

    body = {
        "response": result.text,
        "solved": result.solved,
        "refused": result.refused_by_guard,
        "refusal_reason": result.refusal_reason,
        "notes": result.notes,
        "tool_calls": result.tool_calls,
        "meta": {
            "provider": "ollama",
            "model": result.model,
            "endpoint": result.endpoint,
            "output_tokens": result.output_tokens,
            "remaining_requests": conn.remaining_requests(),
        },
    }
    if result.solved:
        key = level_key(level.value, "live")
        first = session.mark_solved(f"live:{scenario_id}", key)
        body["flag"] = flag_for(scenario_id, key)
        body["awarded"] = points_for(key) if first else 0
        body["first_solve"] = first
        body["score"] = session.score
    return body

"""Live Mode HTTP surface, mounted under /api/live.

Kept in its own router so the offline lab has zero dependency on it. If httpx or
a provider is unavailable, only these endpoints are affected.
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Response
from pydantic import BaseModel, Field

from .flags import flag_for, points_for
from .levels import Level
from .live_engine import PROVIDERS, LiveError, list_scenarios, run_live
from .live_state import (
    check_budget,
    clear_creds,
    get_creds,
    record_usage,
    set_creds,
)
from .state import SESSION_COOKIE, get_or_create

router = APIRouter(prefix="/api/live", tags=["live"])

# Cheap format sanity-check so an obviously wrong key never reaches the provider.
_KEY_PREFIXES = {"anthropic": "sk-ant-", "openai": "sk-"}


def _valid_key_format(provider: str, key: str) -> bool:
    prefix = _KEY_PREFIXES.get(provider)
    return bool(prefix) and key.startswith(prefix)


class KeyIn(BaseModel):
    provider: str = "anthropic"
    model: str = ""
    key: str = Field("", min_length=1)


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
        "providers": [
            {"id": pid, "label": p["label"], "default_model": p["default_model"]}
            for pid, p in PROVIDERS.items()
        ]
    }


@router.get("/scenarios")
def scenarios() -> dict:
    items = list_scenarios()
    # Unbounded Consumption is demonstration-only in Live Mode: it is never sent
    # to a real model (that is exactly the resource-exhaustion we refuse to let a
    # user do to their own quota). It runs against the offline engine instead.
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
                "demo_only": True,
                "demo_reason": (
                    "Not run against a real model on purpose: forcing a live model to "
                    "generate a huge response is the very resource-exhaustion attack "
                    "this challenge is about, and it would burn your own quota. It runs "
                    "against the deterministic offline engine here instead."
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
    creds = get_creds(session.id)
    if creds is None:
        return {"connected": False}
    return {
        "connected": True,
        "provider": creds.provider,
        "model": creds.model,
        "key": creds.masked(),
        "requests_made": creds.requests_made,
        "remaining_requests": creds.remaining_requests(),
        "remaining_tokens": creds.remaining_tokens(),
    }


@router.post("/key")
def set_key(
    payload: KeyIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)

    if payload.provider not in PROVIDERS:
        return {"ok": False, "error": {"kind": "bad_provider", "message": "Unknown provider."}}

    key = payload.key.strip()
    if not _valid_key_format(payload.provider, key):
        return {
            "ok": False,
            "error": {
                "kind": "bad_key_format",
                "message": (
                    f"That does not look like a {payload.provider} key "
                    f"(expected prefix '{_KEY_PREFIXES[payload.provider]}'). "
                    "Nothing was sent to the provider."
                ),
            },
        }

    model = payload.model.strip() or PROVIDERS[payload.provider]["default_model"]
    creds = set_creds(session.id, payload.provider, model, key)
    # The key is never returned - only its masked tail.
    return {
        "ok": True,
        "provider": creds.provider,
        "model": creds.model,
        "key": creds.masked(),
    }


@router.delete("/key")
def delete_key(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = get_or_create(session_id)
    _cookie(response, session)
    clear_creds(session.id)
    return {"ok": True}


@router.post("/demo/{challenge_id}/attempt")
def demo_attempt(
    challenge_id: str,
    payload: LiveAttemptIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    """Run a demonstration-only challenge on the OFFLINE engine - no key, no
    real model, no scoring. Used for Unbounded Consumption in Live Mode.
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

    creds = get_creds(session.id)
    if creds is None:
        return {"error": {"kind": "no_key", "message": "Connect an API key first."}}

    ok, reason = check_budget(creds)
    if not ok:
        return {"error": {"kind": "rate_limited", "message": reason}}

    level = Level.parse(payload.level)
    try:
        result = run_live(scenario_id, level, payload.fields, creds)
    except LiveError as exc:
        # Graceful, typed failure - the offline lab is unaffected.
        return {"error": {"kind": exc.kind, "message": exc.message}}

    if not result.refused_by_guard:
        record_usage(creds, result.output_tokens)

    body = {
        "response": result.text,
        "solved": result.solved,
        "refused": result.refused_by_guard,
        "refusal_reason": result.refusal_reason,
        "notes": result.notes,
        "tool_calls": result.tool_calls,
        "meta": {
            "provider": result.provider,
            "model": result.model,
            "output_tokens": result.output_tokens,
            "remaining_requests": creds.remaining_requests(),
            "remaining_tokens": creds.remaining_tokens(),
        },
    }
    if result.solved:
        first = session.mark_solved(f"live:{scenario_id}", level.value)
        body["flag"] = flag_for(scenario_id, f"live-{level.value}")
        body["awarded"] = points_for(level.value) if first else 0
        body["first_solve"] = first
        body["score"] = session.score
    return body

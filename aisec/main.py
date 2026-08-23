"""FastAPI surface for the AISEC Lab.

A single-page UI plus a small JSON API:

  GET  /                      the lab UI
  GET  /health                liveness / version
  GET  /api/challenges        challenge catalogue (public metadata)
  GET  /api/challenges/{id}   one challenge, plus your solved levels
  POST /api/challenges/{id}/attempt   run an attack
  POST /api/challenges/{id}/verify    submit a flag for points
  GET  /api/hint/{id}?level=  progressive hints
  GET  /api/solution/{id}     reference exploit (spoiler)
  GET  /api/scoreboard        your session score
  POST /api/reset             wipe your session
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .challenges import all_challenges, get
from .challenges.base import Attempt
from .flags import flag_for, level_key, points_for, solutions_enabled, verify
from .levels import LEVEL_NOTES, Level
from .state import SESSION_COOKIE, get_or_create, reset

app = FastAPI(
    title="AISEC Lab",
    version=__version__,
    description="Intentionally vulnerable AI/LLM app for security training. Do not deploy to the public internet.",
)

_STATIC = Path(__file__).parent / "static"
if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

# Optional Live Mode. If it cannot import (e.g. httpx missing), the offline lab
# still runs - Live Mode just stays unavailable.
try:
    from .live_routes import router as live_router

    app.include_router(live_router)
    _LIVE_AVAILABLE = True
except Exception:  # pragma: no cover - defensive: never break offline mode
    _LIVE_AVAILABLE = False


class AttemptIn(BaseModel):
    level: str = "low"
    fields: dict[str, str] = Field(default_factory=dict)


class VerifyIn(BaseModel):
    level: str = "low"
    flag: str = ""
    plane: str = "offline"  # "offline" or "live"


def _session_response(response: Response, session) -> None:
    response.set_cookie(
        SESSION_COOKIE, session.id, httponly=True, samesite="lax", max_age=86400
    )


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "challenges": len(all_challenges()),
        "live_mode": _LIVE_AVAILABLE,
    }


@app.get("/api/challenges", tags=["challenges"])
def list_challenges(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = get_or_create(session_id)
    _session_response(response, session)
    return {
        "levels": [
            {"id": level.value, "note": LEVEL_NOTES[level], "points": points_for(level.value)}
            for level in Level
        ],
        "challenges": [
            {**c.public(), "solved": session.solved.get(c.id, [])}
            for c in all_challenges()
        ],
        "score": session.score,
    }


@app.get("/api/challenges/{challenge_id}", tags=["challenges"])
def get_challenge(
    challenge_id: str,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    challenge = get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge")
    session = get_or_create(session_id)
    _session_response(response, session)
    return {**challenge.public(), "solved": session.solved.get(challenge_id, [])}


@app.post("/api/challenges/{challenge_id}/attempt", tags=["challenges"])
def attempt(
    challenge_id: str,
    payload: AttemptIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    challenge = get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge")

    session = get_or_create(session_id)
    _session_response(response, session)
    session.attempts += 1

    level = Level.parse(payload.level)
    result = challenge.handler(Attempt(level=level, fields=payload.fields), session)

    body = {
        "response": result.response,
        "refused": result.refused,
        "refusal_reason": result.refusal_reason,
        "solved": result.solved,
        "notes": result.notes,
        "meta": result.meta,
        "context": [
            {"source": b.source.value, "label": b.label, "content": b.content}
            for b in result.context
        ],
        "directives": [
            {
                "kind": d.kind.value,
                "origin": d.origin.value,
                "via": d.via,
                "payload": d.payload,
                "raw": d.raw,
            }
            for d in result.directives
        ],
        "tool_calls": [
            {"name": tc.name, "arguments": tc.arguments} for tc in result.tool_calls
        ],
    }

    if result.solved:
        flag = flag_for(challenge_id, level.value)
        first = session.mark_solved(challenge_id, level.value)
        body["flag"] = flag
        body["awarded"] = points_for(level.value) if first else 0
        body["first_solve"] = first
        body["score"] = session.score

    return body


@app.post("/api/challenges/{challenge_id}/verify", tags=["challenges"])
def verify_flag(
    challenge_id: str,
    payload: VerifyIn,
    response: Response,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    challenge = get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge")
    session = get_or_create(session_id)
    _session_response(response, session)

    level = Level.parse(payload.level)
    live = payload.plane == "live"
    key = level_key(level.value, payload.plane)
    ok = verify(challenge_id, key, payload.flag)
    awarded = 0
    if ok:
        solve_id = f"live:{challenge_id}" if live else challenge_id
        first = session.mark_solved(solve_id, key)
        awarded = points_for(key) if first else 0
    return {"valid": ok, "awarded": awarded, "score": session.score}


@app.get("/api/hint/{challenge_id}", tags=["challenges"])
def hint(challenge_id: str, level: int = 0) -> dict:
    challenge = get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge")
    idx = max(0, min(level, len(challenge.hints) - 1))
    return {
        "index": idx,
        "total": len(challenge.hints),
        "hint": challenge.hints[idx] if challenge.hints else "No hints for this one.",
    }


@app.get("/api/solution/{challenge_id}", tags=["challenges"])
def solution(challenge_id: str) -> dict:
    if not solutions_enabled():
        raise HTTPException(status_code=403, detail="solutions disabled on this host")
    challenge = get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="unknown challenge")
    return {"solution": challenge.solution}


@app.get("/api/scoreboard", tags=["challenges"])
def scoreboard(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = get_or_create(session_id)
    _session_response(response, session)
    max_score = sum(points_for(lvl.value) for _ in all_challenges() for lvl in Level)
    return {
        "score": session.score,
        "max_score": max_score,
        "attempts": session.attempts,
        "solved": session.solved,
    }


@app.post("/api/reset", tags=["challenges"])
def reset_session(
    response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)
) -> dict:
    session = reset(session_id)
    _session_response(response, session)
    return {"status": "reset", "score": session.score}


@app.get("/", response_class=HTMLResponse, tags=["ui"])
def index() -> HTMLResponse:
    page = _STATIC / "index.html"
    if page.exists():
        return HTMLResponse(page.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AISEC Lab</h1><p>UI asset missing.</p>", status_code=200)

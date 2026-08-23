"""Per-session lab state: score, solved challenges, and mutable knowledge bases.

Everything is in-memory on purpose. Restart the container and the lab resets.
"""

from __future__ import annotations

import os
import secrets as _secrets
import time
from dataclasses import dataclass, field

from .flags import points_for

SESSION_COOKIE = "aisec_session"

# Bounds so a cookie-less request loop can't exhaust the host's memory.
MAX_SESSIONS = int(os.getenv("AISEC_MAX_SESSIONS", "5000"))
SESSION_TTL_SECONDS = int(os.getenv("AISEC_SESSION_TTL", str(6 * 3600)))
MAX_BUCKET_ITEMS = int(os.getenv("AISEC_MAX_BUCKET_ITEMS", "200"))


@dataclass
class Session:
    id: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    solved: dict[str, list[str]] = field(default_factory=dict)
    score: int = 0
    attempts: int = 0
    # Challenge-owned scratch space (e.g. a poisoned RAG index).
    store: dict[str, list] = field(default_factory=dict)

    def mark_solved(self, challenge_id: str, level: str) -> bool:
        """Record a solve. Returns True if this is the first time."""
        levels = self.solved.setdefault(challenge_id, [])
        if level in levels:
            return False
        levels.append(level)
        self.score += points_for(level)
        return True

    def is_solved(self, challenge_id: str, level: str) -> bool:
        return level in self.solved.get(challenge_id, [])

    def bucket(self, name: str) -> list:
        return self.store.setdefault(name, [])

    def append_capped(self, name: str, item, cap: int = MAX_BUCKET_ITEMS) -> bool:
        """Append to a bucket unless it's full. Returns False if the cap was hit."""
        b = self.bucket(name)
        if len(b) >= cap:
            return False
        b.append(item)
        return True


_SESSIONS: dict[str, Session] = {}


def _prune(now: float) -> None:
    # Drop expired sessions, then evict oldest if still over the cap.
    expired = [sid for sid, s in _SESSIONS.items() if now - s.last_seen > SESSION_TTL_SECONDS]
    for sid in expired:
        _SESSIONS.pop(sid, None)
    if len(_SESSIONS) >= MAX_SESSIONS:
        for sid, _s in sorted(_SESSIONS.items(), key=lambda kv: kv[1].last_seen)[
            : len(_SESSIONS) - MAX_SESSIONS + 1
        ]:
            _SESSIONS.pop(sid, None)


def get_or_create(session_id: str | None) -> Session:
    now = time.time()
    if session_id and session_id in _SESSIONS:
        session = _SESSIONS[session_id]
        session.last_seen = now
        return session
    _prune(now)
    new_id = _secrets.token_urlsafe(18)
    session = Session(id=new_id)
    _SESSIONS[new_id] = session
    return session


def reset(session_id: str | None) -> Session:
    if session_id:
        _SESSIONS.pop(session_id, None)
    return get_or_create(None)

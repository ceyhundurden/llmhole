"""Per-session lab state: score, solved challenges, and mutable knowledge bases.

Everything is in-memory on purpose. Restart the container and the lab resets.
"""

from __future__ import annotations

import secrets as _secrets
import time
from dataclasses import dataclass, field

from .flags import points_for

SESSION_COOKIE = "aisec_session"


@dataclass
class Session:
    id: str
    created_at: float = field(default_factory=time.time)
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


_SESSIONS: dict[str, Session] = {}


def get_or_create(session_id: str | None) -> Session:
    if session_id and session_id in _SESSIONS:
        return _SESSIONS[session_id]
    new_id = _secrets.token_urlsafe(18)
    session = Session(id=new_id)
    _SESSIONS[new_id] = session
    return session


def reset(session_id: str | None) -> Session:
    if session_id:
        _SESSIONS.pop(session_id, None)
    return get_or_create(None)

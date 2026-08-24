from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

MAX_TOKENS_PER_CALL = 512
MAX_REQUESTS = int(os.getenv("LLMHOLE_MAX_LIVE_REQUESTS", "100"))
MAX_CONNS = int(os.getenv("LLMHOLE_MAX_LIVE_CONNS", "1000"))
CONN_TTL_SECONDS = int(os.getenv("LLMHOLE_LIVE_CONN_TTL", str(6 * 3600)))


@dataclass
class LiveConn:
    endpoint: str
    model: str
    requests_made: int = 0
    last_seen: float = field(default_factory=time.time)

    def remaining_requests(self) -> int:
        return max(0, MAX_REQUESTS - self.requests_made)


_conns: dict[str, LiveConn] = {}


def _prune(now: float) -> None:
    for sid in [s for s, c in _conns.items() if now - c.last_seen > CONN_TTL_SECONDS]:
        _conns.pop(sid, None)
    if len(_conns) >= MAX_CONNS:
        oldest = sorted(_conns.items(), key=lambda kv: kv[1].last_seen)
        for sid, _c in oldest[: len(_conns) - MAX_CONNS + 1]:
            _conns.pop(sid, None)


def set_conn(session_id: str, endpoint: str, model: str) -> LiveConn:
    now = time.time()
    _prune(now)
    existing = _conns.get(session_id)
    spent = existing.requests_made if existing else 0
    conn = LiveConn(endpoint=endpoint, model=model, requests_made=spent, last_seen=now)
    _conns[session_id] = conn
    return conn


def get_conn(session_id: str) -> LiveConn | None:
    conn = _conns.get(session_id)
    if conn is not None:
        conn.last_seen = time.time()
    return conn


def clear_conn(session_id: str) -> None:
    _conns.pop(session_id, None)


def check_budget(conn: LiveConn) -> tuple[bool, str | None]:
    if conn.remaining_requests() <= 0:
        return False, (
            f"Session request cap reached ({MAX_REQUESTS}). Reset the session to continue - "
            "reconnecting will not clear it."
        )
    return True, None


def record_usage(conn: LiveConn) -> None:
    conn.requests_made += 1
    conn.last_seen = time.time()

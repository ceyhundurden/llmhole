from __future__ import annotations

import os
from dataclasses import dataclass

MAX_TOKENS_PER_CALL = 512
MAX_REQUESTS = int(os.getenv("LLMHOLE_MAX_LIVE_REQUESTS", "100"))


@dataclass
class LiveConn:
    endpoint: str
    model: str
    requests_made: int = 0

    def remaining_requests(self) -> int:
        return max(0, MAX_REQUESTS - self.requests_made)


_conns: dict[str, LiveConn] = {}


def set_conn(session_id: str, endpoint: str, model: str) -> LiveConn:
    conn = LiveConn(endpoint=endpoint, model=model)
    _conns[session_id] = conn
    return conn


def get_conn(session_id: str) -> LiveConn | None:
    return _conns.get(session_id)


def clear_conn(session_id: str) -> None:
    _conns.pop(session_id, None)


def check_budget(conn: LiveConn) -> tuple[bool, str | None]:
    if conn.remaining_requests() <= 0:
        return False, f"Session request cap reached ({MAX_REQUESTS}). Reset the session to continue."
    return True, None


def record_usage(conn: LiveConn) -> None:
    conn.requests_made += 1

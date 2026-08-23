"""In-memory Live Mode connection state and a light per-session request cap.

Live Mode targets a local Ollama server, so there is no API key and no cost to
protect - nothing here is ever a credential. We keep only the endpoint and model
the user picked, plus a request counter so a runaway loop can't hammer their own
hardware. Nothing is persisted or logged.
"""

from __future__ import annotations

from dataclasses import dataclass

# Per-call output cap (num_predict). Local inference is free but slow, so we keep
# responses bounded to protect the user's own machine / response time.
MAX_TOKENS_PER_CALL = 512
# A generous safety cap on live attempts per session (runaway guard only).
MAX_REQUESTS = 100


@dataclass
class LiveConn:
    endpoint: str
    model: str
    requests_made: int = 0

    def remaining_requests(self) -> int:
        return max(0, MAX_REQUESTS - self.requests_made)


_CONNS: dict[str, LiveConn] = {}


def set_conn(session_id: str, endpoint: str, model: str) -> LiveConn:
    conn = LiveConn(endpoint=endpoint, model=model)
    _CONNS[session_id] = conn
    return conn


def get_conn(session_id: str) -> LiveConn | None:
    return _CONNS.get(session_id)


def clear_conn(session_id: str) -> None:
    _CONNS.pop(session_id, None)


def check_budget(conn: LiveConn) -> tuple[bool, str | None]:
    if conn.remaining_requests() <= 0:
        return False, (
            f"Session request cap reached ({MAX_REQUESTS}). Reset the session to "
            "continue."
        )
    return True, None


def record_usage(conn: LiveConn) -> None:
    conn.requests_made += 1

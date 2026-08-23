"""In-memory Live Mode credentials and per-session rate limiting.

The API key is held only here, in process memory, keyed by session. It is never
persisted, never logged, and only ever surfaced to the user in masked form.
"""

from __future__ import annotations

from dataclasses import dataclass

# Guard rails so a user cannot accidentally drain their own credits.
MAX_REQUESTS = 25          # live attempts per session
MAX_TOKENS_TOTAL = 40_000  # cumulative output-token budget per session
MAX_TOKENS_PER_CALL = 512  # hard cap sent as max_tokens on every request


@dataclass
class LiveCreds:
    provider: str
    model: str
    key: str
    requests_made: int = 0
    tokens_used: int = 0

    def masked(self) -> str:
        if len(self.key) <= 4:
            return "****"
        return "..." + self.key[-4:]

    def remaining_requests(self) -> int:
        return max(0, MAX_REQUESTS - self.requests_made)

    def remaining_tokens(self) -> int:
        return max(0, MAX_TOKENS_TOTAL - self.tokens_used)


_CREDS: dict[str, LiveCreds] = {}


def set_creds(session_id: str, provider: str, model: str, key: str) -> LiveCreds:
    creds = LiveCreds(provider=provider, model=model, key=key)
    _CREDS[session_id] = creds
    return creds


def get_creds(session_id: str) -> LiveCreds | None:
    return _CREDS.get(session_id)


def clear_creds(session_id: str) -> None:
    _CREDS.pop(session_id, None)


def check_budget(creds: LiveCreds) -> tuple[bool, str | None]:
    if creds.remaining_requests() <= 0:
        return False, (
            f"Session request limit reached ({MAX_REQUESTS}). Reset the session to "
            "continue - this cap protects your credits."
        )
    if creds.remaining_tokens() <= 0:
        return False, (
            f"Session token budget spent ({MAX_TOKENS_TOTAL}). Reset the session to "
            "continue."
        )
    return True, None


def record_usage(creds: LiveCreds, output_tokens: int) -> None:
    creds.requests_made += 1
    creds.tokens_used += max(output_tokens, 0)

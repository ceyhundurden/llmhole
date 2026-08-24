from __future__ import annotations

import hashlib
import hmac
import os

DEFAULT_SECRET = "llmhole-default-secret"  # nosec B105
POINTS = {"low": 10, "medium": 25, "high": 50, "very-high": 80}

_secret = os.getenv("LLMHOLE_FLAG_SECRET", DEFAULT_SECRET)
CTF_MODE = os.getenv("LLMHOLE_CTF_MODE", "0") == "1"

if CTF_MODE and _secret == DEFAULT_SECRET:
    raise RuntimeError(
        "LLMHOLE_CTF_MODE=1 but LLMHOLE_FLAG_SECRET is still the built-in default. "
        "Flags would be pre-computable from the public source. Set a unique "
        "LLMHOLE_FLAG_SECRET before hosting a CTF."
    )

_key = _secret.encode()


def solutions_enabled() -> bool:
    return os.getenv("LLMHOLE_ALLOW_SOLUTIONS", "0" if CTF_MODE else "1") == "1"


def level_key(level: str, plane: str = "offline") -> str:
    return f"live-{level}" if plane == "live" else level


def flag_for(challenge_id: str, level: str) -> str:
    digest = hmac.new(_key, f"{challenge_id}:{level}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"HOLE{{{challenge_id}_{level}_{digest}}}"


def points_for(level: str) -> int:
    base = level[5:] if level.startswith("live-") else level
    return POINTS.get(base, 10)


def verify(challenge_id: str, level: str, submitted: str) -> bool:
    return hmac.compare_digest(flag_for(challenge_id, level), submitted.strip())

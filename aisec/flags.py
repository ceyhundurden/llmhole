"""Deterministic per-challenge, per-level flags.

The lab secret is read from AISEC_FLAG_SECRET so a CTF host can rotate flags
without touching code. In CTF mode (AISEC_CTF_MODE=1) the default secret is
rejected at import so nobody accidentally ships pre-computable flags.
"""

from __future__ import annotations

import hashlib
import hmac
import os

DEFAULT_SECRET = "aisec-lab-default-secret"

_RAW_SECRET = os.getenv("AISEC_FLAG_SECRET", DEFAULT_SECRET)
CTF_MODE = os.getenv("AISEC_CTF_MODE", "0") == "1"

if CTF_MODE and _RAW_SECRET == DEFAULT_SECRET:
    raise RuntimeError(
        "AISEC_CTF_MODE=1 but AISEC_FLAG_SECRET is still the built-in default. "
        "Flags would be pre-computable from the public source. Set a unique "
        "AISEC_FLAG_SECRET before hosting a CTF."
    )

_LAB_SECRET = _RAW_SECRET.encode()

POINTS = {"low": 10, "medium": 25, "high": 50, "very-high": 80}


def solutions_enabled() -> bool:
    """Reference solutions are on by default, but off by default in CTF mode."""
    return os.getenv("AISEC_ALLOW_SOLUTIONS", "0" if CTF_MODE else "1") == "1"


def level_key(level: str, plane: str = "offline") -> str:
    """The flag/solve key for a (level, plane). Live flags are namespaced so an
    offline flag and a live flag for the same challenge/level never collide, and
    so verification can round-trip them (the previous scheme could not)."""
    return f"live-{level}" if plane == "live" else level


def flag_for(challenge_id: str, level: str) -> str:
    digest = hmac.new(
        _LAB_SECRET, f"{challenge_id}:{level}".encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"AISEC{{{challenge_id}_{level}_{digest}}}"


def points_for(level: str) -> int:
    # Live keys look like "live-low"; score them by their base level.
    base = level[5:] if level.startswith("live-") else level
    return POINTS.get(base, 10)


def verify(challenge_id: str, level: str, submitted: str) -> bool:
    return hmac.compare_digest(flag_for(challenge_id, level), submitted.strip())

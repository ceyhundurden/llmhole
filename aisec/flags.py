"""Deterministic per-challenge, per-level flags.

The lab secret is read from AISEC_FLAG_SECRET so a CTF host can rotate flags
without touching code. The default is fine for local practice.
"""

from __future__ import annotations

import hashlib
import hmac
import os

_LAB_SECRET = os.getenv("AISEC_FLAG_SECRET", "aisec-lab-default-secret").encode()

POINTS = {"low": 10, "medium": 25, "high": 50, "very-high": 80}


def flag_for(challenge_id: str, level: str) -> str:
    digest = hmac.new(
        _LAB_SECRET, f"{challenge_id}:{level}".encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"AISEC{{{challenge_id}_{level}_{digest}}}"


def points_for(level: str) -> int:
    return POINTS.get(level, 10)


def verify(challenge_id: str, level: str, submitted: str) -> bool:
    return hmac.compare_digest(flag_for(challenge_id, level), submitted.strip())

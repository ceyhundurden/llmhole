"""Security levels and the (intentionally imperfect) guardrails behind them.

Three levels, in the spirit of bWAPP / DVWA:

  low     - no defence at all. Learn the attack primitive here.
  medium  - a naive keyword blocklist applied to the *user* message only.
            Untrusted retrieved content is trusted implicitly, and any
            encoding defeats the string match.
  high    - the blocklist covers every untrusted block and the output is
            scanned for verbatim secrets. Still defeatable, because the
            filter runs on raw bytes while the model normalises afterwards.

No level here is meant to be a correct defence. Each one is a real pattern
seen in production LLM applications, shipped with its real failure mode.
"""

from __future__ import annotations

import re
from enum import Enum

from .engine import Block, Source


class Level(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def parse(cls, value: str | None) -> "Level":
        try:
            return cls(str(value or "low").lower())
        except ValueError:
            return cls.LOW


LEVEL_NOTES: dict[Level, str] = {
    Level.LOW: "No input or output filtering. Everything in the context window is obeyed.",
    Level.MEDIUM: "Keyword blocklist on the user message only. Retrieved content is never inspected.",
    Level.HIGH: "Blocklist on every untrusted block plus verbatim secret redaction on output.",
}

# Words a lazy engineer reaches for first.
_BLOCKLIST = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "forget your instructions",
    "system prompt",
    "initial instructions",
    "your instructions",
    "reveal the secret",
    "api key",
    "passphrase",
    "developer mode",
    "jailbreak",
    "dan mode",
)

_HIGH_EXTRA = (
    "override",
    "bypass",
    "print your",
    "repeat the text above",
    "confidential",
    "exfiltrate",
    "tool:",
)


def _hits(text: str, needles: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return [needle for needle in needles if needle in lowered]


def screen(blocks: list[Block], level: Level) -> tuple[bool, str | None, list[str]]:
    """Run the input guardrail.

    Returns (refused, reason, matched_keywords). Note the guardrail only ever
    sees raw text - `engine.normalise` has not run yet.
    """
    if level is Level.LOW:
        return False, None, []

    if level is Level.MEDIUM:
        scope = [b for b in blocks if b.source is Source.USER]
    else:
        scope = [b for b in blocks if b.source is not Source.SYSTEM]

    needles = _BLOCKLIST if level is Level.MEDIUM else _BLOCKLIST + _HIGH_EXTRA

    matched: list[str] = []
    for block in scope:
        matched.extend(_hits(block.content, needles))

    if matched:
        reason = (
            "Request blocked by the content filter "
            f"(matched: {', '.join(sorted(set(matched))[:4])})."
        )
        return True, reason, sorted(set(matched))
    return False, None, []


def redact_output(text: str, level: Level, secrets: list[str]) -> str:
    """Output guardrail for HIGH: strip verbatim secrets, nothing more.

    Any transform the model applies to the secret before printing it - base64,
    reversal, spacing - walks straight through this.
    """
    if level is not Level.HIGH:
        return text
    for secret in secrets:
        if secret:
            text = re.sub(re.escape(secret), "[REDACTED]", text, flags=re.I)
    return text

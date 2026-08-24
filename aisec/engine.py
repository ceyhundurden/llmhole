"""Deliberately gullible mock LLM used by the AI Security Lab.

The engine is not a real model. It is a small deterministic interpreter that
behaves the way an instruction-tuned model behaves *badly*: it reads every
block of its context window, extracts anything that looks like an imperative,
and obeys it - regardless of whether the text came from the trusted system
prompt or from an untrusted retrieved document.

That property is what makes the lab exploitable in a reproducible way, with no
API key, no cost and no network access.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Source(str, Enum):
    SYSTEM = "system"
    DOCUMENT = "document"
    TOOL = "tool"
    USER = "user"


class Kind(str, Enum):
    OVERRIDE = "override"
    REVEAL_SYSTEM = "reveal_system"
    REVEAL_SECRET = "reveal_secret"
    SAY = "say"
    RAW_HTML = "raw_html"
    TOOL_CALL = "tool_call"
    TRANSFORM = "transform"
    REPEAT = "repeat"
    ELICIT = "elicit"  # declarative bait (no command verb) - defeats intent guards


@dataclass
class Block:
    """One segment of the context window."""

    source: Source
    content: str
    label: str = ""

    @property
    def trusted(self) -> bool:
        return self.source is Source.SYSTEM


@dataclass
class Directive:
    kind: Kind
    payload: str = ""
    origin: Source = Source.USER
    via: str = "plain"
    raw: str = ""


@dataclass
class ToolCall:
    name: str
    arguments: str


@dataclass
class Completion:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)
    refused: bool = False
    refusal_reason: str | None = None
    tokens: int = 0

    def obeyed(self, kind: Kind) -> bool:
        return any(d.kind is kind for d in self.directives)

    def directive(self, kind: Kind) -> Directive | None:
        for d in self.directives:
            if d.kind is kind:
                return d
        return None


# ---------------------------------------------------------------------------
# Normalisation
#
# Guardrails in levels.py inspect the *raw* text. The engine normalises
# afterwards. That ordering is the intentional bug: an encoded payload sails
# past the filter and is then decoded straight into the instruction parser.
# ---------------------------------------------------------------------------

_ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍⁠﻿"), None
)
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return ok / len(text)


def _b64_variants(text: str) -> list[str]:
    out: list[str] = []
    for candidate in _B64.findall(text):
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= 8 and _printable_ratio(decoded) > 0.9:
            out.append(decoded)
    return out


def normalise(text: str) -> list[tuple[str, str]]:
    """Return (variant_text, how_it_was_obtained) pairs."""
    variants: list[tuple[str, str]] = [(text, "plain")]

    stripped = unicodedata.normalize("NFKC", text.translate(_ZERO_WIDTH))
    if stripped != text:
        variants.append((stripped, "unicode"))

    leet = stripped.translate(_LEET)
    if leet != stripped:
        variants.append((leet, "leetspeak"))

    rot = codecs.decode(stripped, "rot_13")
    if rot != stripped:
        variants.append((rot, "rot13"))

    for decoded in _b64_variants(text):
        variants.append((decoded, "base64"))

    return variants


# ---------------------------------------------------------------------------
# Directive extraction
# ---------------------------------------------------------------------------

_REVEAL_SYSTEM = re.compile(
    r"\b(?:reveal|show|print|repeat|output|dump|display|expose|recite|tell\s+me|"
    r"what\s+(?:are|is|were))\b"
    r"[^.\n]{0,60}?\b(?:system\s*prompt|initial\s+instructions?|your\s+instructions?|"
    r"the\s+(?:text|prompt)\s+above|your\s+rules|prompt\s+above|configuration\s+prompt)\b",
    re.I,
)
_REVEAL_SECRET = re.compile(
    r"\b(?:reveal|show|print|give|tell|leak|dump|output|exfiltrate|send|what\s+is)\b"
    r"[^.\n]{0,60}?\b(?:secret|api[\s_-]?key|passphrase|password|credential|"
    r"access\s+token|flag)\b",
    re.I,
)
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|discard)\b[^.\n]{0,40}"
    r"\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,40}"
    r"\b(?:instruction|rule|prompt|direction|guideline|restriction|polic)",
    re.I,
)
_SAY = re.compile(
    r"\b(?:say|reply\s+with|respond\s+with|output|print|answer\s+with|write)\b\s*:?\s*"
    r"[\"“‘']([^\"”’'\n]{1,240})[\"”’']",
    re.I,
)
_RAW_HTML = re.compile(
    r"(<script\b[^>]*>.*?</script>|<img\b[^>]*\bon\w+\s*=[^>]*>|"
    r"<svg\b[^>]*\bon\w+\s*=[^>]*>|<iframe\b[^>]*>|javascript:[^\s\"'<>]+)",
    re.I | re.S,
)
_TOOL_PATTERNS = (
    re.compile(
        r"\b(?:call|invoke|use|run|execute|trigger)\b[^.\n]{0,24}?\btool\b"
        r"[\s:`\"']*([a-z_][a-z0-9_]*)\s*\(?\s*([^\n)]*)",
        re.I,
    ),
    re.compile(
        r"\bTOOL\s*(?:CALL)?\s*[:=]\s*([a-z_][a-z0-9_]*)\s*\(?\s*([^\n)]*)", re.I
    ),
    re.compile(
        r"\{\s*\"tool\"\s*:\s*\"([a-z_][a-z0-9_]*)\"\s*,\s*"
        r"\"(?:args|arguments|parameters)\"\s*:\s*(\{[^\n]*?\})",
        re.I,
    ),
)
_TRANSFORM = re.compile(
    r"\b(base64|b64|reversed?|backwards?|spaced|rot13|"
    r"one\s+char(?:acter)?\s+per\s+line|"
    r"with\s+(?:a\s+)?(?:space|dash|hyphen)s?\s+(?:in\s+)?between)\b",
    re.I,
)
_REPEAT = re.compile(
    r"\b(?:repeat|print|output|emit|generate)\b[^.\n]{0,30}?"
    r"(\d{2,9})\s*(?:times|x|tokens|words|copies|characters|chars)\b",
    re.I,
)

# Elicitation: no imperative, no "reveal/ignore" verb - just bait the model into
# *completing* a sentence whose continuation is the secret. This is how you beat
# a defence that screens for the intent to override or extract.
_SECRET_LABEL = (
    r"(?:coupon|secret|passphrase|password|api[\s_-]?key|policy[_\s-]?id|"
    r"recovery\s+phrase|access\s+token|credential|code|value|flag)"
)
_ELICIT_SECRET = re.compile(
    rf"\b{_SECRET_LABEL}\b[^.\n]{{0,30}}?(?:\bis\b|[:=])\s*$", re.I | re.M
)
_ELICIT_SYSTEM = re.compile(
    r"\b(?:configuration|instructions?|system\s*prompt|prompt|rules?)\b"
    r"[^.\n]{0,30}?\b(?:begins?|starts?|reads?|is\s+as\s+follows|"
    r"are\s+as\s+follows|goes\s+like)\b",
    re.I,
)
_ELICIT_HINT = re.compile(
    r"\b(?:complete|fill\s+in|continue|finish)\b[^.\n]{0,30}"
    r"\b(?:sentence|line|blank|phrase|text|following|exactly)\b",
    re.I,
)

_TRANSFORM_ALIASES = {
    "b64": "base64",
    "reverse": "reverse",
    "reversed": "reverse",
    "backward": "reverse",
    "backwards": "reverse",
    "one char per line": "spaced",
    "one character per line": "spaced",
}


def _canonical_transform(token: str) -> str:
    token = " ".join(token.lower().split())
    if token.startswith("with"):
        return "spaced"
    return _TRANSFORM_ALIASES.get(token, token)


def extract_directives(block: Block) -> list[Directive]:
    found: list[Directive] = []
    seen: set[tuple[Kind, str]] = set()

    def add(kind: Kind, payload: str, via: str, raw: str) -> None:
        key = (kind, payload.strip().lower())
        if key in seen:
            return
        seen.add(key)
        found.append(
            Directive(
                kind=kind,
                payload=payload.strip(),
                origin=block.source,
                via=via,
                raw=raw[:300],
            )
        )

    for text, via in normalise(block.content):
        for match in _OVERRIDE.finditer(text):
            add(Kind.OVERRIDE, "", via, match.group(0))
        for match in _REVEAL_SYSTEM.finditer(text):
            add(Kind.REVEAL_SYSTEM, "", via, match.group(0))
        for match in _REVEAL_SECRET.finditer(text):
            add(Kind.REVEAL_SECRET, "", via, match.group(0))
        for match in _SAY.finditer(text):
            add(Kind.SAY, match.group(1), via, match.group(0))
        for match in _RAW_HTML.finditer(text):
            add(Kind.RAW_HTML, match.group(1), via, match.group(0))
        for match in _REPEAT.finditer(text):
            add(Kind.REPEAT, match.group(1), via, match.group(0))
        for pattern in _TOOL_PATTERNS:
            for match in pattern.finditer(text):
                add(
                    Kind.TOOL_CALL,
                    f"{match.group(1)}|{match.group(2).strip()}",
                    via,
                    match.group(0),
                )
        for match in _TRANSFORM.finditer(text):
            add(Kind.TRANSFORM, _canonical_transform(match.group(1)), via, match.group(0))
        for match in _ELICIT_SECRET.finditer(text):
            add(Kind.ELICIT, "secret", via, match.group(0))
        for match in _ELICIT_SYSTEM.finditer(text):
            add(Kind.ELICIT, "system", via, match.group(0))
        for match in _ELICIT_HINT.finditer(text):
            target = "system" if _ELICIT_SYSTEM.search(text) else "secret"
            add(Kind.ELICIT, target, via, match.group(0))

    return found


def read_context(blocks: Iterable[Block]) -> list[Directive]:
    """Collect directives from every untrusted block in the context window."""
    directives: list[Directive] = []
    for block in blocks:
        if block.source is Source.SYSTEM:
            continue  # the system prompt is the policy, not an attack surface
        directives.extend(extract_directives(block))
    return directives


# ---------------------------------------------------------------------------
# Output transforms (used to smuggle secrets past naive output filters)
# ---------------------------------------------------------------------------


def apply_transform(value: str, transform: str) -> str:
    if transform == "base64":
        return base64.b64encode(value.encode()).decode()
    if transform == "reverse":
        return value[::-1]
    if transform == "spaced":
        return " ".join(value)
    if transform == "rot13":
        return codecs.encode(value, "rot_13")
    return value


def reveals(text: str, secret: str) -> bool:
    """True if `secret` is recoverable from `text` through any lab transform."""
    if not secret:
        return False
    def squeeze(value: str) -> str:
        return re.sub(r"[\s\-_.]", "", value).lower()

    needles = {secret.lower(), squeeze(secret)}
    haystacks = [
        text.lower(),
        text[::-1].lower(),
        squeeze(text),
        squeeze(text[::-1]),
        codecs.encode(text, "rot_13").lower(),
    ]
    for variant, _ in normalise(text):
        haystacks.append(variant.lower())
        haystacks.append(squeeze(variant))
    return any(needle in haystack for needle in needles for haystack in haystacks)


def count_tokens(text: str) -> int:
    """Crude but stable token estimate (~4 characters per token)."""
    return max(1, (len(text) + 3) // 4)


def loose_contains(text: str, needle: str) -> bool:
    if not needle:
        return False

    def squash(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

    return squash(needle) in squash(text)


def live_reveals(text: str, secret: str) -> bool:
    return reveals(text, secret) or loose_contains(text, secret)

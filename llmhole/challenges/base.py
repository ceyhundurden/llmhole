"""Challenge contract and registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..engine import Block, Directive, ToolCall
from ..levels import Level


@dataclass
class Field:
    """One input the UI should render for this challenge."""

    name: str
    label: str
    kind: str = "text"  # text | textarea | select
    placeholder: str = ""
    default: str = ""
    options: list[str] = field(default_factory=list)
    help: str = ""


@dataclass
class Attempt:
    level: Level
    fields: dict[str, str]


@dataclass
class Result:
    response: str
    context: list[Block] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)
    refused: bool = False
    refusal_reason: str | None = None
    solved: bool = False
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


@dataclass
class LiveAdapter:
    build: Callable
    success: Callable
    goal: str = ""
    tools: list | None = None


@dataclass
class Challenge:
    id: str
    title: str
    owasp: str
    difficulty: str
    summary: str
    goal: str
    fields: list[Field]
    hints: list[str]
    solution: dict[str, str]
    handler: Callable[[Attempt, object], Result]
    references: list[str] = field(default_factory=list)
    theme: dict = field(default_factory=dict)
    live: LiveAdapter | None = None

    def public(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "owasp": self.owasp,
            "difficulty": self.difficulty,
            "summary": self.summary,
            "goal": self.goal,
            "theme": self.theme,
            "references": self.references,
            "fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "kind": f.kind,
                    "placeholder": f.placeholder,
                    "default": f.default,
                    "options": f.options,
                    "help": f.help,
                }
                for f in self.fields
            ],
        }


_REGISTRY: dict[str, Challenge] = {}


def register(challenge: Challenge) -> Challenge:
    if challenge.id in _REGISTRY:
        raise ValueError(f"duplicate challenge id: {challenge.id}")
    _REGISTRY[challenge.id] = challenge
    return challenge


def attach_live(challenge_id: str, adapter: LiveAdapter) -> None:
    challenge = _REGISTRY[challenge_id]
    challenge.live = adapter


def live_challenges() -> list[Challenge]:
    return [c for c in _REGISTRY.values() if c.live]


def all_challenges() -> list[Challenge]:
    return list(_REGISTRY.values())


def get(challenge_id: str) -> Challenge | None:
    return _REGISTRY.get(challenge_id)

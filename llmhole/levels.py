from __future__ import annotations

from enum import Enum

from .engine import Block
from .policy import POLICIES, policy_for


class Level(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very-high"

    @classmethod
    def parse(cls, value: str | None) -> Level:
        try:
            return cls(str(value or "low").lower())
        except ValueError:
            return cls.LOW

    @classmethod
    def parse_strict(cls, value: str | None) -> Level:
        # On the API edge a typo must not silently downgrade the user to LOW -
        # they would think they beat a defence that was never switched on.
        try:
            return cls(str(value or "low").lower())
        except ValueError as exc:
            valid = ", ".join(lvl.value for lvl in cls)
            raise ValueError(f"unknown level {value!r}; expected one of: {valid}") from exc

    @property
    def policy(self):
        return policy_for(self.value)


LEVEL_NOTES: dict[Level, str] = {lvl: POLICIES[lvl.value].note for lvl in Level}


def screen(blocks: list[Block], level: Level) -> tuple[bool, str | None, list[str]]:
    refused, reason, guard = level.policy.screen(blocks)
    return refused, reason, [guard] if guard else []


def redact_output(text: str, level: Level, secrets: list[str]) -> str:
    return level.policy.filter_output(text, secrets)


def hardening_for(level: Level) -> str:
    return level.policy.hardening

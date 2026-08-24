"""Optional Live Mode - run a subset of challenges against a *local* LLM.

This module is completely separate from the deterministic offline engine
(`aisec/engine.py`) and is never imported by it. The default lab stays offline,
free and deterministic; nothing here runs unless the user connects a model.

Live Mode targets **Ollama** (https://ollama.com), a local LLM runtime the user
starts on their own machine. There is no API key, no cost, and - once the model
is pulled - no internet: requests go to `http://localhost:11434` and never leave
the box. That makes Live Mode a fully isolated "real model" sandbox.

Guarantees:
  * No credentials are handled anywhere - there is nothing to leak.
  * Every call is output-capped (`num_predict`) and the session is request-capped
    so a runaway loop can't tie up the user's hardware.
  * Failures degrade into typed, actionable errors; the offline lab is untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from .challenges import c01_prompt_injection as _c01
from .challenges import c02_system_prompt_leak as _c02
from .challenges.base import get as get_challenge
from .challenges.base import live_challenges
from .levels import Level, hardening_for, redact_output, screen
from .providers import (
    DEFAULT_ENDPOINT,
    LLMProvider,
    OllamaProvider,
    ProviderError,
    endpoint_allowed,
    normalise_endpoint,
    require_allowed,
)

SUGGESTED_MODELS = [
    {"name": "llama3.2", "note": "3B - fast, easy to jailbreak", "tools": False},
    {"name": "mistral", "note": "7B - classic, permissive", "tools": False},
    {"name": "llama3.1", "note": "8B - supports tool-calling", "tools": True},
    {"name": "qwen2.5", "note": "7B - supports tool-calling", "tools": True},
]


LiveError = ProviderError


@dataclass
class LiveResult:
    text: str
    solved: bool
    model: str
    endpoint: str
    input_tokens: int = 0
    output_tokens: int = 0
    refused_by_guard: bool = False
    refusal_reason: str | None = None
    tool_calls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# --- scenarios -------------------------------------------------------------
# Derived from the challenge registry: a challenge that declares a LiveAdapter
# is a live scenario. Nothing about it is restated here.


def scenario(challenge_id: str):
    challenge = get_challenge(challenge_id)
    if challenge is None or challenge.live is None:
        return None
    return challenge


def scenario_public(challenge) -> dict:
    pub = challenge.public()
    return {
        "id": challenge.id,
        "title": challenge.title,
        "owasp": challenge.owasp,
        "goal": challenge.live.goal or challenge.goal,
        "needs_tools": bool(challenge.live.tools),
        "theme": pub.get("theme", {}),
        "fields": pub["fields"],
    }


def list_scenarios() -> list[dict]:
    return [scenario_public(c) for c in live_challenges()]


def provider_for(conn) -> LLMProvider:
    return OllamaProvider(endpoint=conn.endpoint)


def list_models(endpoint: str) -> list[str]:
    return OllamaProvider(endpoint=endpoint).models()


def run_live(scenario_id: str, level: Level, fields: dict, conn) -> LiveResult:
    challenge = scenario(scenario_id)
    if challenge is None:
        raise LiveError("unknown_scenario", "That scenario is not available in Live Mode.")

    adapter = challenge.live
    system, user, screen_blocks = adapter.build(fields, level)

    # Reuse the exact offline input guard (blocklist) for medium/high.
    refused, reason, _ = screen(screen_blocks, level)
    if refused:
        return LiveResult(
            text="I can't help with that request.",
            solved=False,
            model=conn.model,
            endpoint=conn.endpoint,
            refused_by_guard=True,
            refusal_reason=reason,
            notes=["Blocked by the app-level content filter before reaching the model."],
        )

    reply = provider_for(conn).chat(conn.model, system, user, adapter.tools)
    text, tool_calls = reply.text, reply.tool_calls

    solved = adapter.success(text, tool_calls)
    secrets = [_c01.SECRET, _c02.MARKER]
    display = redact_output(text, level, secrets)

    notes = ["Local model output is non-deterministic - results may vary per run."]
    if adapter.tools:
        if tool_calls:
            notes.append("Tool calls emitted by the model: " + ", ".join(tool_calls))
        else:
            notes.append(
                "The model returned no tool calls. If it never does, it may not "
                "support tool-calling - try llama3.1 or qwen2.5."
            )
    if solved and display != text:
        notes.append(
            "The model leaked it, but the output redactor caught the literal value. "
            "Coax it into an encoded/transformed form to defeat that layer."
        )

    return LiveResult(
        text=display,
        solved=solved,
        model=conn.model,
        endpoint=conn.endpoint,
        input_tokens=reply.input_tokens,
        output_tokens=reply.output_tokens,
        tool_calls=tool_calls,
        notes=notes,
    )

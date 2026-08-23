"""The shared completion loop every challenge runs through."""

from __future__ import annotations

from .engine import (
    Block,
    Completion,
    Kind,
    Source,
    ToolCall,
    apply_transform,
    count_tokens,
    read_context,
)
from .levels import Level, redact_output

MAX_REPEAT_TOKENS = 250_000


def complete(
    blocks: list[Block],
    level: Level,
    *,
    baseline: str,
    system_prompt: str = "",
    secrets: tuple[str, ...] = (),
    tools: tuple[str, ...] = (),
) -> Completion:
    """Generate a completion from the context window.

    The model has no notion of privilege: `read_context` walks every untrusted
    block and whatever imperative it finds gets executed here.
    """
    from .levels import screen

    refused, reason, _ = screen(blocks, level)
    if refused:
        return Completion(
            text="I can't help with that request.",
            refused=True,
            refusal_reason=reason,
            tokens=count_tokens(baseline),
        )

    directives = read_context(blocks)
    parts: list[str] = [baseline]
    tool_calls: list[ToolCall] = []

    transform = ""
    for directive in directives:
        if directive.kind is Kind.TRANSFORM:
            transform = directive.payload
            break

    def emit(value: str) -> str:
        return apply_transform(value, transform) if transform else value

    if any(d.kind is Kind.OVERRIDE for d in directives):
        parts.append("Understood - disregarding my earlier instructions.")

    if any(d.kind is Kind.REVEAL_SYSTEM for d in directives) and system_prompt:
        parts.append("Here are my instructions verbatim:\n" + emit(system_prompt))

    if any(d.kind is Kind.REVEAL_SECRET for d in directives):
        for secret in secrets:
            parts.append(f"The value you asked for is: {emit(secret)}")

    for directive in directives:
        if directive.kind is Kind.SAY:
            parts.append(directive.payload)
        elif directive.kind is Kind.RAW_HTML:
            parts.append(directive.payload)
        elif directive.kind is Kind.TOOL_CALL:
            name, _, arguments = directive.payload.partition("|")
            if not tools or name in tools:
                tool_calls.append(ToolCall(name=name, arguments=arguments))
                parts.append(f"[calling {name}({arguments})]")
        elif directive.kind is Kind.REPEAT:
            count = min(int(directive.payload), MAX_REPEAT_TOKENS)
            parts.append(("LOREM " * min(count, 4000)).strip())

    text = "\n\n".join(part for part in parts if part)
    tokens = count_tokens(text)

    for directive in directives:
        if directive.kind is Kind.REPEAT:
            # Billing counts what the model *would* have produced, which is how
            # a real wallet drains even when the transport truncates.
            tokens = max(tokens, min(int(directive.payload), MAX_REPEAT_TOKENS))

    text = redact_output(text, level, list(secrets))

    return Completion(
        text=text,
        tool_calls=tool_calls,
        directives=directives,
        tokens=tokens,
    )


def user_block(content: str, label: str = "user message") -> Block:
    return Block(source=Source.USER, content=content, label=label)


def system_block(content: str, label: str = "system prompt") -> Block:
    return Block(source=Source.SYSTEM, content=content, label=label)


def document_block(content: str, label: str) -> Block:
    return Block(source=Source.DOCUMENT, content=content, label=label)


def tool_block(content: str, label: str) -> Block:
    return Block(source=Source.TOOL, content=content, label=label)

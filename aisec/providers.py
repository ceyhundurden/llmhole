from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlparse

import httpx

DEFAULT_ENDPOINT = os.getenv("AISEC_OLLAMA_ENDPOINT", "http://localhost:11434").rstrip("/")

ALLOWED_LLM_HOSTS = {
    h.strip().lower()
    for h in os.getenv(
        "AISEC_ALLOWED_LLM_HOSTS", "localhost,127.0.0.1,::1,host.docker.internal"
    ).split(",")
    if h.strip()
}
ALLOWED_LLM_PORTS = {
    int(p) for p in os.getenv("AISEC_ALLOWED_LLM_PORTS", "11434").split(",") if p.strip()
}

MAX_TOKENS_PER_CALL = 512


class ProviderError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class ChatReply:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: list[str] = field(default_factory=list)


class LLMProvider(Protocol):
    name: str
    endpoint: str

    def chat(
        self, model: str, system: str, user: str, tools: list | None = None
    ) -> ChatReply: ...

    def models(self) -> list[str]: ...


def normalise_endpoint(endpoint: str) -> str:
    endpoint = (endpoint or "").strip() or DEFAULT_ENDPOINT
    if not re.match(r"^https?://", endpoint, re.I):
        endpoint = "http://" + endpoint
    return endpoint.rstrip("/")


def endpoint_allowed(endpoint: str) -> bool:
    try:
        parsed = urlparse(normalise_endpoint(endpoint))
    except ValueError:
        return False
    host = (parsed.hostname or "").lower().strip("[]")
    port = parsed.port or 11434
    return (
        parsed.scheme in ("http", "https")
        and host in ALLOWED_LLM_HOSTS
        and port in ALLOWED_LLM_PORTS
    )


def require_allowed(endpoint: str) -> None:
    if endpoint_allowed(endpoint):
        return
    raise ProviderError(
        "endpoint_not_allowed",
        "That endpoint host is not in the allow-list "
        f"({', '.join(sorted(ALLOWED_LLM_HOSTS))}). Set AISEC_ALLOWED_LLM_HOSTS "
        "to permit another host.",
    )


def _unreachable() -> ProviderError:
    return ProviderError(
        "ollama_unreachable",
        "Could not reach Ollama. Is 'ollama serve' running and the model "
        "pulled? Try: ollama pull llama3.",
    )


def _safe_json(response) -> dict:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _http_post(url: str, payload: dict, timeout: float = 120.0):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.post(url, json=payload)
        return response.status_code, _safe_json(response)
    except httpx.HTTPError as exc:
        raise _unreachable() from exc


def _http_get(url: str, timeout: float = 8.0):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            response = client.get(url)
        return response.status_code, _safe_json(response)
    except httpx.HTTPError as exc:
        raise _unreachable() from exc


def _raise_ollama_error(status: int, body: dict, with_tools: bool) -> None:
    err = str(body.get("error", "")) if isinstance(body, dict) else ""
    low = err.lower()
    if "not found" in low or status == 404:
        raise ProviderError(
            "model_not_found",
            f"Ollama does not have that model. Pull it first: ollama pull <model>. ({err})",
        )
    if with_tools and ("tool" in low or "function" in low):
        raise ProviderError(
            "tool_unsupported",
            "This model does not support tool-calling. Try a tool-capable model "
            "such as llama3.1 or qwen2.5.",
        )
    raise ProviderError("provider_error", "The model server returned an error.")


@dataclass
class OllamaProvider:
    endpoint: str = DEFAULT_ENDPOINT
    name: str = "ollama"

    def __post_init__(self):
        self.endpoint = normalise_endpoint(self.endpoint)

    def chat(
        self, model: str, system: str, user: str, tools: list | None = None
    ) -> ChatReply:
        require_allowed(self.endpoint)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"num_predict": MAX_TOKENS_PER_CALL},
        }
        if tools:
            payload["tools"] = tools

        status, body = _http_post(f"{self.endpoint}/api/chat", payload)
        if status != 200:
            _raise_ollama_error(status, body, bool(tools))

        message = body.get("message", {}) or {}
        return ChatReply(
            text=message.get("content", "") or "",
            input_tokens=body.get("prompt_eval_count", 0),
            output_tokens=body.get("eval_count", 0),
            tool_calls=[
                tc.get("function", {}).get("name", "")
                for tc in (message.get("tool_calls") or [])
            ],
        )

    def models(self) -> list[str]:
        require_allowed(self.endpoint)
        status, body = _http_get(f"{self.endpoint}/api/tags")
        if status != 200:
            raise ProviderError("provider_error", "The model server returned an error.")
        return sorted(m.get("name", "") for m in body.get("models", []) if m.get("name"))

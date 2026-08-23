"""Regression tests for the lab's *own* infrastructure - the bugs that are NOT
part of the intentional curriculum. These lock the fixes from the security
review so a real vulnerability can't hide behind an intentional one.
"""

import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from aisec import live_engine
from aisec.flags import flag_for, level_key
from aisec.main import app
from aisec.state import MAX_BUCKET_ITEMS, Session

client = TestClient(app)
REPO_ROOT = Path(__file__).resolve().parent.parent


# --- SSRF: outbound LLM calls are host-allow-listed ------------------------

def test_endpoint_allow_list_accepts_local_and_rejects_external():
    assert live_engine.endpoint_allowed("http://localhost:11434")
    assert live_engine.endpoint_allowed("http://host.docker.internal:11434")
    assert not live_engine.endpoint_allowed("http://169.254.169.254")  # cloud metadata
    assert not live_engine.endpoint_allowed("http://evil.example:11434")
    assert not live_engine.endpoint_allowed("http://internal.corp.local")


def test_endpoint_allow_list_pins_the_port():
    # An allow-listed host on a non-Ollama port must still be refused, so the
    # server can't be used to port-scan the host machine.
    assert not live_engine.endpoint_allowed("http://host.docker.internal:22")
    assert not live_engine.endpoint_allowed("http://localhost:8000")
    assert live_engine.endpoint_allowed("http://localhost:11434")


def test_provider_error_message_hides_status_code():
    import pytest

    with pytest.raises(live_engine.LiveError) as exc:
        live_engine._raise_ollama_error(503, {}, with_tools=False)
    assert exc.value.kind == "provider_error"
    assert "503" not in exc.value.message


def test_multiturn_history_is_capped():
    from aisec.challenges import get
    from aisec.challenges.base import Attempt
    from aisec.levels import Level
    from aisec.state import MAX_BUCKET_ITEMS

    ch = get("multiturn-trust")
    s = Session(id="mt-cap")
    for i in range(MAX_BUCKET_ITEMS + 20):
        ch.handler(Attempt(Level.LOW, {"conversation": "continue", "message": f"m{i}"}), s)
    assert len(s.bucket("c08_history")) <= MAX_BUCKET_ITEMS


def test_models_endpoint_refuses_disallowed_host():
    r = client.get("/api/live/models?endpoint=http://169.254.169.254/latest/meta-data")
    assert r.json()["error"]["kind"] == "endpoint_not_allowed"


def test_connect_refuses_disallowed_host():
    r = client.post("/api/live/connect", json={"endpoint": "http://evil.example", "model": "x"})
    assert r.json()["error"]["kind"] == "endpoint_not_allowed"


def test_upstream_body_is_not_reflected():
    # Non-JSON upstream response must not leak back to the caller.
    class _Resp:
        text = "SECRET INTERNAL PAGE CONTENTS"

        def json(self):
            raise ValueError("not json")

    assert live_engine._safe_json(_Resp()) == {}


# --- session memory is bounded ---------------------------------------------

def test_bucket_is_capped():
    s = Session(id="x")
    for i in range(MAX_BUCKET_ITEMS + 5):
        ok = s.append_capped("kb", i)
        if i >= MAX_BUCKET_ITEMS:
            assert ok is False
    assert len(s.bucket("kb")) == MAX_BUCKET_ITEMS


def test_expired_sessions_are_pruned(monkeypatch):
    import aisec.state as state

    import time

    state._SESSIONS.clear()
    monkeypatch.setattr(state, "SESSION_TTL_SECONDS", 5)
    old = state.get_or_create(None)
    old.last_seen = time.time() - 60  # age it past the TTL
    # A fresh get_or_create prunes the now-stale previous session.
    state.get_or_create(None)
    assert old.id not in state._SESSIONS


# --- Live flag can actually be verified (was a broken feature) -------------

def test_live_flag_verifies_only_on_live_plane():
    flag = flag_for("prompt-injection", level_key("low", "live"))
    ok = client.post(
        "/api/challenges/prompt-injection/verify",
        json={"level": "low", "plane": "live", "flag": flag},
    )
    assert ok.json()["valid"] is True
    # The same flag must NOT validate as an offline flag.
    bad = client.post(
        "/api/challenges/prompt-injection/verify",
        json={"level": "low", "plane": "offline", "flag": flag},
    )
    assert bad.json()["valid"] is False


# --- CTF mode fails fast on the default secret -----------------------------

def test_ctf_mode_rejects_default_secret():
    env = dict(os.environ)
    env["AISEC_CTF_MODE"] = "1"
    env.pop("AISEC_FLAG_SECRET", None)
    r = subprocess.run(
        [sys.executable, "-c", "import aisec.flags"],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode != 0
    assert "AISEC_FLAG_SECRET" in r.stderr


def test_ctf_mode_starts_with_a_custom_secret():
    env = dict(os.environ)
    env["AISEC_CTF_MODE"] = "1"
    env["AISEC_FLAG_SECRET"] = "a-unique-ctf-secret"
    r = subprocess.run(
        [sys.executable, "-c", "import aisec.flags; print('ok')"],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert r.returncode == 0 and "ok" in r.stdout

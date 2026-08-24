# Security policy & scope contract

LLMHole is **intentionally vulnerable** — that is the product. This document
draws the one line that matters: which weaknesses are the *curriculum* (keep
them, they are the point) and which would be *real* bugs in the lab's own
infrastructure (these must stay fixed). The regression suite in
[`tests/test_out_of_scope.py`](tests/test_out_of_scope.py) enforces the second
column so an accidental vulnerability can never hide behind an intentional one.

## In scope — intentional, do NOT "fix"

These are the lessons. They live behind the offline mock engine and the Live
Arena scenarios and are exercised by the test suite.

| Lesson | Where |
|--------|-------|
| Direct & indirect prompt injection | `challenges/c01`, `c03` |
| System-prompt leakage & elicitation | `challenges/c02` |
| RAG / knowledge-base poisoning | `challenges/c04` |
| Insecure output handling (XSS payload generation) | `challenges/c05` |
| Excessive agency (dangerous tool calls) | `challenges/c06` |
| Unbounded consumption | `challenges/c07` |
| Multi-turn trust building | `challenges/c08` |
| Deliberately weak "defenses" (blocklists, redaction) | `levels.py` |

The intentional XSS payload a model produces is **rendered only inside a
`sandbox="allow-scripts"` iframe with no same-origin access** — the payload
fires as a demonstration but cannot touch the lab page.

## Out of scope — real bugs, keep them fixed

Infrastructure of the lab itself. A regression here is a genuine vulnerability.

| Real bug class | Control | Test |
|----------------|---------|------|
| Server-side request forgery via the Live endpoint | Host allow-list (`LLMHOLE_ALLOWED_LLM_HOSTS`), no redirects, upstream body never reflected | `test_endpoint_allow_list_*`, `test_upstream_body_is_not_reflected` |
| Predictable default flag secret | `LLMHOLE_CTF_MODE=1` fails fast on the default secret | `test_ctf_mode_*` |
| Reference solutions exposed during a CTF | Off by default when `LLMHOLE_CTF_MODE=1` | — |
| Container exposed to the network by default | Compose binds `127.0.0.1`; read-only rootfs, dropped caps, no-new-privileges, mem/pids limits | — |
| Unintended DOM XSS (model names) | All model-name output is HTML-escaped | — |
| Unbounded session memory (DoS) | Session TTL + count cap + per-bucket cap; the Live connection table is capped and pruned too | `test_bucket_is_capped`, `test_expired_sessions_are_pruned`, `test_live_conns_are_pruned` |
| Live request cap bypassable by reconnecting | `set_conn` carries the spent budget over | `test_live_request_cap_is_not_reset_by_reconnecting` |
| Live flags un-verifiable | Namespaced flag keys (`level_key`) verify per plane | `test_live_flag_verifies_only_on_live_plane` |

## Hardening knobs

| Env var | Default | Purpose |
|---------|---------|---------|
| `LLMHOLE_BIND` | `127.0.0.1` | Interface the container publishes on |
| `LLMHOLE_CTF_MODE` | `0` | Fail fast on default secret; hide solutions |
| `LLMHOLE_FLAG_SECRET` | dev default | HMAC key for flags — **must** be set in CTF mode |
| `LLMHOLE_ALLOW_SOLUTIONS` | `1` (`0` in CTF) | Serve reference solutions |
| `LLMHOLE_ALLOWED_LLM_HOSTS` | `localhost,127.0.0.1,::1,host.docker.internal` | SSRF allow-list for Live Mode |
| `LLMHOLE_MAX_SESSIONS` | `5000` | Session table cap |
| `LLMHOLE_SESSION_TTL` | `21600` | Session idle TTL (seconds) |
| `LLMHOLE_MAX_BUCKET_ITEMS` | `200` | Per-session scratch bucket cap |
| `LLMHOLE_MAX_LIVE_REQUESTS` | `100` | Live Mode attempts per session (survives reconnect) |
| `LLMHOLE_MAX_LIVE_CONNS` / `LLMHOLE_LIVE_CONN_TTL` | `1000` / `21600` | Live connection table cap and idle TTL |

## Reporting

Found a bug in the **out-of-scope** column (i.e. a real one)? Open an issue that
names the file and shows the failing case. Please do not report the intentional
lessons — those are working as designed.

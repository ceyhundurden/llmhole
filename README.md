# AISEC Lab

A deliberately vulnerable **AI / LLM application** you attack in the browser —
the same idea as [bWAPP](http://www.itsecgames.org/) or DVWA, but the target is
an AI system instead of a classic web app. Pick a challenge, pick a security
level, craft a payload, and watch it land.

> ⚠️ **Intentionally insecure.** Run it locally only. Never expose it to the
> public internet or point it at real data or real model credentials.

## Why this exists

Web-app security has bWAPP. AI security did not have an equivalent playground
that runs offline, for free, deterministically. AISEC Lab fills that gap: every
challenge is a real class of LLM vulnerability from the
**OWASP LLM Top 10 (2025)**, reproduced against a mock model so the attack is
repeatable and needs no API key.

## The mock model (the whole trick)

There is no real LLM and no network call. `aisec/engine.py` is a small,
deliberately *gullible* interpreter that behaves like a badly-built LLM app: it
reads **every block in its context window** — system prompt, your message,
retrieved documents, tool output — extracts anything that looks like an
instruction, and **obeys it regardless of where it came from**. That missing
trust boundary is the root cause behind most of the OWASP LLM Top 10, so the lab
reproduces it faithfully and cheaply.

## Challenges

| # | Challenge | OWASP | What you exploit |
|---|-----------|-------|------------------|
| 1 | Direct Prompt Injection | LLM01 | Override a system prompt to leak a secret coupon |
| 2 | System Prompt Leakage | LLM07 | Extract a hidden configuration block |
| 3 | Indirect Prompt Injection | LLM01 | Plant instructions in a *fetched page* the model summarises |
| 4 | Knowledge Base Poisoning | LLM04 | Poison a RAG index so answers point at your URL |
| 5 | Insecure Output Handling | LLM05 | Get executable HTML/JS (stored XSS) through the model |
| 6 | Excessive Agency | LLM06 | Make an email agent call a dangerous tool from inbox content |
| 7 | Unbounded Consumption | LLM10 | Force a single request to blow the token/cost budget |

## Security levels

Every challenge ships three levels, in the bWAPP tradition. **None of them is a
correct defence** — each is a real pattern shipped in production apps, complete
with its real failure mode.

- **low** — no filtering. Learn the attack primitive.
- **medium** — a keyword blocklist on *your message only*; retrieved content is
  trusted implicitly and any encoding defeats the string match.
- **high** — the blocklist covers every untrusted block *and* the output is
  scanned for verbatim secrets. Still defeatable: the filter runs on raw bytes
  while the model normalises (unicode / leetspeak / base64 / rot13) afterwards,
  and secrets can be smuggled out reversed, spaced, or base64-encoded.

Solve a level and you get a signed **flag** (`AISEC{...}`) and points
(low 10 / medium 25 / high 50), tracked per session for a mini scoreboard.

## Run it

### Docker (recommended)

```bash
docker build -t aisec-lab .
docker run --rm -p 8000:8000 aisec-lab
```

Open <http://localhost:8000>.

### Local (Python 3.12+)

```bash
pip install -r requirements-dev.txt
uvicorn aisec.main:app --reload
```

### Tests

```bash
pytest -q
```

The suite proves every reference exploit still solves its level and that the
guardrails still bite where they should — so the lab stays exploitable *and*
non-trivial as it changes.

## API

The UI is a thin client over a small JSON API:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/challenges` | Catalogue + your solved levels + score |
| GET | `/api/challenges/{id}` | One challenge |
| POST | `/api/challenges/{id}/attempt` | Run an attack (`{level, fields}`) |
| POST | `/api/challenges/{id}/verify` | Submit a flag for points |
| GET | `/api/hint/{id}?level=N` | Progressive hints |
| GET | `/api/solution/{id}` | Reference exploits (disable with `AISEC_ALLOW_SOLUTIONS=0`) |
| GET | `/api/scoreboard` | Session score |
| POST | `/api/reset` | Wipe your session |

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `AISEC_FLAG_SECRET` | `aisec-lab-default-secret` | HMAC key for flags; rotate for CTF hosting |
| `AISEC_ALLOW_SOLUTIONS` | `1` | Set to `0` to hide the reference solutions |

## Project layout

```
aisec/
  engine.py       the gullible mock model + directive extraction
  levels.py       the three security levels and their (broken) guardrails
  runtime.py      the shared completion loop
  flags.py        deterministic signed flags + scoring
  state.py        in-memory per-session score and scratch space
  main.py         FastAPI app + JSON API
  challenges/     one module per vulnerability
  static/         single-page UI
tests/            engine unit tests + per-challenge solve/guardrail tests
```

## Adding a challenge

1. Add `aisec/challenges/cNN_your_thing.py` with a `handler(attempt, session)`
   that builds a context window, calls `runtime.complete(...)`, and sets
   `Result.solved`.
2. `register(Challenge(...))` with fields, hints, and a reference `solution` per
   level.
3. Import it in `aisec/challenges/__init__.py`.
4. The parametrised test in `tests/test_challenges.py` will automatically check
   that your reference solutions solve every level.

## Disclaimer

For education and authorised training only. The vulnerabilities here are real;
that is the point. Keep it off the public internet.

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
| 8 | Multi-Turn Trust Building | LLM01 | Split an attack across turns to beat a per-message classifier |

When an attack lands, the model "gives in" with a randomly chosen confession
line before leaking — the payload that follows stays deterministic, so scoring
is unaffected while the solve feels earned.

## Security levels

Every challenge ships four levels, in the bWAPP tradition. **None of them is a
correct defence** — each is a real pattern shipped in production apps, complete
with its real failure mode.

- **low** — no filtering. Learn the attack primitive.
- **medium** — a keyword blocklist on *your message only*; retrieved content is
  trusted implicitly and any encoding defeats the string match.
- **high** — the blocklist covers every untrusted block *and* the output is
  scanned for verbatim secrets. Still defeatable: the filter runs on raw bytes
  while the model normalises (unicode / leetspeak / base64 / rot13) afterwards,
  and secrets can be smuggled out reversed, spaced, or base64-encoded.
- **very-high** — a *semantic intent guard*, not a keyword list. It normalises
  every encoding first, then blocks the **intent** to override instructions or
  extract secrets. Changing the encoding no longer helps — so you have to change
  strategy. Against the injection challenges this kills the "ignore/reveal"
  vector and pushes you toward **elicitation** (bait the model into *completing*
  a line whose continuation is the secret) — which is closer to how real LLM01
  attacks actually work.

Solve a level and you get a signed **flag** (`AISEC{...}`) and points
(low 10 / medium 25 / high 50 / very-high 80), tracked per session for a mini
scoreboard.

## Installation

Self-hosted, like bWAPP/DVWA — you run it in **your own** environment.

**Prerequisites** — either path works:
- **Docker** (recommended): Docker Engine / Docker Desktop with Compose v2.
- **or Python 3.12+** if you'd rather run it without Docker.
- **Optional:** [Ollama](https://ollama.com) — only needed for the Live Arena
  (a real local model). The default lab is fully offline and needs nothing else.

**1. Get the code**

```bash
git clone https://github.com/ceyhundurden/aisec-lab.git
cd aisec-lab
cp .env.example .env      # optional: change the port / flag secret / bind
```

**2a. Run with Docker (recommended)**

```bash
docker compose up --build
```

**2b. Or run with Python**

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn aisec.main:app --reload
```

Open <http://localhost:8000> (or the `AISEC_PORT` you set) and start with the
**Practice** tab — no key, no internet.

**3. (Optional) Enable Live Arena**

```bash
ollama pull llama3.2      # a small, easy-to-jailbreak model
ollama serve              # usually already running
```

Then open the **Live Arena** tab, keep the pre-filled endpoint, pick your model,
Connect. See [Live Mode](#live-mode-optional--a-local-model-via-ollama) for the
Docker networking note and model suggestions.

**Run the tests**

```bash
pytest -q
```

The test suite proves every reference exploit still solves its level and that
the guardrails still bite where they should — so the lab stays exploitable *and*
non-trivial as it changes.

## Live Mode (optional — a local model via Ollama)

Everything above runs offline against a deterministic mock model. **Live Mode**
is a separate, opt-in tab that runs a subset of the same challenges against a
*real* model — running entirely on **your own machine** via
[Ollama](https://ollama.com). Feel yourself talking an actual LLM into
misbehaving, with no internet and no API key.

- **Fully local, no internet, no key.** Once you've pulled a model, requests go
  to `http://localhost:11434` and never leave your box. There are no credentials
  anywhere and nothing to leak.
- **You run the model.** Install Ollama, then:
  ```bash
  ollama pull llama3.2      # or mistral, llama3.1, qwen2.5, ...
  ollama serve              # usually already running
  ```
  In the Live Arena tab, keep the default endpoint, type the model name, Connect.
- **Bounded by design.** Every call is output-capped (`num_predict=512`) and the
  session has a request cap so a runaway loop can't tie up your hardware.
- **Non-deterministic.** A real model may refuse, comply, or vary between runs —
  a flag may not appear on every attempt. That variance *is* the exercise, and
  the success check is deliberately whitespace/case-tolerant to catch reshaped
  answers.

Live scenarios: direct prompt injection, system-prompt leakage, indirect
injection, insecure output handling, and — via real tool-calling — excessive
agency. **Unbounded Consumption is demonstration-only in Live Mode**: it is never
sent to a real model (forcing a model to emit a huge response is precisely the
resource-exhaustion attack it teaches), so it runs against the offline engine.

If Ollama isn't running or the model isn't pulled, Live Mode returns a clear,
actionable error and the offline lab is completely unaffected.

The endpoint is **pre-filled for you**: `docker compose up` ships
`AISEC_OLLAMA_ENDPOINT=http://host.docker.internal:11434` (the host's Ollama as
seen from inside the container, mapped for Linux too), and a bare `uvicorn` run
defaults to `http://localhost:11434`. Override it with `AISEC_OLLAMA_ENDPOINT`
in `.env` if your Ollama lives elsewhere.

Click **↻ Installed** next to the model field to list the models actually pulled
in your Ollama and pick one — or type any model name you've pulled
(`ollama pull mistral`, `ollama pull qwen2.5`, …).

### Which model?

Smaller, lightly safety-tuned models suit the lab best — they are cheaper to run
*and* easier to talk into misbehaving, which is the whole point.

| Your RAM | Suggested model | Notes |
|----------|-----------------|-------|
| ~8 GB    | `llama3.2` (3B), `mistral` (7B) | Fast, permissive, easy first solves |
| ~16 GB   | `llama3.1` (8B), `qwen2.5` (7B) | Support **tool-calling** (needed for Excessive Agency) |
| 32 GB+   | 13B+ variants | More coherent, a bit harder to jailbreak |

The Excessive Agency scenario needs a **tool-capable** model (e.g. `llama3.1`,
`qwen2.5`). If a model can't do tool-calling, Live Mode says so and points you at
one that can.

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
| GET | `/api/live/providers` | Live Mode: provider (Ollama) + suggested models |
| GET | `/api/live/scenarios` | Live Mode: scenario catalogue |
| POST/DELETE | `/api/live/connect` | Set / clear the local endpoint + model |
| GET | `/api/live/status` | Connection + remaining requests |
| POST | `/api/live/challenges/{id}/attempt` | Run against the local model |
| POST | `/api/live/demo/{id}/attempt` | Offline demo (Unbounded Consumption) |

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `AISEC_FLAG_SECRET` | dev default | HMAC key for flags; **required** in CTF mode |
| `AISEC_ALLOW_SOLUTIONS` | `1` (`0` in CTF) | Set to `0` to hide the reference solutions |
| `AISEC_CTF_MODE` | `0` | Fail fast on the default secret; hide solutions |
| `AISEC_BIND` | `127.0.0.1` | Interface the container publishes on |
| `AISEC_ALLOWED_LLM_HOSTS` | `localhost,127.0.0.1,::1,host.docker.internal` | SSRF allow-list for Live Mode |
| `AISEC_MAX_SESSIONS` / `AISEC_SESSION_TTL` / `AISEC_MAX_BUCKET_ITEMS` | `5000` / `21600` / `200` | Session memory bounds |

## Security & scope

The lab is vulnerable **on purpose**, but its own infrastructure is not.
[`SECURITY.md`](SECURITY.md) draws the line between the intentional lessons
(keep them) and real bugs in the lab itself (SSRF, predictable flag secret,
network exposure, unbounded memory, …), each locked by
[`tests/test_out_of_scope.py`](tests/test_out_of_scope.py). Hosting a CTF? Set a
unique `AISEC_FLAG_SECRET` and `AISEC_CTF_MODE=1`. The Docker image binds to
loopback, runs read-only with dropped capabilities, and only reaches
allow-listed LLM hosts.

## Project layout

```
aisec/
  engine.py       the gullible mock model + directive extraction (incl. elicitation)
  persona.py      randomised confession lines for landed attacks
  levels.py       the four security levels and their (broken) guardrails
  runtime.py      the shared completion loop
  flags.py        deterministic signed flags + scoring
  state.py        in-memory per-session score and scratch space
  main.py         FastAPI app + JSON API
  live_engine.py  OPTIONAL Live Mode: local Ollama client (httpx)
  live_state.py   in-memory endpoint/model + request cap (never persisted)
  live_routes.py  /api/live/* router
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

## License

Licensed under the [Apache License 2.0](LICENSE) — see [NOTICE](NOTICE) for the
attribution and the intentionally-vulnerable warning that must travel with any
redistribution.

A licence grants permission; it does not police behaviour. The real guardrails
around this project are the **run-it-locally-only** warning above and the scope
contract in [SECURITY.md](SECURITY.md) — that document is what tells you (and
any contributor) which weaknesses are the curriculum and which would be genuine
bugs. Read it before you deploy, fork, or file an issue.

## Disclaimer

For education and authorised training only. The vulnerabilities here are real;
that is the point. Keep it off the public internet.

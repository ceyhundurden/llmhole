# House style

How code in this repo is written. This describes what the code actually does —
if you find a file that disagrees, the file is wrong.

## Comments and docstrings

This is a teaching repo, so prose earns its place: **a module docstring on every
module** saying what it is and why it exists, and inline comments wherever the
code encodes a deliberate security decision that would otherwise look like a
bug. The intentional weaknesses in `llmhole/policy.py`, `engine.py` and
`challenges/` are the clearest examples — without a comment, a future reader
"fixes" the lesson.

What not to write: comments that restate the code, or a docstring on a helper
whose name already says everything (`_blk`, `squash`, `emit`). Newer,
mechanical modules (`flags.py`, `live_state.py`) are deliberately bare for that
reason.

## Python

- Guard clauses first, early `return` / `raise`, no `else` after a return.
- Private helpers are module-level and `_`-prefixed. Keep them small.
- Constants UPPER at the top of the file.
- Type hints on signatures; skip the obvious locals.
- Comprehensions, tuple-unpacking, `dict.get` where they read better.
- Short locals when the meaning is local and obvious (`r`, `c`, `s`, `n`).
- Imports at module level; `ruff` enforces this (PLC0415). A function-body
  import usually means a dependency cycle — fix the cycle instead. The one
  legitimate exception is guarding an *optional* dependency, and it carries a
  `# noqa: PLC0415` plus the reason.

## JavaScript

- IIFE per file, `const` / `let`, arrow functions.
- Early returns; ternaries over `if/else` for one-liners.
- Template literals; a `$` / `el` micro-helper pair at the top.
- **Escape anything that came over the network before it touches `innerHTML`.**
  Prefer `textContent`; reach for `innerHTML` only with `esc()`.

## Tests

- `tests/test_out_of_scope.py` guards the lab's own infrastructure. A test there
  is a claim in `SECURITY.md` made executable — add one whenever you fix a real
  bug, so an intentional weakness can never hide an accidental one.

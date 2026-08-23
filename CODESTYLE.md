# ceyhun style

House style for new code in this repo. Not retrofitted onto old files.

## Python
- No docstrings, no inline comments. Names carry the meaning.
- Guard clauses first, early `return` / `raise`, no `else` after a return.
- Private helpers are module-level and `_`-prefixed. Keep them small.
- Constants live UPPER at the top of the file.
- Lean type hints on signatures only; skip the obvious locals.
- Reach for comprehensions, tuple-unpacking, `dict.get`, walrus when it reads.
- Short locals when the meaning is local and obvious (`r`, `c`, `s`, `n`).
- One blank line between defs, none inside a tight block.

## JavaScript
- IIFE per file, `const`/`let`, arrow functions, no comments.
- Early returns; ternaries over `if/else` for one-liners.
- Template literals; a `$`/`el` micro-helper pair at the top.
- Escape anything from the network before it touches `innerHTML`.

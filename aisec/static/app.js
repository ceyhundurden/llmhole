"use strict";

const state = {
  challenges: [],
  levels: [],
  current: null,
  level: "low",
  hintIndex: 0,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...opts,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function loadCatalogue() {
  const data = await api("/api/challenges");
  state.challenges = data.challenges;
  state.levels = data.levels;
  $("#score").textContent = data.score;
  renderList();
}

function renderList() {
  const list = $("#challenge-list");
  list.innerHTML = "";
  for (const c of state.challenges) {
    const item = el("li", "chal-item");
    if (state.current && c.id === state.current.id) item.classList.add("active");
    const top = el("div", "ci-top");
    top.appendChild(el("span", "ci-name", c.title));
    top.appendChild(el("span", "ci-owasp", c.owasp));
    item.appendChild(top);
    const solved = (c.solved || []).length
      ? "solved: " + c.solved.join(", ")
      : "";
    item.appendChild(el("div", "ci-solved", solved));
    item.addEventListener("click", () => selectChallenge(c.id));
    list.appendChild(item);
  }
}

async function selectChallenge(id) {
  const c = await api(`/api/challenges/${id}`);
  state.current = c;
  state.level = "low";
  state.hintIndex = 0;
  renderList();
  renderChallenge();
}

function renderChallenge() {
  const c = state.current;
  $("#empty").hidden = true;
  $("#challenge").hidden = false;
  $("#result").hidden = true;
  $("#hint").hidden = true;
  $("#solution").hidden = true;

  $("#owasp").textContent = c.owasp;
  $("#difficulty").textContent = c.difficulty;
  $("#title").textContent = c.title;
  $("#summary").textContent = c.summary;
  $("#goal").textContent = c.goal;

  const levels = $("#levels");
  levels.innerHTML = "";
  for (const lvl of state.levels) {
    const b = el("button", "level-btn", lvl.id);
    b.dataset.lvl = lvl.id;
    b.type = "button";
    if (lvl.id === state.level) b.classList.add("active");
    if ((c.solved || []).includes(lvl.id)) b.classList.add("solved");
    b.addEventListener("click", () => {
      state.level = lvl.id;
      renderChallenge();
    });
    levels.appendChild(b);
  }
  const note = state.levels.find((l) => l.id === state.level);
  $("#level-note").textContent = note ? note.note : "";

  const form = $("#attack-form");
  form.innerHTML = "";
  for (const f of c.fields) {
    const wrap = el("div", "field");
    wrap.appendChild(el("label", null, f.label));
    let input;
    if (f.kind === "textarea") {
      input = el("textarea");
    } else if (f.kind === "select") {
      input = el("select");
      for (const opt of f.options) {
        const o = el("option", null, opt);
        o.value = opt;
        input.appendChild(o);
      }
    } else {
      input = el("input");
      input.type = "text";
    }
    input.name = f.name;
    input.placeholder = f.placeholder || "";
    if (f.default) input.value = f.default;
    wrap.appendChild(input);
    if (f.help) wrap.appendChild(el("div", "fhelp", f.help));
    form.appendChild(wrap);
  }
}

function collectFields() {
  const fields = {};
  for (const input of $("#attack-form").querySelectorAll("[name]")) {
    fields[input.name] = input.value;
  }
  return fields;
}

async function runAttack() {
  const c = state.current;
  if (!c) return;
  const btn = $("#run");
  btn.disabled = true;
  btn.textContent = "Running…";
  try {
    const data = await api(`/api/challenges/${c.id}/attempt`, {
      method: "POST",
      body: JSON.stringify({ level: state.level, fields: collectFields() }),
    });
    renderResult(data);
    if (data.solved) {
      if (typeof data.score === "number") $("#score").textContent = data.score;
      await refreshSolved();
    }
  } catch (e) {
    alert("Request failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run attack";
  }
}

async function refreshSolved() {
  const fresh = await api(`/api/challenges/${state.current.id}`);
  state.current.solved = fresh.solved;
  const cat = state.challenges.find((x) => x.id === state.current.id);
  if (cat) cat.solved = fresh.solved;
  renderList();
  // repaint level buttons' solved marks
  for (const b of $("#levels").querySelectorAll(".level-btn")) {
    b.classList.toggle("solved", (fresh.solved || []).includes(b.dataset.lvl));
  }
}

function renderResult(data) {
  $("#result").hidden = false;
  const verdict = $("#verdict");
  verdict.className = "verdict";
  if (data.refused) {
    verdict.classList.add("refused");
    verdict.textContent = "⛔ Blocked by a guardrail — " + (data.refusal_reason || "");
  } else if (data.solved) {
    verdict.classList.add("solved");
    verdict.textContent =
      "✅ Solved" +
      (data.first_solve ? ` (+${data.awarded} points)` : " (already scored)");
    if (data.flag) {
      const f = el("span", "flag", data.flag);
      verdict.appendChild(f);
    }
  } else {
    verdict.classList.add("failed");
    verdict.textContent = "❌ Not solved yet — the objective was not met.";
  }

  // Model response is rendered as text (safe). For the XSS challenge we ALSO
  // show what a naive app would render, sandboxed in an iframe, to make the
  // point without exposing this page.
  const resp = $("#response");
  resp.textContent = data.response || "(empty)";

  const notes = $("#notes");
  notes.innerHTML = "";
  for (const n of data.notes || []) notes.appendChild(el("div", "note", n));
  if (data.meta && Object.keys(data.meta).length) {
    const metaText = Object.entries(data.meta)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
      .join("  ·  ");
    notes.appendChild(el("div", "note", metaText));
  }

  const ctx = $("#context");
  ctx.innerHTML = "";
  for (const b of data.context || []) {
    const block = el("div", `ctx-block ctx-${b.source}`);
    const head = el("div", "ctx-head");
    head.appendChild(el("span", "ctx-tag", b.source));
    head.appendChild(el("span", null, b.label || ""));
    block.appendChild(head);
    block.appendChild(el("div", "ctx-body", b.content));
    ctx.appendChild(block);
  }

  const dirs = $("#directives");
  dirs.innerHTML = "";
  const all = [...(data.directives || [])];
  if (!all.length && !(data.tool_calls || []).length) {
    dirs.appendChild(
      el("div", "dir-none", "No directives were extracted from untrusted content.")
    );
  } else {
    for (const d of all) {
      const row = el("div", "dir-row");
      row.appendChild(el("span", "dir-kind", d.kind));
      row.appendChild(el("span", "dir-via", d.via));
      row.appendChild(el("span", null, d.payload || d.raw || ""));
      dirs.appendChild(row);
    }
    for (const tc of data.tool_calls || []) {
      const row = el("div", "dir-row");
      row.appendChild(el("span", "dir-kind", "→ tool"));
      row.appendChild(el("span", "dir-via", "call"));
      row.appendChild(el("span", null, `${tc.name}(${tc.arguments})`));
      dirs.appendChild(row);
    }
  }
}

async function showHint() {
  const c = state.current;
  if (!c) return;
  const data = await api(`/api/hint/${c.id}?level=${state.hintIndex}`);
  const h = $("#hint");
  h.hidden = false;
  h.textContent = `Hint ${data.index + 1}/${data.total}: ${data.hint}`;
  state.hintIndex = Math.min(state.hintIndex + 1, data.total - 1);
}

async function showSolution() {
  const c = state.current;
  if (!c) return;
  if (!confirm("Reveal the reference exploit for all three levels?")) return;
  try {
    const data = await api(`/api/solution/${c.id}`);
    const s = $("#solution");
    s.hidden = false;
    s.textContent = Object.entries(data.solution)
      .map(([lvl, sol]) => `[${lvl}]\n${sol}`)
      .join("\n\n");
  } catch (e) {
    alert("Solutions are disabled on this host.");
  }
}

async function resetSession() {
  if (!confirm("Wipe your score and solved state?")) return;
  await api("/api/reset", { method: "POST" });
  await loadCatalogue();
  if (state.current) await selectChallenge(state.current.id);
}

$("#run").addEventListener("click", runAttack);
$("#hint-btn").addEventListener("click", showHint);
$("#solution-btn").addEventListener("click", showSolution);
$("#reset").addEventListener("click", resetSession);

loadCatalogue().catch((e) => alert("Failed to load lab: " + e.message));

"use strict";

// Live Arena - drives the optional /api/live/* endpoints. Completely separate
// from the offline practice lab in app.js.

(function () {
  const live = {
    providers: [],
    scenarios: [],
    scenario: null,
    level: "low",
    connected: false,
  };

  const $ = (s) => document.querySelector(s);
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
    return res.json();
  }

  // --- tab switching -------------------------------------------------------
  function showPractice() {
    $("#tab-practice").classList.add("active");
    $("#tab-live").classList.remove("active");
    $("#practice-view").hidden = false;
    $("#live-view").hidden = true;
  }
  function showLive() {
    $("#tab-live").classList.add("active");
    $("#tab-practice").classList.remove("active");
    $("#practice-view").hidden = true;
    $("#live-view").hidden = false;
    bootstrap();
  }

  let booted = false;
  async function bootstrap() {
    if (booted) return;
    booted = true;
    const [prov, scen] = await Promise.all([
      api("/api/live/providers"),
      api("/api/live/scenarios"),
    ]);
    live.providers = prov.providers || [];
    live.scenarios = scen.scenarios || [];

    const psel = $("#live-provider");
    psel.innerHTML = "";
    for (const p of live.providers) {
      const o = el("option", null, p.label);
      o.value = p.id;
      o.dataset.default = p.default_model;
      psel.appendChild(o);
    }
    psel.addEventListener("change", syncModelPlaceholder);
    syncModelPlaceholder();

    const ssel = $("#live-scenario");
    ssel.innerHTML = "";
    for (const s of live.scenarios) {
      const o = el("option", null, `${s.owasp} · ${s.title}`);
      o.value = s.id;
      ssel.appendChild(o);
    }
    ssel.addEventListener("change", () => selectScenario(ssel.value));

    await refreshStatus();
    if (live.scenarios.length) selectScenario(live.scenarios[0].id);
    $("#live-runner").hidden = false;
  }

  function syncModelPlaceholder() {
    const opt = $("#live-provider").selectedOptions[0];
    if (opt) $("#live-model").placeholder = opt.dataset.default || "(provider default)";
  }

  async function refreshStatus() {
    const s = await api("/api/live/status");
    const box = $("#live-status");
    if (s.connected) {
      live.connected = true;
      box.innerHTML = "";
      box.appendChild(
        el(
          "span",
          "ok",
          `Connected · ${s.provider} · ${s.model} · key ${s.key}`
        )
      );
      box.appendChild(
        el(
          "span",
          "budget",
          `  —  ${s.remaining_requests} requests / ${s.remaining_tokens} tokens left`
        )
      );
    } else {
      live.connected = false;
      box.textContent = "Not connected. Connect a key to run live scenarios.";
    }
  }

  async function connect() {
    const key = $("#live-key").value.trim();
    if (!key) {
      alert("Enter an API key.");
      return;
    }
    const provider = $("#live-provider").value;
    const model = $("#live-model").value.trim();
    const btn = $("#live-connect");
    btn.disabled = true;
    try {
      const r = await api("/api/live/key", {
        method: "POST",
        body: JSON.stringify({ provider, model, key }),
      });
      if (!r.ok) {
        alert(r.error ? r.error.message : "Could not connect.");
        return;
      }
      $("#live-key").value = ""; // never keep it in the DOM
      await refreshStatus();
    } finally {
      btn.disabled = false;
    }
  }

  async function disconnect() {
    await api("/api/live/key", { method: "DELETE" });
    await refreshStatus();
  }

  function selectScenario(id) {
    live.scenario = live.scenarios.find((s) => s.id === id) || null;
    live.level = "low";
    $("#live-scenario").value = id;
    renderScenario();
  }

  function renderScenario() {
    const s = live.scenario;
    if (!s) return;
    $("#live-goal").textContent = s.goal;
    $("#live-result").hidden = true;

    const banner = $("#live-demo-banner");
    if (s.demo_only) {
      banner.hidden = false;
      banner.textContent = "🧪 Demonstration only — " + (s.demo_reason || "");
      $("#live-run").textContent = "Run offline demo";
    } else {
      banner.hidden = true;
      $("#live-run").textContent = "Run against real model";
    }

    const levels = $("#live-levels");
    levels.innerHTML = "";
    for (const lvl of ["low", "medium", "high"]) {
      const b = el("button", "level-btn", lvl);
      b.type = "button";
      b.dataset.lvl = lvl;
      if (lvl === live.level) b.classList.add("active");
      b.addEventListener("click", () => {
        live.level = lvl;
        renderScenario();
      });
      levels.appendChild(b);
    }

    const form = $("#live-attack-form");
    form.innerHTML = "";
    for (const f of s.fields) {
      const wrap = el("div", "field");
      wrap.appendChild(el("label", null, f.label));
      let input;
      if (f.kind === "textarea") input = el("textarea");
      else input = el("input");
      input.name = f.name;
      input.placeholder = f.placeholder || "";
      if (f.default) input.value = f.default;
      wrap.appendChild(input);
      if (f.help) wrap.appendChild(el("div", "fhelp", f.help));
      form.appendChild(wrap);
    }
  }

  async function run() {
    if (!live.scenario) return;
    const fields = {};
    for (const i of $("#live-attack-form").querySelectorAll("[name]")) {
      fields[i.name] = i.value;
    }
    const btn = $("#live-run");
    const demo = !!live.scenario.demo_only;
    const label = btn.textContent;
    btn.disabled = true;
    btn.textContent = demo ? "Running offline demo…" : "Calling the model…";
    try {
      const path = demo
        ? `/api/live/demo/${live.scenario.id}/attempt`
        : `/api/live/challenges/${live.scenario.id}/attempt`;
      const data = await api(path, {
        method: "POST",
        body: JSON.stringify({ level: live.level, fields }),
      });
      renderResult(data);
      if (!demo) await refreshStatus();
    } catch (e) {
      alert("Request failed: " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  function renderResult(data) {
    $("#live-result").hidden = false;
    const verdict = $("#live-verdict");
    verdict.className = "verdict";
    const notes = $("#live-notes");
    notes.innerHTML = "";
    const resp = $("#live-response");

    if (data.error) {
      verdict.classList.add("refused");
      verdict.textContent = "⛔ " + data.error.message + ` (${data.error.kind})`;
      resp.textContent = "";
      return;
    }
    if (data.refused) {
      verdict.classList.add("refused");
      verdict.textContent = "⛔ Blocked by the app guard — " + (data.refusal_reason || "");
    } else if (data.solved) {
      verdict.classList.add("solved");
      verdict.textContent =
        "✅ The model gave it up" +
        (data.first_solve ? ` (+${data.awarded} points)` : "");
      if (data.flag) verdict.appendChild(el("span", "flag", data.flag));
    } else {
      verdict.classList.add("failed");
      verdict.textContent = "❌ The model held the line this time. Try another angle.";
    }
    resp.textContent = data.response || "(empty)";
    for (const n of data.notes || []) notes.appendChild(el("div", "note", n));
    if (data.tool_calls && data.tool_calls.length) {
      notes.appendChild(el("div", "note", "Tool calls: " + data.tool_calls.join(", ")));
    }
    if (data.meta && data.meta.provider) {
      notes.appendChild(
        el(
          "div",
          "note",
          `${data.meta.provider}/${data.meta.model} · ${data.meta.output_tokens} out-tokens · ` +
            `${data.meta.remaining_requests} requests left`
        )
      );
    } else if (data.meta && Object.keys(data.meta).length) {
      const m = Object.entries(data.meta)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
        .join("  ·  ");
      notes.appendChild(el("div", "note", m));
    }
  }

  $("#tab-practice").addEventListener("click", showPractice);
  $("#tab-live").addEventListener("click", showLive);
  $("#live-connect").addEventListener("click", connect);
  $("#live-disconnect").addEventListener("click", disconnect);
  $("#live-run").addEventListener("click", run);
})();

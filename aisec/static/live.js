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
    live.provider = prov;
    live.scenarios = scen.scenarios || [];

    const psel = $("#live-provider");
    psel.innerHTML = "";
    const o = el("option", null, prov.label);
    o.value = prov.provider;
    psel.appendChild(o);

    $("#live-endpoint").placeholder = prov.default_endpoint;
    if (!$("#live-endpoint").value) $("#live-endpoint").value = prov.default_endpoint;

    populateSuggested(prov.suggested_models || []);
    loadInstalledModels(); // best-effort: show what's actually pulled

    const ssel = $("#live-scenario");
    ssel.innerHTML = "";
    for (const s of live.scenarios) {
      const item = el("option", null, `${s.owasp} · ${s.title}`);
      item.value = s.id;
      ssel.appendChild(item);
    }
    ssel.addEventListener("change", () => selectScenario(ssel.value));

    await refreshStatus();
    if (live.scenarios.length) selectScenario(live.scenarios[0].id);
    $("#live-runner").hidden = false;
  }

  function populateSuggested(models) {
    const dl = $("#live-model-list");
    dl.innerHTML = "";
    for (const m of models) {
      const opt = el("option");
      opt.value = m.name;
      opt.label = `${m.note}${m.tools ? " · tool-capable" : ""}`;
      dl.appendChild(opt);
    }
  }

  async function loadInstalledModels() {
    const endpoint = $("#live-endpoint").value.trim() || $("#live-endpoint").placeholder;
    const hint = $("#live-models-hint");
    try {
      const r = await api("/api/live/models?endpoint=" + encodeURIComponent(endpoint));
      if (r.error) {
        hint.innerHTML = `Couldn't list models (${r.error.kind}). Is Ollama running? Pull one: <code>ollama pull llama3.2</code>.`;
        return;
      }
      const names = r.models || [];
      if (!names.length) {
        hint.innerHTML = "No models installed yet. Pull one: <code>ollama pull llama3.2</code>.";
        return;
      }
      const dl = $("#live-model-list");
      dl.innerHTML = "";
      for (const n of names) {
        const opt = el("option");
        opt.value = n;
        opt.label = "installed";
        dl.appendChild(opt);
      }
      hint.innerHTML = "Installed: " + names.map((n) => `<code>${n}</code>`).join(", ");
      if (!$("#live-model").value && names.length) $("#live-model").value = names[0];
    } catch (e) {
      hint.textContent = "Could not query installed models.";
    }
  }

  async function refreshStatus() {
    const s = await api("/api/live/status");
    const box = $("#live-status");
    if (s.connected) {
      live.connected = true;
      box.innerHTML = "";
      box.appendChild(el("span", "ok", `Connected · ${s.model} @ ${s.endpoint}`));
      box.appendChild(el("span", "budget", `  —  ${s.remaining_requests} requests left`));
    } else {
      live.connected = false;
      box.textContent = "Not connected. Connect a local model to run live scenarios.";
    }
  }

  async function connect() {
    const model = $("#live-model").value.trim();
    if (!model) {
      alert("Enter a model name (e.g. llama3.2). Pull it first with: ollama pull <model>");
      return;
    }
    const endpoint = $("#live-endpoint").value.trim();
    const btn = $("#live-connect");
    btn.disabled = true;
    try {
      const r = await api("/api/live/connect", {
        method: "POST",
        body: JSON.stringify({ endpoint, model }),
      });
      if (!r.ok) {
        alert(r.error ? r.error.message : "Could not connect.");
        return;
      }
      await refreshStatus();
    } finally {
      btn.disabled = false;
    }
  }

  async function disconnect() {
    await api("/api/live/connect", { method: "DELETE" });
    await refreshStatus();
  }

  function selectScenario(id) {
    live.scenario = live.scenarios.find((s) => s.id === id) || null;
    live.level = "low";
    $("#live-scenario").value = id;
    renderScenario();
    clearChat();
  }

  // Which field is the free-text "chat message"; the rest become a context bar.
  function primaryField() {
    const fs = (live.scenario && live.scenario.fields) || [];
    return fs.find((f) => f.kind === "textarea") || fs[0] || null;
  }
  function extraFields() {
    const p = primaryField();
    return ((live.scenario && live.scenario.fields) || []).filter((f) => f !== p);
  }

  function renderScenario() {
    const s = live.scenario;
    if (!s) return;

    const banner = $("#live-demo-banner");
    if (s.demo_only) {
      banner.hidden = false;
      banner.textContent = "🧪 Demonstration only (offline, unscored) — " + (s.demo_reason || "");
    } else {
      banner.hidden = true;
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
        for (const btn of levels.querySelectorAll(".level-btn")) {
          btn.classList.toggle("active", btn.dataset.lvl === lvl);
        }
      });
      levels.appendChild(b);
    }

    // Non-primary fields (e.g. the URL for indirect injection) become a slim
    // context bar; the primary field is the chat input.
    const extra = $("#chat-extra");
    extra.innerHTML = "";
    for (const f of extraFields()) {
      const wrap = el("div", "field");
      wrap.appendChild(el("label", null, f.label));
      const input = el("input");
      input.type = "text";
      input.dataset.name = f.name;
      input.placeholder = f.placeholder || "";
      if (f.default) input.value = f.default;
      wrap.appendChild(input);
      extra.appendChild(wrap);
    }

    const primary = primaryField();
    const input = $("#chat-input");
    input.placeholder = primary
      ? `${primary.label}  —  (Enter to send, Shift+Enter for newline)`
      : "Message the model…";
  }

  // --- chat transcript -----------------------------------------------------

  function clearChat() {
    $("#chat-log").innerHTML = "";
    if (live.scenario) {
      addBubble("system", "🎯 " + live.scenario.goal);
      const primary = primaryField();
      if (primary && primary.help) addBubble("system", primary.help);
    }
  }

  function addBubble(role, text) {
    const wrap = el("div", "bubble-row " + role);
    const av = el("div", "avatar", role === "user" ? "you" : role === "system" ? "•" : "AI");
    const bub = el("div", "bubble");
    bub.textContent = text;
    if (role === "user") {
      wrap.appendChild(bub);
      wrap.appendChild(av);
    } else {
      wrap.appendChild(av);
      wrap.appendChild(bub);
    }
    $("#chat-log").appendChild(wrap);
    scrollDown();
    return bub;
  }

  function addTyping() {
    const wrap = el("div", "bubble-row model typing-row");
    wrap.appendChild(el("div", "avatar", "AI"));
    const bub = el("div", "bubble typing");
    bub.innerHTML = "<span></span><span></span><span></span>";
    wrap.appendChild(bub);
    $("#chat-log").appendChild(wrap);
    scrollDown();
    return wrap;
  }

  function scrollDown() {
    const log = $("#chat-log");
    log.scrollTop = log.scrollHeight;
  }

  function typeText(bubble, text) {
    return new Promise((resolve) => {
      const full = text || "(empty response)";
      let i = 0;
      // Reveal a few chars per tick so long replies don't crawl.
      const step = Math.max(1, Math.round(full.length / 300));
      const timer = setInterval(() => {
        i = Math.min(full.length, i + step);
        bubble.textContent = full.slice(0, i);
        scrollDown();
        if (i >= full.length) {
          clearInterval(timer);
          resolve();
        }
      }, 16);
    });
  }

  function addVerdict(data) {
    let cls = "failed";
    let text = "❌ The model held the line this time. Try another angle.";
    if (data.refused) {
      cls = "refused";
      text = "⛔ Blocked by the app guard — " + (data.refusal_reason || "");
    } else if (data.solved) {
      cls = "solved";
      text =
        "✅ The model gave it up" +
        (data.first_solve ? ` (+${data.awarded} points)` : "") +
        (data.flag ? "\n" + data.flag : "");
    }
    const row = el("div", "bubble-row system");
    row.appendChild(el("div", "avatar", "•"));
    row.appendChild(el("div", "verdict-bubble " + cls, text));
    $("#chat-log").appendChild(row);
    scrollDown();

    const meta = [];
    for (const n of data.notes || []) meta.push(n);
    if (data.tool_calls && data.tool_calls.length) meta.push("Tool calls: " + data.tool_calls.join(", "));
    if (data.meta && data.meta.remaining_requests != null) {
      meta.push(`${data.meta.remaining_requests} requests left`);
    }
    if (meta.length) {
      const row2 = el("div", "bubble-row system");
      row2.appendChild(el("div", "avatar", ""));
      row2.appendChild(el("div", "meta-bubble", meta.join(" · ")));
      $("#chat-log").appendChild(row2);
      scrollDown();
    }
  }

  async function send() {
    if (!live.scenario || live.sending) return;
    const input = $("#chat-input");
    const msg = input.value.trim();
    if (!msg) return;

    const primary = primaryField();
    const fields = {};
    if (primary) fields[primary.name] = msg;
    for (const i of $("#chat-extra").querySelectorAll("[data-name]")) {
      fields[i.dataset.name] = i.value;
    }

    live.sending = true;
    $("#chat-send").disabled = true;
    input.value = "";
    autosize(input);
    addBubble("user", msg);
    const typing = addTyping();

    const demo = !!live.scenario.demo_only;
    const path = demo
      ? `/api/live/demo/${live.scenario.id}/attempt`
      : `/api/live/challenges/${live.scenario.id}/attempt`;

    try {
      const data = await api(path, {
        method: "POST",
        body: JSON.stringify({ level: live.level, fields }),
      });
      typing.remove();

      if (data.error) {
        addBubble("system", "⛔ " + data.error.message + ` (${data.error.kind})`);
      } else {
        const bubble = addBubble("model", "");
        await typeText(bubble, data.response);
        addVerdict(data);
        if (!demo) await refreshStatus();
      }
    } catch (e) {
      typing.remove();
      addBubble("system", "Request failed: " + e.message);
    } finally {
      live.sending = false;
      $("#chat-send").disabled = false;
      input.focus();
    }
  }

  function autosize(ta) {
    ta.style.height = "auto";
    ta.style.height = Math.min(160, ta.scrollHeight) + "px";
  }

  const chatInput = $("#chat-input");
  chatInput.addEventListener("input", () => autosize(chatInput));
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  });

  $("#tab-practice").addEventListener("click", showPractice);
  $("#tab-live").addEventListener("click", showLive);
  $("#live-connect").addEventListener("click", connect);
  $("#live-disconnect").addEventListener("click", disconnect);
  $("#live-refresh-models").addEventListener("click", loadInstalledModels);
  $("#chat-send").addEventListener("click", send);
  $("#chat-clear").addEventListener("click", clearChat);
})();

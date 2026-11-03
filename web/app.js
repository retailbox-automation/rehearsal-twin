(() => {
  const qs = new URLSearchParams(location.search);
  const asked = qs.get("id");
  const rid = asked || "latest";            // live: the newest rehearsal; fixture: falls back to "a"
  const freezeAt = qs.get("at");            // render a still frame at this step, no streaming
  const pace = qs.get("pace");              // forwarded to the event stream
  const $ = (id) => document.getElementById(id);
  const STEPS = ["rehearse", "review", "apply", "compare"];

  const state = { r: null, step: null, rows: 0, summary: false, prod: { files: 0, rows: 0 }, gone: new Set(), added: new Set(), compare: false };
  const t0 = Date.now();

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const short = (h) => `${h.slice(0, 4)}...${h.slice(-4)}`;
  const fmtUptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    return `${d}d ${String(h).padStart(2, "0")}h`;
  };

  function renderStatic() {
    const r = state.r;
    $("script-name").textContent = r.script.name;
    const code = $("code");
    code.replaceChildren(...r.script.lines.map((l, i) => {
      const row = el("div");
      row.append(el("span", "n", String(i + 1)), el("span", "c", l));
      return row;
    }));
    $("scope-paths").textContent = r.scope.paths.join(", ") || "none";
    $("scope-tables").textContent = Object.keys(r.scope.tables).join(", ") || "none";
    $("scope-hosts").textContent = r.scope.hosts.join(", ") || "none";
    $("twin-sub").textContent = r.twin.subtitle;
    const sel = $("preset");
    sel.replaceChildren(...r.presets.map((p) => { const o = el("option", "", p); o.selected = p === r.preset; return o; }));
  }

  function renderSteps() {
    const at = STEPS.indexOf(state.step);
    document.querySelectorAll("#steps li").forEach((li, i) => {
      li.classList.toggle("done", at > i || (state.compare && i === 3));
      li.classList.toggle("active", at === i && !(state.compare && i === 3));
    });
  }

  function renderTwin() {
    const r = state.r, s = r.summary;
    const twin = $("twin");
    twin.dataset.state = state.summary ? "done" : "idle";
    if (!state.summary) {
      $("verdict-text").textContent = state.step ? "rehearsing on the twin..." : "waiting for rehearsal";
      $("outside-text").textContent = "";
      $("blocked-text").textContent = "";
      return;
    }
    $("verdict-text").textContent = s.headline || `deleted ${s.deleted_files} files`;
    const o = $("outside-text");
    o.replaceChildren(el("em", "", String(s.outside_count)), document.createTextNode(` outside declared scope: ${s.outside_paths.join(", ")}`));
    const e = s.egress_line;
    const b = $("blocked-text");
    b.replaceChildren(document.createTextNode(`${e.method} ${e.target} — `), el("em", "", e.note));
  }

  function renderLedger() {
    const body = document.querySelector("#ledger tbody");
    const rows = state.r.ledger_view.slice(0, state.rows);
    while (body.children.length < rows.length) {
      const v = rows[body.children.length];
      const tr = el("tr", state.animate ? "enter" : "");
      const pill = el("span", v.verdict === "in_scope" ? "pill in" : "pill out", v.verdict === "in_scope" ? "in scope" : "out of scope");
      const t = el("td", "t", v.target), vv = el("td", "v"), rr = el("td", "r", v.reason), d = el("td", "d", v.delta);
      vv.append(pill);
      tr.append(t, vv, rr, d);
      body.append(tr);
    }
    const h = state.r.twin_ledger.ledger_sha256;
    let line = state.step && STEPS.indexOf(state.step) >= 1 ? `ledger sha256 ${short(h)}` : "";
    if (state.compare) {
      const c = state.r.compare;
      line += c.match === false
        ? `   predicted \u2260 happened: ${c.surprises.length} surprises`
        : `   predicted = happened: ${c.happened.files_changed} files, ${c.happened.rows_changed} rows, ${c.happened.egress_attempts} egress`;
    }
    $("hash").textContent = line;
  }

  function renderInstances() {
    const ul = $("instances");
    const items = state.r.instances.filter((i) => state.added.has(i.id) || i.dot === "green");
    ul.replaceChildren(...items.map((i) => {
      const gone = state.gone.has(i.id);
      const li = el("li", gone ? "removed" : "");
      li.append(el("span", `dot ${gone ? "gone" : i.dot}`), el("b", "", i.label), el("span", "meta", "\u00b7 " + (gone ? "twin deleted" : i.meta)), el("span", "chev"));
      return li;
    }));
  }

  function renderProd() {
    $("files-changed").textContent = state.prod.files;
    $("rows-changed").textContent = state.prod.rows;
  }

  function renderActions() {
    if (state.r.receipt_url) $("receipt").href = state.r.receipt_url;
    const past = STEPS.indexOf(state.step) >= 2;
    $("approve").disabled = past;
    $("reject").disabled = past;
    $("approve").textContent = past ? "Approved — applied to PROD" : "Approve safer variant";
  }

  function render() {
    renderSteps(); renderTwin(); renderLedger(); renderInstances(); renderProd(); renderActions();
  }

  function reduce(type, data) {
    switch (type) {
      case "step": state.step = data.step; state.compare = data.step === "compare"; break;
      case "instance_add": state.added.add(data.id); break;
      case "instance_remove": state.gone.add(data.id); break;
      case "ledger_row": state.rows = Math.max(state.rows, data.index + 1); break;
      case "twin_summary": state.summary = true; break;
      case "prod_counters": state.prod = { files: data.files_changed, rows: data.rows_changed }; break;
    }
  }

  function playStill(timeline) {
    for (const ev of timeline) {
      reduce(ev.type, ev.data);
      if (ev.type === "step" && ev.data.step === freezeAt) break;
    }
    render();
  }

  function playLive() {
    state.animate = true;
    const src = new EventSource(`/api/rehearsals/${encodeURIComponent(state.r.id || rid)}/events${pace !== null ? `?pace=${encodeURIComponent(pace)}` : ""}`);
    const types = ["step", "instance_add", "instance_remove", "ledger_row", "twin_summary", "prod_counters"];
    for (const t of types) {
      src.addEventListener(t, (m) => { reduce(t, JSON.parse(m.data)); render(); });
    }
    src.addEventListener("view", (m) => {  // live mode: the record as built from the real ledgers
      const v = JSON.parse(m.data);
      if (state.r && v.view_key !== state.r.view_key) {
        document.querySelector("#ledger tbody").replaceChildren();
        state.rows = 0;
        state.summary = false;
      }
      state.r = Object.assign(v, { timeline: state.r ? state.r.timeline : [] });
      renderStatic(); render();
    });
    src.addEventListener("done", () => src.close());
    src.onerror = () => src.close();
  }

  $("approve").addEventListener("click", async () => {
    const a = state.r && state.r.approval;
    if (!a) return;
    $("approve").disabled = true;
    const owner = sessionStorage.getItem(`rt-owner-${state.r.id}`);  // judges approve their own run
    const headers = { "Content-Type": "application/json" };
    if (owner) headers["X-RT-Owner"] = owner;
    const res = await fetch(`/api/rehearsals/${encodeURIComponent(state.r.id)}/approve`, {
      method: "POST", headers, body: JSON.stringify(a) });
    if (!res.ok) { $("approve").disabled = false; $("hash").textContent = `approval refused (${res.status})`; }
  });

  // Live mode: run the preset in the selector; the queue line shows where the run stands.
  const live = () => state.r && (state.r.mode === "live" || state.r.empty);
  $("run").addEventListener("click", async () => {
    const name = $("preset").value;
    const opt = (state.r.preset_options || []).find((o) => o.name === name);
    if (!opt) return;
    $("run").disabled = true;
    const res = await fetch("/api/rehearsals", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preset: opt.id }) });
    const body = await res.json().catch(() => ({}));
    if (res.ok) {
      if (body.owner_key) sessionStorage.setItem(`rt-owner-${body.id}`, body.owner_key);
      location.href = `/?id=${encodeURIComponent(body.id)}`;
      return;
    }
    $("run").disabled = false;
    const d = body.detail || {};
    $("queue").textContent = res.status === 429 ? `not started: ${d.reason || "limit reached"}`
      : res.status === 401 ? "runs are closed right now" : `not started (${res.status})`;
  });

  async function pollQueue() {
    if (!live()) return;
    try {
      const q = await (await fetch("/api/queue")).json();
      const mine = q.waiting.find((w) => w.id === state.r.id);
      let line = `queue \u00b7 ${q.running.length} running \u00b7 ${q.waiting.length} waiting \u00b7 ${q.cap} ${q.cap === 1 ? "twin" : "twins"} at a time`;
      if (mine) line += ` \u00b7 this run is #${mine.position}`;
      if (q.judge && q.judge.mode === "on") line += ` \u00b7 runs today ${q.judge.runs_today}/${q.judge.daily_budget}`;
      $("queue").textContent = line;
    } catch (e) { /* next poll */ }
  }

  function emptyRecord(r) {  // live, nothing rehearsed yet: an idle screen with the run button
    const names = (r.preset_options || []).map((o) => o.name);
    return Object.assign({ script: { name: "", lines: [] }, scope: { paths: [], tables: {}, hosts: [] },
      presets: names, preset: names[0], twin: { label: "twin", subtitle: "Vultr VM from snapshot \u00b7 VPC-only \u00b7 no keys" },
      prod: { name: "prod", uptime_s: 0 }, twin_ledger: { ledger_sha256: "" }, ledger_view: [], instances: [],
      summary: {}, timeline: [] }, r);
  }

  async function main() {
    let res = await fetch(`/api/rehearsals/${encodeURIComponent(rid)}`);
    if (!res.ok && !asked) res = await fetch("/api/rehearsals/a");  // fixture mode
    state.r = await res.json();
    if (state.r.empty) state.r = emptyRecord(state.r);
    $("run").disabled = !live();
    if (live()) { pollQueue(); setInterval(pollQueue, 3000); }
    renderStatic();
    if (state.r.empty) { render(); return; }
    // The prod instance is always listed; the twin appears with its instance_add event.
    state.added = new Set(state.r.instances.filter((i) => i.dot === "green").map((i) => i.id));
    render();
    setInterval(() => {
      $("uptime").textContent = fmtUptime(state.r.prod.uptime_s + (Date.now() - t0) / 1000);
    }, 1000);
    $("uptime").textContent = fmtUptime(state.r.prod.uptime_s);
    if (freezeAt) playStill(state.r.timeline); else playLive();
  }
  main();
})();

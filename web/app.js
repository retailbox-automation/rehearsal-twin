(() => {
  const qs = new URLSearchParams(location.search);
  const rid = qs.get("id") || "a";
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
    $("verdict-text").textContent = `deleted ${s.deleted_files} files`;
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
      line += `   predicted = happened: ${c.happened.files_changed} files, ${c.happened.rows_changed} rows, ${c.happened.egress_attempts} egress`;
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
    const src = new EventSource(`/api/rehearsals/${encodeURIComponent(rid)}/events${pace !== null ? `?pace=${encodeURIComponent(pace)}` : ""}`);
    const types = ["step", "instance_add", "instance_remove", "ledger_row", "twin_summary", "prod_counters"];
    for (const t of types) {
      src.addEventListener(t, (m) => { reduce(t, JSON.parse(m.data)); render(); });
    }
    src.addEventListener("done", () => src.close());
    src.onerror = () => src.close();
  }

  async function main() {
    const res = await fetch(`/api/rehearsals/${encodeURIComponent(rid)}`);
    state.r = await res.json();
    renderStatic();
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

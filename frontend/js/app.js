/* ==========================================================================
   SENTINEL — SPA
   Hash router + fetch client + hand-rolled SVG charts. No dependencies.
   ========================================================================== */
"use strict";

/* ---------------- utilities ---------------- */
const $  = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => Number(n ?? 0).toLocaleString("en-US");

const LEVEL_KEY = { "🔴 Critical": "crit", "🟠 High": "high", "🟡 Medium": "med", "🟢 Low": "low" };
const LEVEL_WORD = { crit: "CRITICAL", high: "HIGH", med: "MEDIUM", low: "LOW" };
const lvl = (level) => LEVEL_KEY[level] || "low";
const scoreCls = (s) => s >= 8 ? "crit" : s >= 6 ? "high" : s >= 3 ? "med" : "low";

let toastTimer = null;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 3200);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch (e) { /* plain text */ }
    const err = new Error(detail);
    err.status = r.status;
    throw err;
  }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("application/json") ? r.json() : r.text();
}

function download(name, text, mime) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ---------------- SVG chart builders ---------------- */

const NS = "http://www.w3.org/2000/svg";
const SEV_COLORS = { crit: "#F87171", high: "#FB923C", med: "#FACC15", low: "#38BDF8" };

function el(name, attrs, parent) {
  const n = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
}

/** Stacked hourly bar chart of incidents by severity. */
function timelineChart(container, rows) {
  if (!rows || !rows.length) { container.innerHTML = '<div class="diag" style="color:var(--faint)">No incidents detected in this dataset.</div>'; return; }
  const byTime = new Map();
  for (const r of rows) {
    if (!byTime.has(r.t)) byTime.set(r.t, {});
    byTime.get(r.t)[lvl(r.level)] = (byTime.get(r.t)[lvl(r.level)] || 0) + r.n;
  }
  const times = [...byTime.keys()].sort();
  const W = 900, H = 190, padB = 24, padT = 10;
  const bw = Math.max(10, (W - 10) / times.length - 6);
  const maxN = Math.max(1, ...times.map(t => Object.values(byTime.get(t)).reduce((a, b) => a + b, 0)));
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", style: "height:190px" });
  for (let i = 1; i < 4; i++) el("line", { x1: 0, x2: W, y1: padT + (H - padB - padT) * i / 4, y2: padT + (H - padB - padT) * i / 4, stroke: "#1E3245", "stroke-width": 1 }, svg);
  times.forEach((t, i) => {
    const x = 8 + i * (W - 16) / times.length;
    let y = H - padB;
    const total = Object.values(byTime.get(t)).reduce((a, b) => a + b, 0);
    for (const k of ["low", "med", "high", "crit"]) {
      const n = byTime.get(t)[k] || 0;
      if (!n) continue;
      const h = (n / maxN) * (H - padB - padT);
      y -= h;
      el("rect", { x, y, width: bw, height: Math.max(h - 1.5, 2), rx: 2, fill: SEV_COLORS[k], opacity: 0.92 }, svg);
    }
    if (times.length <= 14 || i % Math.ceil(times.length / 12) === 0) {
      const tx = el("text", { x: x + bw / 2, y: H - 7, fill: "#64809C", "font-size": 9, "text-anchor": "middle" }, svg);
      tx.textContent = t.slice(11, 16);
    }
  });
  container.classList.add("chart-wrap");
  container.innerHTML = "";
  container.appendChild(svg);
  container.insertAdjacentHTML("beforeend",
    `<div class="legend">${["crit", "high", "med", "low"].map(k => `<span><span class="sw" style="background:${SEV_COLORS[k]}"></span>${LEVEL_WORD[k]}</span>`).join("")}</div>`);
}

/** Horizontal distribution bars. */
function distBars(container, dist, colors) {
  if (!dist || !dist.length) { container.innerHTML = '<div class="diag">No rule detections.</div>'; return; }
  const max = Math.max(...dist.map(d => d.count));
  container.innerHTML = dist.map((d, i) => `
    <div class="pbar-row">
      <div class="pbar-label">${esc(d.category)}</div>
      <div class="pbar-track"><div class="pbar-fill" style="width:${(d.count / max) * 100}%;background:${colors ? colors(i) : "linear-gradient(90deg,var(--bl-700),var(--bl-400))"}"></div></div>
      <div class="pbar-val">${d.count}</div>
    </div>`).join("");
}

/** Risk-over-time line chart for one entity. */
function riskLine(container, bins) {
  if (!bins || !bins.length) { container.innerHTML = '<div class="diag">No timestamped events for this entity.</div>'; return; }
  const W = 560, H = 170, padL = 26, padB = 20, padT = 8;
  const maxR = Math.max(1, ...bins.map(b => b.risk));
  const x = (i) => padL + i * (W - padL - 8) / Math.max(bins.length - 1, 1);
  const y = (v) => padT + (1 - v / maxR) * (H - padB - padT);
  const pts = bins.map((b, i) => `${x(i)},${y(b.risk)}`).join(" ");
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", style: "height:170px" });
  el("path", { d: `M${padL},${H - padB} L${pts.split(" ").join(" L")} L${x(bins.length - 1)},${H - padB} Z`, fill: "rgba(14,165,233,0.10)" }, svg);
  el("polyline", { points: pts, fill: "none", stroke: "#38BDF8", "stroke-width": 2.2, "stroke-linejoin": "round" }, svg);
  bins.forEach((b, i) => {
    if (b.risk > 0) el("circle", { cx: x(i), cy: y(b.risk), r: 2.6, fill: b.risk >= 6 ? "#F87171" : b.risk >= 3 ? "#FB923C" : "#38BDF8" }, svg);
  });
  const lbls = [0, Math.floor(bins.length / 2), bins.length - 1];
  lbls.forEach(i => { const t = el("text", { x: x(i), y: H - 5, fill: "#64809C", "font-size": 9, "text-anchor": "middle" }, svg); t.textContent = bins[i].t.slice(11, 16); });
  container.classList.add("chart-wrap");
  container.innerHTML = "";
  container.appendChild(svg);
}

/** Score breakdown rows with mini bars. */
function breakdownHTML(bd) {
  return bd.map(b => `
    <div class="bd-row">
      <div class="bd-name">${esc(b.label)}</div>
      <div class="bd-val">+${Number(b.value).toFixed(2)} <span class="of">/ ${b.max}</span></div>
      <div class="bd-mini">
        <div class="track"><div class="fill" style="width:${(b.value / Math.max(b.max, 0.01)) * 100}%"></div></div>
        <div class="bd-why">${esc(b.reason)}</div>
      </div>
    </div>`).join("");
}

/* ---------------- shared fragments ---------------- */

function kpiHTML(label, value, note, cls) {
  return `<div class="kpi ${cls || ""}"><div class="k-label">${label}</div><div class="k-value">${value}</div>${note ? `<div class="k-note">${note}</div>` : ""}</div>`;
}

function headHTML(title, sub, extra) {
  return `<div class="page-head head-row"><div><h1 class="page-title">${title}</h1><div class="page-sub">${sub}</div></div>${extra || ""}</div>`;
}

function postureRing(score, label) {
  const col = score >= 80 ? "#F87171" : score >= 60 ? "#FB923C" : score >= 30 ? "#FACC15" : "#38BDF8";
  return `<div class="ring-wrap">
    <svg class="ring" viewBox="0 0 120 120">
      <circle class="bg" cx="60" cy="60" r="52" fill="none" stroke-width="12"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round"
        stroke-dasharray="${2 * Math.PI * 52}" stroke-dashoffset="${2 * Math.PI * 52 * (1 - score / 100)}"
        transform="rotate(-90 60 60)"/>
      <text x="60" y="58" text-anchor="middle" fill="${col}" font-size="26">${score}</text>
      <text x="60" y="76" text-anchor="middle" fill="#64809C" font-size="9">/ 100</text>
    </svg>
    <div>
      <div style="font-size:16px;font-weight:800;letter-spacing:2px;color:${col}">${label}</div>
      <div style="font-size:12px;color:var(--faint);margin-top:5px;line-height:1.6">Overall risk = highest<br>incident score × 10</div>
    </div>
  </div>`;
}

function incCardHTML(i, showId) {
  const k = lvl(i.level);
  return `<div class="inc-card c-lv-${k}" onclick="location.hash='incident/${i.incident_id}'">
    <span class="chip ${k}">${LEVEL_WORD[k]}</span>
    <div class="inc-main">
      <div class="inc-title">${showId ? esc(i.incident_id) + " · " : ""}${esc(i.attack || "Suspicious Activity")} · <span class="ent">${esc(i.entity)}</span></div>
      <div class="inc-sub">${esc(i.summary || i.entity)}</div>
      <div class="inc-sub">${esc(i.first_seen)} → ${esc(i.last_seen)} · ${i.n_detections} detections · ${fmt(i.n_events)} events</div>
    </div>
    <div class="score-badge ${scoreCls(i.risk)}">${Number(i.risk).toFixed(1)}</div>
  </div>`;
}

/* ---------------- views ---------------- */

const Views = {

  /* ============ OVERVIEW ============ */
  async overview(view) {
    view.innerHTML = headHTML('Security <span class="thin">Overview</span>', "Real-time analysis of authentication and web-server activity",
      `<a class="btn" href="#analyze">↑ Analyze a log file</a>`);
    let data;
    try { data = await api("/api/overview"); }
    catch (e) { return this.empty(view); }

    $("#rail-status").innerHTML =
      `<b><span class="pulse-dot"></span>SYSTEM ONLINE</b><br>` +
      `${fmt(data.events)} events · ${data.incidents_total} incidents<br>pipeline ready`;

    const s = data.severity;
    view.insertAdjacentHTML("beforeend", `
      <div class="kpi-strip">
        ${kpiHTML("Total Events", fmt(data.events), "parsed & normalized", "k-accent")}
        ${kpiHTML("Threats Detected", fmt(data.detections_rule + data.detections_ml), `${data.detections_rule} rule · ${data.detections_ml} ML`, "k-high")}
        ${kpiHTML("Critical Incidents", s.critical, "immediate action", s.critical ? "k-crit" : "k-low")}
        ${kpiHTML("High-Risk Incidents", s.high, "review now", s.high ? "k-high" : "k-low")}
        ${kpiHTML("Failed Auth", fmt(data.failed_auth), "401/403 & ssh failures", s.high ? "k-med" : "k-low")}
      </div>
      <div class="grid-side">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Threat Activity</div>
          <div id="ov-timeline"></div></div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Security Posture</div>
          <div id="ov-posture"></div></div>
      </div>
      <div class="grid-2">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Threat Distribution</div><div id="ov-dist"></div></div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Top Risk Entities</div><div id="ov-entities"></div></div>
      </div>
      <div class="panel"><div class="panel-title"><span class="dot"></span>Live Incident Feed
        <span class="right"><a href="#incidents">view all →</a></span></div><div id="ov-feed"></div></div>`);

    $("#ov-posture").innerHTML = postureRing(data.posture.score, data.posture.label) +
      `<div style="font-size:11.5px;color:var(--faint);margin-top:10px">${data.incidents_total} incidents · avg score ${data.avg_risk}/10</div>`;
    timelineChart($("#ov-timeline"), data.timeline);
    distBars($("#ov-dist"), data.distribution);

    $("#ov-entities").innerHTML = data.top_entities.map(e => `
      <div class="inc-card c-lv-${lvl(e.level)}" onclick="location.hash='profiles/${encodeURIComponent(e.entity)}'">
        <div class="inc-main">
          <div class="inc-title" style="font-size:13px"><span class="ent">${esc(e.ip)}</span></div>
          <div class="inc-sub">last activity ${esc(e.last)}</div>
        </div>
        <div style="font-size:11.5px;color:var(--faint)">${e.detections} det · ${fmt(e.fails)} fail</div>
        <div class="score-badge ${scoreCls(e.risk)}" style="font-size:17px">${Number(e.risk).toFixed(1)}</div>
      </div>`).join("");

    $("#ov-feed").innerHTML = data.feed.map(f => `
      <div class="inc-card c-lv-${lvl(f.level)}" onclick="location.hash='incident/${f.incident_id}'">
        <span class="chip ${lvl(f.level)}">${LEVEL_WORD[lvl(f.level)]}</span>
        <div class="inc-main">
          <div class="inc-title">${esc(f.incident_id)} · <span class="ent">${esc(f.entity)}</span></div>
          <div class="inc-sub">${esc(f.summary)}</div>
          <div class="inc-sub">${esc(f.window)}</div>
        </div>
        <div class="score-badge ${scoreCls(f.risk)}" style="font-size:17px">${Number(f.risk).toFixed(1)}</div>
      </div>`).join("");
  },

  empty(view) {
    $("#rail-status").innerHTML = `<b><span class="pulse-dot off"></span>AWAITING DATA</b><br>No analysis loaded.<br>Run the demo or upload logs.`;
    view.insertAdjacentHTML("beforeend", `
      <div class="panel"><div class="empty">
        <div class="e-mark"><svg viewBox="0 0 24 24" fill="none" stroke="#7CC6FB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 4v6c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-4z"/></svg></div>
        <div class="e-title">SENTINEL</div>
        <div class="e-sub">Behavior-driven threat detection &amp; dynamic risk intelligence.<br>
          Ingest auth logs or web-server access logs — detect brute force, credential abuse,<br>
          SQL injection, XSS, path traversal and behavioral anomalies — with explainable risk scoring.</div>
        <div class="e-actions">
          <a class="btn primary" href="#analyze">Run the security demo →</a>
          <a class="btn" href="#analyze">Upload a log file</a>
        </div>
      </div></div>`);
  },

  /* ============ ANALYZE ============ */
  async analyze(view) {
    view.innerHTML = headHTML('Analyze <span class="thin">Logs</span>', "Upload server logs and uncover suspicious behavior");
    let demoInfo = { web: { features: [] }, ssh: { features: [] } };
    try { demoInfo = await api("/api/demo-info"); } catch (e) { /* optional */ }

    view.insertAdjacentHTML("beforeend", `
      <div class="grid-side">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Log Source</div>
          <div class="dropzone" id="dz">
            <div class="dz-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#7CC6FB" stroke-width="2" stroke-linecap="round"><path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 20h16"/></svg></div>
            <div class="dz-title">Drop a log file here, or click to browse</div>
            <div class="dz-sub">Apache / Nginx access logs · SSH &amp; auth syslog · JSON lines<br>Auto-detect enabled · parsed in chunks · malformed lines never dropped</div>
          </div>
          <input type="file" id="file-in" accept=".log,.txt,.csv,.json" style="display:none">
          <div id="az-progress" style="display:none">
            <div class="progress-track"><div class="progress-fill" id="az-fill"></div></div>
            <div class="stepper" id="az-steps"></div>
          </div>
          <div id="az-diag" style="margin-top:12px"></div>
        </div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Security Demos</div>
          <div class="demo-card">
            <div class="d-name">🌐 Web attack sample <button class="btn primary" id="run-web" style="margin-left:auto;padding:6px 14px">▶ Run</button></div>
            <div class="d-feats">${demoInfo.web.features.map(f => `✓ ${esc(f)}`).join("<br>")}</div>
          </div>
          <div class="demo-card">
            <div class="d-name">🔑 SSH / auth sample <button class="btn" id="run-ssh" style="margin-left:auto;padding:6px 14px">▶ Run</button></div>
            <div class="d-feats">${demoInfo.ssh.features.map(f => `✓ ${esc(f)}`).join("<br>")}</div>
          </div>
          <div style="font-size:11px;color:var(--faint);line-height:1.7;margin-top:10px">
            Samples are generated locally and clearly labeled. The full pipeline runs:
            parse → rules → ML → correlate → score → recommendations.</div>
        </div>
      </div>`);

    const STAGES = [
      ["Parsing & normalizing logs", 15], ["Rule-based detection", 35], ["ML anomaly detection", 55],
      ["Incident correlation", 72], ["Risk scoring", 88], ["AI recommendations", 100],
    ];

    function startProgress() {
      $("#az-progress").style.display = "block";
      $("#az-steps").innerHTML = STAGES.map(([n]) =>
        `<div class="step" data-stage="${esc(n)}"><span class="s-ico">·</span>${esc(n)}</div>`).join("");
      $("#az-fill").style.width = "4%";
      $("#az-diag").innerHTML = "";
    }

    function stageProgress(stage, pct, detail) {
      $("#az-fill").style.width = pct + "%";
      $$("#az-steps .step").forEach(el => {
        const mine = el.dataset.stage === stage;
        const idx = STAGES.findIndex(([n]) => n === stage);
        const done = STAGES.findIndex(([n]) => n === el.dataset.stage) < idx || pct === 100;
        el.classList.toggle("active", mine && pct !== 100);
        el.classList.toggle("done", done);
        el.querySelector(".s-ico").textContent = done ? "✓" : mine ? "◉" : "·";
        if (mine && detail) {
          let d = el.querySelector(".s-detail");
          if (!d) { d = document.createElement("span"); d.className = "s-detail"; el.appendChild(d); }
          d.textContent = detail;
        }
      });
    }

    async function runAnalysis(fd, qs) {
      startProgress();
      stageProgress("Parsing & normalizing logs", 6, "reading file");
      try {
        // The pipeline is fast server-side; narrate the stages while it runs.
        const p = api("/api/analyze" + (qs || ""), { method: "POST", body: fd });
        const narration = (async () => {
          for (const [n, pct] of STAGES) {
            await new Promise(r => setTimeout(r, 420));
            stageProgress(n, pct, n === STAGES[STAGES.length - 1][0] ? "done" : "…");
          }
        })();
        const [result] = await Promise.all([p, narration]);
        stageProgress("AI recommendations", 100, `done in ${result.seconds}s`);
        const ing = result.stages.ingest;
        $("#az-diag").innerHTML = `
          <div class="panel" style="margin:0"><div class="panel-title"><span class="dot"></span>Parser Status</div>
            <div class="diag">
              <div class="d-row"><span class="ok">✓</span>File loaded: <b>&nbsp;${esc(result.file_name || "sample")}</b></div>
              <div class="d-row"><span class="ok">✓</span>Format detected: <b>&nbsp;${esc(result.format)}</b>&nbsp;(auto-detect)</div>
              <div class="d-row"><span class="ok">✓</span>Lines scanned: <b>&nbsp;${fmt(ing.total_lines)}</b></div>
              <div class="d-row"><span class="ok">✓</span>Entries parsed: <b>&nbsp;${fmt(ing.parsed)}</b></div>
              <div class="d-row"><span class="${ing.n_rejected ? "bad" : "ok"}">${ing.n_rejected ? "✕" : "✓"}</span>Invalid/rejected lines: <b>&nbsp;${fmt(ing.n_rejected)}</b></div>
            </div>
            <div style="display:flex;gap:10px;margin-top:14px">
              <a class="btn primary" href="#overview">→ Open Security Overview</a>
              <a class="btn" href="#incidents">View incidents</a>
            </div>
          </div>`;
        toast(`Analysis complete — ${result.incidents} incidents in ${result.seconds}s`);
      } catch (e) {
        $("#az-progress").style.display = "none";
        $("#az-diag").innerHTML = `<div class="panel" style="border-color:var(--crit)"><div class="diag">
          <div class="d-row"><span class="bad">✕</span><b>Parser error</b>&nbsp;— ${esc(e.message)}</div></div></div>`;
        toast("Analysis failed");
      }
    }

    const dz = $("#dz"), fin = $("#file-in");
    dz.addEventListener("click", () => fin.click());
    dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag"); });
    dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
    dz.addEventListener("drop", (e) => { e.preventDefault(); dz.classList.remove("drag"); if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });
    fin.addEventListener("change", () => fin.files[0] && upload(fin.files[0]));

    function upload(file) {
      toast(`Analyzing ${file.name}…`);
      const fd = new FormData();
      fd.append("file", file, file.name);
      runAnalysis(fd);
    }

    $("#run-web").addEventListener("click", () => runAnalysis(new FormData(), "?demo=web"));
    $("#run-ssh").addEventListener("click", () => runAnalysis(new FormData(), "?demo=ssh"));
  },

  /* ============ INCIDENTS ============ */
  async incidents(view) {
    view.innerHTML = headHTML('Security <span class="thin">Incidents</span>', "Grouped, scored and explained threat incidents — sorted by risk");
    view.insertAdjacentHTML("beforeend", `
      <div class="panel"><div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
        <input class="input" id="inc-q" placeholder="Filter by entity, attack type or summary…" style="flex:2;min-width:220px">
        <div class="seg" id="inc-sev">
          <button class="seg-btn on" data-v="">All</button>
          <button class="seg-btn" data-v="🔴 Critical">Critical</button>
          <button class="seg-btn" data-v="🟠 High">High</button>
          <button class="seg-btn" data-v="🟡 Medium">Medium</button>
          <button class="seg-btn" data-v="🟢 Low">Low</button>
        </div>
      </div><div id="inc-count" style="font-size:12px;color:var(--faint);margin-top:8px"></div></div>
      <div id="inc-list"></div>`);

    let sev = "";
    async function load() {
      const q = $("#inc-q").value.trim();
      const rows = await api(`/api/incidents?q=${encodeURIComponent(q)}&severity=${encodeURIComponent(sev)}`);
      $("#inc-count").textContent = `Showing ${rows.length} incident${rows.length === 1 ? "" : "s"}`;
      $("#inc-list").innerHTML = rows.length
        ? rows.map(r => incCardHTML(r, true)).join("")
        : `<div class="panel"><div class="diag">No incidents match the current filters.</div></div>`;
    }
    $("#inc-q").addEventListener("input", () => load().catch(() => { }));
    $("#inc-sev").addEventListener("click", (e) => {
      const b = e.target.closest(".seg-btn"); if (!b) return;
      $$("#inc-sev .seg-btn").forEach(x => x.classList.remove("on"));
      b.classList.add("on"); sev = b.dataset.v;
      load().catch(() => { });
    });
    await load();
  },

  /* ============ INCIDENT DETAIL ============ */
  async incident(view, id) {
    let d;
    try { d = await api(`/api/incidents/${encodeURIComponent(id)}`); }
    catch (e) {
      view.innerHTML = headHTML("Incident", "");
      view.insertAdjacentHTML("beforeend", `<div class="panel"><div class="diag"><div class="d-row"><span class="bad">✕</span>${esc(e.message)} — reopen from the <a href="#incidents">Incidents page</a>.</div></div></div>`);
      return;
    }
    const k = lvl(d.level);
    view.innerHTML = headHTML(`${LEVEL_WORD[k]} — ${esc(d.entity)}`,
      `${d.incident_id} · ${d.n_events} evidence events · ${d.n_detections} detections`,
      `<button class="btn" id="inc-export">⬇ Export incident report</button>`);

    view.insertAdjacentHTML("beforeend", `
      <div class="kpi-strip">
        ${kpiHTML("Risk Score", `${Number(d.risk).toFixed(1)}<span style="font-size:14px;color:var(--faint)"> / 10</span>`, "explainable breakdown below", `k-${k}`)}
        ${kpiHTML("Severity", LEVEL_WORD[k], d.level.replace(/[^ ]+ /, ""), "")}
        ${kpiHTML("Entity", `<span style="font-size:16px;font-family:var(--mono)">${esc(d.entity)}</span>`, esc(d.first_seen) + " → " + esc(d.last_seen), "k-accent")}
        ${kpiHTML("Evidence", fmt(d.n_events), d.n_detections + " detections", "k-med")}
      </div>
      <div class="grid-side">
        <div>
          <div class="panel"><div class="panel-title"><span class="dot"></span>Why This Was Flagged</div>
            ${breakdownHTML(d.breakdown)}
            <div class="bd-row" style="border-top:1px solid var(--border)">
              <div class="bd-name">TOTAL</div>
              <div class="bd-val" style="font-size:15px">${Number(d.risk).toFixed(1)} <span class="of">/ 10</span></div>
              <div class="bd-mini"><div class="bd-why">${esc(d.risk_total_reason)}</div></div>
            </div>
          </div>
          <div class="panel"><div class="panel-title"><span class="dot"></span>Attack Timeline</div><div id="dt-timeline"></div></div>
        </div>
        <div>
          <div class="panel"><div class="panel-title"><span class="dot"></span>Recommended Response</div><div id="dt-response"></div></div>
          <div class="panel"><div class="panel-title"><span class="dot"></span>Detection Sources</div><div id="dt-dets"></div></div>
        </div>
      </div>
      <div class="panel"><div class="panel-title"><span class="dot"></span>Evidence — ${fmt(d.evidence.length)} raw log lines</div>
        <div class="evidence-scroll"><table class="tbl"><thead><tr>
          <th>timestamp</th><th>source</th><th>user / path</th><th>event</th><th>status</th><th>host</th><th>raw line</th>
        </tr></thead><tbody>
        ${d.evidence.slice(0, 200).map(e => `<tr>
          <td style="font-family:var(--mono);white-space:nowrap">${esc(e.timestamp)}</td>
          <td style="font-family:var(--mono)">${esc(e.source_ip || "-")}</td>
          <td style="font-family:var(--mono)">${esc(e.user || "-")}</td>
          <td>${esc(e.event_type)}</td>
          <td><span class="chip ${e.status === "fail" ? "crit" : e.status === "success" ? "low" : "ghost"}" style="font-size:9px">${esc(e.status || "-")}</span></td>
          <td>${esc(e.host || "-")}</td>
          <td style="font-family:var(--mono);font-size:10.5px;color:var(--muted);max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.raw_line)}</td>
        </tr>`).join("")}
        </tbody></table></div></div>`);

    // timeline bars
    const tl = $("#dt-timeline");
    if (d.timeline.length) {
      const maxE = Math.max(...d.timeline.map(b => b.events));
      tl.innerHTML = d.timeline.map(b => {
        const wF = (b.fails / maxE) * 100, wS = (b.success / maxE) * 100;
        return `<div class="tl-row"><span class="tl-t">${esc(b.t)}</span>
          <div class="tl-track">${wF ? `<div class="tl-fail" style="width:${wF}%"></div>` : ""}${wS ? `<div class="tl-ok" style="width:${wS}%"></div>` : ""}</div>
          <span class="tl-meta">${b.events} events${b.fails ? ` · <span class="f">${b.fails} failed</span>` : ""}${b.success ? ` · <span class="s">${b.success} ok</span>` : ""}</span></div>`;
      }).join("");
    } else tl.innerHTML = '<div class="diag">No timeline data.</div>';

    // response
    const resp = $("#dt-response");
    if (d.summary || d.actions.length) {
      resp.innerHTML =
        (d.summary ? `<div style="font-size:13px;color:var(--muted);line-height:1.65;margin-bottom:10px">${esc(d.summary)}</div>` : "") +
        d.actions.map((a, i) => `<div class="diag"><div class="d-row"><span class="ok">${i + 1}.</span>${esc(a)}</div></div>`).join("") +
        (d.llm_fallback ? `<div style="font-size:10.5px;color:var(--faint);margin-top:10px">[built-in playbook — set GEMINI_API_KEY for AI-written guidance]</div>` : "");
    } else resp.innerHTML = '<div class="diag">No recommendation cached.</div>';

    // detections
    $("#dt-dets").innerHTML = d.detections.map(x => `
      <div class="det-row">
        <div class="d-head"><span class="${x.kind === "ml" ? "badge-ml" : "badge-rule"}">${x.kind.toUpperCase()}</span>${esc(x.name)}</div>
        <div class="d-desc">${esc(x.description)}</div>
      </div>`).join("");

    $("#inc-export").addEventListener("click", async () => {
      const md = await api(`/api/reports/incident/${encodeURIComponent(d.incident_id)}`);
      download(`${d.incident_id}_report.md`, md, "text/markdown");
      toast("Incident report downloaded");
    });
  },

  /* ============ RISK PROFILES ============ */
  async profiles(view, sel) {
    view.innerHTML = headHTML('Risk <span class="thin">Profiles</span>', "Per-entity risk posture and how it evolved over time — dynamic risk profiling");
    let entities;
    try { entities = await api("/api/entities"); }
    catch (e) { return this.empty(view); }
    if (!entities.length) return this.empty(view);

    view.insertAdjacentHTML("beforeend", `
      <div class="panel"><div style="display:flex;gap:10px;flex-wrap:wrap">
        ${entities.map(e => `<button class="seg-btn ${e.entity === sel ? "on" : ""}" data-e="${esc(e.entity)}"
          style="border:1px solid var(--border);border-radius:8px;padding:7px 13px;background:var(--surface-2)">
          ${esc(e.entity)} <b style="color:var(--${{ crit: "crit", high: "high", med: "med", low: "low" }[lvl(e.level)]})">${Number(e.risk).toFixed(1)}</b></button>`).join("")}
      </div></div>
      <div id="pf-body"></div>`);

    const pick = sel && entities.some(e => e.entity === sel) ? entities.find(e => e.entity === sel) : entities[0];
    $$("#view [data-e]").forEach(b => b.addEventListener("click", () => { location.hash = `profiles/${encodeURIComponent(b.dataset.e)}`; }));

    const e = pick;
    $("#pf-body").innerHTML = `
      <div class="kpi-strip">
        ${kpiHTML("Risk Score", `${Number(e.risk).toFixed(1)}<span style="font-size:14px;color:var(--faint)"> / 10</span>`, e.incident_id, `k-${lvl(e.level)}`)}
        ${kpiHTML("Events", fmt(e.n_events), "attributed to entity", "k-accent")}
        ${kpiHTML("Failed Auth", fmt(e.n_fail), "401/403 or SSH fails", e.n_fail ? "k-high" : "k-low")}
        ${kpiHTML("Anomalies", e.n_anomalies, "ML windows", e.n_anomalies ? "k-med" : "k-low")}
      </div>
      <div class="grid-2">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Behavior Over Time</div><div id="pf-line"></div>
          <div style="font-size:11px;color:var(--faint);margin-top:8px">Risk signal per 10-min bin: failed requests + attack indicators + compromise bonus. Rising line = escalating behavior.</div></div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Profile</div>
          <div class="diag" style="font-size:13px;line-height:2">
            <div class="d-row"><span style="width:110px;color:var(--faint)">ENTITY</span><b style="font-family:var(--mono)">${esc(e.entity)}</b></div>
            <div class="d-row"><span style="width:110px;color:var(--faint)">TYPE</span>${e.user ? "User + IP" : "IP Address"}</div>
            <div class="d-row"><span style="width:110px;color:var(--faint)">SEVERITY</span><span class="chip ${lvl(e.level)}">${LEVEL_WORD[lvl(e.level)]}</span></div>
            <div class="d-row"><span style="width:110px;color:var(--faint)">FIRST SEEN</span>${esc(e.first_seen)}</div>
            <div class="d-row"><span style="width:110px;color:var(--faint)">LAST SEEN</span>${esc(e.last_seen)}</div>
            <div class="d-row"><span style="width:110px;color:var(--faint)">DETECTIONS</span>${e.n_detections}</div>
          </div>
          ${e.recommendation ? `<div style="font-size:12px;color:var(--muted);line-height:1.65;margin-top:12px;border-top:1px solid var(--border);padding-top:10px">${esc(e.recommendation)}…</div>` : ""}
          <div style="margin-top:14px"><a class="btn primary" href="#incident/${e.incident_id}">Open full incident →</a></div>
        </div>
      </div>`;
    riskLine($("#pf-line"), e.behavior);
  },

  /* ============ THREAT INTEL ============ */
  async intel(view) {
    view.innerHTML = headHTML('Threat <span class="thin">Intelligence</span>', "Source reputation built from observed evidence in this dataset");
    let rows;
    try { rows = await api("/api/intel"); }
    catch (e) { return this.empty(view); }

    view.insertAdjacentHTML("beforeend", `
      <div class="panel"><div class="diag">
        <div class="d-row"><span class="ok">✓</span><span><b>Evidence-based:</b> everything below is computed from the analyzed log — internal (RFC1918) vs external classification, observed attack volume, activity windows.</span></div>
        <div class="d-row"><span style="color:var(--high)">◌</span><span><b>External feeds (AbuseIPDB, VirusTotal, OTX):</b> not integrated. Planned as an optional module behind the same incident pipeline — nothing on this page is fabricated.</span></div>
      </div></div>
      <div class="panel"><div class="panel-title"><span class="dot"></span>Source Reputation <span class="right">local evidence</span></div>
        ${rows.map(r => `
          <div class="inc-card" style="cursor:default">
            <div class="inc-main">
              <div class="inc-title" style="font-size:13.5px"><span class="ent">${esc(r.ip)}</span>
                <span class="chip ${r.zone === "external" ? "crit" : "ghost"}" style="margin-left:8px">${esc(r.zone)}</span></div>
              <div class="inc-sub">${fmt(r.events)} events · ${fmt(r.fails)} failed · active ${esc(String(r.first))} → ${esc(String(r.last))}</div>
            </div>
            <div class="score-badge ${scoreCls(r.risk)}">${Number(r.risk).toFixed(1)}</div>
          </div>`).join("")}
      </div>`);
  },

  /* ============ REPORTS ============ */
  async reports(view) {
    view.innerHTML = headHTML('Reports', "Shareable audit reports — summary, incidents, risk breakdowns, evidence");
    view.insertAdjacentHTML("beforeend", `
      <div class="grid-side">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Full Run Report</div>
          <div style="font-size:12.5px;color:var(--muted);margin-bottom:12px">Executive summary · severity counts · every incident with score breakdown · pipeline stats.</div>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <button class="btn primary" id="rp-md">⬇ Markdown</button>
            <button class="btn" id="rp-preview">Preview</button>
          </div>
          <div id="rp-prev" style="display:none;margin-top:12px"></div>
        </div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Data Export</div>
          <div style="display:flex;flex-direction:column;gap:9px">
            <button class="btn wide" id="ex-inc">⬇ incidents.csv</button>
            <button class="btn wide" id="ex-det">⬇ detections.csv</button>
            <button class="btn wide" id="ex-json">⬇ analysis.json</button>
          </div>
        </div>
      </div>
      <div class="panel"><div class="panel-title"><span class="dot"></span>Per-Incident Reports</div><div id="rp-list"></div></div>`);

    $("#rp-md").addEventListener("click", async () => {
      const md = await api("/api/reports/run");
      download("security_run_report.md", md, "text/markdown");
      toast("Run report downloaded");
    });
    $("#rp-preview").addEventListener("click", async () => {
      const md = await api("/api/reports/run");
      const p = $("#rp-prev");
      p.style.display = "block";
      p.innerHTML = `<pre style="white-space:pre-wrap;font-family:var(--mono);font-size:11.5px;color:var(--muted);max-height:320px;overflow:auto;border:1px solid var(--border);border-radius:10px;padding:14px">${esc(md.slice(0, 6000))}${md.length > 6000 ? "\n\n…(truncated — download for full report)" : ""}</pre>`;
    });
    $("#ex-inc").addEventListener("click", async () => download("incidents.csv", await api("/api/exports/incidents.csv"), "text/csv"));
    $("#ex-det").addEventListener("click", async () => download("detections.csv", await api("/api/exports/detections.csv"), "text/csv"));
    $("#ex-json").addEventListener("click", async () => download("analysis.json", await api("/api/exports/analysis.json"), "application/json"));

    const rows = await api("/api/incidents");
    $("#rp-list").innerHTML = rows.map(r => `
      <div class="inc-card" style="cursor:default">
        <span class="chip ${lvl(r.level)}">${LEVEL_WORD[lvl(r.level)]}</span>
        <div class="inc-main">
          <div class="inc-title" style="font-size:13px">${esc(r.incident_id)} · <span class="ent">${esc(r.entity)}</span></div>
          <div class="inc-sub">${esc(r.attack)} · ${fmt(r.n_events)} evidence events</div>
        </div>
        <button class="btn" data-dl="${esc(r.incident_id)}">⬇</button>
      </div>`).join("");
    $$("#rp-list [data-dl]").forEach(b => b.addEventListener("click", async () => {
      const md = await api(`/api/reports/incident/${b.dataset.dl}`);
      download(`${b.dataset.dl}_report.md`, md, "text/markdown");
      toast(`${b.dataset.dl} report downloaded`);
    }));
  },

  /* ============ SETTINGS ============ */
  async settings(view) {
    view.innerHTML = headHTML('Settings', "System configuration and detection transparency");
    const s = await api("/api/settings");
    view.insertAdjacentHTML("beforeend", `
      <div class="grid-2">
        <div class="panel"><div class="panel-title"><span class="dot"></span>Detection Engine</div>
          <div class="diag" style="line-height:1.9">
            <div class="d-row"><b>Rule engine</b>&nbsp;— ${s.rules.count} rules over normalized events</div>
            <div class="d-row" style="color:var(--faint);padding-left:14px">SSH: ${esc(s.rules.ssh.join(" · "))}</div>
            <div class="d-row" style="color:var(--faint);padding-left:14px">Web: ${esc(s.rules.web.join(" · "))}</div>
            <div class="d-row"><b>ML anomaly detection</b>&nbsp;— ${esc(s.ml.model)}</div>
            <div class="d-row" style="color:var(--faint);padding-left:14px">Unsupervised · ${s.ml.trees} trees · contamination ${s.ml.contamination} · ${esc(s.ml.windows)} · ${s.ml.features} engineered features · z-score driver attribution</div>
            <div class="d-row"><b>Scoring</b>&nbsp;— 6-component explainable model, ${esc(s.scoring.range)}</div>
            <div class="d-row" style="color:var(--faint);padding-left:14px">${esc(s.scoring.components.join(" · "))}</div>
          </div></div>
        <div class="panel"><div class="panel-title"><span class="dot"></span>Recommendation Engine</div>
          <div class="diag" style="line-height:2">
            <div class="d-row">Active mode: <b style="color:var(--bl-300)">&nbsp;${esc(s.recommendation.mode)}</b></div>
            <div class="d-row">Provider chain: Gemini → deterministic playbook</div>
            <div class="d-row"><span class="chip ${s.recommendation.gemini_key ? "low" : "med"}">GEMINI_API_KEY: ${s.recommendation.gemini_key ? "set" : "not set"}</span></div>
            <div class="d-row" style="color:var(--faint)">Prompts are built from structured incident data — never raw log dumps.</div>
          </div></div>
      </div>
      <div class="panel"><div class="panel-title"><span class="dot"></span>System</div>
        <div class="diag">
          <div class="d-row">Python ${esc(s.runtime.python)} · storage: ${esc(s.runtime.storage)} · parsers: ${esc(s.runtime.parsers)}</div>
          <div class="d-row" style="color:var(--faint)">Recommendation cache: per-incident, persisted in SQLite. No external network calls except optional LLM APIs for recommendations.</div>
        </div></div>`);
  },
};

/* ---------------- router ---------------- */

const ROUTES = [
  { re: /^#\/?$/, view: "overview" },
  { re: /^#\/?overview$/, view: "overview" },
  { re: /^#\/?analyze$/, view: "analyze" },
  { re: /^#\/?incidents$/, view: "incidents" },
  { re: /^#\/?incident\/([^/]+)$/, view: "incident" },
  { re: /^#\/?profiles(?:\/([^/]+))?$/, view: "profiles" },
  { re: /^#\/?intel$/, view: "intel" },
  { re: /^#\/?reports$/, view: "reports" },
  { re: /^#\/?settings$/, view: "settings" },
];

let navToken = 0;

async function route() {
  const h = location.hash || "#overview";
  const view = $("#view");
  for (const r of ROUTES) {
    const m = h.match(r.re);
    if (!m) continue;
    $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.nav === r.view));
    const token = ++navToken;
    try {
      await Views[r.view](view, m[1] ? decodeURIComponent(m[1]) : undefined);
    } catch (e) {
      if (token !== navToken) return;      // superseded navigation
      view.insertAdjacentHTML("beforeend", `<div class="panel"><div class="diag"><div class="d-row"><span class="bad">✕</span>${esc(e.message)}</div></div></div>`);
    }
    return;
  }
  location.hash = "#overview";
}

window.addEventListener("hashchange", route);

/* sidebar navigation — the .nav-item divs only had styling, never a handler */
$$(".nav-item").forEach(n => {
  n.setAttribute("role", "link");
  n.addEventListener("click", () => {
    const target = "#" + n.dataset.nav;
    if (location.hash === target) route();   // re-click same section: re-render
    else location.hash = target;
  });
});

/* ---------------- reset button (sidebar, persistent) ---------------- */

let resetArmTimer = null;

document.getElementById("reset-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (!btn.classList.contains("arm")) {          // first click: arm (two-step confirm)
    btn.classList.add("arm");
    clearTimeout(resetArmTimer);
    resetArmTimer = setTimeout(() => btn.classList.remove("arm"), 3500);
    return;
  }
  btn.classList.remove("arm");                   // second click: confirm
  clearTimeout(resetArmTimer);
  btn.disabled = true;
  try {
    const res = await api("/api/reset", { method: "POST" });
    toast(res.message || "Analysis cleared");
    $("#rail-status").innerHTML = `<b><span class="pulse-dot off"></span>AWAITING DATA</b><br>No analysis loaded.<br>Run the demo or upload logs.`;
    navToken++;                                  // cancel in-flight view loads
    if (location.hash && location.hash !== "#analyze") location.hash = "#analyze";
    else route();
  } catch (err) {
    toast(err.status === 405
      ? "Reset not supported by the running server — restart uvicorn to pick up the latest code."
      : (err.message || "Reset failed"));
  } finally {
    btn.disabled = false;
  }
});

route();   // views handle the empty (no-analysis) state themselves

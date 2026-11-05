"use strict";
// Networks, device risk, the network health score, connection readiness,
// the best-time heatmap and the details panel's Ping / Merge tools. Shares
// helpers and `state` with app.js, which loads after this file.

// ------------------------------------------------------------------ networks

// Each network is identified by its router's MAC address.
const currentNetwork = () => state.net?.gateway_mac || null;

function networkName(gw) {
  const g = state.devices.find((d) => d.is_gateway && d.mac === gw);
  if (!g) return "Unknown network";
  if (g.label) return g.label;
  if (g.ip === "172.20.10.1") return "iPhone hotspot";
  if (gw === currentNetwork() && state.router?.identity?.model) return `${state.router.identity.manufacturer || ""} ${state.router.identity.model}`.trim();
  if (g.model) return `${(g.vendor || "").split(/[ ,]/)[0]} ${g.model}`.trim();
  return deviceName(g);
}

// Networks this computer has been on, the current one first.
function knownNetworks() {
  const cur = currentNetwork();
  return state.devices
    .filter((d) => d.is_gateway)
    .sort((a, b) => (b.mac === cur) - (a.mac === cur) || b.last_seen - a.last_seen)
    .map((g) => ({ id: g.mac, name: networkName(g.mac), current: g.mac === cur, last_seen: g.last_seen }));
}

const onNetwork = (d, net) => d.is_self || d.network === net || (d.network == null && net === currentNetwork());

// ------------------------------------------------------------------ device risk

// How much attention a device deserves, from what NetWatch has seen of it.
// Returns { score 0–100, level none|low|medium|high, reasons: [text] }.
function deviceRisk(d) {
  if (d.is_self) return { score: 0, level: "none", reasons: [] };
  let score = 0;
  const reasons = [];
  const add = (pts, why) => { score += pts; reasons.push(why); };
  for (const p of d.open_ports || []) {
    if (RISKY_PORTS.has(p)) add(35, `${PORT_LABEL[p]} (port ${p}) is open; it's often unencrypted or a common target`);
    else if ([22, 139, 445, 1883].includes(p)) add(8, `${PORT_LABEL[p]} (port ${p}) accepts connections`);
  }
  const forwards = (state.router?.mappings || []).filter((m) => m.internal_client === d.ip && onNetwork(d, currentNetwork()));
  if (forwards.length) add(30, `Reachable from the internet through ${forwards.length} port forward${forwards.length > 1 ? "s" : ""} (${forwards.map((m) => `${m.protocol} ${m.external_port}`).join(", ")})`);
  for (const a of openAlerts().filter((a) => a.key === d.mac || a.key === d.ip || (d.aliases || []).includes(a.key))) {
    if (a.severity === "high") add(30, a.title);
    else if (a.severity === "medium") add(15, a.title);
    else add(5, a.title);
  }
  if (!d.trusted && !d.is_gateway) add(15, "Not marked as trusted yet");
  if (!d.label && !d.hostname && !d.friendly_name && !d.vendor && !d.model) add(10, "NetWatch couldn't identify it");
  score = Math.min(100, score);
  const level = score >= 50 ? "high" : score >= 20 ? "medium" : score > 0 ? "low" : "none";
  return { score, level, reasons };
}

const RISK_WORD = { none: "No concerns", low: "Low", medium: "Worth a look", high: "High" };

function riskiestHtml(limit = 6) {
  const list = state.devices
    .filter((d) => onNetwork(d, currentNetwork()) && !d.is_self)
    .map((d) => [d, deviceRisk(d)])
    .filter(([, r]) => r.score > 0)
    .sort((a, b) => b[1].score - a[1].score)
    .slice(0, limit);
  if (!list.length) return `<div class="empty">Nothing stands out. Every device on this network is trusted, with no risky ports or open alerts.</div>`;
  return list.map(([d, r]) => `<div class="dev-mini click" data-mac="${esc(d.mac)}">
      <span class="risk-pill ${r.level}">${r.score}</span>
      <div class="grow"><div class="truncate">${esc(deviceName(d))}</div><div class="muted small truncate" title="${esc(r.reasons.join(" · "))}">${esc(r.reasons[0])}${r.reasons.length > 1 ? ` · +${r.reasons.length - 1} more` : ""}</div></div>
    </div>`).join("");
}

// ------------------------------------------------------------------ health score

// One number for "how is my network doing", with what costs points.
function healthScore() {
  const parts = [];
  const take = (pts, why, goto) => { if (pts > 0) parts.push({ pts: Math.round(pts), why, goto }); };
  const recent = state.health.slice(-60);
  const lat = recent.map((h) => h.internet_ms).filter((v) => v != null);
  if (recent.length) {
    const loss = 1 - lat.length / recent.length;
    take(Math.min(25, loss * 60), `${Math.round(loss * 100)}% of recent connection checks failed`, "network");
    const med = median(lat);
    if (med != null) take(med > 150 ? 15 : med > 80 ? 8 : 0, `Internet latency is high (${fmtMs(med)})`, "network");
  }
  if (state.outage) take(30, "The internet is down right now", "network");
  const outs = state.outages.filter((o) => o.start > Date.now() - 86_400_000).length;
  take(Math.min(20, outs * 5), `${outs} outage${outs > 1 ? "s" : ""} in the last 24 hours`, "history");
  const open = openAlerts();
  const high = open.filter((a) => a.severity === "high").length;
  const med = open.filter((a) => a.severity === "medium").length;
  take(Math.min(30, high * 10), `${high} high-severity alert${high > 1 ? "s" : ""} open`, "alerts");
  take(Math.min(16, med * 4), `${med} medium alert${med > 1 ? "s" : ""} open`, "alerts");
  if (typeof securityChecks === "function") {
    const checks = securityChecks();
    const bad = checks.filter((c) => c.status === "bad").length;
    const warn = checks.filter((c) => c.status === "warn").length;
    take(Math.min(24, bad * 8 + warn * 3), `${bad + warn} security check${bad + warn > 1 ? "s need" : " needs"} attention`, "security");
  }
  const untrusted = state.devices.filter((d) => d.online && !d.trusted && onNetwork(d, currentNetwork())).length;
  take(Math.min(12, untrusted * 3), `${untrusted} untrusted device${untrusted > 1 ? "s" : ""} online`, "devices");
  parts.sort((a, b) => b.pts - a.pts);
  const score = Math.max(0, 100 - parts.reduce((a, p) => a + p.pts, 0));
  const level = score >= 85 ? "good" : score >= 60 ? "warn" : "bad";
  return { score, level, parts };
}

function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

function gaugeSvg(score, level) {
  const r = 46, c = 2 * Math.PI * r;
  return `<svg class="gauge ${level}" viewBox="0 0 120 120" width="120" height="120" role="img" aria-label="Score ${score} out of 100">
    <circle class="track" cx="60" cy="60" r="${r}"/>
    <circle class="fill" cx="60" cy="60" r="${r}" stroke-dasharray="${(score / 100) * c} ${c}" transform="rotate(-90 60 60)"/>
    <text x="60" y="66" text-anchor="middle">${score}</text></svg>`;
}

function renderScorePanel() {
  const el = $("#ov-score");
  if (!el) return;
  const { score, level, parts } = healthScore();
  const word = level === "good" ? "Healthy" : level === "warn" ? "Needs a little attention" : "Needs attention";
  el.innerHTML = `
    <div class="panel-head"><h2>Network health</h2><span class="muted small">connection, alerts, security and devices</span></div>
    <div class="score-wrap">${gaugeSvg(score, level)}
      <div class="grow"><div class="score-word">${word}</div>
        ${parts.length
          ? `<ul class="score-parts">${parts.slice(0, 5).map((p) => `<li class="click" data-goto="${p.goto}"><span>${esc(p.why)}</span><b>−${p.pts}</b></li>`).join("")}</ul>`
          : `<p class="muted">Nothing is costing points right now.</p>`}
      </div></div>`;
}

// ------------------------------------------------------------------ readiness

// Whether the connection is good enough for common things, from the last
// ~10 minutes of checks and the latest speed test.
function readiness() {
  const recent = state.health.slice(-60);
  const lat = recent.map((h) => h.internet_ms).filter((v) => v != null);
  if (lat.length < 5) return null;
  const loss = 100 * (1 - lat.length / recent.length);
  const ping = median(lat);
  let jit = 0;
  for (let i = 1; i < lat.length; i++) jit += Math.abs(lat[i] - lat[i - 1]);
  jit /= Math.max(1, lat.length - 1);
  const st = [...state.speedtests].reverse().find((r) => Date.now() - r.ts < 7 * 86_400_000);
  const down = st?.down_mbps, up = st?.up_mbps;
  const rate = (ok, fine) => (ok ? "good" : fine ? "warn" : "bad");
  const rows = [
    { name: "Browsing and email", r: rate(ping < 150 && loss < 3, ping < 400 && loss < 10), why: `${fmtMs(ping)} latency` },
    { name: "Video calls", r: rate(ping < 100 && jit < 20 && loss < 1 && (up ?? 3) >= 3, ping < 200 && jit < 40 && loss < 3 && (up ?? 1.5) >= 1.5), why: `jitter ±${Math.round(jit)} ms, ${loss.toFixed(loss < 1 ? 1 : 0)}% loss${up != null ? `, ${up} Mb/s up` : ""}` },
    { name: "Online gaming", r: rate(ping < 50 && jit < 10 && loss < 0.5, ping < 90 && jit < 25 && loss < 2), why: `${fmtMs(ping)} latency, jitter ±${Math.round(jit)} ms` },
    { name: "HD streaming", r: down == null ? "unknown" : rate(down >= 10, down >= 5), why: down != null ? `${down} Mb/s down` : "run a speed test to rate this" },
    { name: "4K streaming", r: down == null ? "unknown" : rate(down >= 25, down >= 15), why: down != null ? `${down} Mb/s down` : "run a speed test to rate this" },
    { name: "Big downloads and backups", r: down == null ? "unknown" : rate(down >= 50 && (up ?? 0) >= 10, down >= 15), why: down != null ? `${down} down / ${up} up Mb/s` : "run a speed test to rate this" },
  ];
  return { rows, ping, jit, loss, st };
}

const READY_WORD = { good: "Great", warn: "OK", bad: "Poor", unknown: "Unknown" };

function readinessHtml() {
  const r = readiness();
  if (!r) return `<div class="empty">Collecting connection checks…</div>`;
  return `<div class="ready-list">${r.rows.map((x) => `<div class="ready-row"><span class="ready-badge ${x.r}">${READY_WORD[x.r]}</span><span class="grow">${esc(x.name)}</span><span class="muted small">${esc(x.why)}</span></div>`).join("")}</div>
    <p class="muted small" style="margin:10px 0 0">From the last ${Math.round(state.health.slice(-60).length / 6)} minutes of checks${r.st ? ` and the speed test ${ago(r.st.ts)}` : ""}.</p>`;
}

function renderReadiness() {
  for (const id of ["#ov-ready", "#net-ready"]) {
    const el = $(id);
    if (el) el.innerHTML = readinessHtml();
  }
}

// ------------------------------------------------------------------ best time heatmap

const heat = { data: null, at: 0, metric: "latency" };

async function loadHeat() {
  heat.at = Date.now();
  try { heat.data = await invoke("get_history", { range: "30d" }); } catch { heat.data = []; }
  if (state.view === "history") render();
}

// Weekday × 2-hour grid of the last 30 days: when the connection is at its best.
function renderHeatmap() {
  const el = $("#hist-heat");
  if (!el) return;
  if (!heat.data || Date.now() - heat.at > 10 * 60_000) { if (Date.now() - heat.at > 5000) loadHeat(); }
  const cells = Array.from({ length: 7 }, () => Array.from({ length: 12 }, () => ({ n: 0, lat: 0, loss: 0 })));
  for (const p of heat.data || []) {
    const t = new Date(p.t + 3_600_000);
    const c = cells[(t.getDay() + 6) % 7][Math.floor(t.getHours() / 2)];
    if (p.inet_ms != null) { c.lat += p.inet_ms; c.n++; }
    if (p.loss != null) c.loss = Math.max(c.loss, p.loss);
  }
  const vals = cells.flat().filter((c) => c.n).map((c) => (heat.metric === "latency" ? c.lat / c.n : c.loss));
  if (!vals.length) { el.innerHTML = `<div class="empty">Not enough history yet. NetWatch needs a few days of checks to show patterns.</div>`; return; }
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  let best = null;
  let rows = "";
  cells.forEach((row, di) => {
    rows += `<div class="heat-row"><span>${days[di]}</span>${row.map((c, hi2) => {
      if (!c.n) return `<i class="none" data-tip="${days[di]} ${hi2 * 2}:00–${hi2 * 2 + 2}:00 · no data"></i>`;
      const v = heat.metric === "latency" ? c.lat / c.n : c.loss;
      const k = hi > lo ? (v - lo) / (hi - lo) : 0;
      const score = (c.lat / c.n) * (1 + c.loss / 5);
      if (!best || score < best.score) best = { score, di, h: hi2 * 2 };
      return `<i style="--k:${k.toFixed(3)}" data-tip="${days[di]} ${hi2 * 2}:00–${hi2 * 2 + 2}:00 · ${fmtMs(c.lat / c.n)} avg · ${c.loss.toFixed(1)}% worst loss"></i>`;
    }).join("")}</div>`;
  });
  const axis = `<div class="heat-row axis"><span></span>${Array.from({ length: 12 }, (_, i) => `<b>${i % 3 === 0 ? `${i * 2}:00` : ""}</b>`).join("")}</div>`;
  el.innerHTML = `${best ? `<p class="heat-best">Best time for big downloads and updates: <b>${["Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays", "Sundays"][best.di]} ${best.h}:00–${best.h + 2}:00</b></p>` : ""}
    <div class="heat">${rows}${axis}</div>
    <div class="heat-scale"><span>${heat.metric === "latency" ? fmtMs(lo) : `${lo.toFixed(1)}%`}</span><i></i><span>${heat.metric === "latency" ? fmtMs(hi) : `${hi.toFixed(1)}%`}</span></div>`;
}

// ------------------------------------------------------------------ details panel: ping and merge

const pings = new Map(); // mac → { running, results: [ms|null] }

async function pingNow(mac) {
  pings.set(mac, { running: true, results: [] });
  state.drawerSig = "";
  render();
  try {
    pings.set(mac, { running: false, results: await invoke("ping_device", { mac, count: 5 }) });
  } catch (e) {
    pings.set(mac, { running: false, results: [], error: String(e) });
  }
  state.drawerSig = "";
  render();
}

function pingHtml(d) {
  const p = pings.get(d.mac);
  let out = "";
  if (p?.running) out = `<span class="muted">Pinging…</span>`;
  else if (p?.error) out = `<span class="muted">${esc(p.error)}</span>`;
  else if (p) {
    const ok = p.results.filter((v) => v != null);
    const lost = p.results.length - ok.length;
    out = `<div class="port-list">${p.results.map((v) => `<span class="chip ${v == null ? "bad" : ""}">${v == null ? "lost" : fmtMs(v)}</span>`).join("")}</div>
      <div class="muted small" style="margin-top:6px">${ok.length ? `min ${fmtMs(Math.min(...ok))} · avg ${fmtMs(ok.reduce((a, b) => a + b, 0) / ok.length)} · max ${fmtMs(Math.max(...ok))} · ` : ""}${lost ? `${lost} of ${p.results.length} lost` : "no loss"}</div>`;
  }
  const here = onNetwork(d, currentNetwork());
  return `<div class="row"><button class="btn" data-action="ping-now" ${p?.running || !here ? "disabled" : ""}>Ping now</button>${here ? "" : `<span class="muted small">Only devices on the network you're on now</span>`}</div>${out ? `<div style="margin-top:10px">${out}</div>` : ""}`;
}

function mergeHtml(d) {
  if (d.is_gateway) return "";
  const others = state.devices.filter((x) => x.mac !== d.mac && !x.is_gateway && (!d.is_self || !x.is_self));
  if (!others.length) return "";
  others.sort((a, b) => deviceName(a).localeCompare(deviceName(b)));
  return `<div>
    <h3>Same device?</h3>
    <p class="muted small" style="margin:0 0 8px">Phones and laptops use a different private address on each network, and some change it over time. NetWatch merges these automatically when it can tell; merge by hand when you know two entries are one device.</p>
    <div class="row"><select id="merge-with" aria-label="Device to merge with"><option value="">Merge with…</option>${others.map((x) => `<option value="${esc(x.mac)}">${esc(deviceName(x))} · ${esc(x.ip)} · ${esc(x.mac)}</option>`).join("")}</select>
    <button class="btn" data-action="merge">Merge</button></div></div>`;
}

async function mergeDevices(mac) {
  const other = $("#merge-with")?.value;
  if (!other) return;
  const a = state.devices.find((x) => x.mac === mac), b = state.devices.find((x) => x.mac === other);
  if (!confirm(`Merge "${deviceName(b)}" into "${deviceName(a)}"? Their history, names, notes and tags are combined into one entry.`)) return;
  const keep = await call("merge_devices", { a: mac, b: other });
  state.drawerMac = keep;
  state.drawerSig = "";
  toast({ severity: "info", title: "Merged", detail: "The two entries are now one device." });
}

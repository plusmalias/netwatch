"use strict";
// The menu-bar popover. Draws the summary the backend builds (get_mini) and
// polls it only while the popover is showing; Rust says when that is.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const POLL_MS = 2000;
const SPARK_SPAN = 10 * 60_000;
const ACCESS_NOTE = "macOS asks again after every restart.";
let timer = null;
let accessError = "";

const $ = (sel) => document.querySelector(sel);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function fmtBits(bps) {
  if (!bps) return "0 b/s";
  const units = ["b/s", "Kb/s", "Mb/s", "Gb/s"];
  let i = 0;
  while (bps >= 1000 && i < units.length - 1) { bps /= 1000; i++; }
  return `${bps >= 100 || i === 0 ? Math.round(bps) : bps.toFixed(1)} ${units[i]}`;
}

function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

const fmtMs = (ms) => (ms == null ? "—" : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`);

function ago(ts) {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const SEV_ICON = {
  high: '<svg viewBox="0 0 24 24"><path d="M12 3 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/></svg>',
  medium: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg>',
  low: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11v5.5"/></svg>',
};

const CAPTURE_LABEL = {
  stopped: "Capture off",
  needs_permission: "Capture needs access",
  unavailable: "Capture unavailable",
  error: "Capture error",
};

// The last ten minutes of internet round trips; a missed check is a red tick.
function sparkline(samples) {
  if (samples.length < 2) return "";
  const W = 70, H = 22;
  const t1 = Date.now(), t0 = t1 - SPARK_SPAN;
  const max = Math.max(50, ...samples.map(([, v]) => v ?? 0));
  let d = "", pen = false, fails = "";
  for (const [ts, v] of samples) {
    const x = Math.min(W - 1, Math.max(1, ((ts - t0) / SPARK_SPAN) * (W - 2) + 1));
    if (v == null) { pen = false; fails += `<rect class="spark-fail" x="${(x - 1).toFixed(1)}" y="0" width="2" height="${H}"/>`; continue; }
    const y = H - 2 - (v / max) * (H - 4);
    d += `${pen ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
    pen = true;
  }
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${fails}<path d="${d}"/></svg>`;
}

function renderHead(m) {
  document.documentElement.dataset.theme = m.theme || "light";
  $("#m-dot").className = `dot ${m.level}`;
  $("#m-status").textContent = m.status;
  const c = m.capture;
  $("#m-sub").textContent = c.state === "running" ? `Monitoring ${c.interface || ""}`.trim() : CAPTURE_LABEL[c.state] || c.state;

  const access = $("#m-access");
  access.hidden = c.state !== "needs_permission";
  $("#m-access-msg").textContent = accessError || ACCESS_NOTE;
}

function renderRows(m) {
  const d = m.devices;
  $("#m-devices").textContent = `${d.online} online`;
  $("#m-devices-sub").textContent = `${d.asleep ? `${d.asleep} asleep · ` : ""}${d.total} seen`;

  const lastCheck = m.latency[m.latency.length - 1];
  $("#m-inet").textContent = m.internet_ms != null ? fmtMs(m.internet_ms) : lastCheck && lastCheck[1] == null ? "No reply" : "—";
  $("#m-router").textContent = `router ${fmtMs(m.router_ms)}`;
  $("#m-spark").innerHTML = sparkline(m.latency);

  const r = m.rates;
  $("#m-speed-k").textContent = r && !r.household ? "This computer" : "Network";
  $("#m-speed").textContent = r ? `↓ ${fmtBits(r.down_bps)}   ↑ ${fmtBits(r.up_bps)}` : "No live reading";

  $("#m-data").textContent = m.today_bytes != null ? fmtBytes(m.today_bytes) : "—";
  const cap = m.cap;
  const level = !cap ? "" : cap.pct >= 100 ? "bad" : cap.pct >= 80 ? "warn" : "";
  $("#m-meter").innerHTML = cap ? `<div class="meter ${level}"><i style="width:${Math.min(100, cap.pct).toFixed(1)}%"></i></div>` : "";
  $("#m-data-sub").textContent = cap ? `${Math.round(cap.pct)}% of ${fmtBytes(cap.cap_bytes)}` : m.today_bytes == null ? "router doesn't report usage" : "";
}

function renderAlerts(m) {
  $("#m-alerts-head").textContent = m.open_alerts ? `Alerts · ${m.open_alerts} open` : "Alerts";
  const rows = m.alerts.map((a) => `<button class="mini-alert ${esc(a.severity)}" data-act="alerts" title="${esc(a.title)}">
      <span class="sev ${esc(a.severity)}">${SEV_ICON[a.severity] || ""}</span>
      <span class="title">${esc(a.title)}</span><span class="time">${ago(a.last_ts)}</span></button>`);
  const more = m.open_alerts - m.alerts.length;
  if (more > 0) rows.push(`<button class="btn link small mini-more" data-act="alerts">View ${more} more</button>`);
  $("#m-alerts").innerHTML = rows.length ? rows.join("") : '<div class="mini-none">No open alerts.</div>';
}

function render(m) {
  renderHead(m);
  renderRows(m);
  renderAlerts(m);
  const scan = $("#m-scan");
  scan.disabled = m.scanning;
  scan.textContent = m.scanning ? "Scanning…" : "Scan now";
}

async function refresh() {
  try {
    render(await invoke("get_mini"));
  } catch (e) {
    // Keep showing the last summary; the next poll tries again.
  }
}

function start() {
  if (timer) return;
  refresh();
  timer = setInterval(refresh, POLL_MS);
}

function stop() {
  clearInterval(timer);
  timer = null;
}

async function grant(btn) {
  btn.disabled = true;
  accessError = "";
  try {
    await invoke("grant_capture_access");
  } catch (e) {
    accessError = String(e);
  } finally {
    btn.disabled = false;
  }
  refresh();
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-act]");
  if (!btn) return;
  switch (btn.dataset.act) {
    case "open": return invoke("show_main", {});
    case "alerts": return invoke("show_main", { view: "alerts" });
    case "scan": return invoke("scan_network").then(refresh);
    case "grant": return grant(btn);
  }
});

async function init() {
  // Rust shows and hides this window; polling follows it.
  listen("mini-shown", start);
  listen("mini-hidden", stop);
  await refresh();
}

init();

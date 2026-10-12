"use strict";
// The Timeline page: one history of what happened on the network, built
// from alerts, device sessions, outages, mobile link changes and speed tests.
// Shares helpers and `state` with app.js, which loads after this file.

const TL_DAYS = 7;

function timelineEvents() {
  const since = Date.now() - TL_DAYS * 86_400_000;
  const ev = [];
  const add = (ts, group, icon, title, detail, tone) => { if (ts >= since) ev.push({ ts, group, icon, title, detail, tone }); };
  // Alerts, except the kinds rebuilt below from richer sources.
  const rebuilt = new Set(["presence", "outage", "link_downgrade", "new_device"]);
  for (const a of state.alerts) {
    if (rebuilt.has(a.kind)) continue;
    const group = a.kind === "daily_summary" ? "summary" : a.kind.startsWith("host_") ? "connection" : "security";
    add(a.ts, group, a.severity, a.title, a.detail, a.severity === "high" ? "bad" : a.severity === "info" ? "" : "warn");
  }
  // Devices: first appearance, then each online session.
  for (const d of state.devices) {
    if (d.is_self) continue;
    const name = deviceName(d);
    add(d.first_seen, "devices", "device", `New device: ${name}`, `${d.ip} · ${d.mac}${d.vendor ? ` · ${d.vendor}` : ""}`, d.trusted ? "" : "warn");
    for (const [start, end] of d.sessions || []) {
      if (start !== d.first_seen) add(start, "devices", "joined", `${name} joined`, d.ip, "good");
      if (Date.now() - end > 5 * 60_000) add(end, "devices", "left", `${name} left`, `Online for ${fmtDuration((end - start) / 1000)}`, "");
    }
  }
  for (const o of state.outages) {
    add(o.start, "connection", "outage", o.kind === "router" ? "Router unreachable" : "Internet down",
      o.end ? `For ${fmtDuration((o.end - o.start) / 1000)}, until ${hhmm(o.end)}` : "Ongoing", "bad");
  }
  if (state.outage) add(state.outage.start, "connection", "outage", "Internet down", "Ongoing", "bad");
  const order = ["No service", "2G", "3G", "4G", "4G+"];
  for (const c of state.linkLog) {
    const down = order.indexOf(c.to) < order.indexOf(c.from);
    add(c.ts, "connection", down ? "down" : "up", `Mobile link ${c.from} → ${c.to}`, down ? "Dropped to an older network" : "Back on a faster network", down ? "warn" : "good");
  }
  for (const r of state.speedtests) {
    add(r.ts, "connection", "speed", `Speed test: ${r.down_mbps} down / ${r.up_mbps} up Mb/s`, `Latency ${Math.round(r.latency_ms)} ms · used ${fmtBytes(r.bytes_used)}`, "");
  }
  return ev.sort((a, b) => b.ts - a.ts);
}

const TL_ICON = {
  high: ICONS_LAZY("high"), medium: ICONS_LAZY("medium"), low: ICONS_LAZY("low"), info: ICONS_LAZY("info"), device: ICONS_LAZY("device"),
  joined: '<svg viewBox="0 0 24 24"><path d="M5 12h12M13 7l5 5-5 5"/></svg>',
  left: '<svg viewBox="0 0 24 24"><path d="M19 12H7M11 7l-5 5 5 5"/></svg>',
  outage: '<svg viewBox="0 0 24 24"><path d="M2 8.5a15 15 0 0 1 20 0M5.5 12a10 10 0 0 1 13 0M9 15.5a5 5 0 0 1 6 0M12 19h.01M3 3l18 18"/></svg>',
  down: '<svg viewBox="0 0 24 24"><path d="M12 5v14M6 13l6 6 6-6"/></svg>',
  up: '<svg viewBox="0 0 24 24"><path d="M12 19V5M6 11l6-6 6 6"/></svg>',
  speed: '<svg viewBox="0 0 24 24"><path d="M4 16a8 8 0 1 1 16 0"/><path d="m12 16 4-5"/></svg>',
};
// Icons shared with app.js are resolved when used (app.js loads later).
function ICONS_LAZY(k) { return { lazy: k }; }
const tlIcon = (k) => { const i = TL_ICON[k]; return i && i.lazy ? ICONS[i.lazy] : i || ""; };

function renderTimeline() {
  const f = state.tlFilter;
  const all = timelineEvents();
  const list = all.filter((e) => f === "all" || e.group === f).slice(0, 400);
  let html = "";
  let day = "";
  for (const e of list) {
    const d = new Date(e.ts);
    const label = d.toDateString() === new Date().toDateString() ? "Today"
      : d.toDateString() === new Date(Date.now() - 86_400_000).toDateString() ? "Yesterday"
      : d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
    if (label !== day) { day = label; html += `<h3 class="tl-day">${esc(label)}</h3>`; }
    html += `<div class="tl-row ${e.tone}">
      <span class="tl-time">${hhmm(e.ts)}</span>
      <span class="tl-icon">${tlIcon(e.icon)}</span>
      <div class="grow"><div class="tl-title">${esc(e.title)}</div>${e.detail ? `<div class="muted small tl-detail">${esc(e.detail)}</div>` : ""}</div>
    </div>`;
  }
  $("#tl-list").innerHTML = html || `<div class="panel empty">Nothing in the last ${TL_DAYS} days${f === "all" ? "" : " for this filter"}.</div>`;
  const counts = { devices: 0, connection: 0, security: 0, summary: 0 };
  for (const e of all) counts[e.group]++;
  document.querySelectorAll("#tl-filter button").forEach((b) => {
    const n = b.dataset.f === "all" ? all.length : counts[b.dataset.f];
    b.textContent = `${b.dataset.label} ${n ? `(${n})` : ""}`.trim();
  });
}

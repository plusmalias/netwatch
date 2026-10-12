"use strict";
// The weekly report and the command palette (⌘K). Shares helpers and
// `state` with app.js, which loads after this file.

// ------------------------------------------------------------------ weekly report

async function weeklyReport() {
  let hist = [];
  try { hist = await invoke("get_history", { range: "7d" }); } catch {}
  const now = Date.now();
  const since = now - 7 * 86_400_000;
  const day0 = dayStart(now);
  const days = Array.from({ length: 7 }, (_, i) => {
    const s = addDays(day0, i - 6);
    const [rx, tx] = usageSplit(s, addDays(s, 1));
    return { label: new Date(s).toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" }), rx, tx };
  });
  const maxDay = Math.max(1, ...days.map((d) => d.rx + d.tx));
  const outs = state.outages.filter((o) => o.start >= since);
  const downMs = outs.reduce((a, o) => a + ((o.end || now) - o.start), 0);
  const checks = hist.filter((p) => p.loss != null);
  const uptime = checks.length ? 100 - checks.reduce((a, p) => a + p.loss, 0) / checks.length : null;
  const lat = hist.filter((p) => p.inet_ms != null);
  const avgLat = lat.length ? lat.reduce((a, p) => a + p.inet_ms, 0) / lat.length : null;
  const alerts = state.alerts.filter((a) => a.ts >= since && a.severity !== "info");
  const bySev = (s) => alerts.filter((a) => a.severity === s).length;
  const newDevices = state.devices.filter((d) => d.first_seen >= since);
  const tests = state.speedtests.filter((t) => t.ts >= since);
  const checksList = securityChecks().filter((c) => c.status !== "info");
  const r = state.router?.identity;
  const e = esc;
  const kpi = (label, value, sub) => `<div class="kpi"><div class="l">${e(label)}</div><div class="v">${value}</div><div class="s">${e(sub)}</div></div>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>NetWatch weekly report</title>
<style>
  body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:#101828;background:#f4f6f9;margin:0;padding:32px}
  .wrap{max-width:900px;margin:0 auto}
  h1{font-size:26px;margin:0} h2{font-size:16px;margin:28px 0 10px}
  .muted{color:#667085}
  .card{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:16px 18px;margin-top:12px}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:18px}
  .kpi{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:14px 16px}
  .kpi .l{color:#475467;font-size:12px;font-weight:600}.kpi .v{font-size:24px;font-weight:750;margin:4px 0}.kpi .s{color:#667085;font-size:12px}
  table{width:100%;border-collapse:collapse} th{text-align:left;color:#667085;font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding:8px 10px;border-bottom:1px solid #e3e7ed}
  td{padding:8px 10px;border-bottom:1px solid #eef1f4} tr:last-child td{border-bottom:0}
  .bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:#eef1f4;min-width:160px}
  .bar i{display:block;height:100%} .rx{background:#2a78d6}.tx{background:#eb6834;margin-left:2px}
  .tag{display:inline-block;font-size:11px;font-weight:650;padding:1px 8px;border-radius:10px;border:1px solid #e3e7ed}
  .bad{background:#fdecec}.warn{background:#fdf4e3}.good{background:#e7f6ee}
  @media print{body{background:#fff;padding:0}.card,.kpi{break-inside:avoid}}
</style></head><body><div class="wrap">
<h1>Weekly network report</h1>
<div class="muted">${e(new Date(since).toLocaleDateString([], { day: "numeric", month: "long" }))} – ${e(new Date(now).toLocaleDateString([], { day: "numeric", month: "long", year: "numeric" }))}
 · ${e([r?.manufacturer, r?.model].filter(Boolean).join(" ") || "Router")} ${state.net?.gateway_ip ? `(${e(state.net.gateway_ip)})` : ""}${state.publicInfo?.org ? ` · ${e(state.publicInfo.org.replace(/^AS\d+\s+/, ""))}` : ""}</div>
<div class="kpis">
  ${kpi("Uptime", uptime != null ? `${uptime.toFixed(2)}%` : "—", "internet reachable")}
  ${kpi("Average latency", avgLat != null ? `${Math.round(avgLat)} ms` : "—", "to 1.1.1.1 / 8.8.8.8")}
  ${kpi("Data used", state.router?.counters ? fmtBytes(days.reduce((a, d) => a + d.rx + d.tx, 0)) : "—", "whole network")}
  ${kpi("Outages", String(outs.length), outs.length ? `${fmtDuration(downMs / 1000)} offline` : "none")}
</div>
<h2>Data use by day</h2>
<div class="card"><table><thead><tr><th>Day</th><th>Downloaded</th><th>Uploaded</th><th></th></tr></thead><tbody>
${days.map((d) => `<tr><td>${e(d.label)}</td><td>${fmtBytes(d.rx)}</td><td>${fmtBytes(d.tx)}</td><td><div class="bar"><i class="rx" style="width:${(d.rx / maxDay) * 100}%"></i><i class="tx" style="width:${(d.tx / maxDay) * 100}%"></i></div></td></tr>`).join("")}
</tbody></table></div>
<h2>Security checkup</h2>
<div class="card"><table><tbody>
${checksList.map((c) => `<tr><td><span class="tag ${c.status}">${e(CHECK_LABEL[c.status])}</span></td><td><b>${e(c.title)}</b><div class="muted">${e(c.detail)}</div></td></tr>`).join("") || "<tr><td>Nothing to report.</td></tr>"}
</tbody></table></div>
<h2>Alerts</h2>
<div class="card">${alerts.length ? `<p class="muted">${bySev("high")} high · ${bySev("medium")} medium · ${bySev("low")} low</p><table><tbody>
${alerts.slice(-40).reverse().map((a) => `<tr><td class="muted">${e(new Date(a.ts).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" }))}</td><td><b>${e(a.title)}</b></td></tr>`).join("")}
</tbody></table>` : "No alerts this week."}</div>
<h2>Devices</h2>
<div class="card"><p class="muted">${state.devices.length} known · ${newDevices.length} new this week · ${state.devices.filter((d) => !d.trusted).length} not marked trusted</p>
<table><thead><tr><th>Device</th><th>Type</th><th>IP</th><th>MAC</th><th>Last seen</th></tr></thead><tbody>
${state.devices.map((d) => `<tr><td><b>${e(deviceName(d))}</b>${d.first_seen >= since ? ' <span class="tag warn">new</span>' : ""}${d.trusted ? "" : ' <span class="tag">untrusted</span>'}</td><td>${e(deviceKind(d)[1])}</td><td>${e(d.ip)}</td><td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${e(d.mac)}</td><td>${e(d.online ? "Online" : ago(d.last_seen))}</td></tr>`).join("")}
</tbody></table></div>
${outs.length ? `<h2>Outages</h2><div class="card"><table><tbody>${outs.map((o) => `<tr><td>${e(new Date(o.start).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" }))}</td><td>${o.kind === "router" ? "Router unreachable" : "Internet down"}</td><td>${fmtDuration(((o.end || now) - o.start) / 1000)}</td></tr>`).join("")}</tbody></table></div>` : ""}
${tests.length ? `<h2>Speed tests</h2><div class="card"><table><tbody>${tests.map((t) => `<tr><td>${e(new Date(t.ts).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" }))}</td><td>${t.down_mbps} Mb/s down</td><td>${t.up_mbps} Mb/s up</td><td>${Math.round(t.latency_ms)} ms</td></tr>`).join("")}</tbody></table></div>` : ""}
<p class="muted" style="margin-top:28px">Generated by NetWatch on ${e(new Date().toLocaleString())}.</p>
</div></body></html>`;
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const path = await call("save_export", { name: `NetWatch-report-${stamp}.html`, content: html });
  invoke("open_export", { path }).catch(() => {});
  toast({ severity: "info", title: "Weekly report saved", detail: `Opened it in your browser. Saved to ${path}. Use File → Print to save it as a PDF.`, onClick: () => invoke("reveal_file", { path }) });
}

// ------------------------------------------------------------------ command palette

function paletteItems() {
  const items = [];
  const page = (view, words = "") => items.push({ kind: "Page", label: VIEW_TITLES[view], hint: TAB_LABELS[view] && VIEW_TITLES[view] !== TAB_LABELS[view] ? TAB_LABELS[view] : "", words, run: () => setView(view) });
  page("overview", "home dashboard");
  page("timeline", "activity history events log");
  page("devices", "devices list");
  page("map", "network map topology");
  page("network", "router internet connection speed");
  page("wifi", "wifi channel analyzer");
  page("history", "history latency uptime 30 days");
  page("bluetooth", "bluetooth map trackers nearby batteries");
  page("traffic", "traffic apps bandwidth dns");
  page("connections", "connections sockets");
  page("security", "checkup security");
  page("audit", "audit port certificate https evil twin startup items launch listening dns hijack");
  page("alerts", "alerts");
  page("settings", "settings preferences notifications");
  const act = (label, words, run) => items.push({ kind: "Action", label, words, run });
  act("Run the weekly port audit now", "audit ports open devices security", () => { setView("audit"); auditRunPorts(); });
  act("Scan the network now", "scan refresh discover", () => { state.scanning = true; render(); call("scan_network"); });
  act("Run a speed test", "speed bandwidth test", () => { setView("network"); $('[data-action="speed-test"]')?.click(); });
  act("Trace route to 1.1.1.1", "traceroute path hops", () => { setView("network"); $('[data-action="trace"]')?.click(); });
  act("Check DNS servers", "dns benchmark resolver", () => { setView("network"); $('[data-action="dns-check"]')?.click(); });
  act("Run DNS leak test", "vpn leak privacy", () => { setView("network"); runLeakTest(); });
  act("Create weekly report", "report pdf export summary", () => weeklyReport());
  act("Export devices as CSV", "export csv spreadsheet", () => exportDevices());
  act(state.bt?.scan_state === "scanning" ? "Stop Bluetooth listening" : "Start Bluetooth listening", "bluetooth scan ble", () => call("set_ble_scan", { on: state.bt?.scan_state !== "scanning" }));
  act("Acknowledge all alerts", "ack clear alerts", () => call("ack_alert", { id: null }));
  act("Switch light / dark appearance", "theme dark light mode", async () => {
    const next = { ...state.settings, theme: (state.settings?.theme || "light") === "dark" ? "light" : "dark" };
    state.settings = await call("set_settings", { settings: next });
    applyTheme();
    render();
  });
  for (const d of state.devices) {
    items.push({
      kind: "Device", label: deviceName(d), hint: `${d.ip} · ${deviceKind(d)[1]}${d.online ? "" : " · offline"}`,
      words: [d.ip, d.mac, d.vendor, d.hostname, d.model, ...(d.tags || [])].filter(Boolean).join(" "),
      run: () => { setView("devices"); openDrawer(d.mac); },
    });
  }
  return items;
}

function paletteMatches(q) {
  const items = state.palette.items;
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return items.filter((i) => i.kind !== "Device").slice(0, 14);
  return items
    .map((i) => {
      const hay = `${i.label} ${i.hint || ""} ${i.words || ""}`.toLowerCase();
      if (!words.every((w) => hay.includes(w))) return null;
      // Prefer label prefix matches, then label matches.
      const label = i.label.toLowerCase();
      const score = (label.startsWith(words[0]) ? 0 : label.includes(words[0]) ? 1 : 2) + (i.kind === "Page" ? 0 : 0.5);
      return { i, score };
    })
    .filter(Boolean)
    .sort((a, b) => a.score - b.score)
    .slice(0, 14)
    .map((x) => x.i);
}

function openPalette() {
  state.palette = { items: paletteItems(), sel: 0, list: [] };
  $("#palette").hidden = false;
  const input = $("#palette-input");
  input.value = "";
  input.focus();
  renderPalette();
}

function closePalette() {
  state.palette = null;
  $("#palette").hidden = true;
}

function renderPalette() {
  const P = state.palette;
  if (!P) return;
  P.list = paletteMatches($("#palette-input").value);
  P.sel = Math.min(P.sel, Math.max(0, P.list.length - 1));
  $("#palette-list").innerHTML = P.list.length
    ? P.list.map((it, n) => `<div class="pal-item ${n === P.sel ? "sel" : ""}" data-pal="${n}">
        <span class="pal-kind">${esc(it.kind)}</span><span class="pal-label">${esc(it.label)}</span>${it.hint ? `<span class="pal-hint">${esc(it.hint)}</span>` : ""}</div>`).join("")
    : '<div class="empty">No matches.</div>';
  $("#palette-list .sel")?.scrollIntoView({ block: "nearest" });
}

function runPalette(n) {
  const it = state.palette?.list[n];
  closePalette();
  if (it) it.run();
}

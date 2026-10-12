"use strict";
// The Audit page and the audit items in the Security checkup. The audits run
// in the backend (audit.rs); `state.audit` is their saved state plus what is
// running now, pushed by the "audit" event. Shares helpers and `state` with
// app.js, which loads after this file.

const AUDIT_DAY = 86_400_000;

// "in 6 days", "in 3 h", "due now"
function auditIn(ts) {
  if (!ts) return "—";
  const d = ts - Date.now();
  if (d < 60_000) return "due now";
  if (d < 3_600_000) return `in ${Math.round(d / 60_000)} min`;
  if (d < AUDIT_DAY) return `in ${Math.round(d / 3_600_000)} h`;
  const days = Math.round(d / AUDIT_DAY);
  return `in ${days} day${days === 1 ? "" : "s"}`;
}

const auditPortChip = (p, fresh) => {
  const label = PORT_LABEL[p] ? ` ${esc(PORT_LABEL[p])}` : "";
  const risky = RISKY_PORTS.has(p);
  if (fresh) return `<span class="chip ${risky ? "bad" : "warn"}" data-tip="Opened since the previous audit">New: ${p}${label}</span>`;
  return `<span class="chip ${risky ? "bad" : ""}">${p}${label}</span>`;
};

const auditOffNote = () => '<p class="muted small">This audit is switched off. <button class="btn link" data-goto="settings">Turn it on in Settings</button></p>';

// ------------------------------------------------------------------ panels

function auditPortsPanel(a, s) {
  const p = a.ports;
  const running = !!a.live?.ports_running;
  const devices = Object.values(p.devices || {}).sort((x, y) => y.opened.length - x.opened.length || x.name.localeCompare(y.name));
  const table = devices.length
    ? `<table class="table compact"><thead><tr><th>Device</th><th>Open ports</th><th>Closed since last audit</th><th>Checked</th></tr></thead><tbody>
        ${devices.map((d) => `<tr class="${d.opened.length ? "row-new" : ""}">
          <td><div class="primary">${esc(d.name)}</div><div class="muted small mono">${esc(d.ip)}</div></td>
          <td>${d.open.length ? `<div class="chips">${d.open.map((x) => auditPortChip(x, d.opened.includes(x))).join("")}</div>` : '<span class="muted">None of the common ports</span>'}${d.baseline ? ' <span class="muted small">Baseline</span>' : ""}</td>
          <td>${d.closed.length ? `<span class="muted">${d.closed.join(", ")}</span>` : '<span class="muted">—</span>'}</td>
          <td class="muted" title="${esc(fullTime(d.checked_at))}">${ago(d.checked_at)}</td></tr>`).join("")}</tbody></table>`
    : '<p class="muted small">No results yet. The first audit sets each device\'s baseline, so nothing alerts until the second one.</p>';
  const runs = [...(p.runs || [])].reverse();
  const history = runs.length
    ? `<div class="panel-head" style="margin-top:14px"><h2>Recent runs <span class="muted">(last ${runs.length} of 12)</span></h2></div>
       <table class="table compact"><thead><tr><th>When</th><th class="num">Devices</th><th class="num">Opened</th><th class="num">Closed</th></tr></thead><tbody>
       ${runs.map((r) => `<tr><td title="${esc(fullTime(r.ts))}">${esc(fullTime(r.ts))}</td><td class="num">${r.devices}</td><td class="num">${r.opened ? `<b>${r.opened}</b>` : 0}</td><td class="num">${r.closed}</td></tr>`).join("")}</tbody></table>`
    : "";
  return `<div class="panel">
    <div class="panel-head"><h2>Port audit</h2>
      <button class="btn" data-action="audit-ports"${running ? " disabled" : ""}>${running ? "Running…" : "Run audit now"}</button></div>
    <p class="muted small">Once a week NetWatch checks the common ports (remote access, file sharing, printing, cameras) on every device that's online, this computer included, two at a time. A device's first result is its baseline; ports that open afterwards raise an alert, and ports that close are just recorded.</p>
    ${s.port_audit ? "" : auditOffNote()}
    <dl class="facts compact">
      <dt>Last run</dt><dd>${p.last_run ? `${ago(p.last_run)} <span class="muted small">(${esc(fullTime(p.last_run))})</span>` : "Not yet"}</dd>
      <dt>Next run</dt><dd>${!s.port_audit ? "Off" : p.last_run ? `${auditIn(a.ports_next)} <span class="muted small">(${esc(fullTime(a.ports_next))})</span>` : "Shortly after the first scan finishes"}</dd>
    </dl>
    ${table}${history}</div>`;
}

function auditListenersPanel(a, s) {
  const l = a.listeners;
  const live = new Set((a.live?.listening || []).map((x) => `${x.process}:${x.port}`));
  const rows = Object.values(l.known || {}).sort((x, y) => Number(y.new) - Number(x.new) || x.port - y.port);
  const fresh = rows.filter((r) => r.new).length;
  const table = rows.length
    ? `<table class="table compact"><thead><tr><th>App</th><th class="num">Port</th><th>Status</th><th>Now</th></tr></thead><tbody>
        ${rows.map((r) => `<tr class="${r.new ? "row-new" : ""}">
          <td><b>${esc(r.process)}</b></td><td class="num">${r.port}</td>
          <td>${r.new ? `<span class="chip warn" title="${esc(fullTime(r.first_seen))}">New, ${ago(r.first_seen)}</span>` : '<span class="chip">Baseline</span>'}</td>
          <td>${live.has(`${r.process}:${r.port}`) ? '<span class="dot good"></span> Listening' : '<span class="muted">Not listening</span>'}</td></tr>`).join("")}</tbody></table>`
    : '<p class="muted small">Taking the baseline…</p>';
  return `<div class="panel">
    <div class="panel-head"><h2>Listening apps</h2></div>
    <p class="muted small">Apps on this computer that accept connections from other devices (TCP, not just from this computer). NetWatch looks every minute. What's listening the first time is the baseline; a new app or port raises an alert.</p>
    ${s.listener_watch ? "" : auditOffNote()}
    <p class="small">${l.baseline_at ? `Baseline taken ${ago(l.baseline_at)}. ${rows.length - fresh} in the baseline, ${fresh ? `<b>${fresh} new</b>` : "none new"}.` : ""}</p>
    ${table}</div>`;
}

function auditLaunchPanel(a, s) {
  const l = a.launch;
  const items = [...(l.items || [])].sort((x, y) => Number(!!y.risk) - Number(!!x.risk) || Number(y.new) - Number(x.new) || x.label.localeCompare(y.label));
  const table = items.length
    ? `<table class="table compact"><thead><tr><th>Item</th><th>Runs</th><th>Where</th><th>Status</th></tr></thead><tbody>
        ${items.map((i) => `<tr class="${i.risk ? "row-bad" : i.new ? "row-new" : ""}">
          <td><div class="primary truncate" title="${esc(i.path)}">${esc(i.label)}</div><div class="muted small">${i.run_at_load ? "Runs at login or startup" : "Runs when needed"}</div></td>
          <td class="mono truncate" title="${esc(i.program || "")}">${esc(i.program || "—")}</td>
          <td class="muted">${esc(i.scope)}</td>
          <td><div class="chips">${i.risk ? `<span class="chip bad" data-tip="${esc(`This item ${i.risk}`)}">Check this</span>` : ""}${i.new ? `<span class="chip warn" title="${esc(fullTime(i.first_seen))}">New, ${ago(i.first_seen)}</span>` : '<span class="chip">Baseline</span>'}</div></td></tr>`).join("")}</tbody></table>`
    : `<p class="muted small">${l.scanned_at ? "No startup items found." : "Scanning… Startup items are checked on macOS only."}</p>`;
  return `<div class="panel">
    <div class="panel-head"><h2>Startup items</h2></div>
    <p class="muted small">Launch agents and daemons are programs macOS starts for you (in ~/Library/LaunchAgents, /Library/LaunchAgents and /Library/LaunchDaemons). Malware often adds one to survive a restart. NetWatch looks every 5 minutes. A new item raises an alert, a serious one if its program lives in a temporary or hidden folder or fails its signature check. NetWatch's own login item is left out.</p>
    ${s.launch_watch ? "" : auditOffNote()}
    <p class="small">${l.scanned_at ? `Scanned ${ago(l.scanned_at)}. ${items.length} item${items.length === 1 ? "" : "s"}, ${items.filter((i) => i.new).length} new, ${items.filter((i) => i.risk).length} flagged.` : ""}</p>
    ${table}</div>`;
}

function auditNetworkPanel(a, s) {
  const net = state.net;
  const rec = net?.gateway_mac ? a.network?.networks?.[net.gateway_mac] : null;
  let dnsHtml;
  if (!net) dnsHtml = '<p class="muted small">Not connected to a network.</p>';
  else if (!net.gateway_mac) dnsHtml = '<p class="muted small">NetWatch needs your router\'s address to keep a baseline for this network. It will start once the router is found.</p>';
  else if (!rec) dnsHtml = '<p class="muted small">Recording this network\'s settings…</p>';
  else dnsHtml = `<dl class="facts compact">
      <dt>This network</dt><dd>Router <span class="mono">${esc(rec.gateway_ip || net.gateway_ip || "")}</span> <span class="muted small mono">${esc(rec.gateway_mac)}</span></dd>
      <dt>DNS servers now</dt><dd class="mono">${(rec.dns_now || []).map(esc).join(", ") || "—"}</dd>
      <dt>DNS servers seen here</dt><dd class="mono">${[...(rec.dns_seen || [])].map(esc).join(", ") || "—"}</dd>
      <dt>DHCP server</dt><dd class="mono">${esc(rec.dhcp_last || "—")}</dd>
      <dt>First seen</dt><dd>${rec.first_seen ? `${ago(rec.first_seen)} <span class="muted small">(${esc(fullTime(rec.first_seen))})</span>` : "—"}</dd>
    </dl>`;

  const w = a.live?.wifi;
  let wifiHtml;
  if (!w) wifiHtml = '<p class="muted small">Not checked yet.</p>';
  else if (!w.names_visible) wifiHtml = `<p class="muted">Wi-Fi network names are hidden from apps without Location permission, so look-alike networks can't be spotted until it's allowed.</p>${locationNote()}`;
  else {
    const flagChip = (ap) => ap.ours ? '<span class="chip good">This connection</span>'
      : ap.flag === "weaker" ? '<span class="chip bad" data-tip="Same name, weaker or no security">Weaker security</span>'
      : ap.flag === "new" ? `<span class="chip warn" title="${esc(fullTime(ap.first_seen))}">New, ${ago(ap.first_seen)}</span>`
      : '<span class="chip">Seen at baseline</span>';
    wifiHtml = `<p class="small">Access points using the name <b>${esc(w.ssid)}</b>: ${w.aps.length}${w.aps.length > 1 ? ". More than one is normal with a mesh system or extender." : "."}</p>
      <table class="table compact"><thead><tr><th>Channel</th><th>Address (BSSID)</th><th>Security</th><th class="num">Signal</th><th>Status</th></tr></thead><tbody>
      ${w.aps.map((ap) => `<tr class="${ap.flag === "weaker" ? "row-bad" : ap.flag === "new" ? "row-new" : ""}">
        <td>${ap.channel ?? "—"}${ap.band ? ` <span class="muted small">${esc(ap.band)}</span>` : ""}</td>
        <td class="mono small">${esc(ap.bssid || "—")}</td>
        <td>${esc(ap.security || "Unknown")}</td><td class="num">${ap.rssi != null ? `${ap.rssi} dBm` : "—"}</td><td>${flagChip(ap)}</td></tr>`).join("")}</tbody></table>`;
    // Everything recorded for this name over time, not just what's in range now.
    // Records are keyed by BSSID, or by "channel@band" when there was none.
    const seen = Object.entries(a.wifi?.seen?.[w.ssid] || {}).sort((x, y) => x[1].first_seen - y[1].first_seen);
    if (seen.length) {
      wifiHtml += `<p class="small" style="margin-top:10px">Access points seen using <b>${esc(w.ssid)}</b> so far:</p>
        <div class="chips">${seen.map(([k, r]) => {
          const [kch, kband] = k.split("@");
          const ch = r.channel ?? (k.includes(":") ? null : kch);
          const band = r.band ?? kband;
          const where = ch != null ? `${ch}${band && band !== "?" ? ` · ${band}` : ""}` : "";
          return `<span class="chip ${r.baseline ? "" : "warn"}" title="${esc(`First seen ${fullTime(r.first_seen)}`)}">${k.includes(":") ? `<span class="mono">${esc(k)}</span>${where ? ` · ${esc(where)}` : ""}` : esc(where)}${r.baseline ? "" : ", new"}</span>`;
        }).join("")}</div>`;
    }
  }
  return `<div class="panel">
    <div class="panel-head"><h2>Network integrity</h2></div>
    <h3 class="audit-sub">DNS and router settings</h3>
    <p class="muted small">Each network (told apart by its router) has its own baseline. A DNS server this network has never used raises a possible-hijack alert; a different DHCP server raises a lower one.</p>
    ${s.dns_watch ? "" : auditOffNote()}
    ${dnsHtml}
    <h3 class="audit-sub">Look-alike Wi-Fi networks</h3>
    <p class="muted small">Another access point with your network's name and weaker or no security could be an "evil twin". One with the same security from an address (BSSID) NetWatch hasn't seen before is a gentler heads-up. Needs Location permission to see Wi-Fi names and addresses.</p>
    ${s.evil_twin_watch ? "" : auditOffNote()}
    ${wifiHtml}</div>`;
}

// What a watched site's certificate looks like right now: [status, label].
function auditCertState(e) {
  if (!e) return ["off", "Checking soon…"];
  if (!e.info) return ["off", e.error ? "Couldn't check" : "Checking soon…"];
  const days = Math.floor((e.info.not_after - Date.now()) / AUDIT_DAY);
  if (e.info.not_after <= Date.now()) return ["bad", "Expired"];
  if (e.untrusted) return ["bad", "Not trusted"];
  if (days <= 3) return ["bad", "Expires very soon"];
  if (days <= 14) return ["warn", "Expires soon"];
  return ["good", "OK"];
}

const auditHostnames = () => (state.settings?.watch_hosts || []).filter((t) => {
  const host = t.includes(":") ? t.slice(0, t.lastIndexOf(":")) : t;
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(host);
});

function auditCertsPanel(a, s) {
  const c = a.certs;
  const running = !!a.live?.certs_running;
  const hosts = auditHostnames();
  const rows = hosts.map((t) => {
    const e = (c.entries || []).find((x) => x.target === t);
    const [st, label] = auditCertState(e);
    const days = e?.info ? Math.floor((e.info.not_after - Date.now()) / AUDIT_DAY) : null;
    const renewed = e?.changes?.length ? e.changes[e.changes.length - 1] : null;
    return `<tr class="${st === "bad" ? "row-bad" : st === "warn" ? "row-new" : ""}">
      <td><b>${esc(t)}</b>${e?.info ? `<div class="muted small">${esc(e.info.subject)}</div>` : ""}</td>
      <td class="num">${days == null ? "—" : days < 0 ? "Expired" : days === 0 ? "< 1 day" : `${days} day${days === 1 ? "" : "s"}`}${e?.info ? `<div class="muted small">until ${esc(new Date(e.info.not_after).toLocaleDateString())}</div>` : ""}</td>
      <td>${esc(e?.info?.issuer || "—")}${renewed ? `<div class="muted small" title="${esc(`${renewed.old_issuer} → ${renewed.new_issuer}`)}">${renewed.issuer_changed ? "Issuer changed" : "Renewed"} ${ago(renewed.ts)}</div>` : ""}</td>
      <td><span class="chip ${st === "off" ? "" : st}">${esc(label)}</span>${e?.untrusted ? `<div class="muted small">${esc(e.untrusted)}</div>` : ""}${e?.error ? `<div class="muted small">${esc(e.error)}</div>` : ""}</td>
      <td class="muted" title="${esc(e ? fullTime(e.checked_at) : "")}">${e ? ago(e.checked_at) : "—"}</td></tr>`;
  }).join("");
  const table = hosts.length
    ? `<table class="table compact"><thead><tr><th>Site</th><th class="num">Days left</th><th>Issuer</th><th>Status</th><th>Checked</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<p class="muted small">No sites to check. Add a website, such as <span class="mono">example.com</span>, under Watched hosts on the <button class="btn link" data-goto="network">Connection page</button> and NetWatch checks its HTTPS certificate too (port 443, or the port you give). IP addresses are skipped.</p>';

  const ic = c.intercept;
  const verdicts = {
    ok: ["good", "No interception found", "Big public sites presented certificates from the public certificate authorities, as expected."],
    intercepted: ["bad", "HTTPS may be intercepted", "Every site NetWatch could reach presented a certificate from an authority outside the public list. A proxy or security software on this computer or network is re-signing HTTPS traffic."],
    inconclusive: ["warn", "Mixed results", "Some sites checked out and some didn't. That's not enough to say; NetWatch will look again."],
    offline: ["off", "Couldn't reach the test sites", "There was no connection to check with. NetWatch will try again shortly."],
  };
  const v = ic && (verdicts[ic.verdict] || verdicts.offline);
  const probeLine = (p) => `<li><span class="mono">${esc(p.host)}</span> ${p.verified ? "verified" : !p.reachable ? "couldn't connect" : p.unknown_issuer ? "unknown issuer" : "failed"}</li>`;
  const intercept = ic
    ? `<dl class="facts compact"><dt>Result</dt><dd><span class="chip ${v[0] === "off" ? "" : v[0]}">${esc(v[1])}</span> <span class="muted small">${esc(v[2])}</span></dd>
        <dt>Sites tried</dt><dd><ul class="plain">${ic.probes.map(probeLine).join("")}</ul></dd>
        <dt>Last checked</dt><dd>${ago(ic.checked_at)} <span class="muted small">(${esc(fullTime(ic.checked_at))})</span></dd></dl>`
    : '<p class="muted small">Not checked yet.</p>';
  return `<div class="panel">
    <div class="panel-head"><h2>Certificates</h2>
      <button class="btn" data-action="audit-certs"${running ? " disabled" : ""}>${running ? "Checking…" : "Check now"}</button></div>
    <p class="muted small">NetWatch opens a secure connection to each watched site every 6 hours, using its own list of trusted authorities rather than the Mac's keychain. It alerts when a certificate is about to expire (14 days: medium, 3 days: high), is already expired, can't be verified, or switches to a different issuer. A renewal by the same issuer is just recorded.</p>
    ${s.cert_checks ? "" : auditOffNote()}
    <dl class="facts compact"><dt>Last run</dt><dd>${c.last_run ? `${ago(c.last_run)} <span class="muted small">(next ${auditIn(a.certs_next)})</span>` : "Not yet"}</dd></dl>
    ${table}
    <h3 class="audit-sub">HTTPS interception check</h3>
    <p class="muted small">Once a day NetWatch connects to apple.com, cloudflare.com and google.com and checks their certificates against the same independent list. If every one of them that answers fails that check, something is re-signing your HTTPS traffic.</p>
    ${intercept}</div>`;
}

function renderAudit() {
  const a = state.audit;
  const s = state.settings || {};
  $("#audit-body").innerHTML = a
    ? [auditPortsPanel(a, s), auditListenersPanel(a, s), auditLaunchPanel(a, s), auditNetworkPanel(a, s), auditCertsPanel(a, s)].join("")
    : '<div class="panel empty">Loading…</div>';
}

// ------------------------------------------------------------------ actions

async function auditRunPorts() {
  if (state.audit) state.audit.live = { ...state.audit.live, ports_running: true };
  render();
  try { await call("run_port_audit"); } catch { if (state.audit) state.audit.live.ports_running = false; render(); }
}

async function auditRunCerts() {
  if (state.audit) state.audit.live = { ...state.audit.live, certs_running: true };
  render();
  try { await call("run_cert_check"); } catch { if (state.audit) state.audit.live.certs_running = false; render(); }
}

// ------------------------------------------------------------------ security checkup

// How serious a group of open alerts is: high → problem, medium → worth a look, low → tidy-up.
const auditStatus = (list) => (list.some((x) => x.severity === "high") ? "bad" : list.some((x) => x.severity === "medium") ? "warn" : "note");

// Adds one checkup item per audit. `add` is securityChecks' own helper.
function auditChecks(add) {
  const a = state.audit;
  const s = state.settings;
  if (!a || !s) return;
  const open = openAlerts();
  const alertsOf = (kind) => open.filter((x) => x.kind === kind);
  const see = { label: "See audit", goto: "audit" };
  const off = { label: "Settings", goto: "settings" };
  const list = (alerts) => alerts.slice(0, 3).map((x) => x.title).join("; ") + (alerts.length > 3 ? "…" : "");

  // Weekly port audit
  const ports = alertsOf("port_audit");
  if (!s.port_audit) add("info", "Weekly port audit is off", "NetWatch isn't checking your devices for newly opened ports.", off);
  else if (!a.ports.last_run) add("info", "Port audit hasn't run yet", "It runs by itself soon after the first scan, then every week. You can run it now.", { label: "Run audit now", action: "audit-ports" });
  else if (ports.length) add(auditStatus(ports), `${ports.length} newly opened port${ports.length > 1 ? "s" : ""} found by the port audit`, `${list(ports)}. Turn off services you don't use.`, see);
  else add("good", "No new open ports", `The port audit checked ${a.ports.runs[a.ports.runs.length - 1]?.devices ?? 0} device${a.ports.runs[a.ports.runs.length - 1]?.devices === 1 ? "" : "s"} ${ago(a.ports.last_run)}; next one ${auditIn(a.ports_next)}.`, see);

  // Listening apps
  const listeners = alertsOf("new_listener");
  if (!s.listener_watch) add("info", "Listening-app watch is off", "NetWatch isn't looking for apps that start accepting connections.", off);
  else if (!a.listeners.baseline_at) add("info", "Learning which apps listen", "NetWatch is taking a baseline of the apps that accept connections.", see);
  else if (listeners.length) add(auditStatus(listeners), `${listeners.length} app${listeners.length > 1 ? "s" : ""} started accepting connections`, `${list(listeners)}. Normal for sharing and media apps; quit anything you don't recognise.`, see);
  else add("good", "No new listening apps", `${Object.keys(a.listeners.known).length} app${Object.keys(a.listeners.known).length === 1 ? "" : "s"} known to accept connections; nothing new since the baseline.`, see);

  // Startup items
  const launch = alertsOf("launch_item");
  const flagged = (a.launch.items || []).filter((i) => i.risk && !i.new);
  if (!s.launch_watch) add("info", "Startup-item watch is off", "NetWatch isn't looking for new launch agents and daemons.", off);
  else if (!a.launch.baseline_at) add("info", "Startup items not scanned yet", "NetWatch checks them every few minutes (macOS only).", see);
  else {
    if (launch.length) add(auditStatus(launch), `${launch.length} new startup item${launch.length > 1 ? "s" : ""}`, `${list(launch)}. Malware often adds one of these to survive a restart.`, see);
    if (flagged.length) add("warn", `${flagged.length} startup item${flagged.length > 1 ? "s" : ""} run from temporary or hidden folders`, `${flagged.slice(0, 3).map((i) => i.label).join(", ")}${flagged.length > 3 ? "…" : ""}. Programs that start automatically don't normally live there.`, see);
    if (!launch.length && !flagged.length) add("good", "No new startup items", `${a.launch.items.length} startup item${a.launch.items.length === 1 ? "" : "s"} watched; nothing new since the baseline.`, see);
  }

  // DNS and router
  const dns = alertsOf("dns_change");
  const dhcp = alertsOf("dhcp_change");
  const rec = state.net?.gateway_mac ? a.network?.networks?.[state.net.gateway_mac] : null;
  if (!s.dns_watch) add("info", "DNS and router watch is off", "NetWatch isn't watching for changes to your DNS or DHCP servers.", off);
  else if (dns.length) add(auditStatus(dns), "Your DNS servers changed", `${list(dns)}. If you didn't change them, your router or this Mac may have been tampered with.`, see);
  else if (dhcp.length) add("note", "A different DHCP server answered", `${list(dhcp)}. Expected after swapping a router; otherwise look for an unfamiliar device.`, see);
  else if (rec) add("good", "DNS and DHCP servers unchanged", `This network still uses ${(rec.dns_now || []).join(", ") || "its usual DNS"} and DHCP ${rec.dhcp_last || "server"}.`, see);
  else add("info", "DNS and router settings not recorded yet", "NetWatch keeps a baseline for each network once it knows the router's address.", see);

  // Look-alike Wi-Fi
  const twins = alertsOf("evil_twin");
  const w = a.live?.wifi;
  if (!s.evil_twin_watch) add("info", "Look-alike Wi-Fi check is off", "NetWatch isn't looking for other networks copying your Wi-Fi name.", off);
  else if (twins.length) add(auditStatus(twins), `${twins.length} look-alike Wi-Fi ${twins.length > 1 ? "networks" : "network"}`, `${list(twins)}.`, see);
  else if (w && !w.names_visible) {
    const h = locationHelp();
    add("info", "Look-alike Wi-Fi check needs Location permission", `macOS hides Wi-Fi network names from apps without it, so copies of your network's name can't be spotted.${h ? ` ${h.text}` : ""}`, h?.button || see);
  }
  else if (w) add("good", `No look-alikes of “${w.ssid}”`, `${w.aps.length} access point${w.aps.length === 1 ? "" : "s"} use your network's name, all as expected.`, see);
  else add("info", "Look-alike Wi-Fi check hasn't run yet", "It starts once the Wi-Fi scan has results.", see);

  // Certificates and interception
  const certAlerts = alertsOf("cert");
  const hosts = auditHostnames();
  const states = hosts.map((t) => ({ t, e: (a.certs.entries || []).find((x) => x.target === t) })).filter((x) => x.e?.info);
  if (!s.cert_checks) add("info", "Certificate checks are off", "NetWatch isn't checking watched sites' certificates or looking for HTTPS interception.", off);
  else {
    if (!hosts.length) add("info", "No site certificates checked", "Watch a website (Connection page → Watched hosts) and NetWatch warns before its certificate expires or changes.", { label: "Watch a site", goto: "network" });
    else if (certAlerts.length) add(auditStatus(certAlerts), `${certAlerts.length} certificate problem${certAlerts.length > 1 ? "s" : ""}`, `${list(certAlerts)}.`, see);
    else if (states.length) {
      const soonest = states.reduce((m, x) => (x.e.info.not_after < m.e.info.not_after ? x : m));
      const days = Math.floor((soonest.e.info.not_after - Date.now()) / AUDIT_DAY);
      add("good", `${states.length} site certificate${states.length > 1 ? "s look" : " looks"} fine`, `The soonest to expire is ${soonest.t}, in ${days} day${days === 1 ? "" : "s"}.`, see);
    } else add("info", "Certificates not checked yet", "The first check runs shortly.", see);
    const ic = a.certs.intercept;
    const hijack = alertsOf("tls_intercept");
    if (hijack.length || ic?.verdict === "intercepted") add("bad", "HTTPS may be intercepted", "Big public sites presented certificates that don't chain to a public authority. A proxy or security software may be re-signing your HTTPS traffic.", see);
    else if (ic?.verdict === "ok") add("good", "HTTPS isn't being intercepted", `Checked ${ago(ic.checked_at)} against the public certificate authorities, independent of this Mac's keychain.`, see);
    else if (ic?.verdict === "inconclusive") add("note", "HTTPS interception check was inconclusive", "Some test sites verified and some didn't; NetWatch will look again.", see);
    else add("info", "HTTPS interception not checked yet", ic ? "No test site could be reached." : "It runs about once a day.", see);
  }
}

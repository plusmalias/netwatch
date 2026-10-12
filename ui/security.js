"use strict";
// The Security checkup page: one list of what NetWatch knows, each item
// marked good, worth a look, or a problem, with a way to act on it.
// Shares helpers and `state` with app.js, which loads after this file.

const CHECK_LABEL = { bad: "Problem", warn: "Worth a look", note: "Tidy-up", good: "Good", info: "Not checked" };
const CHECK_ICON = {
  bad: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
  warn: '<svg viewBox="0 0 24 24"><path d="M12 3 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/></svg>',
  good: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16 10"/></svg>',
  info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11v5.5"/></svg>',
};
CHECK_ICON.note = CHECK_ICON.info;

function securityChecks() {
  const out = [];
  const add = (status, title, detail, action) => out.push({ status, title, detail, action });
  const r = state.router;
  const admin = r?.identity?.admin_url;

  // Router
  if (r?.checked) {
    if (r.upnp) add("warn", "UPnP is on at your router", "Any device on your network can open ports to the internet without asking. Turn UPnP off in the router's settings unless a game console or media server needs it.", admin && { label: "Open router settings", url: admin });
    else add("good", "UPnP is off", "Devices can't open ports on your router by themselves.");
    const maps = r.mappings || [];
    if (r.upnp && r.mappings) {
      if (maps.length) add("warn", `${maps.length} port forward${maps.length > 1 ? "s" : ""} open on your router`, `${maps.map((m) => `${m.protocol} ${m.external_port} → ${m.internal_client}`).join(", ")}. Each one lets the internet reach a device here.`, { label: "See forwards", goto: "network" });
      else add("good", "No port forwards", "Nothing on your network is opened up to the internet through the router.");
    }
    if (r.status?.cgnat) add("good", "Not directly reachable from the internet", "Your provider uses carrier-grade NAT, so incoming connections from the internet can't reach your network.");
  } else {
    add("info", "Router not checked yet", "NetWatch is still looking for your router.");
  }

  // Wi-Fi
  const sec = state.wifi?.current?.security;
  if (sec) {
    if (/^(Open|WEP)/.test(sec)) add("bad", `Wi-Fi security is weak (${sec})`, "Anyone nearby can join or listen in. Set the router to WPA2 (AES) or WPA3 with a strong password.", admin && { label: "Open router settings", url: admin });
    else if (/^(WPA Personal|WPA\/WPA2)/.test(sec)) add("warn", `Wi-Fi allows outdated WPA (${sec})`, "Switch the router's Wi-Fi security to WPA2-PSK (AES) only, or WPA2/WPA3, so old, weaker encryption isn't accepted.", admin && { label: "Open router settings", url: admin });
    else add("good", `Wi-Fi security is strong (${sec})`, "Your network uses modern encryption.");
  }

  // This computer
  const fw = state.firewall;
  if (fw) {
    if (!fw.enabled) add("bad", "This computer's firewall is off", "Turn it on in System Settings → Network → Firewall.");
    else add("good", "This computer's firewall is on", fw.block_all ? "It blocks all incoming connections." : fw.stealth ? "Stealth mode is on too." : "Consider turning on stealth mode so this computer doesn't answer probes.");
  }

  // Apps on this computer that accept connections from the network
  if (state.listeners) {
    const open = state.listeners;
    const names = [...new Set(open.map((l) => l.process || "unknown"))];
    if (!open.length) add("good", "No apps on this computer accept network connections", "Nothing is listening on your network interfaces.");
    else if (fw?.block_all) add("good", `${names.length} app${names.length > 1 ? "s" : ""} listen for connections, but your firewall blocks them`, `${names.slice(0, 6).join(", ")}${names.length > 6 ? "…" : ""}. Block-all mode stops other devices reaching them.`);
    else add("warn", `${names.length} app${names.length > 1 ? "s" : ""} on this computer accept connections from the network`, `${open.slice(0, 8).map((l) => `${l.process || "unknown"} (port ${l.port})`).join(", ")}${open.length > 8 ? "…" : ""}. Other devices on your Wi-Fi can try to connect. Quit apps you don't need sharing, or turn on the firewall.`, { label: "See connections", goto: "connections" });
  }

  // Devices
  const untrusted = state.devices.filter((d) => !d.trusted && d.online);
  if (untrusted.length) add("warn", `${untrusted.length} device${untrusted.length > 1 ? "s" : ""} online that you haven't marked as trusted`, `${untrusted.slice(0, 4).map(deviceName).join(", ")}${untrusted.length > 4 ? "…" : ""}. Check each one is yours, then mark it trusted so new arrivals stand out.`, { label: "Review devices", goto: "devices", filter: "untrusted" });
  else if (state.devices.length) add("good", "Every online device is trusted", "New devices raise an alert when they join.");
  const exposed = state.devices.filter((d) => (d.open_ports || []).some((p) => RISKY_PORTS.has(p)));
  const checked = state.devices.filter((d) => d.open_ports != null).length;
  if (exposed.length) add("bad", `Remote-access services open on ${exposed.length} device${exposed.length > 1 ? "s" : ""}`, `${exposed.map((d) => `${deviceName(d)} (${d.open_ports.filter((p) => RISKY_PORTS.has(p)).map((p) => PORT_LABEL[p]).join(", ")})`).join("; ")}. Turn these off if you don't use them.`, { label: "Review devices", goto: "devices" });
  else if (checked) add("good", "No risky services found", `Checked ${checked} device${checked > 1 ? "s" : ""} for Telnet, FTP, Remote Desktop and VNC.`);
  else add("info", "Devices' open ports not checked", "Open a device and press Check common ports to look for remote-access services.", { label: "Open devices", goto: "devices" });

  // Alerts and detection
  const open = openAlerts();
  const high = open.filter((a) => a.severity === "high").length;
  if (high) add("bad", `${high} high-severity alert${high > 1 ? "s" : ""} open`, "These need a look: spoofing, rogue DHCP, or malware lookups.", { label: "See alerts", goto: "alerts" });
  else if (open.length) add("warn", `${open.length} open alert${open.length > 1 ? "s" : ""}`, "Nothing high-severity. Review and acknowledge them.", { label: "See alerts", goto: "alerts" });
  else add("good", "No open alerts", "Nothing needs attention right now.");
  if (state.capture.state === "running") add("good", "Traffic monitoring is on", "Spoofing, rogue DHCP, port-scan and malware-lookup detection are active.");
  else add("warn", "Traffic monitoring is off", "Spoofing, rogue DHCP, port-scan and malware-lookup detection need it.", { label: "Settings", goto: "settings" });
  const feeds = state.feeds?.blocklist?.updated;
  if (feeds && Date.now() - feeds < 3 * 86_400_000) add("good", "Threat lists are up to date", `Updated ${ago(feeds)}.`);
  else add("warn", "Threat lists are out of date", "NetWatch couldn't refresh its malware and botnet lists recently.", { label: "Settings", goto: "settings" });

  // DNS
  const mine = (state.dnsCheck.results || []).filter((x) => x.label.startsWith("Your DNS"));
  if (mine.some((x) => x.nxdomain_hijack)) add("warn", "Your DNS redirects addresses that don't exist", "Your provider sends mistyped addresses to its own pages. A public resolver such as 1.1.1.1 or 9.9.9.9 avoids that.", { label: "See DNS check", goto: "network" });
  else if (mine.length && mine.every((x) => x.answered > 0)) add("good", "Your DNS server answers normally", `${mine.map((x) => x.server).join(", ")} didn't redirect a made-up address.`);
  else add("info", "DNS not checked", "Run the DNS check to test your DNS server's speed and honesty.", { label: "Check DNS", action: "dns-check" });

  // Bluetooth
  const bt = state.bt;
  const suspects = (bt?.nearby || []).filter(isSuspectTracker);
  if (suspects.length) add("warn", `${suspects.length} unknown tracker${suspects.length > 1 ? "s" : ""} nearby`, `${suspects.map((d) => d.tracker).join(", ")}. If one stays with you, check your belongings.`, { label: "Open Bluetooth", goto: "bluetooth" });
  else if (bt?.scan_state === "scanning") add("good", "No unknown trackers nearby", "NetWatch is listening for AirTags, Tiles, SmartTags and Find My Device tags.");
  else add("info", "Not watching for Bluetooth trackers", "Turn on listening to be warned about unknown item trackers near you.", { label: "Open Bluetooth", goto: "bluetooth" });
  // Bluetooth hygiene. macOS makes the Mac discoverable while System Settings → Bluetooth is open.
  const ctrl = bt?.info?.controller;
  if (ctrl?.powered) {
    if (ctrl.discoverable) add("warn", "This Mac is discoverable over Bluetooth", "Any device nearby can see it and try to pair. macOS does this while System Settings → Bluetooth is open, so close that window; if it stays discoverable afterwards, turn Bluetooth off and on again.", { label: "Open Bluetooth", goto: "bluetooth" });
    else add("good", "This Mac isn't discoverable over Bluetooth", "Only devices you've already paired can find it.");
  }
  const stale = bt?.stale_paired || [];
  if (stale.length) add("note", `${stale.length} paired Bluetooth device${stale.length > 1 ? "s" : ""} unused for 30+ days`, `${stale.map((s) => `${s.name} (${s.last_connected ? `last connected ${ago(s.last_connected)}` : "not connected since NetWatch started tracking it"})`).join(", ")}. Remove pairings you no longer use in System Settings → Bluetooth, so an old device can't reconnect.`, { label: "Open Bluetooth", goto: "bluetooth" });

  // Security audits (audit.js)
  auditChecks(add);

  // Data allowance
  const cap = state.settings?.data_cap_gb;
  if (cap && state.router?.counters) {
    const used = usageTotal(cycleStartMs(state.settings.cycle_day || 1));
    const pct = (used / (cap * 1e9)) * 100;
    if (pct >= 80) add(pct >= 100 ? "bad" : "warn", `${Math.round(pct)}% of your data allowance used`, `${fmtBytes(used)} of ${cap} GB this cycle.`, { label: "See usage", goto: "network" });
  }

  const order = { bad: 0, warn: 1, note: 2, info: 3, good: 4 };
  return out.sort((a, b) => order[a.status] - order[b.status]);
}

// Listening sockets on non-loopback addresses, one row per app and port.
async function refreshListeners() {
  try {
    const conns = await invoke("list_connections");
    const seen = new Set();
    state.listeners = conns
      .filter((c) => c.proto === "TCP" && c.state === "Listen" && !/^(127\.|::1$)/.test(c.local_ip))
      .filter((c) => { const k = `${c.process}:${c.local_port}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .map((c) => ({ process: c.process, port: c.local_port, addr: c.local_ip }))
      .sort((a, b) => a.port - b.port);
  } catch {
    state.listeners = null;
  }
  if (state.view === "security") render();
}

function renderSecurity() {
  const checks = securityChecks();
  const n = (s) => checks.filter((c) => c.status === s).length;
  const todo = n("bad") + n("warn");
  $("#sec-summary").innerHTML = `
    <div class="hero">${todo ? `${todo} thing${todo > 1 ? "s" : ""} to look at` : "Everything checks out"}</div>
    <div class="sub">${n("bad")} problem${n("bad") === 1 ? "" : "s"} · ${n("warn")} worth a look · ${n("good")} good${n("note") ? ` · ${n("note")} tidy-up` : ""}${n("info") ? ` · ${n("info")} not checked yet` : ""}</div>`;
  $("#sec-list").innerHTML = checks.map((c) => {
    const a = c.action;
    const btn = !a ? "" : a.url
      ? `<button class="btn small" data-url="${esc(a.url)}">${esc(a.label)}</button>`
      : a.action
        ? `<button class="btn small" data-action="${esc(a.action)}">${esc(a.label)}</button>`
        : `<button class="btn small" data-goto="${esc(a.goto)}"${a.filter ? ` data-filter="${esc(a.filter)}"` : ""}>${esc(a.label)}</button>`;
    return `<div class="check ${c.status}">
      <span class="check-badge ${c.status}">${CHECK_ICON[c.status]}${CHECK_LABEL[c.status]}</span>
      <div><div class="title">${esc(c.title)}</div><div class="detail">${esc(c.detail)}</div></div>
      <div>${btn}</div></div>`;
  }).join("");
}

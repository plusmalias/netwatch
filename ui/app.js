"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const HISTORY_POINTS = 300;

const state = {
  view: "overview",
  net: null,
  devices: [],
  alerts: [],
  capture: { state: "stopped" },
  feeds: null,
  traffic: null,
  dns: [],
  scanning: false,
  scanPhase: "",
  dataDir: "",
  history: [], // this computer's throughput, { ts, rx, tx } in bits/s
  conns: [],
  connError: "",
  devFilter: "all",
  devNet: "all", // network (router MAC) shown in Devices, or "all"
  connFilter: "internet",
  alertFilter: "open",
  dnsMode: "log",
  drawerMac: null,
  drawerSig: "",
  portChecks: new Set(),
  // Network-wide monitors (see network.js)
  settings: null,
  router: null,
  wan: [], // household throughput from the router, { ts, rx_bps, tx_bps }
  usage: new Map(), // local hour start → [rx, tx]
  forecast: null, // where this billing cycle's data use is heading (see forecastInfo)
  health: [],
  healthSupported: true,
  outage: null,
  outages: [],
  wifi: null,
  firewall: null,
  publicInfo: null,
  publicError: null,
  speed: { running: false, phase: null, mbps: null, error: null },
  speedtests: [],
  speedNext: null, // when the next scheduled speed test is due (ms), if scheduled
  apps: null,
  usageView: "days",
  bt: null, // { info, nearby, scan_state }
  bleFilter: "all",
  bleCategory: null,
  bleBand: null, // show only this proximity band in the nearby list
  btMapFilter: "all", // All · Mine · Trackers · Wi-Fi on the map
  btDrawer: null, // the Bluetooth device open in the details panel
  btDrawerSig: "",
  mifi: null, // the 4G hotspot's status
  linkLog: [],
  watch: [], // watched hosts
  listeners: null, // apps on this computer accepting network connections
  audit: null, // the security audits' saved state (see audit.js)
  location: null, // { status, last_read } of Location Services permission, never a position
  locate: null, // the Bluetooth device being located
  tlFilter: "all",
  histRange: "24h",
  historyData: [],
  historyLoaded: 0,
  historyFor: null,
  leak: null,
  vpn: null,
  palette: null,
  trace: { running: false, target: "1.1.1.1", hops: [], error: null },
  dnsCheck: { running: false, results: [], error: null },
  expertInfo: new Map(), // alert kind → ATT&CK details, for expert mode
  expertOpen: new Set(), // ids of the alert cards with "Expert details" open
};

// ------------------------------------------------------------------ helpers

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

// Decimal units, like carriers and routers count data allowances.
function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

const fmtMs = (ms) => (ms == null ? "—" : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`);

function ago(ts) {
  if (!ts) return "—";
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// 450136 → "5d 5h"
function fmtDuration(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`;
}

const clock = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const hhmm = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const fullTime = (ts) => (ts ? new Date(ts).toLocaleString() : "");
const shortDate = (ts) => new Date(ts).toLocaleDateString([], { day: "numeric", month: "short" });

const isRandomMac = (mac) => (parseInt(mac.slice(0, 2), 16) & 2) !== 0;
const isOnline = (d) => d.online;
// On the network (answers ARP) but not answering pings or connections:
// usually a phone or laptop that's asleep.
const isAsleep = (d) => d.online && !d.is_self && !d.is_gateway && Date.now() - (d.last_reply || 0) > 5 * 60_000;
const presenceDot = (d) => (isAsleep(d) ? "idle" : isOnline(d) ? "good" : "off");
const presenceWord = (d) => (isAsleep(d) ? "Online, asleep" : isOnline(d) ? "Online" : "Offline");

function call(cmd, args) {
  return invoke(cmd, args).catch((e) => {
    toast({ severity: "info", title: "Something went wrong", detail: String(e) });
    throw e;
  });
}

// ------------------------------------------------------------------ icons

const ICONS = {
  router: '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 16.5h.01M11 16.5h.01M8 9.5a6 6 0 0 1 8 0M5.5 7a9.5 9.5 0 0 1 13 0"/></svg>',
  computer: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/></svg>',
  phone: '<svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.5h2"/></svg>',
  media: '<svg viewBox="0 0 24 24"><rect x="2.5" y="5" width="19" height="12" rx="1.5"/><path d="M8 21h8"/><path d="m10 8.5 4.5 2.5-4.5 2.5z"/></svg>',
  speaker: '<svg viewBox="0 0 24 24"><rect x="6" y="2.5" width="12" height="19" rx="2"/><circle cx="12" cy="14.5" r="3"/><path d="M12 7h.01"/></svg>',
  printer: '<svg viewBox="0 0 24 24"><path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="1.5"/><path d="M6 14h12v7H6z"/></svg>',
  home: '<svg viewBox="0 0 24 24"><path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-5h4v5"/></svg>',
  storage: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
  device: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/></svg>',
  high: '<svg viewBox="0 0 24 24"><path d="M12 3 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/></svg>',
  medium: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg>',
  low: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11v5.5"/></svg>',
  info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11v5.5"/></svg>',
};

// Icons for the KPI cards.
const TILE_ICONS = {
  devices: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/></svg>',
  alerts: '<svg viewBox="0 0 24 24"><path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/></svg>',
  latency: '<svg viewBox="0 0 24 24"><path d="M4 16a8 8 0 1 1 16 0"/><path d="m12 16 4-5"/></svg>',
  data: '<svg viewBox="0 0 24 24"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg>',
  router: '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 16.5h.01M11 16.5h.01M8 9.5a6 6 0 0 1 8 0M5.5 7a9.5 9.5 0 0 1 13 0"/></svg>',
  wifi: '<svg viewBox="0 0 24 24"><path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0"/><path d="M12 19.5h.01"/></svg>',
  globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
};
const tileIcon = (k, tone = "") => `<div class="tile-icon ${tone}">${TILE_ICONS[k]}</div>`;

function applyTheme() {
  document.documentElement.dataset.theme = state.settings?.theme || "light";
}

const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
const sevBadge = (s) => `<span class="sev ${s}">${ICONS[s]}${SEVERITY_LABEL[s]}</span>`;

const SERVICE_LABEL = {
  googlecast: "Chromecast", airplay: "AirPlay", raop: "AirPlay audio", hap: "HomeKit", homekit: "HomeKit",
  matter: "Matter", ipp: "Printer", ipps: "Printer", printer: "Printer", "pdl-datastream": "Printer",
  smb: "File sharing", afpovertcp: "File sharing", ssh: "SSH", "sftp-ssh": "SSH", rfb: "Screen sharing",
  "companion-link": "Apple device", "spotify-connect": "Spotify", sonos: "Sonos", "amzn-wplay": "Fire TV",
  http: "Web interface", upnp: "UPnP", workstation: "Computer", androidtvremote2: "Android TV",
  remotepairing: "Apple device", "apple-mobdev2": "Apple device", airport: "AirPort", "touch-able": "Apple TV remote",
  mediaremotetv: "Apple TV", sleepproxy: "Sleep proxy", "nvstream": "GameStream", "home-assistant": "Home Assistant",
};
const HIDDEN_SERVICES = new Set(["device-info", "services"]);

const PORT_LABEL = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
  445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP", 1883: "MQTT", 3389: "RDP", 5000: "UPnP/HTTP",
  5900: "VNC", 7000: "AirPlay", 8008: "HTTP alt", 8009: "Cast", 8080: "HTTP proxy", 8443: "HTTPS alt",
  8883: "MQTT TLS", 9100: "Printing", 32400: "Plex", 49152: "UPnP", 62078: "iOS sync",
};
const RISKY_PORTS = new Set([21, 23, 3389, 5900]);

function serviceLabels(d) {
  return [...new Set(d.services.filter((s) => !HIDDEN_SERVICES.has(s)).map((s) => SERVICE_LABEL[s] || s))];
}

function deviceKind(d) {
  const has = (s) => d.services.includes(s);
  const text = `${d.label || ""} ${d.friendly_name || ""} ${d.vendor || ""} ${d.model || ""} ${d.hostname || ""}`.toLowerCase();
  if (d.is_gateway) return ["router", "Router"];
  if (d.is_self) return ["computer", "This computer"];
  if (has("ipp") || has("ipps") || has("printer") || has("pdl-datastream")) return ["printer", "Printer"];
  if (has("googlecast") || has("amzn-wplay") || has("androidtvremote2") || has("mediaremotetv") || /tv|roku|chromecast|fire ?tv/.test(text)) return ["media", "TV / streaming"];
  if (has("sonos") || has("raop") || has("spotify-connect") || /sonos|speaker|homepod|echo/.test(text)) return ["speaker", "Speaker"];
  if (has("hap") || has("matter") || /espressif|tuya|shelly|nest|ring|hue|philips|ecobee|wyze/.test(text)) return ["home", "Smart home"];
  if (/synology|qnap|nas|western digital/.test(text)) return ["storage", "Storage"];
  if (/macbook|imac|mac mini|mac studio|desktop|laptop/.test(text)) return ["computer", "Computer"];
  if (has("remotepairing") || has("apple-mobdev2") || /iphone|ipad|android|pixel|galaxy|phone/.test(text)) return ["phone", "Phone / tablet"];
  if (has("smb") || has("ssh") || has("rfb") || has("companion-link") || /macbook|imac|desktop|laptop|pc|raspberry/.test(text))
    return ["computer", "Computer"];
  if (isRandomMac(d.mac) && !d.vendor) return ["phone", "Phone / laptop"];
  return ["device", "Device"];
}

// Best guess at the operating system, from DHCP fingerprints, advertised
// services and model names, then the ping TTL. Returns [os, how we know].
function osGuess(d) {
  const v = (d.dhcp_vendor || "").toLowerCase();
  const has = (s) => d.services.includes(s);
  const text = `${d.model || ""} ${d.hostname || ""} ${d.friendly_name || ""}`.toLowerCase();
  if (d.is_self && /Mac/.test(navigator.userAgent)) return ["macOS", "this computer"];
  if (v.startsWith("msft")) return ["Windows", "DHCP"];
  if (v.startsWith("android-dhcp")) return [`Android ${v.split("-")[2] || ""}`.trim(), "DHCP"];
  if (/iphone|ipad/.test(text) || has("remotepairing") || has("apple-mobdev2")) return ["iOS / iPadOS", "advertised services"];
  if (/macbook|imac|macmini|mac ?mini|macpro|mac studio|^mac\d/.test(text)) return ["macOS", "model name"];
  if (has("androidtvremote2")) return ["Android TV", "advertised services"];
  if (has("companion-link")) return ["Apple (macOS or iOS)", "advertised services"];
  if (v.startsWith("dhcpcd") || v.startsWith("udhcp")) return ["Linux", "DHCP"];
  if ((d.dhcp_params || "").startsWith("1,121,3,6,15,") && d.dhcp_params.includes("252")) return ["Apple (macOS or iOS)", "DHCP fingerprint"];
  if (d.ttl > 64 && d.ttl <= 128) return ["Windows", "ping TTL"];
  if (d.ttl > 128) return ["Embedded / network device", "ping TTL"];
  return null;
}

// Devices often advertise names padded with serials or UUIDs; hide that noise.
function cleanName(s) {
  if (!s) return null;
  s = s.replace(/\.local\.?$/i, "");
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return null;
  const t = s.replace(/[-_ ]?[0-9a-f]{12,}$/i, "").trim();
  return t || null;
}

function deviceName(d) {
  if (d.is_gateway && !d.label && !d.friendly_name) return d.vendor ? `Router (${d.vendor.split(/[ ,]/)[0]})` : "Router";
  return d.label || cleanName(d.friendly_name) || cleanName(d.hostname) || cleanName(d.model) || (d.vendor ? `${d.vendor} device` : isRandomMac(d.mac) ? "Private device" : "Unknown device");
}

function deviceSubtitle(d) {
  const bits = d.is_self ? ["This computer"] : [];
  if (d.vendor) bits.push(d.vendor);
  else if (isRandomMac(d.mac)) bits.push("Private MAC address");
  const name = deviceName(d);
  if (d.model && d.model !== d.vendor && d.model !== name) bits.push(d.model);
  const host = cleanName(d.hostname);
  if (host && host !== name) bits.push(host);
  return bits.join(" · ");
}

// ------------------------------------------------------------------ chrome

// Top navigation sections and the pages (sub-tabs) inside each.
const NAV = {
  overview: ["overview"],
  activity: ["timeline"],
  devices: ["devices", "map"],
  network: ["network", "wifi", "history"],
  bluetooth: ["bluetooth"],
  traffic: ["traffic", "connections"],
  security: ["security", "audit", "alerts"],
  settings: ["settings"],
};
const VIEW_TITLES = {
  overview: "Overview", timeline: "Activity", devices: "Devices", map: "Network map", network: "Connection",
  wifi: "Wi-Fi analyzer", history: "History", bluetooth: "Bluetooth and nearby", traffic: "Traffic",
  connections: "Connections", security: "Security checkup", audit: "Security audits", alerts: "Alerts", settings: "Settings",
};
const TAB_LABELS = {
  devices: "All devices", map: "Network map", network: "Connection", wifi: "Wi-Fi analyzer", history: "History",
  traffic: "Traffic", connections: "Connections", security: "Checkup", audit: "Audit", alerts: "Alerts",
};
const VIEW_SUBS = {
  overview: "Your network at a glance",
  timeline: "Everything that happened on your network in the last 7 days",
  devices: "Every device NetWatch has seen on your network",
  map: "How your devices connect, and which are online now",
  network: "Your router, internet connection, Wi-Fi and the tools to test them",
  wifi: "Nearby Wi-Fi networks by channel, and the least crowded channel for your router",
  history: "Latency, packet loss, outages and throughput over time",
  bluetooth: "Your Bluetooth devices, what's nearby, and unknown trackers",
  traffic: "What this computer is sending and receiving, and which apps use the most",
  connections: "Every open connection on this computer and the app behind it",
  security: "What NetWatch can check about your network's security",
  audit: "Weekly port audit, new listening apps and startup items, DNS and Wi-Fi look-alikes, certificates",
  alerts: "Everything NetWatch has flagged",
  settings: "Notifications, data allowance, Bluetooth, threat lists and more",
};
const groupOf = (view) => Object.keys(NAV).find((g) => NAV[g].includes(view)) || "overview";
const lastInGroup = {};

function setView(view) {
  state.view = view;
  const group = groupOf(view);
  lastInGroup[group] = view;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.group === group));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  $("#view-title").textContent = VIEW_TITLES[view];
  $("#view-sub").textContent = VIEW_SUBS[view] || "";
  const tabs = NAV[group];
  const sub = $("#subnav");
  sub.hidden = tabs.length < 2;
  sub.innerHTML = tabs.length < 2 ? "" : tabs.map((v) =>
    `<button class="subnav-item ${v === view ? "active" : ""}" data-view="${v}">${esc(TAB_LABELS[v] || VIEW_TITLES[v])}<span class="count" id="tab-count-${v}"></span></button>`).join("");
  $("main").scrollTop = 0;
  hideTip();
  if (view === "connections") refreshConnections();
  if (view === "settings") loadCustomList();
  if (view === "security") refreshListeners();
  if (view === "network") invoke("vpn_status").then((v) => { state.vpn = v; if (state.view === "network") render(); }).catch(() => {});
  if (view === "history") state.historyLoaded = 0;
  if (view !== "bluetooth") { closeLocate(); closeBtDrawer(); }
  render();
}

// Info alerts (devices joining/leaving) are a log, not something to act on.
const openAlerts = () => state.alerts.filter((a) => !a.acknowledged && a.severity !== "info");

function renderChrome() {
  const n = state.net;
  $("#net-summary").innerHTML = n
    ? `<span class="dot ${state.outage ? "bad" : "good"}"></span><b>${esc(n.interface)}</b> ${esc(n.ip)} <span class="sep">·</span> Router ${esc(n.gateway_ip || "unknown")}`
    : '<span class="dot off"></span>Not connected';

  const online = state.devices.filter(isOnline).length;
  $("#nav-devices").textContent = state.devices.length ? `${online}` : "";
  $("#nav-network").innerHTML = state.outage ? '<span class="dot bad" title="Connection down"></span>' : "";
  const suspects = (state.bt?.nearby || []).filter(isSuspectTracker).length;
  $("#nav-bluetooth").textContent = suspects || "";
  // The Security badge counts problems found plus open alerts.
  const problems = securityChecks().filter((c) => c.status === "bad").length;
  const open = openAlerts().length;
  $("#nav-security").textContent = problems + open || "";
  const tabCount = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || ""; };
  tabCount("tab-count-alerts", open);
  tabCount("tab-count-security", problems);
  tabCount("tab-count-devices", state.devices.length);

  const c = state.capture;
  const pill = {
    running: ["good", `Monitoring ${c.interface || ""}`],
    stopped: ["off", "Capture off"],
    needs_permission: ["warn", "Capture needs access"],
    unavailable: ["warn", "Capture unavailable"],
    error: ["bad", "Capture error"],
  }[c.state] || ["off", c.state];
  $("#capture-pill").innerHTML = `<span class="dot ${pill[0]}"></span>${esc(pill[1])}`;

  const banner = $("#capture-banner");
  if (c.state === "needs_permission" || c.state === "unavailable" || c.state === "error") {
    const canGrant = c.state === "needs_permission";
    banner.hidden = false;
    banner.innerHTML = `<div class="grow"><b>Traffic monitoring is off.</b> ${esc(c.message || "")}
      Device discovery, the Network page and connection checks still work.</div>
      ${canGrant ? '<button class="btn primary" data-action="grant">Grant access</button>' : '<button class="btn" data-action="start-capture">Retry</button>'}`;
  } else {
    banner.hidden = true;
  }

  const btn = $("#scan-btn");
  btn.disabled = state.scanning;
  btn.textContent = state.scanning ? "Scanning…" : "Scan network";
  $("#scan-phase").textContent = state.scanPhase;
}

// ------------------------------------------------------------------ charts

function niceStep(max, ticks) {
  const raw = max / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  return (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
}

const tip = () => $("#tooltip");
function placeTip(clientX, clientY) {
  const t = tip();
  t.style.left = `${Math.min(clientX + 14, window.innerWidth - t.offsetWidth - 8)}px`;
  t.style.top = `${Math.min(clientY + 14, window.innerHeight - t.offsetHeight - 8)}px`;
}
function hideTip() {
  tip().hidden = true;
  document.querySelectorAll(".chart").forEach((c) => {
    delete c.dataset.hoverX;
    c.querySelector(".hover-layer")?.replaceChildren();
  });
}
const tipRow = (cls, label, value) =>
  `<div class="t-row"><i class="t-key ${cls}"></i>${esc(label)}<b>${esc(value)}</b></div>`;

/**
 * A time-series line chart in an existing `.chart` element.
 * points: [{ ts, [key]: number|null }], series: [{ key, label, cls }]
 * Null values break the line (e.g. a ping that got no reply).
 */
function lineChart(el, { points, series, span, now, fmt, minTop, ticks, bands = [], emptyMsg, aria }) {
  const W = el.clientWidth || 600;
  const H = el.clientHeight || 180;
  const pad = { l: 64, r: 10, t: 8, b: 22 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  if (emptyMsg) {
    el.innerHTML = `<svg viewBox="0 0 ${W} ${H}"><text class="empty-msg" x="${W / 2}" y="${H / 2}" text-anchor="middle">${esc(emptyMsg)}</text></svg>`;
    return;
  }
  const t0 = now - span;
  const visible = points.filter((p) => p.ts >= t0);
  const vals = visible.flatMap((p) => series.map((s) => p[s.key])).filter((v) => v != null);
  const maxVal = Math.max(minTop, ...vals);
  const step = niceStep(maxVal, 4);
  const top = Math.ceil(maxVal / step) * step;
  const x = (ts) => pad.l + ((ts - t0) / span) * iw;
  const y = (v) => pad.t + ih - (v / top) * ih;

  let grid = "";
  for (let v = 0; v <= top + 1e-9; v += step) {
    grid += `<line class="gridline" x1="${pad.l}" x2="${W - pad.r}" y1="${y(v)}" y2="${y(v)}"/>
      <text class="axis-label" x="${pad.l - 8}" y="${y(v) + 4}" text-anchor="end">${esc(fmt(v))}</text>`;
  }
  ticks.forEach((tk, i) => {
    const anchor = i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle";
    grid += `<text class="axis-label" x="${x(tk.ts)}" y="${H - 4}" text-anchor="${anchor}">${esc(tk.label)}</text>`;
  });
  const bandSvg = bands
    .filter((b) => (b.end ?? now) >= t0)
    .map((b) => {
      const bx = x(Math.max(b.start, t0));
      const bw = Math.max(2, x(Math.min(b.end ?? now, now)) - bx);
      return `<rect class="band" x="${bx}" y="${pad.t}" width="${bw}" height="${ih}"/>`;
    })
    .join("");
  const path = (key) => {
    let d = "";
    let pen = false;
    for (const p of visible) {
      if (p[key] == null) { pen = false; continue; }
      d += `${pen ? "L" : "M"}${x(p.ts).toFixed(1)},${y(p[key]).toFixed(1)}`;
      pen = true;
    }
    return d;
  };
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(aria)}">
    ${bandSvg}${grid}
    ${[...series].reverse().map((s) => `<path class="series ${s.cls}" d="${path(s.key)}"/>`).join("")}
    <g class="hover-layer"></g>
    <rect class="hit" x="${pad.l}" y="${pad.t}" width="${iw}" height="${ih}" fill="transparent"/>
  </svg>`;

  const svg = el.querySelector("svg");
  const layer = svg.querySelector(".hover-layer");
  const showAt = (clientX, clientY) => {
    const rect = svg.getBoundingClientRect();
    const ts = t0 + ((((clientX - rect.left) / rect.width) * W - pad.l) / iw) * span;
    let best = null;
    for (const p of visible) if (!best || Math.abs(p.ts - ts) < Math.abs(best.ts - ts)) best = p;
    if (!best) return hideTip();
    const px = x(best.ts);
    layer.innerHTML = `<line class="crosshair" x1="${px}" x2="${px}" y1="${pad.t}" y2="${pad.t + ih}"/>` +
      series.filter((s) => best[s.key] != null).map((s) => `<circle class="hover-dot ${s.cls}" cx="${px}" cy="${y(best[s.key])}" r="4.5"/>`).join("");
    const inBand = bands.find((b) => best.ts >= b.start && best.ts <= (b.end ?? now));
    tip().hidden = false;
    tip().innerHTML = `<div class="t-head">${clock(best.ts)}</div>` +
      series.map((s) => tipRow(s.cls, s.label, best[s.key] == null ? "no reply" : fmt(best[s.key]))).join("") +
      (inBand ? `<div class="t-note">${esc(inBand.label)}</div>` : "");
    placeTip(clientX, clientY);
    el.dataset.hoverX = clientX;
    el.dataset.hoverY = clientY;
  };
  const hit = svg.querySelector(".hit");
  hit.addEventListener("mousemove", (e) => showAt(e.clientX, e.clientY));
  hit.addEventListener("mouseleave", hideTip);
  // Keep the crosshair in place while the chart refreshes under the cursor.
  if (el.dataset.hoverX) showAt(+el.dataset.hoverX, +el.dataset.hoverY);
}

/**
 * Stacked columns: cols = [{ label, tip, values: [a, b] }], series = [{ label, cls }].
 * Columns are capped at 24px with a 2px surface gap between segments.
 */
function columnChart(el, { cols, series, fmt, every = 1, aria }) {
  const W = el.clientWidth || 600;
  const H = el.clientHeight || 180;
  const pad = { l: 64, r: 10, t: 8, b: 22 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const maxVal = Math.max(1e6, ...cols.map((c) => c.values[0] + c.values[1]));
  const step = niceStep(maxVal, 4);
  const top = Math.ceil(maxVal / step) * step;
  const y = (v) => pad.t + ih - (v / top) * ih;
  const band = iw / cols.length;
  const bw = Math.max(2, Math.min(24, band - 4));
  let grid = "";
  for (let v = 0; v <= top + 1e-9; v += step) {
    grid += `<line class="gridline" x1="${pad.l}" x2="${W - pad.r}" y1="${y(v)}" y2="${y(v)}"/>
      <text class="axis-label" x="${pad.l - 8}" y="${y(v) + 4}" text-anchor="end">${esc(fmt(v))}</text>`;
  }
  // A column whose top corners are rounded (the data end); the baseline stays square.
  const capped = (x0, y0, w, h) => {
    const r = Math.min(4, w / 2, h);
    return `M${x0},${y0 + h}V${y0 + r}Q${x0},${y0} ${x0 + r},${y0}H${x0 + w - r}Q${x0 + w},${y0} ${x0 + w},${y0 + r}V${y0 + h}Z`;
  };
  let marks = "";
  cols.forEach((c, i) => {
    const cx = pad.l + band * i + (band - bw) / 2;
    let base = y(0);
    const segs = c.values.map((v, k) => ({ v, k })).filter((s) => s.v > 0);
    segs.forEach((s, j) => {
      const h = Math.max(1, (s.v / top) * ih - (j > 0 ? 2 : 0));
      const topY = base - (j > 0 ? 2 : 0) - h;
      const cls = series[s.k].cls;
      marks += j === segs.length - 1
        ? `<path class="col ${cls}" d="${capped(cx, topY, bw, h)}"/>`
        : `<rect class="col ${cls}" x="${cx}" y="${topY}" width="${bw}" height="${h}"/>`;
      base = topY;
    });
    if (i % every === 0 || i === cols.length - 1) {
      marks += `<text class="axis-label" x="${pad.l + band * i + band / 2}" y="${H - 4}" text-anchor="middle">${esc(c.label)}</text>`;
    }
  });
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(aria)}">${grid}<g class="hover-layer"></g>${marks}
    ${cols.map((_, i) => `<rect class="hit-col" data-i="${i}" x="${pad.l + band * i}" y="${pad.t}" width="${band}" height="${ih}" fill="transparent"/>`).join("")}</svg>`;
  const layer = el.querySelector(".hover-layer");
  el.querySelectorAll(".hit-col").forEach((r) => {
    r.addEventListener("mousemove", (e) => {
      const c = cols[+r.dataset.i];
      layer.innerHTML = `<rect class="col-hover" x="${r.getAttribute("x")}" y="${pad.t}" width="${band}" height="${ih}"/>`;
      tip().hidden = false;
      tip().innerHTML = `<div class="t-head">${esc(c.tip)}</div>` +
        series.map((s, k) => tipRow(s.cls, s.label, fmt(c.values[k]))).join("") +
        `<div class="t-row t-total">Total<b>${esc(fmt(c.values[0] + c.values[1]))}</b></div>`;
      placeTip(e.clientX, e.clientY);
    });
    r.addEventListener("mouseleave", hideTip);
  });
}

function timeTicks(now, span, count, label) {
  return Array.from({ length: count + 1 }, (_, m) => {
    const ts = now - span + (m * span) / count;
    return { ts, label: m === count ? "now" : label(span - (m * span) / count) };
  });
}

function legend(items) {
  return items.map((i) => `<span class="key"><i class="swatch ${i.cls}"></i>${esc(i.label)}${i.value != null ? ` <b>${esc(i.value)}</b>` : ""}</span>`).join("");
}

// Throughput: the whole household from the router's counters when it reports
// them, otherwise this computer's own traffic from capture.
function renderThroughput(el, legendEl, titleEl, { preferHousehold }) {
  const household = preferHousehold && state.router?.counters && state.wan.length > 1;
  const src = household
    ? state.wan.map((w) => ({ ts: w.ts, rx: w.rx_bps, tx: w.tx_bps }))
    : state.history;
  const last = src[src.length - 1];
  if (titleEl) titleEl.innerHTML = household
    ? 'Throughput <span class="muted">· whole network, from your router</span>'
    : 'Throughput <span class="muted">· this computer</span>';
  legendEl.innerHTML = legend([
    { cls: "s1", label: "Download", value: fmtBits(last?.rx || 0) },
    { cls: "s2", label: "Upload", value: fmtBits(last?.tx || 0) },
  ]);
  const span = household ? 10 * 60_000 : HISTORY_POINTS * 1000;
  const now = last?.ts || Date.now();
  const empty = !household && state.capture.state !== "running" && src.length < 2;
  lineChart(el, {
    points: src,
    series: [{ key: "rx", label: "Download", cls: "s1" }, { key: "tx", label: "Upload", cls: "s2" }],
    span,
    now,
    fmt: fmtBits,
    minTop: 8000,
    ticks: timeTicks(now, span, 5, (ms) => `-${Math.round(ms / 60000)}m`),
    emptyMsg: empty ? (state.router?.counters ? "Waiting for the router's first readings…" : "Throughput appears here once traffic capture is running.") : null,
    aria: "Download and upload throughput over time",
  });
}

// ------------------------------------------------------------------ views

function renderOverview() {
  const online = state.devices.filter(isOnline);
  const untrusted = state.devices.filter((d) => !d.trusted);
  const open = openAlerts();
  const bySev = (s) => open.filter((a) => a.severity === s).length;
  const h = state.health[state.health.length - 1];
  const inet = state.outage
    ? { value: state.outage.kind === "router" ? "No router" : "Down", sub: `since ${hhmm(state.outage.start)}`, bad: true }
    : h
      ? { value: h.internet_ms != null ? fmtMs(h.internet_ms) : "No reply", sub: `latency · router ${fmtMs(h.gateway_ms)}` }
      : { value: "—", sub: "Checking…" };
  const today = usageTotal(dayStart(Date.now()));
  const fc = forecastInfo();
  // The forecast sentence when there is one (the cycle summary stays in its tooltip).
  const dataSub = fc?.f.projected != null
    ? `<span class="dot ${fc.level}"></span> ${esc(fc.text)}${fc.level === "bad" ? ` · ${esc(fc.delta)}` : ""}`
    : esc(cycleSummary());
  $("#tiles").innerHTML = `
    <div class="tile click" data-goto="devices"><div class="label">Devices online</div>${tileIcon("devices")}<div class="value">${online.length}</div>
      <div class="sub">${state.devices.length} seen · ${untrusted.length} untrusted</div></div>
    <div class="tile click" data-goto="alerts"><div class="label">Open alerts</div>${tileIcon("alerts", open.some((a) => a.severity === "high") ? "red" : open.length ? "amber" : "green")}<div class="value">${open.length}</div>
      <div class="sub">${["high", "medium", "low"].map((s) => `<span class="sev-inline">${sevBadge(s)} ${bySev(s)}</span>`).join("")}</div></div>
    <div class="tile click" data-goto="network"><div class="label">Internet</div>${tileIcon("latency", inet.bad ? "red" : "violet")}<div class="value">${inet.bad ? `<span class="dot bad"></span> ` : ""}${esc(inet.value)}</div>
      <div class="sub">${esc(inet.sub)}</div></div>
    <div class="tile click" data-goto="history"><div class="label">Data used today</div>${tileIcon("data", "green")}<div class="value">${state.router?.counters ? fmtBytes(today) : "—"}</div>
      <div class="sub"${fc?.f.projected != null ? ` title="${esc(cycleSummary())}"` : ""}>${state.router?.counters ? dataSub : state.router?.checked ? "Your router doesn't report usage" : "Asking your router…"}</div></div>`;

  renderThroughput($("#ov-chart"), $("#ov-legend"), $("#ov-chart-title"), { preferHousehold: true });
  renderScorePanel();
  renderReadiness();

  const recent = [...state.alerts].reverse().slice(0, 6);
  $("#ov-alerts").innerHTML = recent.length
    ? recent.map((a) => `<div class="alert-mini">${sevBadge(a.severity)}<span class="title" title="${esc(a.title)}">${esc(a.title)}</span><span class="time">${ago(a.last_ts)}</span></div>`).join("")
    : `<div class="empty">No alerts. NetWatch is watching for new devices, spoofing, scans and malware lookups.</div>`;

  const newest = [...state.devices].sort((a, b) => b.first_seen - a.first_seen).slice(0, 6);
  $("#ov-devices").innerHTML = newest.length
    ? newest.map((d) => `<div class="dev-mini click" data-mac="${esc(d.mac)}">
          <span class="dot ${presenceDot(d)}" title="${presenceWord(d)}"></span>
          <div class="grow"><div class="truncate">${esc(deviceName(d))}</div><div class="muted small">${esc(d.ip)} · first seen ${ago(d.first_seen)}</div></div>
          ${d.trusted ? "" : '<span class="chip warn">Untrusted</span>'}</div>`).join("")
    : `<div class="empty">${state.scanning ? "Scanning…" : "No devices yet."}</div>`;
}

function filteredDevices() {
  const q = $("#dev-search").value.trim().toLowerCase();
  return state.devices
    .filter((d) => state.devNet === "all" || (state.devNet === "current" ? onNetwork(d, currentNetwork()) : onNetwork(d, state.devNet)))
    .filter((d) => state.devFilter !== "online" || isOnline(d))
    .filter((d) => state.devFilter !== "untrusted" || !d.trusted)
    .filter((d) => state.devFilter !== "watched" || d.notify_presence)
    .filter((d) => !q || [deviceName(d), d.ip, d.mac, d.vendor, d.hostname, d.model, osGuess(d)?.[0], d.notes, ...(d.tags || [])].some((v) => (v || "").toLowerCase().includes(q.replace(/^#/, ""))))
    .sort((a, b) => (b.is_gateway - a.is_gateway) || (b.is_self - a.is_self) || (isOnline(b) - isOnline(a)) || ipNum(a.ip) - ipNum(b.ip));
}

function renderDevices() {
  const nets = knownNetworks();
  const sel = $("#dev-net");
  sel.hidden = nets.length < 2;
  const opts = `<option value="all">All networks</option><option value="current">This network</option>${nets.map((n) => `<option value="${esc(n.id)}">${esc(n.name)}${n.current ? " (connected)" : ""}</option>`).join("")}`;
  if (sel.dataset.sig !== opts) { sel.innerHTML = opts; sel.dataset.sig = opts; }
  sel.value = state.devNet;
  const list = filteredDevices();
  $("#dev-table tbody").innerHTML = list.map((d) => {
    const [kind, kindLabel] = deviceKind(d);
    const os = osGuess(d);
    const services = serviceLabels(d);
    const chips = services.map((s) => `<span class="chip">${esc(s)}</span>`);
    if (os && !services.includes(os[0])) chips.unshift(`<span class="chip">${esc(os[0])}</span>`);
    if (isAsleep(d)) chips.unshift('<span class="chip">Asleep</span>');
    for (const p of d.open_ports || []) if (RISKY_PORTS.has(p)) chips.push(`<span class="chip bad">${PORT_LABEL[p]} open</span>`);
    if (d.notify_presence) chips.push('<span class="chip">Watched</span>');
    if (!d.is_self && !d.is_gateway && d.network && d.network !== currentNetwork() && state.devNet === "all") chips.push(`<span class="chip">${esc(networkName(d.network))}</span>`);
    if ((d.aliases || []).length) chips.push(`<span class="chip" title="${esc(d.aliases.join(", "))}">${d.aliases.length + 1} addresses</span>`);
    for (const t of d.tags || []) chips.push(`<span class="chip tag">#${esc(t)}</span>`);
    return `<tr class="click" data-mac="${esc(d.mac)}">
      <td><span class="dot ${presenceDot(d)}" title="${presenceWord(d)}"></span></td>
      <td><div class="name-cell"><span class="kind" title="${esc(kindLabel)}">${ICONS[kind]}</span>
        <div style="min-width:0"><div class="primary truncate">${esc(deviceName(d))}</div><div class="secondary truncate">${esc(deviceSubtitle(d) || kindLabel)}</div></div></div></td>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono">${esc(d.mac)}</td>
      <td><div class="chips">${chips.join("") || '<span class="muted">—</span>'}</div></td>
      <td class="num">${isOnline(d) && !isAsleep(d) && d.rtt_ms != null && !d.is_self ? fmtMs(d.rtt_ms) : '<span class="muted">—</span>'}</td>
      <td title="${esc(fullTime(d.last_seen))}">${isOnline(d) ? "Now" : ago(d.last_seen)}</td>
      <td><button class="switch" role="switch" aria-checked="${d.trusted}" aria-label="Trusted" data-trust="${esc(d.mac)}"></button></td>
    </tr>`;
  }).join("");
  const empty = $("#dev-empty");
  empty.hidden = list.length > 0;
  empty.textContent = state.devices.length ? "No devices match." : state.scanning ? "Scanning your network…" : "No devices found yet. Press Scan network.";
}

const ipNum = (ip) => ip.split(".").reduce((n, o) => n * 256 + (+o || 0), 0);

function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

async function exportDevices() {
  const head = ["Name", "Tags", "Type", "OS", "IP address", "MAC address", "Vendor", "Model", "Hostname", "Services", "Online", "Latency (ms)", "First seen", "Last seen", "Trusted", "Open ports"];
  const rows = filteredDevices().map((d) => [
    deviceName(d), (d.tags || []).join("; "), deviceKind(d)[1], osGuess(d)?.[0], d.ip, d.mac, d.vendor, d.model, d.hostname,
    serviceLabels(d).join("; "), d.online ? "yes" : "no", d.online ? d.rtt_ms : "",
    new Date(d.first_seen).toISOString(), new Date(d.last_seen).toISOString(), d.trusted ? "yes" : "no",
    (d.open_ports || []).join(" "),
  ]);
  const csv = [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
  const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, "").replace("T", "-");
  const path = await call("save_export", { name: `NetWatch-devices-${stamp}.csv`, content: csv });
  toast({ severity: "info", title: `Exported ${rows.length} devices`, detail: `Saved to ${path}. Click to show it.`, onClick: () => invoke("reveal_file", { path }) });
}

function renderTraffic() {
  renderThroughput($("#tr-chart"), $("#tr-legend"), null, { preferHousehold: false });
  renderApps();
  const t = state.traffic;
  const hosts = t?.hosts || [];
  const max = Math.max(1, ...hosts.map((h) => h.bytes_in + h.bytes_out));
  const lanNames = new Map(state.devices.map((d) => [d.ip, deviceName(d)]));
  $("#tr-totals").textContent = t ? `${fmtBytes(t.total_rx)} in · ${fmtBytes(t.total_tx)} out` : "";
  $("#host-table tbody").innerHTML = hosts.slice(0, 60).map((h) => {
    const name = h.name || lanNames.get(h.ip);
    const ports = [...h.ports].slice(0, 4).map((p) => PORT_LABEL[p] || p).join(", ");
    return `<tr>
      <td><div class="truncate" title="${esc(name || h.ip)}">${h.flagged ? '<span class="chip bad">Blocklisted</span> ' : ""}${esc(name || h.ip)}</div>
        <div class="muted small">${name ? esc(h.ip) + " · " : ""}${h.lan ? "Local network" : "Internet"}</div></td>
      <td class="small">${esc(ports)}</td>
      <td class="num">${fmtBytes(h.bytes_in)}</td>
      <td class="num">${fmtBytes(h.bytes_out)}</td>
      <td><div class="share" title="${fmtBytes(h.bytes_in + h.bytes_out)}"><i style="width:${(((h.bytes_in + h.bytes_out) / max) * 100).toFixed(1)}%"></i></div></td>
    </tr>`;
  }).join("");
  const he = $("#host-empty");
  he.hidden = hosts.length > 0;
  he.textContent = state.capture.state === "running" ? "Waiting for traffic…" : "Turn on traffic capture to see which hosts this computer talks to.";
  renderDns();
}

function renderApps() {
  const panel = $("#apps-panel");
  panel.hidden = state.apps == null;
  if (state.apps == null) return;
  const apps = state.apps;
  const max = Math.max(1, ...apps.map((a) => a.bytes_in + a.bytes_out));
  const total = apps.reduce((n, a) => [n[0] + a.bytes_in, n[1] + a.bytes_out], [0, 0]);
  $("#apps-totals").textContent = apps.length ? `${fmtBytes(total[0])} in · ${fmtBytes(total[1])} out since NetWatch started` : "";
  $("#apps-table tbody").innerHTML = apps.slice(0, 40).map((a) => `<tr>
      <td><div class="truncate"><b>${esc(a.name)}</b></div>${a.processes > 1 ? `<div class="muted small">${a.processes} processes</div>` : ""}</td>
      <td class="num">${a.rate_in ? fmtBits(a.rate_in * 8) : '<span class="muted">—</span>'}</td>
      <td class="num">${a.rate_out ? fmtBits(a.rate_out * 8) : '<span class="muted">—</span>'}</td>
      <td class="num">${fmtBytes(a.bytes_in)}</td>
      <td class="num">${fmtBytes(a.bytes_out)}</td>
      <td><div class="share" title="${fmtBytes(a.bytes_in + a.bytes_out)}"><i style="width:${(((a.bytes_in + a.bytes_out) / max) * 100).toFixed(1)}%"></i></div></td>
    </tr>`).join("");
  const empty = $("#apps-empty");
  empty.hidden = apps.length > 0;
  empty.textContent = "Measuring… apps appear here once they use the network.";
}

// Registrable-ish domain: "a.b.example.co.uk" → "example.co.uk".
function baseDomain(name) {
  const parts = name.toLowerCase().split(".");
  if (parts.length <= 2) return name.toLowerCase();
  const sld = parts[parts.length - 2];
  const n = sld.length <= 3 && ["co", "com", "net", "org", "gov", "edu", "ac"].includes(sld) ? 3 : 2;
  return parts.slice(-n).join(".");
}

function renderDns() {
  const q = $("#dns-search").value.trim().toLowerCase();
  const rows = [...state.dns].reverse().filter((d) => !q || d.name.toLowerCase().includes(q) || d.client.includes(q));
  const live = state.capture.state === "running";
  if (state.dnsMode === "top") {
    const counts = new Map();
    for (const d of rows) {
      const k = baseDomain(d.name);
      const c = counts.get(k) || { n: 0, last: 0, blocked: false };
      c.n++; c.last = Math.max(c.last, d.ts); c.blocked ||= d.blocked;
      counts.set(k, c);
    }
    const top = [...counts.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 60);
    const max = Math.max(1, ...top.map(([, c]) => c.n));
    $("#dns-list").innerHTML = top.length
      ? top.map(([k, c]) => `<div class="dns-row top ${c.blocked ? "flag" : ""}">
          <span class="time num">${c.n}</span>
          <div><div class="name">${c.blocked ? sevBadge("high") + " " : ""}${esc(k)}</div>
          <div class="share"><i style="width:${((c.n / max) * 100).toFixed(1)}%"></i></div></div></div>`).join("")
      : `<div class="empty">${live ? "No lookups yet." : "DNS lookups appear here once capture is running."}</div>`;
    return;
  }
  $("#dns-list").innerHTML = rows.length
    ? rows.slice(0, 250).map((d) => `<div class="dns-row ${d.blocked ? "flag" : ""}">
        <span class="time">${clock(d.ts)}</span>
        <div><div class="name">${d.blocked ? sevBadge("high") + " " : ""}${esc(d.name)} <span class="muted">${esc(d.qtype)}</span></div>
        <div class="ans">${esc(d.answers.slice(0, 3).join(", ") || "no answer")}</div></div></div>`).join("")
    : `<div class="empty">${live ? "No lookups yet. (Browsers using DNS-over-HTTPS won't appear here.)" : "DNS lookups appear here once capture is running."}</div>`;
}

async function refreshConnections() {
  if (state.view !== "connections") return;
  try {
    state.conns = await invoke("list_connections");
    state.connError = "";
  } catch (e) {
    state.conns = [];
    state.connError = String(e);
  }
  renderConnections();
}

function renderConnections() {
  const q = $("#conn-search").value.trim().toLowerCase();
  const f = state.connFilter;
  const list = state.conns
    .filter((c) => (f === "listen" ? c.scope === "listen" && (c.proto === "UDP" || c.state === "Listen") : c.scope !== "listen"))
    .filter((c) => f !== "internet" || c.scope === "internet" || c.flagged)
    .filter((c) => !q || [c.process, c.remote_ip, c.remote_name, c.local_ip, String(c.local_port), String(c.remote_port)].some((v) => (v || "").toLowerCase().includes(q)))
    .sort((a, b) => (b.flagged - a.flagged) || (a.process || "~").localeCompare(b.process || "~"));
  $("#conn-count").textContent = `${list.length} shown`;
  $("#conn-table tbody").innerHTML = list.slice(0, 500).map((c) => `<tr>
    <td>${c.flagged ? '<span class="chip bad">Blocklisted</span> ' : ""}<b>${esc(c.process || "unknown")}</b> <span class="muted small">${c.pid ?? ""}</span></td>
    <td>${c.proto}</td>
    <td class="mono">${esc(c.local_ip)}:${c.local_port}</td>
    <td>${!c.remote_ip ? '<span class="muted">—</span>' : c.remote_name
      ? `<div class="truncate">${esc(c.remote_name)}</div><div class="muted small mono">${esc(c.remote_ip)}:${c.remote_port}</div>`
      : `<span class="mono">${esc(c.remote_ip)}:${c.remote_port}</span>`}</td>
    <td>${esc(c.state)}</td></tr>`).join("");
  const empty = $("#conn-empty");
  empty.hidden = list.length > 0;
  empty.textContent = state.connError || (state.conns.length ? "No connections match." : "Loading…");
}

// Expert mode: what an alert kind means in ATT&CK terms, plus the raw alert.
function expertHtml(a) {
  const open = state.expertOpen.has(a.id);
  const info = state.expertInfo.get(a.kind);
  let body = "";
  if (open) {
    const json = JSON.stringify(a, null, 2);
    const row = (label, html) => `<dt>${label}</dt><dd>${html}</dd>`;
    const techs = info?.techniques.length
      ? info.techniques.map((t) => `<div><button class="btn link" data-url="${esc(t.url)}" title="Open on attack.mitre.org">${esc(t.id)} · ${esc(t.name)}</button></div>`).join("")
      : '<span class="muted">No ATT&amp;CK technique maps cleanly to this alert (it is operational, or has common innocent causes).</span>';
    body = `<div class="expert-body"><dl class="facts compact">
        ${info ? row("Technique", techs) : ""}
        ${info?.tactic ? row("Tactic", esc(info.tactic)) : ""}
        ${info ? row("Why it matters", esc(info.why)) : ""}
        ${info ? row("What to do", `<ol>${info.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>`) : ""}
        ${row("Raw alert", `<pre class="hint mono expert-json">${esc(json)}</pre><button class="btn small" data-copy-alert="${a.id}">Copy</button>`)}
      </dl></div>`;
  }
  return `<div class="expert"><button class="btn link expert-toggle" data-expert="${a.id}" aria-expanded="${open}">${open ? "▾" : "▸"} Expert details</button>${body}</div>`;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fall back to a hidden text box in webviews that block the clipboard API.
    const box = document.createElement("textarea");
    box.value = text;
    box.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(box);
    box.select();
    const ok = document.execCommand("copy");
    box.remove();
    if (!ok) throw new Error("copy failed");
  }
}

function renderAlerts() {
  const expert = state.settings?.expert_mode === true;
  const list = [...state.alerts].reverse().filter((a) => state.alertFilter === "all" || !a.acknowledged);
  $("#alert-list").innerHTML = list.length
    ? list.map((a) => `<div class="alert-card ${a.severity} ${a.acknowledged ? "acked" : ""}">
        ${sevBadge(a.severity)}
        <div><div class="title">${esc(a.title)}</div><div class="detail">${esc(a.detail)}</div>
          <div class="meta" title="${esc(fullTime(a.ts))}">${ago(a.ts)}${a.count > 1 ? ` · seen ${a.count} times, last ${ago(a.last_ts)}` : ""}</div>${expert ? expertHtml(a) : ""}</div>
        ${a.acknowledged ? '<span class="muted small">Acknowledged</span>' : `<button class="btn small" data-ack="${a.id}">Acknowledge</button>`}
      </div>`).join("")
    : `<div class="panel empty">${state.alertFilter === "open" ? "No open alerts." : "No alerts recorded."}</div>`;
}

function renderSettings() {
  const c = state.capture;
  const running = c.state === "running";
  $("#capture-settings").innerHTML = `
    <span class="pill">${$("#capture-pill").innerHTML}</span>
    ${running ? '<button class="btn" data-action="stop-capture">Stop capture</button>' : '<button class="btn" data-action="start-capture">Start capture</button>'}
    ${c.state === "needs_permission" ? '<button class="btn primary" data-action="grant">Grant access</button>' : ""}
    ${c.message && !running ? `<div class="hint" style="flex-basis:100%">${esc(c.message)}</div>` : ""}`;

  const s = state.settings;
  renderLocationStatus();
  if (s && !document.activeElement?.closest("#prefs, #data-plan, #audit-prefs, #export-prefs, #location-prefs")) {
    $("#pref-notify").value = s.notify;
    $("#pref-keep").setAttribute("aria-checked", s.keep_running);
    $("#pref-login").setAttribute("aria-checked", s.launch_at_login);
    $("#pref-tray-text").value = s.tray_text || "off";
    $("#pref-public").setAttribute("aria-checked", s.public_ip_lookup);
    $("#pref-summary").setAttribute("aria-checked", s.daily_summary);
    $("#pref-theme").value = s.theme || "light";
    $("#pref-cap").value = s.data_cap_gb ?? "";
    $("#pref-cycle").value = s.cycle_day;
    $("#pref-st-schedule").value = s.speedtest_schedule || "off";
    $("#pref-st-size").value = s.speedtest_size || "light";
    for (const [id, key] of AUDIT_PREFS) $(id).setAttribute("aria-checked", s[key] !== false);
    $("#pref-location").setAttribute("aria-checked", s.location === true);
    $("#pref-expert").setAttribute("aria-checked", s.expert_mode === true);
    $("#pref-log-file").setAttribute("aria-checked", s.log_file === true);
    $("#pref-siem-target").value = s.siem_target || "";
    $("#pref-siem-format").value = s.siem_format || "cef";
  }
  if (s) $("#show-log").disabled = !s.log_file;
  if (s) $("#speedtest-note").textContent = speedtestNote(s);

  const f = state.feeds;
  if (f) {
    $("#feed-facts").innerHTML = `
      <dt>Malware domains</dt><dd>${f.blocklist.domains.toLocaleString()}</dd>
      <dt>Botnet server IPs</dt><dd>${f.blocklist.ips.toLocaleString()}</dd>
      <dt>Last updated</dt><dd>${f.updating ? "Updating…" : f.blocklist.updated ? `${ago(f.blocklist.updated)} (${fullTime(f.blocklist.updated)})` : "Never"}</dd>
      <dt>Vendor database</dt><dd>${f.vendors ? `${f.vendors.toLocaleString()} manufacturers` : "Not downloaded"}</dd>
      ${f.error ? `<dt>Last error</dt><dd>${esc(f.error)}</dd>` : ""}`;
    $("#update-feeds").disabled = f.updating;
  }
  $("#about-facts").innerHTML = `
    <dt>Data folder</dt><dd class="mono">${esc(state.dataDir)}</dd>
    <dt>Automatic scans</dt><dd>Every 5 minutes, plus a presence check of known devices every minute</dd>
    <dt>Device counted as online</dt><dd>Answered a ping, a connection check or ARP, or was seen on the network, in the last 5 minutes. Devices that only answer ARP are shown as asleep.</dd>
    <dt>Connection checks</dt><dd>Router and internet (1.1.1.1, 8.8.8.8) latency every 10 seconds</dd>`;
}

// Security audits panel in Settings: switch id → setting.
const AUDIT_PREFS = [
  ["#pref-port-audit", "port_audit"], ["#pref-listener-watch", "listener_watch"], ["#pref-launch-watch", "launch_watch"],
  ["#pref-dns-watch", "dns_watch"], ["#pref-twin-watch", "evil_twin_watch"], ["#pref-cert-checks", "cert_checks"],
];

async function savePrefs() {
  const cap = parseFloat($("#pref-cap").value);
  const next = {
    ...state.settings,
    notify: $("#pref-notify").value,
    keep_running: $("#pref-keep").getAttribute("aria-checked") === "true",
    launch_at_login: $("#pref-login").getAttribute("aria-checked") === "true",
    tray_text: $("#pref-tray-text").value,
    public_ip_lookup: $("#pref-public").getAttribute("aria-checked") === "true",
    daily_summary: $("#pref-summary").getAttribute("aria-checked") === "true",
    theme: $("#pref-theme").value,
    data_cap_gb: Number.isFinite(cap) && cap > 0 ? cap : null,
    cycle_day: Math.min(28, Math.max(1, parseInt($("#pref-cycle").value, 10) || 1)),
    speedtest_schedule: $("#pref-st-schedule").value,
    speedtest_size: $("#pref-st-size").value,
    expert_mode: $("#pref-expert").getAttribute("aria-checked") === "true",
    location: $("#pref-location").getAttribute("aria-checked") === "true",
    log_file: $("#pref-log-file").getAttribute("aria-checked") === "true",
    siem_target: $("#pref-siem-target").value.trim(),
    siem_format: $("#pref-siem-format").value,
  };
  for (const [id, key] of AUDIT_PREFS) next[key] = $(id).getAttribute("aria-checked") === "true";
  state.settings = await call("set_settings", { settings: next });
  if (next.siem_target && !state.settings.siem_target) {
    toast({ severity: "info", title: "SIEM address not saved", detail: "Use host:port, like siem.lan:514." });
  }
  applyTheme();
  render();
}

async function loadCustomList() {
  $("#custom-list").value = await invoke("get_custom_blocklist");
}

// ------------------------------------------------------------------ drawer

function openDrawer(mac) {
  closeBtDrawer();
  state.drawerMac = mac;
  state.drawerSig = "";
  $("#drawer").hidden = false;
  renderDrawer();
}

function closeDrawer() {
  $("#drawer").hidden = true;
  state.drawerMac = null;
}

// Seven rows, one per local day, with the periods the device was online.
function presenceHtml(d) {
  const now = Date.now();
  const day0 = new Date(); day0.setHours(0, 0, 0, 0);
  let rows = "";
  for (let i = 0; i < 7; i++) {
    const start = new Date(day0); start.setDate(start.getDate() - i);
    const end = new Date(start); end.setDate(end.getDate() + 1);
    const s = start.getTime();
    const len = end.getTime() - s;
    const e = Math.min(end.getTime(), now);
    const segs = (d.sessions || [])
      .filter(([a, b]) => b >= s && a < e)
      .map(([a, b]) => {
        const a2 = Math.max(a, s), b2 = Math.min(Math.max(b, a + 60_000), e);
        return `<i style="left:${((a2 - s) / len) * 100}%;width:${(((b2 - a2) / len) * 100).toFixed(2)}%" data-tip="${esc(`${hhmm(a)} – ${b >= now - 180_000 ? "now" : hhmm(b)}`)}"></i>`;
      })
      .join("");
    const future = i === 0 ? `<u style="left:${((now - s) / len) * 100}%"></u>` : "";
    const label = i === 0 ? "Today" : i === 1 ? "Yesterday" : start.toLocaleDateString([], { weekday: "short", day: "numeric" });
    rows += `<div class="pres-row"><span>${esc(label)}</span><div class="pres-track">${segs}${future}</div></div>`;
  }
  return `<div class="presence">${rows}<div class="pres-row axis"><span></span><div class="pres-axis"><b>0:00</b><b>6:00</b><b>12:00</b><b>18:00</b><b>24:00</b></div></div></div>`;
}

function presenceSummary(d) {
  if (d.is_self) return "This computer";
  if (isAsleep(d)) return "On the network but not answering pings or connections. It's probably asleep.";
  if (d.online) {
    const cur = d.sessions?.[d.sessions.length - 1];
    return `Online${cur ? ` since ${new Date(cur[0]).toDateString() === new Date().toDateString() ? hhmm(cur[0]) : fullTime(cur[0])}` : ""}${d.rtt_ms != null ? ` · ${fmtMs(d.rtt_ms)} away` : ""}`;
  }
  return `Offline · last seen ${ago(d.last_seen)} (${fullTime(d.last_seen)})`;
}

function renderDrawer() {
  const d = state.devices.find((x) => x.mac === state.drawerMac);
  if (!d) { closeDrawer(); return; }
  const checking = state.portChecks.has(d.mac);
  // Only rebuild when something shown changed (or a minute passed, for "x ago").
  const sig = JSON.stringify(d) + checking + JSON.stringify(pings.get(d.mac) || null) + Math.floor(Date.now() / 60000);
  if (sig === state.drawerSig) return;
  state.drawerSig = sig;
  const [, kindLabel] = deviceKind(d);
  const os = osGuess(d);
  $("#drawer-title").textContent = deviceName(d);
  const ports = d.open_ports;
  const portHtml = checking
    ? '<span class="muted">Checking common ports…</span>'
    : ports == null
      ? '<span class="muted">Not checked yet.</span>'
      : ports.length
        ? `<div class="port-list">${ports.map((p) => `<span class="chip ${RISKY_PORTS.has(p) ? "bad" : ""}">${p} · ${PORT_LABEL[p] || "open"}</span>`).join("")}</div>`
        : '<span class="muted">None of the common ports are open.</span>';
  const fact = (k, v) => (v ? `<dt>${k}</dt><dd>${v}</dd>` : "");
  // Don't rebuild while the user is typing in one of the drawer's fields.
  const typing = ["notes-input", "tags-input", "merge-with"].includes(document.activeElement?.id);
  if (typing) { state.drawerSig = ""; return; }
  // Keep focus and typing intact if the user is editing the name.
  const editing = document.activeElement?.id === "label-input";
  const body = $("#drawer-body");
  const html = `
    <div>
      <h3>Name</h3>
      <div class="row"><input type="text" id="label-input" placeholder="${esc(deviceName(d))}" value="${esc(d.label || "")}"><button class="btn" data-action="save-label">Save</button></div>
    </div>
    <div>
      <h3>Presence</h3>
      <div class="row" style="margin-bottom:10px;align-items:flex-start"><span class="dot ${presenceDot(d)}" style="margin-top:5px"></span><span>${esc(presenceSummary(d))}</span></div>
      ${d.is_self ? "" : presenceHtml(d)}
      ${d.is_self ? "" : `<div class="row" style="margin-top:12px"><button class="switch" role="switch" aria-checked="${d.notify_presence}" data-watch="${esc(d.mac)}" aria-label="Alert when it joins or leaves"></button>
        <span>Alert me when it joins or leaves</span></div>`}
    </div>
    <div>
      <h3>Identity</h3>
      <dl class="facts">
        ${fact("Type", esc(kindLabel))}
        ${fact("Operating system", os ? `${esc(os[0])} <span class="muted small">· from ${esc(os[1])}</span>` : "")}
        ${fact("IP address", `<span class="mono">${esc(d.ip)}</span>`)}
        ${fact("MAC address", `<span class="mono">${esc(d.mac)}</span>${isRandomMac(d.mac) ? '<div class="muted small">Randomized for privacy, so the vendor is hidden</div>' : ""}`)}
        ${fact("Also seen as", (d.aliases || []).length ? `${d.aliases.map((m) => `<span class="mono">${esc(m)}</span>`).join("<br>")}<div class="muted small">Earlier private addresses of this device, merged into one entry</div>` : "")}
        ${fact("Network", d.is_self ? "" : d.network ? `${esc(networkName(d.network))}${d.network === currentNetwork() ? ' <span class="muted small">· connected now</span>' : ""}` : "")}
        ${fact("Vendor", esc(d.vendor))}
        ${fact("Hostname", esc(d.hostname))}
        ${fact("Advertised as", esc(d.friendly_name))}
        ${fact("Model", esc(d.model))}
        ${fact("Services", serviceLabels(d).map(esc).join(", "))}
        ${fact("DHCP client", esc(d.dhcp_vendor))}
        ${fact("Latency", d.rtt_ms != null && !d.is_self ? `${fmtMs(d.rtt_ms)}${d.ttl ? ` <span class="muted small">· TTL ${d.ttl}</span>` : ""}` : "")}
        ${fact("Discovered via", esc(d.sources.join(", ")))}
        ${fact("First seen", esc(fullTime(d.first_seen)))}
        ${fact("Last seen", `${esc(fullTime(d.last_seen))} (${ago(d.last_seen)})`)}
      </dl>
    </div>
    ${d.is_self ? "" : (() => {
      const r = deviceRisk(d);
      return `<div>
      <h3>Risk</h3>
      <div class="row" style="align-items:flex-start"><span class="risk-pill ${r.level}">${r.score}</span><div><b>${RISK_WORD[r.level]}</b>
        ${r.reasons.length ? `<ul class="risk-reasons">${r.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : '<div class="muted small">Trusted, no risky ports, no open alerts.</div>'}</div></div>
    </div>`;
    })()}
    ${d.is_self ? "" : `<div>
      <h3>Ping</h3>
      ${pingHtml(d)}
    </div>`}
    <div>
      <h3>Open ports</h3>
      ${portHtml}
      <div class="row" style="margin-top:10px">
        <button class="btn" data-action="check-ports" ${checking ? "disabled" : ""}>${ports == null ? "Check common ports" : "Check again"}</button>
        ${d.ports_checked_at && !checking ? `<span class="muted small">Checked ${ago(d.ports_checked_at)}</span>` : ""}
      </div>
      <p class="muted small" style="margin-top:8px">Tries to connect to 26 well-known service ports on this device only.</p>
    </div>
    <div>
      <h3>Notes and tags</h3>
      <input type="text" id="tags-input" placeholder="Tags, separated by commas (e.g. kids, smart home)" value="${esc((d.tags || []).join(", "))}">
      <textarea id="notes-input" rows="3" placeholder="Notes: where it is, who owns it…" style="margin-top:8px;font-family:inherit">${esc(d.notes || "")}</textarea>
      <div class="row" style="margin-top:8px"><button class="btn" data-action="save-meta">Save notes</button></div>
    </div>
    ${d.is_self ? "" : `<div>
      <h3>Wake-on-LAN</h3>
      <div class="row"><button class="btn" data-action="wake">Send wake-up packet</button></div>
      <p class="muted small" style="margin-top:6px">Wakes computers and consoles that have Wake-on-LAN turned on. Phones don't support it${isRandomMac(d.mac) ? ", and devices using a private MAC address may not answer to it" : ""}.</p>
    </div>`}
    <div>
      <h3>Trust</h3>
      <div class="row"><button class="switch" role="switch" aria-checked="${d.trusted}" data-trust="${esc(d.mac)}"></button>
      <span>${d.trusted ? "Trusted — you recognize this device" : "Not trusted yet"}</span></div>
    </div>
    ${mergeHtml(d)}
    ${d.is_self || d.is_gateway ? "" : `<div><button class="btn danger-ghost" data-action="forget">Forget device</button>
      <p class="muted small" style="margin-top:6px">It reappears (and alerts as new) if it shows up again.</p></div>`}`;
  if (editing) {
    // Re-render everything except the name field.
    const value = $("#label-input").value;
    body.innerHTML = html;
    const input = $("#label-input");
    input.value = value;
    input.focus();
  } else {
    body.innerHTML = html;
  }
}

// ------------------------------------------------------------------ toasts

function toast(a) {
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `${ICONS[a.severity] ? `<span class="sev ${a.severity}">${ICONS[a.severity]}</span>` : ""}<div class="title">${esc(a.title)}</div>
    <div class="sub">${esc(a.detail).slice(0, 160)}${a.detail.length > 160 ? "…" : ""}</div>`;
  el.addEventListener("click", () => {
    el.remove();
    if (a.onClick) a.onClick();
    else if (a.id) setView("alerts");
  });
  $("#toasts").prepend(el);
  setTimeout(() => el.remove(), a.severity === "high" ? 15000 : 7000);
  while ($("#toasts").children.length > 4) $("#toasts").lastChild.remove();
}

// ------------------------------------------------------------------ render loop

const RENDERERS = {
  overview: () => renderOverview(),
  devices: () => renderDevices(),
  network: () => { renderNetwork(); renderReadiness(); },
  security: () => { renderSecurity(); $("#sec-risky").innerHTML = riskiestHtml(8); },
  audit: () => renderAudit(),
  timeline: () => renderTimeline(),
  map: () => (typeof renderMap === "function" ? renderMap() : null),
  wifi: () => (typeof renderWifiAnalyzer === "function" ? renderWifiAnalyzer() : null),
  history: () => { renderHistory(); renderHeatmap(); },
  bluetooth: () => renderBluetooth(),
  traffic: () => renderTraffic(),
  connections: () => renderConnections(),
  alerts: () => renderAlerts(),
  settings: () => renderSettings(),
};

let renderQueued = false;
function render() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    renderChrome();
    RENDERERS[state.view]();
    if (!$("#drawer").hidden) renderDrawer();
  });
}

const renderIf = (...views) => { if (views.includes(state.view)) render(); };

function pushHistory(snap) {
  const prev = state.history[state.history.length - 1];
  if (prev && snap.ts <= prev.ts) return;
  state.history.push({ ts: snap.ts, rx: snap.rx_bps, tx: snap.tx_bps });
  if (state.history.length > HISTORY_POINTS + 5) state.history.splice(0, state.history.length - HISTORY_POINTS - 5);
}

// ------------------------------------------------------------------ wiring

document.addEventListener("click", async (e) => {
  if (state.palette && !e.target.closest(".palette-box") && e.target.closest("#palette")) return closePalette();
  const t = e.target.closest("button, [data-mac], [data-goto], [data-group], [data-pal]");
  if (!t) return;
  if (t.dataset.view) return setView(t.dataset.view);
  if (t.dataset.group) return setView(lastInGroup[t.dataset.group] || NAV[t.dataset.group][0]);
  if (t.id === "sec-risk-map") NMAP.color = "risk";
  if (t.dataset.goto) {
    if (t.dataset.filter && t.dataset.goto === "devices") {
      state.devFilter = t.dataset.filter;
      segOn($("#dev-filter"), $(`#dev-filter [data-f="${t.dataset.filter}"]`));
    }
    return setView(t.dataset.goto);
  }
  if (t.dataset.trust) {
    e.stopPropagation();
    const d = state.devices.find((x) => x.mac === t.dataset.trust);
    if (d) {
      d.trusted = !d.trusted;
      render();
      call("set_trusted", { mac: d.mac, trusted: d.trusted });
    }
    return;
  }
  if (t.dataset.watch) {
    const d = state.devices.find((x) => x.mac === t.dataset.watch);
    if (d) {
      d.notify_presence = !d.notify_presence;
      render();
      call("set_notify_presence", { mac: d.mac, on: d.notify_presence });
    }
    return;
  }
  if (t.dataset.locate) return openLocate(t.dataset.locate);
  if (t.dataset.pal != null && t.closest("#palette")) return runPalette(+t.dataset.pal);
  if (t.dataset.unwatch) return removeWatch(t.dataset.unwatch);
  if (t.dataset.cat) {
    state.bleCategory = state.bleCategory === t.dataset.cat ? null : t.dataset.cat;
    return render();
  }
  if (t.dataset.mine) {
    return call("set_ble_mine", { id: t.dataset.mine, mine: t.dataset.on === "1" });
  }
  if (t.dataset.pref) {
    t.setAttribute("aria-checked", t.getAttribute("aria-checked") !== "true");
    return savePrefs();
  }
  if (t.dataset.ack) return call("ack_alert", { id: +t.dataset.ack });
  if (t.dataset.expert) {
    const id = +t.dataset.expert;
    if (!state.expertOpen.delete(id)) state.expertOpen.add(id);
    return render();
  }
  if (t.dataset.copyAlert) {
    const a = state.alerts.find((x) => x.id === +t.dataset.copyAlert);
    if (a) {
      copyText(JSON.stringify(a, null, 2)).then(
        () => toast({ severity: "info", title: "Copied", detail: "The alert's JSON is on the clipboard." }),
        () => toast({ severity: "info", title: "Couldn't copy", detail: "Select the text and copy it by hand." }),
      );
    }
    return;
  }
  if (t.dataset.url) return call("open_url", { url: t.dataset.url });
  const seg = t.closest(".seg");
  if (seg && t.dataset.f) {
    if (seg.id === "heat-metric") { heat.metric = t.dataset.f; segOn(seg, t); return render(); }
    const key = { "dev-filter": "devFilter", "conn-filter": "connFilter", "alert-filter": "alertFilter", "dns-mode": "dnsMode", "usage-view": "usageView", "ble-filter": "bleFilter", "tl-filter": "tlFilter", "hist-range": "histRange" }[seg.id];
    if (key) { state[key] = t.dataset.f; segOn(seg, t); return render(); }
  }
  if (t.dataset.mac && !t.matches("button")) return openDrawer(t.dataset.mac);

  const mac = state.drawerMac;
  switch (t.dataset.action) {
    case "grant":
      t.disabled = true;
      try { state.capture = await call("grant_capture_access"); } finally { t.disabled = false; render(); }
      return;
    case "start-capture": state.capture = await call("start_capture"); return render();
    case "stop-capture": state.capture = await call("stop_capture"); return render();
    case "audit-ports":
      return auditRunPorts();
    case "audit-certs":
      return auditRunCerts();
    case "check-ports":
      state.portChecks.add(mac);
      render();
      call("check_ports", { mac }).catch(() => { state.portChecks.delete(mac); render(); });
      return;
    case "save-label":
      await call("set_label", { mac, label: $("#label-input").value });
      $("#label-input").blur();
      return;
    case "forget":
      closeDrawer();
      return call("forget_device", { mac });
    case "speed-test":
      state.speed = { running: true, phase: "latency", mbps: null, error: null };
      render();
      return call("run_speed_test").catch(() => { state.speed.running = false; render(); });
    case "refresh-public":
      return call("refresh_public");
    case "export-devices":
      return exportDevices();
    case "ble-on":
      state.bt = { ...(state.bt || {}), scan_state: "starting" };
      render();
      return call("set_ble_scan", { on: true });
    case "ble-off":
      return call("set_ble_scan", { on: false });
    case "locate-close":
      return closeLocate();
    case "locate-beep":
      return toggleBeep();
    case "add-watch":
      return addWatch();
    case "show-log":
      return invoke("reveal_file", { path: `${state.dataDir}/alerts.jsonl` });
    case "siem-test": {
      // Send to what is saved, so save what was just typed first.
      await savePrefs();
      if (!state.settings.siem_target) return;
      const target = await call("send_test_event");
      return toast({ severity: "info", title: "Test event sent", detail: `Sent to ${target} over UDP. UDP has no replies, so check your SIEM for it.` });
    }
    case "allow-location":
      return allowLocation();
    case "location-settings":
      return call("open_location_settings");
    case "leak-test":
      return runLeakTest();
    case "report":
      return weeklyReport();
    case "palette":
      return openPalette();
    case "trace": {
      const target = $("#trace-target").value.trim() || "1.1.1.1";
      state.trace = { running: true, target, hops: [], error: null };
      render();
      try { state.trace.hops = await invoke("run_traceroute", { target }); } catch (err) { state.trace.error = String(err); }
      state.trace.running = false;
      return render();
    }
    case "dns-check":
      state.dnsCheck = { running: true, results: [], error: null };
      render();
      try { state.dnsCheck.results = await invoke("run_dns_check"); } catch (err) { state.dnsCheck.error = String(err); }
      state.dnsCheck.running = false;
      return render();
    case "wake":
      await call("wake_device", { mac });
      return toast({ severity: "info", title: "Wake-up packet sent", detail: "If the device supports Wake-on-LAN and it's enabled, it should come online within a minute." });
    case "ping-now":
      return pingNow(mac);
    case "merge":
      return mergeDevices(mac);
    case "save-meta":
      await call("set_device_meta", { mac, notes: $("#notes-input").value, tags: $("#tags-input").value.split(",") });
      return toast({ severity: "info", title: "Saved", detail: "Notes and tags updated." });
  }
});

function segOn(group, btn) {
  group.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === btn));
}

// A tooltip for any element with data-tip (presence segments, meters…).
document.addEventListener("mousemove", (e) => {
  const tipped = e.target.closest?.("[data-tip]");
  if (tipped) {
    tip().hidden = false;
    tip().innerHTML = `<div class="t-head" style="margin:0">${esc(tipped.dataset.tip)}</div>`;
    placeTip(e.clientX, e.clientY);
    return;
  }
  // Charts redraw under the cursor; make sure a tooltip never outlives the hover.
  if (!e.target.closest?.(".chart svg")) {
    if (!tip().hidden) hideTip();
  }
});

$("#scan-btn").addEventListener("click", () => { state.scanning = true; render(); call("scan_network"); });
$("#trust-all").addEventListener("click", () => call("trust_all"));
$("#ack-all").addEventListener("click", () => call("ack_alert", { id: null }));
$("#clear-alerts").addEventListener("click", () => { if (confirm("Delete all alert history?")) call("clear_alerts"); });
$("#update-feeds").addEventListener("click", () => call("update_feeds"));
$("#save-custom").addEventListener("click", async () => {
  await call("set_custom_blocklist", { text: $("#custom-list").value });
  toast({ severity: "info", title: "Blocklist saved", detail: "New entries apply to lookups from now on." });
});
$("#pref-notify").addEventListener("change", savePrefs);
$("#pref-theme").addEventListener("change", savePrefs);
$("#pref-tray-text").addEventListener("change", savePrefs);
$("#pref-save-plan").addEventListener("click", savePrefs);
$("#pref-st-schedule").addEventListener("change", savePrefs);
$("#pref-st-size").addEventListener("change", savePrefs);
$("#pref-siem-target").addEventListener("change", savePrefs);
$("#pref-siem-format").addEventListener("change", savePrefs);
$("#drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
  const mod = e.metaKey || e.ctrlKey;
  if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); return state.palette ? closePalette() : openPalette(); }
  if (state.palette) {
    if (e.key === "Escape") return closePalette();
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const P = state.palette;
      P.sel = (P.sel + (e.key === "ArrowDown" ? 1 : -1) + Math.max(1, P.list.length)) % Math.max(1, P.list.length);
      return renderPalette();
    }
    if (e.key === "Enter") { e.preventDefault(); return runPalette(state.palette.sel); }
    return;
  }
  // ⌘1–⌘7 jump between sections, ⌘, opens Settings.
  const groups = ["overview", "activity", "devices", "network", "bluetooth", "traffic", "security"];
  if (mod && /^[1-7]$/.test(e.key)) { e.preventDefault(); const g = groups[+e.key - 1]; return setView(lastInGroup[g] || NAV[g][0]); }
  if (mod && e.key === ",") { e.preventDefault(); return setView("settings"); }
  // Escape closes the Locate window first when it is open over the details panel.
  if (e.key === "Escape") { closeDrawer(); if (state.locate) closeLocate(); else closeBtDrawer(); }
  if (e.key === "Enter" && e.target.id === "watch-input") addWatch();
  if (e.key === "Enter" && e.target.id === "label-input") $('[data-action="save-label"]').click();
  if (e.key === "Enter" && e.target.closest?.("#data-plan")) savePrefs();
  if (e.key === "Enter" && e.target.id === "trace-target") $('[data-action="trace"]').click();
});
["#dev-search", "#conn-search", "#dns-search"].forEach((s) => $(s).addEventListener("input", render));
$("#dev-net").addEventListener("change", (e) => { state.devNet = e.target.value; render(); });
$("#palette-input").addEventListener("input", () => { if (state.palette) { state.palette.sel = 0; renderPalette(); } });
window.addEventListener("resize", render);

function mergeUsage(rows) {
  for (const [h, rx, tx] of rows) state.usage.set(h, [rx, tx]);
}

async function init() {
  const snap = await invoke("get_snapshot");
  Object.assign(state, {
    net: snap.net,
    devices: snap.devices,
    alerts: snap.alerts,
    capture: snap.capture,
    feeds: snap.feeds,
    traffic: snap.traffic.ts ? snap.traffic : null,
    dns: snap.dns,
    scanning: snap.scanning,
    dataDir: snap.data_dir,
    settings: snap.settings,
    router: snap.router,
    wan: snap.wan,
    health: snap.health,
    healthSupported: snap.health_supported,
    outage: snap.outage,
    outages: snap.outages,
    wifi: snap.wifi,
    firewall: snap.firewall,
    publicInfo: snap.public,
    publicError: snap.public_error,
    speedtests: snap.speedtests,
    speedNext: snap.speedtest_next,
    forecast: snap.forecast,
    apps: snap.apps,
    bt: snap.bt,
    mifi: snap.mifi,
    linkLog: snap.link_log,
    watch: snap.watch,
    audit: snap.audit,
    location: snap.location,
  });
  btIngest(snap.bt);
  state.expertInfo = new Map((await invoke("get_expert_info").catch(() => [])).map((e) => [e.kind, e]));
  state.speed.running = snap.speed_running;
  applyTheme();
  mergeUsage(snap.usage);

  listen("devices", (e) => {
    state.devices = e.payload;
    for (const d of state.devices) if (state.portChecks.has(d.mac) && d.ports_checked_at && Date.now() - d.ports_checked_at < 60000) state.portChecks.delete(d.mac);
    render();
  });
  listen("alert", (e) => {
    const { alert, is_new } = e.payload;
    const i = state.alerts.findIndex((a) => a.id === alert.id);
    if (i >= 0) state.alerts[i] = alert; else state.alerts.push(alert);
    if (is_new) toast(alert);
    render();
  });
  listen("alerts", (e) => {
    state.alerts = e.payload;
    // Alert ids start over after "Clear history"; don't let a new card inherit an open one.
    state.expertOpen = new Set([...state.expertOpen].filter((id) => state.alerts.some((a) => a.id === id)));
    render();
  });
  // The menu-bar popover asks for a page (e.g. "alerts").
  listen("goto", (e) => { if (VIEW_TITLES[e.payload]) setView(e.payload); });
  listen("traffic", (e) => {
    state.traffic = e.payload;
    pushHistory(e.payload);
    renderIf("overview", "traffic");
  });
  listen("dns", (e) => {
    state.dns.push(...e.payload);
    if (state.dns.length > 500) state.dns.splice(0, state.dns.length - 500);
  });
  listen("scan", (e) => {
    state.scanning = e.payload.running;
    state.scanPhase = e.payload.phase;
    if (!e.payload.running) setTimeout(() => { if (!state.scanning) { state.scanPhase = ""; render(); } }, 6000);
    render();
  });
  listen("capture", (e) => { state.capture = e.payload; render(); });
  listen("feeds", (e) => { state.feeds = e.payload; render(); });
  listen("net", (e) => { state.net = e.payload; render(); });
  listen("settings", (e) => { state.settings = e.payload; applyTheme(); render(); });
  listen("router", (e) => { state.router = e.payload; renderIf("overview", "network"); });
  listen("wan", (e) => {
    state.wan.push(e.payload);
    if (state.wan.length > 200) state.wan.splice(0, state.wan.length - 200);
    renderIf("overview", "network");
  });
  listen("usage", (e) => { mergeUsage(e.payload); renderIf("overview", "network"); });
  listen("forecast", (e) => { state.forecast = e.payload; renderIf("overview", "network"); });
  listen("speedschedule", (e) => { state.speedNext = e.payload; renderIf("network"); });
  listen("health", (e) => {
    state.health.push(e.payload.sample);
    if (state.health.length > 360) state.health.splice(0, state.health.length - 360);
    state.outage = e.payload.outage;
    render();
  });
  listen("outages", (e) => { state.outages = e.payload; renderIf("network"); });
  listen("wifi", (e) => { state.wifi = e.payload.wifi; state.firewall = e.payload.firewall; renderIf("network", "bluetooth", "wifi"); });
  listen("location", (e) => { state.location = e.payload; render(); });
  listen("public", (e) => { [state.publicInfo, state.publicError] = e.payload; renderIf("network"); });
  listen("apps", (e) => { state.apps = e.payload; renderIf("traffic"); });
  listen("mifi", (e) => {
    state.mifi = e.payload.status;
    state.linkLog = e.payload.log;
    renderIf("network", "overview");
  });
  listen("watch", (e) => { state.watch = e.payload; renderIf("network"); });
  listen("audit", (e) => { state.audit = e.payload; renderIf("audit", "security"); });
  listen("ble_locate", (e) => {
    if (state.locate?.id === e.payload.id) {
      locateSample(e.payload.rssi, e.payload.ts);
      renderLocate();
    }
  });
  listen("bt", (e) => {
    state.bt = e.payload;
    btIngest(e.payload);
    // Without fast updates (e.g. before the first one), use the 2-second list.
    const L = state.locate;
    const d = L && e.payload.nearby.find((x) => x.id === L.id);
    if (d?.rssi != null && (!L.samples.length || Date.now() - L.samples[L.samples.length - 1].ts > 1500)) {
      locateSample(d.rssi, Date.now());
      renderLocate();
    }
    renderIf("bluetooth");
    renderChrome();
  });
  listen("speedtest", (e) => {
    const p = e.payload;
    if (p.running) {
      state.speed = { running: true, phase: p.phase, mbps: p.mbps, error: null };
    } else {
      state.speed = { running: false, phase: null, mbps: null, error: p.error };
      if (p.result) state.speedtests.push(p.result);
      if (p.error) toast({ severity: "info", title: "Speed test failed", detail: p.error });
    }
    renderIf("network", "history");
  });

  wireMap();
  setInterval(refreshConnections, 3000);
  setInterval(render, 30000); // keep "x minutes ago" fresh
  render();
}

init();

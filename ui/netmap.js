"use strict";
// The network map: one network at a time, three layouts (ring, by type,
// by latency), status or risk colouring, a 7-day replay, drag-to-arrange
// with saved positions, zoom and pan, a right-click menu, and PNG / SVG
// export. Shares helpers and `state` with app.js, which loads after it.

const NMAP = {
  net: null, // which network (router MAC) is shown
  layout: "ring",
  color: "status",
  kinds: new Set(), // device kinds to emphasise; empty = all
  q: "",
  t: null, // replay time (ms), or null for live
  playing: null, // replay timer
  speed: 1,
  zoom: 1,
  px: 0,
  py: 0,
  drag: null, // { kind: "node"|"pan", … } while the mouse is down
  moved: false,
  pins: loadPins(),
};
const MAP_W = 960;
const MAP_DAY = 86_400_000;

// An ICONS svg string, positioned inside a parent SVG.
const placeIcon = (svg, x, y, size) => svg.replace("<svg ", `<svg x="${x - size / 2}" y="${y - size / 2}" width="${size}" height="${size}" `);

function loadPins() {
  try { return JSON.parse(localStorage.getItem("netwatch.mapPins") || "{}"); } catch { return {}; }
}
function savePins() {
  try { localStorage.setItem("netwatch.mapPins", JSON.stringify(NMAP.pins)); } catch { /* private mode: positions last this session */ }
}
const pinKey = () => `${NMAP.net}|${NMAP.layout}`;

const KIND_ORDER = ["computer", "phone", "media", "speaker", "home", "printer", "storage", "device"];
const KIND_NAMES = { computer: "Computers", phone: "Phones and tablets", media: "TV and streaming", speaker: "Speakers", home: "Smart home", printer: "Printers", storage: "Storage", device: "Other" };

// Online at replay time `t`, from the device's recorded sessions.
const wasOnline = (d, t) => (d.sessions || []).some(([a, b]) => a <= t && t <= b + 60_000);

function mapStatus(d) {
  if (NMAP.t != null) return wasOnline(d, NMAP.t) ? "good" : "off";
  if (d.is_self && NMAP.net !== currentNetwork()) return "off";
  return presenceDot(d);
}

function latencyClass(d) {
  if (mapStatus(d) === "off") return "off";
  if (NMAP.t != null || d.rtt_ms == null || isAsleep(d)) return "up";
  return d.rtt_ms < 20 ? "fast" : d.rtt_ms < 80 ? "ok" : "slow";
}

function matchesQuery(d) {
  const q = NMAP.q.trim().toLowerCase();
  if (!q) return true;
  return [deviceName(d), d.ip, d.mac, d.vendor, d.hostname, d.model, ...(d.tags || [])].some((v) => (v || "").toLowerCase().includes(q));
}

// ------------------------------------------------------------------ layouts

function layoutRing(devices, cx, cy, R) {
  const pos = new Map();
  const n = devices.length;
  const rings = n > 16 ? 2 : 1;
  devices.forEach((d, i) => {
    const r = rings === 2 ? (i % 2 ? R * 1.3 : R * 0.82) : R;
    const a = -Math.PI / 2 + (i / Math.max(1, n)) * Math.PI * 2 + Math.PI / Math.max(1, n);
    pos.set(d.mac, [cx + Math.cos(a) * r, cy + Math.sin(a) * r * 0.78]);
  });
  return { pos, extras: "" };
}

function layoutByType(devices, cx, cy, R) {
  const pos = new Map();
  const groups = KIND_ORDER.map((k) => [k, devices.filter((d) => deviceKind(d)[0] === k)]).filter(([, g]) => g.length);
  let extras = "";
  groups.forEach(([k, g], gi) => {
    const a = -Math.PI / 2 + (gi / groups.length) * Math.PI * 2 + (groups.length > 1 ? Math.PI / groups.length : 0);
    const gx = cx + Math.cos(a) * R, gy = cy + Math.sin(a) * R * 0.8;
    const rr = g.length === 1 ? 0 : 40 + g.length * 12;
    g.forEach((d, i) => {
      const b = (i / g.length) * Math.PI * 2 - Math.PI / 2;
      pos.set(d.mac, [gx + Math.cos(b) * rr, gy + Math.sin(b) * rr]);
    });
    extras += `<circle class="map-cluster" cx="${gx}" cy="${gy}" r="${rr + 44}"/>
      <text class="map-cluster-label" x="${gx}" y="${gy - rr - 50}" text-anchor="middle">${esc(KIND_NAMES[k])} · ${g.length}</text>`;
  });
  return { pos, extras, clusterLinks: true };
}

// Distance from the router follows round-trip time on a log scale.
function layoutLatency(devices, cx, cy, R) {
  const pos = new Map();
  const r0 = 70, rMax = R * 1.15;
  const rFor = (ms) => r0 + (rMax - r0) * Math.min(1, Math.max(0, Math.log10(Math.max(1, ms)) / Math.log10(500)));
  let extras = "";
  for (const ms of [1, 10, 100]) {
    const r = rFor(ms);
    extras += `<ellipse class="map-guide" cx="${cx}" cy="${cy}" rx="${r}" ry="${r * 0.78}"/>
      <text class="map-guide-label" x="${cx + r + 4}" y="${cy - 4}">${ms} ms</text>`;
  }
  extras += `<ellipse class="map-guide none" cx="${cx}" cy="${cy}" rx="${rMax + 46}" ry="${(rMax + 46) * 0.78}"/>
    <text class="map-guide-label" x="${cx + rMax + 50}" y="${cy - 4}">no reply</text>`;
  const n = devices.length;
  devices.forEach((d, i) => {
    const ms = d.is_self ? 0.5 : mapStatus(d) !== "off" && !isAsleep(d) ? d.rtt_ms : null;
    const r = ms == null ? rMax + 46 : rFor(ms);
    const a = -Math.PI / 2 + (i / Math.max(1, n)) * Math.PI * 2 + Math.PI / Math.max(1, n);
    pos.set(d.mac, [cx + Math.cos(a) * r, cy + Math.sin(a) * r * 0.78]);
  });
  return { pos, extras };
}

// ------------------------------------------------------------------ render

function renderMap() {
  if (NMAP.drag) return; // don't rebuild under the mouse
  const el = $("#netmap");
  const nets = knownNetworks();
  if (!NMAP.net || !nets.some((n) => n.id === NMAP.net)) NMAP.net = currentNetwork() || nets[0]?.id || null;
  renderMapControls(nets);

  const W = Math.max(640, el.clientWidth || MAP_W);
  const all = state.devices.filter((d) => !d.is_gateway && onNetwork(d, NMAP.net));
  const devices = [...all].sort((a, b) => (b.is_self - a.is_self) || KIND_ORDER.indexOf(deviceKind(a)[0]) - KIND_ORDER.indexOf(deviceKind(b)[0]) || ipNum(a.ip) - ipNum(b.ip));
  const gw = state.devices.find((d) => d.is_gateway && d.mac === NMAP.net);
  const isCur = NMAP.net === currentNetwork();
  const H = devices.length > 16 ? 700 : 600;
  const cx = W / 2, cy = H / 2 + 40;
  const R = Math.min(W * 0.34, H * 0.34);
  const L = (NMAP.layout === "type" ? layoutByType : NMAP.layout === "latency" ? layoutLatency : layoutRing)(devices, cx, cy, R);
  const pins = NMAP.pins[pinKey()] || {};
  for (const [mac, p] of Object.entries(pins)) if (L.pos.has(mac)) L.pos.set(mac, p);

  const h = state.health[state.health.length - 1];
  const inetDown = isCur && !!state.outage && NMAP.t == null;
  const iy = 56;
  let links = "", nodes = "";
  links += `<line class="map-link ${inetDown ? "down" : isCur ? "up" : "off"}" x1="${cx}" y1="${iy + 22}" x2="${cx}" y2="${cy - 30}"/>`;
  if (isCur && NMAP.t == null) links += `<text class="map-link-label" x="${cx + 10}" y="${(iy + cy) / 2}">${inetDown ? "Down" : h?.internet_ms != null ? fmtMs(h.internet_ms) : ""}</text>`;
  nodes += `<g class="map-node inet" data-tip="${esc(`Internet${state.publicInfo?.org ? ` · ${state.publicInfo.org.replace(/^AS\d+\s+/, "")}` : ""}`)}">
    <circle cx="${cx}" cy="${iy}" r="22"/>${placeIcon(TILE_ICONS.globe, cx, iy, 20)}
    <text class="map-label strong" x="${cx - 32}" y="${iy + 5}" text-anchor="end">Internet</text></g>`;

  // Devices the router exposes to the internet through port forwards.
  const forwards = isCur ? state.router?.mappings || [] : [];
  const exposed = new Map();
  for (const m of forwards) {
    const d = devices.find((x) => x.ip === m.internal_client);
    if (d) exposed.set(d.mac, [...(exposed.get(d.mac) || []), `${m.protocol} ${m.external_port}`]);
  }

  let online = 0, asleep = 0;
  const riskCount = { high: 0, medium: 0, low: 0, none: 0 };
  for (const d of devices) {
    const [x, y] = L.pos.get(d.mac);
    const st = mapStatus(d);
    if (st === "good") online++;
    if (st === "idle") asleep++;
    const risk = deviceRisk(d);
    riskCount[risk.level]++;
    const [kind, kindLabel] = deviceKind(d);
    const name = deviceName(d);
    const dim = (NMAP.kinds.size && !NMAP.kinds.has(kind)) || !matchesQuery(d);
    const hit = !dim && (NMAP.q.trim() || NMAP.kinds.size);
    links += `<line class="map-link ${latencyClass(d)}${dim ? " dim" : ""}" data-to="${esc(d.mac)}" x1="${cx}" y1="${cy}" x2="${x}" y2="${y}"/>`;
    if (exposed.has(d.mac)) {
      links += `<line class="map-link exposed" data-to="${esc(d.mac)}" data-from-inet="1" x1="${cx}" y1="${iy}" x2="${x}" y2="${y}"/>`;
    }
    const tipBits = [name, d.ip, kindLabel, NMAP.t != null ? (st === "good" ? "online then" : "offline then") : presenceWord(d),
      NMAP.t == null && d.rtt_ms != null && d.online && !isAsleep(d) && !d.is_self ? fmtMs(d.rtt_ms) : null,
      NMAP.color === "risk" && risk.score ? `risk ${risk.score}: ${risk.reasons[0]}` : null,
      exposed.has(d.mac) ? `open to the internet: ${exposed.get(d.mac).join(", ")}` : null];
    // Cluster titles sit above each group, so names go below in that layout.
    const below = NMAP.layout === "type" || y >= cy - 10;
    const colorCls = NMAP.color === "risk" ? ` risk-${risk.level}` : "";
    nodes += `<g class="map-node ${st}${d.is_self ? " self" : ""}${colorCls}${dim ? " dim" : ""}${hit ? " hit" : ""}${pins[d.mac] ? " pinned" : ""}" data-mac="${esc(d.mac)}" data-node="${esc(d.mac)}" transform="translate(${x} ${y})" data-tip="${esc(tipBits.filter(Boolean).join(" · "))}">
      <circle r="20"/>${placeIcon(ICONS[kind], 0, 0, 17)}
      ${NMAP.color === "risk" && risk.score ? `<text class="map-risk" x="0" y="34" text-anchor="middle">${risk.score}</text>` : `<circle class="map-status ${st}" cx="14" cy="-14" r="5"/>`}
      ${exposed.has(d.mac) ? `<g class="map-exposed" transform="translate(-15 -15)"><circle r="7"/><path d="M-3 0h6M0-3v6"/></g>` : ""}
      <text class="map-label" x="0" y="${below ? (NMAP.color === "risk" && risk.score ? 50 : 36) : -28}" text-anchor="middle">${esc(name.length > 20 ? name.slice(0, 19) + "…" : name)}</text>
      <text class="map-sub" x="0" y="${below ? (NMAP.color === "risk" && risk.score ? 64 : 50) : -42}" text-anchor="middle">${esc(d.is_self ? "This computer" : d.ip)}</text></g>`;
  }
  const gwName = NMAP.net ? networkName(NMAP.net) : "Router";
  nodes += `<g class="map-node router"${gw ? ` data-mac="${esc(gw.mac)}"` : ""} data-tip="${esc(`${gwName} · ${gw?.ip || ""}${isCur && state.mifi ? ` · ${state.mifi.generation}` : ""}`)}">
    <circle cx="${cx}" cy="${cy}" r="30"/>${placeIcon(ICONS.router, cx, cy, 24)}
    <text class="map-label strong" x="${cx}" y="${cy + 48}" text-anchor="middle">${esc(gwName)}</text>
    <text class="map-sub" x="${cx}" y="${cy + 62}" text-anchor="middle">${esc(gw?.ip || "")}${isCur && state.mifi ? ` · ${esc(state.mifi.generation)}` : ""}</text></g>`;

  const vp = `translate(${NMAP.px} ${NMAP.py}) scale(${NMAP.zoom})`;
  el.innerHTML = `<svg id="map-svg" viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Map of the devices on ${esc(gwName)}">
    <rect class="map-bg" x="-5000" y="-5000" width="10000" height="10000"/>
    <g id="map-vp" transform="${vp}">${L.extras}${links}${nodes}</g></svg>
    ${devices.length ? "" : `<div class="map-empty">No devices recorded on this network yet.</div>`}`;

  const legend = NMAP.color === "risk"
    ? `<span class="key"><i class="dot bad"></i>High <b>${riskCount.high}</b></span>
       <span class="key"><i class="dot warn"></i>Worth a look <b>${riskCount.medium}</b></span>
       <span class="key"><i class="dot low"></i>Low <b>${riskCount.low}</b></span>
       <span class="key"><i class="dot good"></i>No concerns <b>${riskCount.none}</b></span>`
    : `<span class="key"><i class="dot good"></i>Online <b>${online}</b></span>
       ${NMAP.t == null ? `<span class="key"><i class="dot idle"></i>Asleep <b>${asleep}</b></span>` : ""}
       <span class="key"><i class="dot off"></i>Offline <b>${devices.length - online - asleep}</b></span>
       ${NMAP.t == null && isCur ? `<span class="key"><i class="line fast"></i>&lt;20 ms</span><span class="key"><i class="line ok"></i>&lt;80 ms</span><span class="key"><i class="line slow"></i>slower</span>` : ""}`;
  $("#map-legend").innerHTML = legend + (exposed.size ? `<span class="key"><i class="line exposed"></i>Open to the internet <b>${exposed.size}</b></span>` : "");
}

function renderMapControls(nets) {
  const sel = $("#map-net");
  const opts = nets.map((n) => `<option value="${esc(n.id)}"${n.id === NMAP.net ? " selected" : ""}>${esc(n.name)}${n.current ? " (connected)" : ` · last ${ago(n.last_seen)}`}</option>`).join("");
  if (sel.dataset.sig !== opts) { sel.innerHTML = opts || `<option>No networks yet</option>`; sel.dataset.sig = opts; }
  sel.value = NMAP.net || "";
  segOn($("#map-layout"), $(`#map-layout [data-f="${NMAP.layout}"]`));
  segOn($("#map-color"), $(`#map-color [data-f="${NMAP.color}"]`));
  const kinds = [...new Set(state.devices.filter((d) => !d.is_gateway && onNetwork(d, NMAP.net)).map((d) => deviceKind(d)[0]))]
    .sort((a, b) => KIND_ORDER.indexOf(a) - KIND_ORDER.indexOf(b));
  $("#map-kinds").innerHTML = kinds.map((k) => `<button class="cat-chip${NMAP.kinds.has(k) ? " on" : ""}" data-mapkind="${k}">${ICONS[k]}${esc(KIND_NAMES[k])}</button>`).join("");
  const range = $("#map-time");
  const now = Date.now();
  range.min = String(now - 7 * MAP_DAY);
  range.max = String(now);
  range.step = String(5 * 60_000);
  if (NMAP.t == null) range.value = String(now);
  else range.value = String(NMAP.t);
  const atT = NMAP.t != null
    ? `${new Date(NMAP.t).toLocaleString([], { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}`
    : "Live";
  $("#map-time-label").textContent = atT;
  $("#map-live").hidden = NMAP.t == null;
  $("#map-play").innerHTML = NMAP.playing ? "❚❚ Pause" : "▶ Replay";
  $("#map-speed").textContent = `${NMAP.speed}×`;
}

// ------------------------------------------------------------------ replay

function mapPlay() {
  if (NMAP.playing) { clearInterval(NMAP.playing); NMAP.playing = null; return render(); }
  if (NMAP.t == null || NMAP.t >= Date.now() - 60_000) NMAP.t = Date.now() - 7 * MAP_DAY;
  NMAP.playing = setInterval(() => {
    NMAP.t += 15 * 60_000 * NMAP.speed;
    if (NMAP.t >= Date.now()) { clearInterval(NMAP.playing); NMAP.playing = null; NMAP.t = null; }
    renderIf("map");
  }, 120);
  render();
}

function mapLive() {
  if (NMAP.playing) clearInterval(NMAP.playing);
  NMAP.playing = null;
  NMAP.t = null;
  render();
}

// ------------------------------------------------------------------ zoom, pan, drag

function svgPoint(evt) {
  const svg = $("#map-svg");
  const pt = svg.createSVGPoint();
  pt.x = evt.clientX; pt.y = evt.clientY;
  const p = pt.matrixTransform(svg.getScreenCTM().inverse());
  return { x: p.x, y: p.y, wx: (p.x - NMAP.px) / NMAP.zoom, wy: (p.y - NMAP.py) / NMAP.zoom };
}

function applyViewport() {
  $("#map-vp")?.setAttribute("transform", `translate(${NMAP.px} ${NMAP.py}) scale(${NMAP.zoom})`);
}

function mapFit() {
  NMAP.zoom = 1; NMAP.px = 0; NMAP.py = 0;
  applyViewport();
}

function wireMap() {
  const host = $("#netmap");
  host.addEventListener("wheel", (e) => {
    if (!$("#map-svg")) return;
    e.preventDefault();
    const p = svgPoint(e);
    const z = Math.min(4, Math.max(0.4, NMAP.zoom * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    // Keep the point under the cursor still.
    NMAP.px = p.x - p.wx * z;
    NMAP.py = p.y - p.wy * z;
    NMAP.zoom = z;
    applyViewport();
  }, { passive: false });

  host.addEventListener("mousedown", (e) => {
    if (e.button !== 0 || !$("#map-svg")) return;
    closeMapMenu();
    const node = e.target.closest("[data-node]");
    const p = svgPoint(e);
    NMAP.moved = false;
    if (node) {
      const m = /translate\(([-\d.]+) ([-\d.]+)\)/.exec(node.getAttribute("transform"));
      NMAP.drag = { kind: "node", mac: node.dataset.node, el: node, ox: +m[1] - p.wx, oy: +m[2] - p.wy };
    } else if (!e.target.closest(".map-node")) {
      NMAP.drag = { kind: "pan", sx: p.x - NMAP.px, sy: p.y - NMAP.py };
      host.classList.add("panning");
    }
  });

  window.addEventListener("mousemove", (e) => {
    const D = NMAP.drag;
    if (!D) return;
    const p = svgPoint(e);
    NMAP.moved = true;
    hideTip();
    if (D.kind === "pan") {
      NMAP.px = p.x - D.sx;
      NMAP.py = p.y - D.sy;
      return applyViewport();
    }
    const x = p.wx + D.ox, y = p.wy + D.oy;
    D.el.setAttribute("transform", `translate(${x} ${y})`);
    D.x = x; D.y = y;
    for (const l of document.querySelectorAll(`#map-vp line[data-to="${CSS.escape(D.mac)}"]`)) {
      l.setAttribute("x2", x); l.setAttribute("y2", y);
    }
  });

  window.addEventListener("mouseup", () => {
    const D = NMAP.drag;
    if (!D) return;
    NMAP.drag = null;
    host.classList.remove("panning");
    if (D.kind === "node" && NMAP.moved && D.x != null) {
      const k = pinKey();
      NMAP.pins[k] = { ...(NMAP.pins[k] || {}), [D.mac]: [Math.round(D.x), Math.round(D.y)] };
      savePins();
      render();
    }
  });

  // A drag ends with a click; don't let it open the details panel.
  host.addEventListener("click", (e) => {
    if (NMAP.moved) { e.stopPropagation(); NMAP.moved = false; }
  }, true);

  host.addEventListener("contextmenu", (e) => {
    const node = e.target.closest("[data-node]");
    if (!node) return;
    e.preventDefault();
    openMapMenu(node.dataset.node, e.clientX, e.clientY);
  });

  $("#map-net").addEventListener("change", (e) => { NMAP.net = e.target.value; mapFit(); render(); });
  $("#map-search").addEventListener("input", (e) => { NMAP.q = e.target.value; render(); });
  $("#map-time").addEventListener("input", (e) => {
    if (NMAP.playing) { clearInterval(NMAP.playing); NMAP.playing = null; }
    const v = +e.target.value;
    NMAP.t = v >= Date.now() - 5 * 60_000 ? null : v;
    render();
  });
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-mapkind], [data-mapact], #map-play, #map-live, #map-speed, #map-fit, #map-reset, #map-export-png, #map-export-svg, #map-layout button, #map-color button");
    if (!t) { if (!e.target.closest("#map-menu")) closeMapMenu(); return; }
    if (t.dataset.mapkind) {
      const k = t.dataset.mapkind;
      if (!NMAP.kinds.delete(k)) NMAP.kinds.add(k);
      return render();
    }
    if (t.dataset.mapact) return mapAction(t.dataset.mapact, t.closest("#map-menu").dataset.mac);
    if (t.closest("#map-layout")) { NMAP.layout = t.dataset.f; return render(); }
    if (t.closest("#map-color")) { NMAP.color = t.dataset.f; return render(); }
    switch (t.id) {
      case "map-play": return mapPlay();
      case "map-live": return mapLive();
      case "map-speed": NMAP.speed = NMAP.speed >= 8 ? 1 : NMAP.speed * 2; return render();
      case "map-fit": return mapFit();
      case "map-reset": delete NMAP.pins[pinKey()]; savePins(); mapFit(); return render();
      case "map-export-png": return exportMap("png");
      case "map-export-svg": return exportMap("svg");
    }
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMapMenu(); });
}

// ------------------------------------------------------------------ right-click menu

function openMapMenu(mac, x, y) {
  const d = state.devices.find((v) => v.mac === mac);
  if (!d) return;
  const m = $("#map-menu");
  const pinned = !!NMAP.pins[pinKey()]?.[mac];
  const here = NMAP.net === currentNetwork();
  const item = (act, label, on = true) => (on ? `<button data-mapact="${act}">${label}</button>` : "");
  m.innerHTML = `<div class="menu-head">${esc(deviceName(d))}<span>${esc(d.ip)}</span></div>
    ${item("details", "Open details")}
    ${item("ping", "Ping now", here && !d.is_self)}
    ${item("ports", "Check common ports", here)}
    ${item("wake", "Send Wake-on-LAN", !d.is_self)}
    ${item("trust", d.trusted ? "Mark as not trusted" : "Mark as trusted", !d.is_self)}
    ${item("copy-ip", "Copy IP address")}
    ${item("copy-mac", "Copy MAC address")}
    ${item("unpin", "Return to automatic position", pinned)}`;
  m.dataset.mac = mac;
  m.hidden = false;
  const r = m.getBoundingClientRect();
  m.style.left = `${Math.min(x, window.innerWidth - r.width - 8)}px`;
  m.style.top = `${Math.min(y, window.innerHeight - r.height - 8)}px`;
}

function closeMapMenu() {
  const m = $("#map-menu");
  if (m) m.hidden = true;
}

async function mapAction(act, mac) {
  closeMapMenu();
  const d = state.devices.find((v) => v.mac === mac);
  if (!d) return;
  switch (act) {
    case "details": return openDrawer(mac);
    case "ping": {
      toast({ severity: "info", title: `Pinging ${deviceName(d)}…`, detail: "Five pings, a few seconds." });
      try {
        const r = await invoke("ping_device", { mac, count: 5 });
        const ok = r.filter((v) => v != null);
        toast({ severity: "info", title: `${deviceName(d)}: ${ok.length} of ${r.length} replies`, detail: ok.length ? `Average ${fmtMs(ok.reduce((a, b) => a + b, 0) / ok.length)}, fastest ${fmtMs(Math.min(...ok))}, slowest ${fmtMs(Math.max(...ok))}.` : "No replies. It may be asleep or blocking pings." });
      } catch (e) { toast({ severity: "info", title: "Couldn't ping", detail: String(e) }); }
      return;
    }
    case "ports":
      state.portChecks.add(mac);
      openDrawer(mac);
      call("check_ports", { mac }).catch(() => { state.portChecks.delete(mac); render(); });
      return;
    case "wake":
      await call("wake_device", { mac });
      return toast({ severity: "info", title: "Wake-up packet sent", detail: "If it supports Wake-on-LAN, it should come online within a minute." });
    case "trust":
      d.trusted = !d.trusted;
      render();
      return call("set_trusted", { mac, trusted: d.trusted });
    case "copy-ip": return copyText(d.ip).then(() => toast({ severity: "info", title: "Copied", detail: d.ip }));
    case "copy-mac": return copyText(d.mac).then(() => toast({ severity: "info", title: "Copied", detail: d.mac }));
    case "unpin": {
      const p = NMAP.pins[pinKey()];
      if (p) { delete p[mac]; savePins(); }
      return render();
    }
  }
}

// ------------------------------------------------------------------ export

// A standalone copy of the map with the theme's colours written in.
function mapSvgForExport() {
  const src = $("#map-svg");
  const clone = src.cloneNode(true);
  const props = ["fill", "stroke", "stroke-width", "stroke-dasharray", "stroke-linecap", "stroke-linejoin", "opacity", "font-size", "font-weight", "font-family"];
  const a = [src, ...src.querySelectorAll("*")];
  const b = [clone, ...clone.querySelectorAll("*")];
  a.forEach((el, i) => {
    const cs = getComputedStyle(el);
    b[i].setAttribute("style", props.map((p) => `${p}:${cs.getPropertyValue(p)}`).join(";"));
  });
  clone.querySelector(".map-bg")?.setAttribute("style", `fill:${getComputedStyle(document.body).getPropertyValue("--surface") || "#fff"}`);
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const [, , w, h] = src.getAttribute("viewBox").split(" ").map(Number);
  clone.setAttribute("width", w);
  clone.setAttribute("height", h);
  return { text: new XMLSerializer().serializeToString(clone), w, h };
}

async function exportMap(kind) {
  if (!$("#map-svg")) return;
  const { text, w, h } = mapSvgForExport();
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
  const base = `NetWatch-map-${stamp}`;
  let path;
  if (kind === "svg") {
    path = await call("save_export", { name: `${base}.svg`, content: text });
  } else {
    try {
      const img = new Image();
      img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(text)}`;
      await img.decode();
      const c = document.createElement("canvas");
      c.width = w * 2; c.height = h * 2;
      const g = c.getContext("2d");
      g.scale(2, 2);
      g.drawImage(img, 0, 0, w, h);
      path = await call("save_export", { name: `${base}.png`, content: c.toDataURL("image/png").split(",")[1] });
    } catch {
      path = await call("save_export", { name: `${base}.svg`, content: text });
      toast({ severity: "info", title: "Saved as SVG instead", detail: "The picture couldn't be drawn as PNG here." });
    }
  }
  toast({ severity: "info", title: "Map saved", detail: path });
  call("open_export", { path }).catch(() => {});
}


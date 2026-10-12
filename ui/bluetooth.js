"use strict";
// The Bluetooth page: paired devices, the nearby scan, tracker warnings, the
// proximity map of nearby Bluetooth devices and Wi-Fi networks, device details
// and the presence summary of your own devices.
// Shares helpers and `state` with app.js, which loads after this file.

// Proximity bands. Bluetooth devices are banded by the backend (bt_bands.rs,
// which smooths the distance and adds hysteresis); only Wi-Fi networks are
// banded here, with the same rule.
const BANDS = [
  { name: "Touching", range: "< 1 m" },
  { name: "Same room", range: "1–3 m" },
  { name: "Nearby", range: "3–10 m" },
  { name: "Far", range: "10 m +" },
];
const BAND_EDGES = [1, 3, 10];
const BAND_MARGIN = 1.25;
const plainBand = (m) => BAND_EDGES.filter((e) => m >= e).length;
// Mirrors `band_for` in bt_bands.rs: stay in the current band until the
// distance is clearly (25%) past a boundary.
function bandFor(prev, m) {
  if (prev == null || prev < 0 || prev > 3) return plainBand(m);
  let b = prev;
  while (b < 3 && m >= BAND_EDGES[b] * BAND_MARGIN) b++;
  while (b > 0 && m < BAND_EDGES[b - 1] / BAND_MARGIN) b--;
  return b;
}

const BT_STALE_MS = 60_000; // not heard for this long: the dot fades
const BT_DROP_MS = 10 * 60_000; // …and after this it leaves the map
const BT_SPARK_MS = 10 * 60_000;
const PRESENT_MS = 150_000; // a device of yours counts as here if heard this recently

// Wi-Fi access points transmit far more power than Bluetooth tags, so they
// get their own path-loss guess: about -35 dBm at 1 m, losing 30 dB per decade.
const wifiDistance = (rssi) => Math.min(100, Math.max(0.3, Math.pow(10, (-35 - rssi) / 30)));

const fmtDist = (m) => (m == null ? "—" : m < 1 ? "< 1 m" : m < 10 ? `≈ ${m.toFixed(1)} m` : `≈ ${Math.round(m)} m`);

// Icons for the device categories the backend assigns (see bt_types.rs).
// (app.js's ICONS load after this file, so shared icons are looked up lazily.)
const SHARED_ICON = { phone: "phone", computer: "computer", tv: "media", speaker: "speaker", printer: "printer", home: "home" };
const btIcon = (k) => (SHARED_ICON[k] ? ICONS[SHARED_ICON[k]] : BT_ICONS[k]) || BT_ICONS.bluetooth;
const BT_ICONS = {
  tablet: '<svg viewBox="0 0 24 24"><rect x="4.5" y="2.5" width="15" height="19" rx="2"/><path d="M11 18.5h2"/></svg>',
  watch: '<svg viewBox="0 0 24 24"><rect x="6.5" y="6.5" width="11" height="11" rx="3"/><path d="M9 6.5 9.5 3h5l.5 3.5M9 17.5l.5 3.5h5l.5-3.5"/></svg>',
  fitness: '<svg viewBox="0 0 24 24"><path d="M3 12h4l2-5 4 10 2-5h6"/></svg>',
  headphones: '<svg viewBox="0 0 24 24"><path d="M4 15v-3a8 8 0 0 1 16 0v3"/><rect x="3" y="14" width="4" height="6" rx="1.5"/><rect x="17" y="14" width="4" height="6" rx="1.5"/></svg>',
  tracker: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/></svg>',
  car: '<svg viewBox="0 0 24 24"><path d="M5 16V11l2-5h10l2 5v5"/><path d="M3 16h18v3H3z"/><circle cx="7.5" cy="13" r=".8"/><circle cx="16.5" cy="13" r=".8"/></svg>',
  lock: '<svg viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5M12 14.5v2.5"/></svg>',
  garage: '<svg viewBox="0 0 24 24"><path d="M3 10 12 4l9 6v10H3z"/><path d="M7 20v-7h10v7M7 15.5h10M7 18h10"/></svg>',
  solar: '<svg viewBox="0 0 24 24"><path d="M4 18 6.5 9h11L20 18z"/><path d="M5.3 13.5h13.4M10 9l-1 9M14 9l1 9M12 2.5v2M7 4l1 1.5M17 4l-1 1.5"/></svg>',
  scooter: '<svg viewBox="0 0 24 24"><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.5 18h7M15 18l-2.5-12H10M12.5 6h2.5"/></svg>',
  game: '<svg viewBox="0 0 24 24"><path d="M7 8h10a4 4 0 0 1 4 4v1.5a3 3 0 0 1-5.4 1.8L14.5 14h-5l-1.1 1.3A3 3 0 0 1 3 13.5V12a4 4 0 0 1 4-4z"/><path d="M8 10.5v3M6.5 12h3M16 11h.01M17.5 12.5h.01"/></svg>',
  health: '<svg viewBox="0 0 24 24"><path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10z"/></svg>',
  appliance: '<svg viewBox="0 0 24 24"><rect x="5" y="3" width="14" height="18" rx="2"/><circle cx="12" cy="13" r="4"/><path d="M8 6h.01M11 6h.01"/></svg>',
  sensor: '<svg viewBox="0 0 24 24"><path d="M10 13.5V5a2 2 0 0 1 4 0v8.5a4 4 0 1 1-4 0z"/></svg>',
  bluetooth: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10-5 4V3l5 4L7 17"/></svg>',
};

const CATEGORY_LABEL = {
  phone: "phone", tablet: "tablet", computer: "computer", watch: "smartwatch", fitness: "fitness tracker",
  headphones: "headphones", speaker: "speaker", tracker: "tracker", car: "car", tv: "TV / media",
  home: "smart home", lock: "smart lock", garage: "garage / gate", solar: "solar", scooter: "e-scooter",
  printer: "printer", game: "controller", health: "health device", appliance: "appliance", sensor: "sensor",
};

function bleLabel(d) {
  if (d.name) return d.name;
  if (d.brand && d.kind) return `${d.brand} ${d.kind.toLowerCase()}`;
  return d.kind || (d.brand || d.maker ? `${d.brand || d.maker} device` : "Unknown device");
}

function bleDetail(d) {
  const kind = d.kind && !bleLabel(d).toLowerCase().includes(d.kind.toLowerCase()) ? d.kind : null;
  const brand = d.brand && !bleLabel(d).includes(d.brand) ? d.brand : null;
  return [kind, brand, d.maker && d.maker !== d.brand && d.maker !== brand ? `chip by ${d.maker}` : null,
    d.tracker && d.separated ? "away from its owner" : null,
    d.services?.length ? d.services.slice(0, 3).join(", ") : null].filter(Boolean).join(" · ");
}

function isSuspectTracker(d) {
  if (!d.tracker || d.mine || d.paired) return false;
  return d.tracker === "Apple Find My" || d.tracker === "Google Find My Device" ? d.separated : true;
}

// The tracker banner's line about the "travelling with you" check, which needs Location.
function trackerTravelNote() {
  const st = state.location?.status;
  if (!st || st === "unavailable") return "";
  if (st === "allowed") return " It also warns you if one is still near after this Mac has moved 1 km or more.";
  if (st === "off") return ' To also be warned if one travels with you, <button class="btn link" data-action="allow-location">allow location</button>.';
  return ' The travel warning needs <button class="btn link" data-goto="settings">Location permission</button>.';
}

function signalBars(rssi) {
  const n = rssi == null ? 0 : rssi >= -60 ? 4 : rssi >= -70 ? 3 : rssi >= -80 ? 2 : 1;
  return `<span class="bars" aria-label="${n} of 4 bars">${[1, 2, 3, 4].map((i) => `<i class="${i <= n ? "on" : ""}" style="height:${3 + i * 2}px"></i>`).join("")}</span>`;
}

// ------------------------------------------------------------------ signal history

// RSSI samples per device from the "bt" events, for the details panel's
// sparkline. Collected whichever page is showing, and only when the device
// was actually heard again (not just re-reported).
const btSamples = new Map();

function btIngest(bt) {
  const now = Date.now();
  for (const d of bt?.nearby || []) {
    if (d.rssi == null) continue;
    let s = btSamples.get(d.id);
    if (!s) btSamples.set(d.id, (s = []));
    const last = s[s.length - 1];
    if (last && d.last_seen - last.ts < 1500) continue;
    s.push({ ts: d.last_seen, rssi: d.rssi });
    while (s.length && s[0].ts < now - BT_SPARK_MS) s.shift();
  }
  for (const [id, s] of btSamples) if (!s.length || s[s.length - 1].ts < now - BT_SPARK_MS) btSamples.delete(id);
}

// ------------------------------------------------------------------ proximity map

// One half-ring per band around "This Mac" at the bottom centre. A single
// radio can't tell direction, so dots are only placed by band, grouped by
// type and spread evenly along it. Drawn in a fixed 720-wide space that
// scales with the page.
const MAP = { w: 720, h: 326, cx: 360, base: 290, hole: 34, thick: 78, squash: 0.78, theta0: (26 * Math.PI) / 180 };
const bandInner = (k) => MAP.hole + k * MAP.thick;
const bandOuter = (k) => MAP.hole + (k + 1) * MAP.thick;
// A point in band k at angle theta (π = far left, 0 = far right); off = -0.5..0.5 across the band.
function mapPoint(k, theta, off = 0) {
  const rho = bandInner(k) + MAP.thick * (0.5 + off);
  return [MAP.cx + rho * Math.cos(theta), MAP.base - rho * MAP.squash * Math.sin(theta)];
}
// How many dots fit along a band: in one row, or zig-zagging in two.
const MAP_CAP = [0, 1, 2, 3].map((k) => {
  const rho = bandInner(k) + MAP.thick / 2;
  const a = MAP.theta0;
  const b = Math.PI - MAP.theta0;
  let len = 0;
  for (let i = 0; i < 40; i++) {
    const t = a + ((b - a) * (i + 0.5)) / 40;
    len += (Math.hypot(rho * Math.sin(t), rho * MAP.squash * Math.cos(t)) * (b - a)) / 40;
  }
  return { one: Math.floor(len / 15), two: Math.floor((2 * len) / 15) };
});

const star = () => Array.from({ length: 10 }, (_, i) => {
  const a = -Math.PI / 2 + (i * Math.PI) / 5;
  const r = i % 2 ? 3.6 : 8.6;
  return `${i ? "L" : "M"}${(r * Math.cos(a)).toFixed(1)} ${(r * Math.sin(a)).toFixed(1)}`;
}).join("") + "z";
const SQUARE = "M-2.5-5.5h5a3 3 0 0 1 3 3v5a3 3 0 0 1-3 3h-5a3 3 0 0 1-3-3v-5a3 3 0 0 1 3-3z";
// ★ yours, ◆ unknown tracker, ▢ Wi-Fi, ● any other Bluetooth device.
const SHAPES = {
  mine: star(),
  tracker: "M0-8.5L7.5 0 0 8.5-7.5 0z",
  wifi: SQUARE,
  "wifi-own": SQUARE,
  ble: "M-5.5 0a5.5 5.5 0 1 0 11 0a5.5 5.5 0 1 0-11 0z",
};
const MAP_FILTERS = {
  all: () => true,
  mine: (i) => i.shape === "mine",
  trackers: (i) => i.tracker,
  wifi: (i) => i.shape.startsWith("wifi"),
};

const wifiMapId = (x) => (x.bssid ? `wifi-${x.bssid}` : `wifi-${x.ssid || ""}-${x.channel}-${x.band}-${x.security}-${x.phy}`);
let wifiTrack = new Map(); // id → { own, label, smooth, band, tip }
let wifiSeen = null;

// Wi-Fi is scanned once a minute, so there is little to smooth: average each
// network's distance with the last scan's and apply the band margin.
function wifiIngest(w) {
  const next = new Map();
  const add = (id, own, label, rssi, desc) => {
    let key = id;
    for (let n = 2; next.has(key); n++) key = `${id}#${n}`; // hidden networks can share an id
    const raw = wifiDistance(rssi);
    const prev = wifiTrack.get(key);
    const smooth = prev ? Math.exp((Math.log(prev.smooth) + Math.log(raw)) / 2) : raw;
    const band = bandFor(prev?.band, smooth);
    next.set(key, { own, label, smooth, band, tip: `${desc} · ${rssi} dBm · ${fmtDist(raw)} · ${BANDS[band].name}` });
  };
  const c = w?.current;
  if (c?.rssi != null) add("wifi-current", true, "Your Wi-Fi", c.rssi, `Your Wi-Fi router · channel ${c.channel}`);
  for (const x of w ? nearbyOthers(w) : []) {
    if (x.rssi == null) continue;
    add(wifiMapId(x), false, x.ssid || `Wi-Fi ch ${x.channel}`, x.rssi, `${x.ssid || "Wi-Fi network (name hidden)"} · channel ${x.channel} ${x.band || ""}`.trim());
  }
  wifiTrack = next;
}

function bleTip(d) {
  const label = bleLabel(d);
  const lower = label.toLowerCase();
  const type = d.kind || CATEGORY_LABEL[d.category];
  const maker = d.brand || d.maker;
  const band = d.band ?? (d.distance_m != null ? plainBand(d.distance_m) : null);
  return [
    label,
    type && !lower.includes(type.toLowerCase()) ? type : null,
    maker && !label.includes(maker) ? maker : null,
    d.tracker ? `${d.tracker}${d.mine || d.paired ? " (yours)" : d.separated ? ", away from its owner" : ""}` : d.mine ? "Yours" : d.paired ? "Yours (paired)" : null,
    `${d.rssi ?? "?"} dBm`,
    `${fmtDist(d.distance_m)}${band != null ? ` · ${BANDS[band].name}` : ""}`,
  ].filter(Boolean).join(" · ");
}

// Everything on the map: Bluetooth devices heard in the last 10 minutes and
// the Wi-Fi networks from the last scan.
function mapItems() {
  const now = Date.now();
  const items = [];
  for (const d of state.bt?.nearby || []) {
    if (d.distance_m == null || now - d.last_seen > BT_DROP_MS) continue;
    const suspect = isSuspectTracker(d);
    items.push({
      id: d.id, ble: true, tracker: !!d.tracker,
      shape: d.mine || d.paired ? "mine" : suspect ? "tracker" : "ble",
      rank: d.mine || d.paired ? 0 : suspect ? 2 : d.tracker ? 3 : d.category || d.name ? 4 : 4.5,
      sub: d.category || "~", band: d.band ?? plainBand(d.distance_m),
      label: bleLabel(d), stale: now - d.last_seen > BT_STALE_MS, tip: bleTip(d),
    });
  }
  if (state.wifi !== wifiSeen) {
    wifiSeen = state.wifi;
    wifiIngest(state.wifi);
  }
  for (const [id, t] of wifiTrack) {
    items.push({ id, ble: false, tracker: false, shape: t.own ? "wifi-own" : "wifi", rank: t.own ? 1 : 5, sub: "~", band: t.band, label: t.label, stale: false, tip: t.tip });
  }
  return items;
}

// Yours first, then trackers, then by kind. The tie-breakers are stable
// (never the signal), so dots don't swap places as readings change.
const byDisplay = (a, b) => Math.floor(a.rank) - Math.floor(b.rank) || (a.sub < b.sub ? -1 : a.sub > b.sub ? 1 : 0) || a.label.localeCompare(b.label) || (a.id < b.id ? -1 : 1);
// Which dots to keep when a band is crowded, and which get a label first.
const byPriority = (a, b) => a.rank - b.rank || (a.stale - b.stale) || byDisplay(a, b);

// Positions the shown items in their bands, and decides which get a label.
function layoutMap(items) {
  const pos = new Map();
  const more = [0, 0, 0, 0];
  for (let k = 0; k < 4; k++) {
    let inBand = items.filter((i) => i.band === k);
    if (inBand.length > MAP_CAP[k].two) {
      more[k] = inBand.length - MAP_CAP[k].two;
      inBand = [...inBand].sort(byPriority).slice(0, MAP_CAP[k].two);
    }
    inBand.sort(byDisplay);
    const zig = inBand.length > MAP_CAP[k].one;
    inBand.forEach((it, i) => {
      const theta = Math.PI - MAP.theta0 - ((i + 0.5) / inBand.length) * (Math.PI - 2 * MAP.theta0);
      const [x, y] = mapPoint(k, theta, zig ? (i % 2 ? 0.2 : -0.2) : 0);
      pos.set(it.id, { x, y, label: null });
    });
  }
  // Labels, most important first, each on the first side where it fits
  // without touching a dot, a pill or another label.
  const boxes = [[0, MAP.base + 4, MAP.w, MAP.h]];
  for (const p of pos.values()) boxes.push([p.x - 8, p.y - 8, p.x + 8, p.y + 8]);
  for (let k = 0; k < 4; k++) if (more[k]) boxes.push(pillBox(k, more[k]));
  const free = (b) => b[0] >= 4 && b[2] <= MAP.w - 4 && b[1] >= 4 && boxes.every((o) => b[2] <= o[0] || b[0] >= o[2] || b[3] <= o[1] || b[1] >= o[3]);
  for (const it of [...items].filter((i) => pos.has(i.id)).sort(byPriority)) {
    const p = pos.get(it.id);
    const text = it.label.length > 22 ? `${it.label.slice(0, 21)}…` : it.label;
    const w = text.length * 5.9 + 4;
    const tries = [
      { dx: 10, dy: 4, anchor: "start", box: [p.x + 9, p.y - 7, p.x + 9 + w, p.y + 7] },
      { dx: -10, dy: 4, anchor: "end", box: [p.x - 9 - w, p.y - 7, p.x - 9, p.y + 7] },
      { dx: 0, dy: -12, anchor: "middle", box: [p.x - w / 2, p.y - 22, p.x + w / 2, p.y - 10] },
      { dx: 0, dy: 21, anchor: "middle", box: [p.x - w / 2, p.y + 10, p.x + w / 2, p.y + 23] },
      { dx: 9, dy: -9, anchor: "start", box: [p.x + 8, p.y - 22, p.x + 8 + w, p.y - 10] },
      { dx: -9, dy: -9, anchor: "end", box: [p.x - 8 - w, p.y - 22, p.x - 8, p.y - 10] },
      { dx: 9, dy: 19, anchor: "start", box: [p.x + 8, p.y + 8, p.x + 8 + w, p.y + 22] },
      { dx: -9, dy: 19, anchor: "end", box: [p.x - 8 - w, p.y + 8, p.x - 8, p.y + 22] },
    ];
    const t = tries.find((c) => free(c.box));
    if (t) {
      p.label = { text, dx: t.dx, dy: t.dy, anchor: t.anchor };
      boxes.push(t.box);
    }
  }
  return { pos, more };
}

// Where a band's "+N more" pill sits: its right end, near the baseline.
function pillPos(k) {
  return mapPoint(k, (9 * Math.PI) / 180);
}
function pillBox(k, n) {
  const [x, y] = pillPos(k);
  const w = `+${n} more`.length * 6.2 + 14;
  return [x - w / 2, y - 9, x + w / 2, y + 9];
}

function mapSkeleton() {
  let s = "";
  for (let k = 3; k >= 0; k--) {
    const ro = bandOuter(k);
    const ri = bandInner(k);
    const { cx, base, squash } = MAP;
    s += `<path class="band b${k}" d="M${cx - ro} ${base}A${ro} ${ro * squash} 0 0 1 ${cx + ro} ${base}L${cx + ri} ${base}A${ri} ${ri * squash} 0 0 0 ${cx - ri} ${base}z"/>`;
  }
  for (let k = 0; k < 4; k++) {
    const x = MAP.cx - (bandInner(k) + MAP.thick / 2);
    s += `<text class="band-name" x="${x}" y="${MAP.base + 15}" text-anchor="middle">${BANDS[k].name}</text>
      <text class="band-range" x="${x}" y="${MAP.base + 27}" text-anchor="middle">${BANDS[k].range}</text>`;
  }
  s += `<circle class="mac" cx="${MAP.cx}" cy="${MAP.base}" r="7"/>
    <text class="band-name strong" x="${MAP.cx}" y="${MAP.base + 22}" text-anchor="middle">This Mac</text>
    <g id="bt-marks"></g><g id="bt-more"></g>`;
  return `<svg viewBox="0 0 ${MAP.w} ${MAP.h}" role="img" aria-label="Nearby Wi-Fi networks and Bluetooth devices by estimated distance from this Mac">${s}</svg>`;
}

const markEls = new Map(); // id → <g>, kept between renders so dots glide
const moreEls = new Map(); // band → <g> for the "+N more" pill
const svgNS = "http://www.w3.org/2000/svg";
const svgEl = (tag, attrs = {}) => {
  const e = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
};

function createMark(it, x, y) {
  const g = svgEl("g", { class: "bt-mark enter" });
  g.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`;
  g.append(svgEl("circle", { class: "hit", r: 11 }), svgEl("path", { class: "shape" }), svgEl("text", { class: "lbl off", x: 10, y: 4 }));
  if (it.ble) {
    g.dataset.ble = "1";
    g.setAttribute("tabindex", "0");
    g.setAttribute("role", "button");
  }
  g.dataset.id = it.id;
  $("#bt-marks").append(g);
  void g.getBoundingClientRect(); // so the fade-in and later glides start from here
  requestAnimationFrame(() => g.classList.remove("enter"));
  return g;
}

function renderBtMap() {
  const el = $("#bt-map");
  if (!el.firstChild) el.innerHTML = mapSkeleton();
  document.querySelectorAll("#bt-map-filter [data-mf]").forEach((b) => b.classList.toggle("on", b.dataset.mf === state.btMapFilter));
  const items = mapItems();
  const shown = items.filter(MAP_FILTERS[state.btMapFilter] || MAP_FILTERS.all);
  const { pos, more } = layoutMap(shown);
  const live = new Set(items.map((i) => i.id));
  for (const it of items) {
    const p = pos.get(it.id);
    let g = markEls.get(it.id);
    if (!g) {
      g = createMark(it, p?.x ?? MAP.cx, p?.y ?? MAP.base);
      markEls.set(it.id, g);
    }
    if (p) g.style.transform = `translate(${p.x.toFixed(1)}px, ${p.y.toFixed(1)}px)`;
    const lbl = g.querySelector(".lbl");
    if (p?.label) {
      lbl.textContent = p.label.text;
      lbl.setAttribute("x", p.label.dx);
      lbl.setAttribute("y", p.label.dy);
      lbl.setAttribute("text-anchor", p.label.anchor);
    }
    lbl.classList.toggle("off", !p?.label);
    const path = g.querySelector(".shape");
    if (path.dataset.shape !== it.shape) {
      path.dataset.shape = it.shape;
      path.setAttribute("d", SHAPES[it.shape]);
    }
    g.setAttribute("class", `bt-mark ${it.shape}${it.stale ? " stale" : ""}${p ? "" : " hidden"}${g.classList.contains("enter") ? " enter" : ""}`);
    g.setAttribute("data-tip", it.tip);
    g.setAttribute("aria-label", it.tip);
  }
  // Devices that aged out or left the scan fade away, then go.
  for (const [id, g] of markEls) {
    if (live.has(id)) continue;
    markEls.delete(id);
    g.classList.add("gone");
    setTimeout(() => g.remove(), 700);
  }
  for (let k = 0; k < 4; k++) {
    let g = moreEls.get(k);
    if (!g) {
      g = svgEl("g", { class: "bt-more hidden" });
      g.dataset.btmore = k;
      g.setAttribute("role", "button");
      g.setAttribute("tabindex", "0");
      g.append(svgEl("rect", { y: -9, height: 18, rx: 9 }), svgEl("text", { y: 4, "text-anchor": "middle" }));
      const [x, y] = pillPos(k);
      g.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`;
      $("#bt-more").append(g);
      moreEls.set(k, g);
    }
    if (more[k]) {
      const text = `+${more[k]} more`;
      const w = text.length * 6.2 + 14;
      g.querySelector("text").textContent = text;
      g.querySelector("rect").setAttribute("x", -w / 2);
      g.querySelector("rect").setAttribute("width", w);
      g.setAttribute("data-tip", `${more[k]} more in ${BANDS[k].name}. Click to list them below.`);
      g.setAttribute("aria-label", `${more[k]} more devices in ${BANDS[k].name}`);
    }
    g.classList.toggle("hidden", !more[k]);
  }
  const n = (shape) => items.filter((i) => i.shape === shape).length;
  const key = (shape, label, count) => `<span class="key"><svg viewBox="-9 -9 18 18" class="lk ${shape}"><path d="${SHAPES[shape]}"/></svg>${label} <b>${count}</b></span>`;
  $("#bt-map-legend").innerHTML = [
    key("mine", "Yours", n("mine")),
    n("tracker") ? key("tracker", "Unknown tracker", n("tracker")) : "",
    key("ble", "Bluetooth", n("ble")),
    key("wifi", "Wi-Fi", n("wifi") + n("wifi-own")),
  ].join("");
}

// ------------------------------------------------------------------ your devices: presence

const btDayStart = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime(); };

// Time within today covered by [start, end] sessions.
function nearbyMsToday(sessions, now = Date.now()) {
  const s0 = btDayStart();
  let sum = 0;
  for (const [a, b] of sessions || []) {
    const lo = Math.max(a, s0);
    const hi = Math.min(b, now);
    if (hi > lo) sum += hi - lo;
  }
  return sum;
}
const seenToday = (sessions) => (sessions || []).some(([, b]) => b >= btDayStart());
const fmtNear = (ms, any) => (ms < 60_000 ? (any ? "< 1 min" : "0 min") : fmtDuration(Math.round(ms / 60_000) * 60).replace(/ 0s$/, ""));

const presenceFor = (key) => (state.bt?.presence || []).find((e) => e.key === key);
const isHere = (e) => (e.kind === "paired"
  ? (state.bt?.info?.paired || []).some((p) => p.key === e.key && p.connected)
  : state.bt?.scan_state === "scanning" && Date.now() - e.last_present < PRESENT_MS);

const ADDRESS_NOTE = "Phones and tags change their Bluetooth address every so often, so a device you mark as yours may appear as several entries. Paired devices keep one entry.";

// A 0:00–24:00 bar for today with the time the device was around.
function todayBar(sessions) {
  const now = Date.now();
  const s0 = btDayStart();
  const len = 86_400_000;
  const segs = (sessions || [])
    .filter(([a, b]) => b >= s0 && a < now)
    .map(([a, b]) => {
      const a2 = Math.max(a, s0);
      const b2 = Math.min(Math.max(b, a + 60_000), s0 + len);
      return `<i style="left:${((a2 - s0) / len) * 100}%;width:${(((b2 - a2) / len) * 100).toFixed(2)}%" data-tip="${esc(`${hhmm(a)} – ${b >= now - 180_000 ? "now" : hhmm(b)}`)}"></i>`;
    })
    .join("");
  return `<div class="presence"><div class="pres-row"><span>Today</span><div class="pres-track">${segs}<u style="left:${((now - s0) / len) * 100}%"></u></div></div>
    <div class="pres-row axis"><span></span><div class="pres-axis"><b>0:00</b><b>6:00</b><b>12:00</b><b>18:00</b><b>24:00</b></div></div></div>`;
}

// "Your devices nearby today": paired devices and devices marked as yours.
function renderToday() {
  const list = (state.bt?.presence || []).map((e) => ({ e, ms: nearbyMsToday(e.sessions), here: isHere(e) }));
  list.sort((a, b) => b.here - a.here || b.ms - a.ms || a.e.name.localeCompare(b.e.name));
  $("#bt-today").innerHTML = list.length
    ? list.map(({ e, ms, here }) => `<button class="today-row" data-btopen="${esc(e.key)}" data-btkind="${e.kind}">
        <span class="dot ${here ? "good" : "off"}"></span>
        <span class="grow"><b class="truncate">${esc(e.name || "Device")}</b><span class="muted small">${e.kind === "paired" ? "Paired" : "Marked as yours"}</span></span>
        <span class="today-time"><b>${esc(fmtNear(ms, seenToday(e.sessions)))}</b><span class="muted small">${here ? "here now" : e.last_present ? `last seen ${esc(ago(e.last_present))}` : "not seen yet"}</span></span>
      </button>`).join("")
    : '<div class="empty">Nothing recorded yet. Paired devices are recorded while they are connected. Open a nearby device and turn on “This is mine” to record when it is around.</div>';
}

// ------------------------------------------------------------------ details panel

function openBtDrawer(target) {
  state.btDrawer = target;
  state.btDrawerSig = "";
  closeDrawer();
  $("#bt-drawer").hidden = false;
  renderBtDrawer();
}

function closeBtDrawer() {
  if (!state.btDrawer) return;
  state.btDrawer = null;
  $("#bt-drawer").hidden = true;
}

const fact = (k, v) => (v ? `<dt>${k}</dt><dd>${v}</dd>` : "");

function presenceSection(e, hint) {
  if (!e) return `<div><h3>Nearby today</h3><p class="muted small" style="margin:0">${esc(hint)}</p></div>`;
  const ms = nearbyMsToday(e.sessions);
  return `<div><h3>Nearby today</h3>
    <div class="row" style="margin-bottom:10px;align-items:flex-start"><span class="dot ${isHere(e) ? "good" : "off"}" style="margin-top:5px"></span>
      <span><b>${esc(fmtNear(ms, seenToday(e.sessions)))}</b> today · ${isHere(e) ? "here now" : e.last_present ? `last seen ${esc(ago(e.last_present))}` : "not seen yet"}</span></div>
    ${todayBar(e.sessions)}
    <p class="muted small" style="margin:10px 0 0">${esc(ADDRESS_NOTE)}</p></div>`;
}

function bleDrawer(id) {
  const d = (state.bt?.nearby || []).find((x) => x.id === id);
  const entry = presenceFor(id);
  const mine = d ? d.mine : !!entry;
  const title = d ? bleLabel(d) : entry?.name || "Device";
  const mineToggle = `<div><div class="row"><button class="switch" role="switch" aria-checked="${mine}" data-mine="${esc(id)}" data-on="${mine ? "0" : "1"}" aria-label="This is mine"></button><span>This is mine</span></div>
    <p class="muted small" style="margin:8px 0 0">${mine ? "Marked as yours: it never raises unknown-tracker alerts, and NetWatch records when it is nearby, on this computer only." : "Mark it to stop unknown-tracker alerts for it and to keep a record of when it is nearby, on this computer only."}</p></div>`;
  if (!d) {
    return { title, html: `<p class="muted" style="margin:0">NetWatch hasn't heard this device in the last half hour.</p>${presenceSection(entry, "")}${mineToggle}` };
  }
  const cat = CATEGORY_LABEL[d.category];
  const band = d.band ?? (d.distance_m != null ? plainBand(d.distance_m) : null);
  const samples = btSamples.get(id) || [];
  const tracker = d.tracker
    ? `${esc(d.tracker)}${d.separated ? " · away from its owner" : ""}${d.mine || d.paired ? " · yours" : isSuspectTracker(d) ? " · not marked as yours" : ""}`
    : "";
  const facts = [
    fact("Type", esc(d.kind || cat || "Unidentified")),
    cat && d.kind && cat.toLowerCase() !== d.kind.toLowerCase() ? fact("Category", esc(cat)) : "",
    fact("Brand", esc(d.brand || "")),
    d.maker && d.maker !== d.brand ? fact("Chip maker", esc(d.maker)) : "",
    fact("Tracker", tracker),
    fact("Services", d.services?.length ? `<div class="chips">${d.services.map((s) => `<span class="chip">${esc(s)}</span>`).join("")}</div>` : '<span class="muted">None advertised</span>'),
    fact("TX power", d.tx_power != null ? `${d.tx_power} dBm` : '<span class="muted">Not advertised</span>'),
    fact("Signal now", d.rssi != null ? `${signalBars(d.rssi)} ${d.rssi} dBm` : "—"),
    fact("Distance", d.distance_m != null ? `${esc(fmtDist(d.distance_m))}${band != null ? ` · ${esc(BANDS[band].name)}` : ""} <span class="muted small">estimated</span>` : "—"),
    fact("First heard", `<span title="${esc(fullTime(d.first_seen))}">${esc(ago(d.first_seen))} · ${esc(hhmm(d.first_seen))}</span>`),
    fact("Last heard", `<span title="${esc(fullTime(d.last_seen))}">${esc(ago(d.last_seen))} · ${esc(hhmm(d.last_seen))}</span>`),
  ].join("");
  const html = `
    <div><dl class="facts">${facts}</dl></div>
    <div><h3>Signal · last 10 minutes</h3><div class="chart short" id="bt-spark"></div></div>
    ${mine ? presenceSection(entry, "") : presenceSection(null, "Mark this device as yours to keep a record of when it is nearby.")}
    <div><button class="btn" data-locate="${esc(id)}">Locate</button></div>
    ${mineToggle}`;
  return { title, html, samples };
}

function pairedDrawer(key) {
  const p = (state.bt?.info?.paired || []).find((x) => x.key === key);
  const entry = presenceFor(key);
  if (!p) return { title: entry?.name || "Device", html: '<p class="muted" style="margin:0">This device is no longer paired with this computer.</p>' };
  const facts = [
    fact("Type", esc(p.kind || "Bluetooth device")),
    fact("Maker", esc(p.vendor || "")),
    fact("Firmware", esc(p.firmware || "")),
    fact("Status", p.connected ? "Connected" : `Not connected${p.last_connected ? ` · last connected ${esc(ago(p.last_connected))}` : ""}`),
    fact("Signal", p.rssi != null ? `${p.rssi} dBm` : ""),
    fact("Battery", p.battery.length ? `<div class="chips">${p.battery.map(([label, pct]) => `<span class="chip ${battTone(pct)}">${esc(label)} ${pct}%</span>`).join("")}</div>` : ""),
  ].join("");
  return { title: p.name, html: `<div><dl class="facts">${facts}</dl></div>${presenceSection(entry, "NetWatch records when a paired device is connected. Nothing recorded yet.")}` };
}

const battTone = (pct) => (pct <= 15 ? "bad" : pct <= 30 ? "warn" : "");

function renderBtDrawer() {
  const T = state.btDrawer;
  if (!T) return;
  const r = T.type === "paired" ? pairedDrawer(T.id) : bleDrawer(T.id);
  // Only rebuild when something shown changed (or 15 s passed, for the clock and chart).
  const sig = r.html + Math.floor(Date.now() / 15_000) + (r.samples ? r.samples.length : "");
  if (sig === state.btDrawerSig) return;
  state.btDrawerSig = sig;
  $("#bt-drawer-title").textContent = r.title;
  const body = $("#bt-drawer-body");
  const top = body.scrollTop;
  body.innerHTML = r.html;
  body.scrollTop = top;
  const chart = $("#bt-spark");
  if (chart) {
    const now = Date.now();
    lineChart(chart, {
      points: r.samples.map((s) => ({ ts: s.ts, rssi: s.rssi + 100 })),
      series: [{ key: "rssi", label: "Signal", cls: "s1" }],
      span: BT_SPARK_MS,
      now,
      fmt: (v) => `${Math.round(v - 100)} dBm`,
      minTop: 70,
      ticks: timeTicks(now, BT_SPARK_MS, 5, (ms) => `-${Math.round(ms / 60_000)}m`),
      emptyMsg: r.samples.length < 2 ? "Collecting signal readings…" : null,
      aria: "Signal strength over the last 10 minutes",
    });
  }
}

// Clicks and keys on the map, the filter chips, the details panel and lists.
document.addEventListener("click", (e) => {
  const t = e.target;
  const mf = t.closest?.("[data-mf]");
  if (mf) { state.btMapFilter = mf.dataset.mf; return render(); }
  const more = t.closest?.("[data-btmore]");
  if (more) { state.bleBand = +more.dataset.btmore; return render(); }
  if (t.closest?.("[data-bandclear]")) { state.bleBand = null; return render(); }
  if (t.closest?.("[data-btclose]")) return closeBtDrawer();
  const mark = t.closest?.(".bt-mark[data-ble]");
  if (mark) return openBtDrawer({ type: "ble", id: mark.dataset.id });
  const open = t.closest?.("[data-btopen]");
  // Buttons inside a row (Locate, Mine) keep their own meaning.
  if (open && (open.matches("button") || !t.closest("button, a, input"))) {
    openBtDrawer({ type: open.dataset.btkind === "paired" ? "paired" : "ble", id: open.dataset.btopen });
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const t = e.target;
  if (t.matches?.(".bt-mark[data-ble]")) { e.preventDefault(); openBtDrawer({ type: "ble", id: t.dataset.id }); }
  else if (t.matches?.(".bt-more")) { e.preventDefault(); state.bleBand = +t.dataset.btmore; render(); }
});

function renderBtStatus() {
  const bt = state.bt || {};
  const ctrl = bt.info?.controller;
  const st = bt.scan_state || "off";
  const count = (bt.nearby || []).length;
  const btOff = st === "bluetooth_off" || ctrl?.powered === false;
  let msg;
  let action;
  if (st === "scanning" && !btOff) {
    msg = `<span class="dot good"></span> Listening · ${count} device${count === 1 ? "" : "s"} heard in the last 30 minutes`;
    action = '<button class="btn" data-action="ble-off">Stop listening</button>';
  } else if (st === "starting") {
    msg = '<span class="dot warn"></span> Starting… macOS may ask for Bluetooth permission.';
    action = '<button class="btn" data-action="ble-off">Cancel</button>';
  } else if (btOff) {
    msg = '<span class="dot off"></span> Bluetooth is turned off on this computer. Turn it on in Control Center or System Settings → Bluetooth.';
    action = st === "off" ? '<button class="btn primary" data-action="ble-on">Start listening</button>' : '<button class="btn" data-action="ble-off">Stop listening</button>';
  } else if (st === "off") {
    msg = "Listen for the Bluetooth signals nearby devices broadcast. NetWatch only listens. It never connects to, pairs with or sends anything to them.";
    action = '<button class="btn primary" data-action="ble-on">Start listening</button>';
  } else {
    msg = `<span class="dot bad"></span> ${esc(st)}`;
    action = '<button class="btn" data-action="ble-on">Try again</button>';
  }
  $("#bt-status").innerHTML = `<div class="grow">${msg}</div>${action}`;
  $("#bt-controller").textContent = ctrl
    ? [ctrl.powered ? "Bluetooth on" : "Bluetooth off", ctrl.chipset?.replace(/_/g, " "), ctrl.discoverable ? "discoverable" : null].filter(Boolean).join(" · ")
    : /Mac/.test(navigator.userAgent) ? "" : "Paired devices are listed on macOS.";
}

function renderPaired() {
  const list = [...(state.bt?.info?.paired || [])].sort((a, b) => b.connected - a.connected || a.name.localeCompare(b.name));
  const powered = state.bt?.info?.controller?.powered;
  $("#paired").innerHTML = list.length
    ? list.map((p) => `<div class="paired click" data-btopen="${esc(p.key)}" data-btkind="paired">
        <span class="dot ${p.connected ? "good" : "off"}" title="${p.connected ? "Connected" : "Not connected"}"></span>
        <div class="grow"><div><b>${esc(p.name)}</b> <span class="muted small">${esc([p.kind, p.vendor].filter(Boolean).join(" · "))}</span></div>
          <div class="muted small">${p.connected ? "Connected" : `Not connected${p.last_connected ? ` · last connected ${esc(ago(p.last_connected))}` : ""}`}${p.rssi != null ? ` · ${p.rssi} dBm` : ""}${p.firmware ? ` · firmware ${esc(p.firmware)}` : ""}</div></div>
        <div class="chips">${p.battery.map(([label, pct]) => `<span class="chip ${battTone(pct)}" title="${esc(label)} battery${pct <= 15 ? ": low" : ""}">${esc(label)} ${pct}%</span>`).join("")}</div>
      </div>`).join("")
    : `<div class="empty">${powered === false ? "Turn Bluetooth on to see your paired devices." : state.bt?.info ? "No paired devices." : "Reading paired devices…"}</div>`;
}

function renderNearby() {
  const f = state.bleFilter;
  const all = state.bt?.nearby || [];
  const counts = new Map();
  for (const d of all) {
    const k = d.category || "other";
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const cat = state.bleCategory;
  const band = state.bleBand;
  const bandOf = (d) => d.band ?? (d.distance_m != null ? plainBand(d.distance_m) : -1);
  $("#ble-categories").innerHTML = (band != null
    ? `<button class="cat-chip on" data-bandclear title="Show every distance">${esc(BANDS[band].name)} only <b>✕</b></button>`
    : "") + (all.length
    ? [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) =>
        `<button class="cat-chip ${cat === k ? "on" : ""}" data-cat="${esc(k)}">${btIcon(k)}<span>${n} ${esc(k === "other" ? "unidentified" : CATEGORY_LABEL[k] || k)}</span></button>`).join("")
    : "");
  const list = all
    .filter((d) => f !== "trackers" || d.tracker)
    .filter((d) => f !== "named" || d.name)
    .filter((d) => !cat || (d.category || "other") === cat)
    .filter((d) => band == null || bandOf(d) === band)
    .slice(0, 150);
  const suspects = all.filter(isSuspectTracker);
  $("#tracker-banner").hidden = !suspects.length;
  $("#tracker-banner").innerHTML = suspects.length
    ? `<div class="grow"><b>${suspects.length} unknown tracker${suspects.length > 1 ? "s" : ""} nearby.</b> ${esc(suspects.map((d) => d.tracker).join(", "))}. If one stays with you for 15 minutes, NetWatch alerts you.${trackerTravelNote()} Mark trackers you own as yours.</div>`
    : "";
  $("#nearby-table tbody").innerHTML = list.map((d) => `<tr class="click" data-btopen="${esc(d.id)}">
      <td><div class="name-cell"><span class="kind" title="${esc(d.kind || "Bluetooth device")}">${btIcon(d.category)}</span>
        <div style="min-width:0"><div class="truncate"><b>${esc(bleLabel(d))}</b>${isSuspectTracker(d) ? ' <span class="chip warn">Unknown tracker</span>' : d.tracker && d.mine ? ' <span class="chip">Yours</span>' : ""}</div>
        <div class="muted small truncate">${esc(bleDetail(d) || "Advertising, no details")}</div></div></div></td>
      <td class="nowrap">${signalBars(d.rssi)} <span class="small">${d.rssi ?? "—"} dBm</span></td>
      <td class="num">${fmtDist(d.distance_m)}</td>
      <td title="${esc(fullTime(d.first_seen))}">${esc(ago(d.first_seen))}</td>
      <td class="nowrap"><button class="btn small" data-locate="${esc(d.id)}">Locate</button>${d.tracker ? ` <button class="btn small" data-mine="${esc(d.id)}" data-on="${d.mine ? "0" : "1"}">${d.mine ? "Not mine" : "Mine"}</button>` : ""}</td>
    </tr>`).join("");
  const empty = $("#nearby-empty");
  empty.hidden = list.length > 0;
  empty.textContent = state.bt?.scan_state === "scanning"
    ? (all.length ? "Nothing matches." : "Listening… devices appear as they advertise.")
    : "Start listening to see nearby Bluetooth devices.";
}

function renderBluetooth() {
  renderSpam();
  renderBtStatus();
  renderBtMap();
  renderToday();
  renderNearby();
  renderPaired();
  renderBtDrawer();
}

// ------------------------------------------------------------------ locate mode

let beepTimer = null;
let audioCtx = null;

function openLocate(id) {
  const d = (state.bt?.nearby || []).find((x) => x.id === id);
  state.locate = { id, samples: d?.rssi != null ? [{ ts: Date.now(), rssi: d.rssi }] : [], ema: d?.rssi ?? null, history: [], beep: false };
  $("#locate").hidden = false;
  invoke("set_ble_locate", { id });
  renderLocate();
}

function closeLocate() {
  if (!state.locate) return;
  state.locate = null;
  $("#locate").hidden = true;
  clearTimeout(beepTimer);
  invoke("set_ble_locate", { id: null });
}

function locateSample(rssi, ts) {
  const L = state.locate;
  if (!L) return;
  L.samples.push({ ts, rssi });
  const cutoff = ts - 60_000;
  while (L.samples.length && L.samples[0].ts < cutoff) L.samples.shift();
  // Signal strength jumps around; smooth it so the trend means something.
  L.ema = L.ema == null ? rssi : L.ema * 0.7 + rssi * 0.3;
  L.history.push({ ts, ema: L.ema });
  while (L.history.length && L.history[0].ts < ts - 10_000) L.history.shift();
}

function locateTrend() {
  const h = state.locate?.history || [];
  if (h.length < 4) return ["Listening…", ""];
  const now = h[h.length - 1];
  const past = h.find((p) => p.ts >= now.ts - 4000) || h[0];
  const diff = now.ema - past.ema;
  if (diff > 2) return ["Warmer, getting closer", "good"];
  if (diff < -2) return ["Colder, moving away", "bad"];
  return ["Steady", ""];
}

function renderLocate() {
  const L = state.locate;
  if (!L) return;
  const d = (state.bt?.nearby || []).find((x) => x.id === L.id);
  $("#locate-title").textContent = d ? bleLabel(d) : "Device";
  const ema = L.ema;
  const pct = ema == null ? 0 : Math.max(2, Math.min(100, ((ema + 100) / 65) * 100));
  const [trend, tone] = locateTrend();
  const dist = ema == null ? null : bluetoothDistance(ema, d?.tx_power);
  $("#locate-body").innerHTML = `
    <div class="loc-big">${ema == null ? "—" : Math.round(ema)}<span> dBm</span></div>
    <div class="loc-sub">${ema == null ? "Waiting for a signal…" : `${fmtDist(dist)} away (rough)`}</div>
    <div class="loc-trend ${tone}">${esc(trend)}</div>
    <div class="meter loc-meter"><i style="width:${pct.toFixed(1)}%"></i></div>
    <div class="chart short" id="locate-chart"></div>
    <p class="muted small">Walk slowly and watch the number. It rises (towards −40) as you get closer. Hold the laptop still for a second or two at each spot; bodies and walls make the signal jumpy. ${d ? esc(bleDetail(d)) : ""}</p>`;
  $("#locate-beep").textContent = L.beep ? "Beeps on" : "Beeps off";
  $("#locate-beep").classList.toggle("primary", L.beep);
  const now = Date.now();
  lineChart($("#locate-chart"), {
    points: L.samples.map((s) => ({ ts: s.ts, rssi: s.rssi + 100 })),
    series: [{ key: "rssi", label: "Signal", cls: "s1" }],
    span: 60_000,
    now,
    fmt: (v) => `${Math.round(v - 100)} dBm`,
    minTop: 70,
    ticks: timeTicks(now, 60_000, 4, (ms) => `-${Math.round(ms / 1000)}s`),
    emptyMsg: L.samples.length < 2 ? "Collecting signal readings…" : null,
    aria: "Signal strength over the last minute",
  });
}

// Same path-loss guess the backend uses (bluetooth.rs `distance_m`).
function bluetoothDistance(rssi, tx) {
  const at1m = tx != null ? tx - 41 : -59;
  return Math.min(100, Math.max(0.1, Math.pow(10, (at1m - rssi) / 22)));
}

function beepLoop() {
  const L = state.locate;
  if (!L || !L.beep) return;
  try {
    audioCtx ||= new AudioContext();
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    const strength = L.ema == null ? 0 : Math.max(0, Math.min(1, (L.ema + 100) / 60));
    o.frequency.value = 330 + strength * 660;
    g.gain.setValueAtTime(0.12, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.12);
    o.connect(g).connect(audioCtx.destination);
    o.start();
    o.stop(audioCtx.currentTime + 0.13);
    // Faster beeps the closer it is.
    beepTimer = setTimeout(beepLoop, 1400 - strength * 1250);
  } catch {
    L.beep = false;
  }
}

function toggleBeep() {
  const L = state.locate;
  if (!L) return;
  L.beep = !L.beep;
  clearTimeout(beepTimer);
  if (L.beep) beepLoop();
  renderLocate();
}

function renderSpam() {
  const s = state.bt?.spam;
  const el = $("#spam-banner");
  const recent = s && Date.now() - s.ts < 15 * 60_000;
  el.hidden = !recent;
  if (recent) {
    el.innerHTML = `<div class="grow"><b>Bluetooth pop-up spam detected at ${hhmm(s.ts)}.</b> ${s.devices} fake "${esc(s.kind)}" devices appeared within 10 seconds. Someone nearby is running a spam tool. It can't pair with your devices; just decline any unexpected pairing prompts.</div>`;
  }
}

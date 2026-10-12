"use strict";
// Network map, Wi-Fi channel analyzer, long-term history and the privacy
// (VPN / DNS leak) check. Shares helpers and `state` with app.js, which
// loads after this file.

// ------------------------------------------------------------------ network map

// An ICONS svg string, positioned inside a parent SVG.
const placeIcon = (svg, x, y, size) => svg.replace("<svg ", `<svg x="${x - size / 2}" y="${y - size / 2}" width="${size}" height="${size}" `);

function renderMap() {
  const el = $("#netmap");
  const W = Math.max(640, el.clientWidth || 900);
  const devices = state.devices.filter((d) => !d.is_gateway);
  const gw = state.devices.find((d) => d.is_gateway);
  const n = devices.length;
  const rings = n > 16 ? 2 : 1;
  const H = rings === 2 ? 640 : 540;
  const cx = W / 2;
  const cy = H / 2 + 34;
  const R1 = Math.min(W * 0.36, H * 0.34);
  // Group similar devices next to each other around the ring.
  const order = ["computer", "phone", "media", "speaker", "home", "printer", "storage", "device"];
  const sorted = [...devices].sort((a, b) => (b.is_self - a.is_self) || order.indexOf(deviceKind(a)[0]) - order.indexOf(deviceKind(b)[0]) || ipNum(a.ip) - ipNum(b.ip));
  const h = state.health[state.health.length - 1];
  let links = "";
  let nodes = "";
  // Internet above the router.
  const iy = 52;
  const inetDown = !!state.outage;
  links += `<line class="map-link ${inetDown ? "down" : "up"}" x1="${cx}" y1="${iy + 22}" x2="${cx}" y2="${cy - 30}"/>`;
  links += `<text class="map-link-label" x="${cx + 10}" y="${(iy + cy) / 2}">${inetDown ? "Down" : h?.internet_ms != null ? fmtMs(h.internet_ms) : ""}</text>`;
  nodes += `<g class="map-node inet" data-tip="${esc(`Internet${state.publicInfo?.org ? ` · ${state.publicInfo.org.replace(/^AS\d+\s+/, "")}` : ""}`)}">
    <circle cx="${cx}" cy="${iy}" r="22"/>${placeIcon(TILE_ICONS.globe, cx, iy, 20)}
    <text class="map-label strong" x="${cx - 32}" y="${iy + 5}" text-anchor="end">Internet</text></g>`;
  sorted.forEach((d, i) => {
    const ring = rings === 2 && i % 2 === 1 ? 2 : 1;
    const R = ring === 2 ? R1 * 1.32 : R1 * (rings === 2 ? 0.82 : 1);
    const a = -Math.PI / 2 + (i / Math.max(1, n)) * Math.PI * 2 + Math.PI / Math.max(1, n);
    const x = cx + Math.cos(a) * R;
    const y = cy + Math.sin(a) * R * 0.78;
    const st = presenceDot(d);
    links += `<line class="map-link ${st === "off" ? "off" : "up"}" x1="${cx}" y1="${cy}" x2="${x}" y2="${y}"/>`;
    const [kind, kindLabel] = deviceKind(d);
    const name = deviceName(d);
    const tip = [name, d.ip, kindLabel, presenceWord(d), d.rtt_ms != null && d.online && !isAsleep(d) ? fmtMs(d.rtt_ms) : null].filter(Boolean).join(" · ");
    const below = Math.sin(a) > -0.2;
    nodes += `<g class="map-node ${st}${d.is_self ? " self" : ""}" data-mac="${esc(d.mac)}" data-tip="${esc(tip)}">
      <circle cx="${x}" cy="${y}" r="20"/>${placeIcon(ICONS[kind], x, y, 17)}
      <circle class="map-status ${st}" cx="${x + 14}" cy="${y - 14}" r="5"/>
      <text class="map-label" x="${x}" y="${below ? y + 36 : y - 28}" text-anchor="middle">${esc(name.length > 20 ? name.slice(0, 19) + "…" : name)}</text>
      <text class="map-sub" x="${x}" y="${below ? y + 50 : y - 42}" text-anchor="middle">${esc(d.is_self ? "This computer" : d.ip)}</text></g>`;
  });
  const gwName = gw ? (state.router?.identity?.model ? `${state.router.identity.manufacturer || ""} ${state.router.identity.model}`.trim() : deviceName(gw)) : "Router";
  nodes += `<g class="map-node router"${gw ? ` data-mac="${esc(gw.mac)}"` : ""} data-tip="${esc(`${gwName} · ${state.net?.gateway_ip || ""}${state.mifi ? ` · ${state.mifi.generation}` : ""}`)}">
    <circle cx="${cx}" cy="${cy}" r="30"/>${placeIcon(ICONS.router, cx, cy, 24)}
    <text class="map-label strong" x="${cx}" y="${cy + 48}" text-anchor="middle">${esc(gwName)}</text>
    <text class="map-sub" x="${cx}" y="${cy + 62}" text-anchor="middle">${esc(state.net?.gateway_ip || "")}${state.mifi ? ` · ${esc(state.mifi.generation)}` : ""}</text></g>`;
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Map of the devices on your network">${links}${nodes}</svg>`;
  const on = devices.filter((d) => d.online && !isAsleep(d)).length;
  const asleep = devices.filter(isAsleep).length;
  $("#map-legend").innerHTML = `
    <span class="key"><i class="dot good"></i>Online <b>${on}</b></span>
    <span class="key"><i class="dot idle"></i>Asleep <b>${asleep}</b></span>
    <span class="key"><i class="dot off"></i>Offline <b>${devices.length - on - asleep}</b></span>`;
}

// ------------------------------------------------------------------ Wi-Fi analyzer

function channelScore(ch, others) {
  // How much nearby signal overlaps a 2.4 GHz channel (channels 5 apart don't overlap).
  return others.reduce((sum, x) => {
    if (x.band !== "2.4 GHz" || x.channel == null || x.rssi == null) return sum;
    const d = Math.abs(x.channel - ch);
    return d >= 5 ? sum : sum + (1 - d / 5) * Math.max(0, x.rssi + 100);
  }, 0);
}

function wifiChart(el, nets, band, mine) {
  const W = el.clientWidth || 800;
  const H = el.clientHeight || 250;
  const pad = { l: 46, r: 14, t: 14, b: 26 };
  const [lo, hi, ticks] = band === "2.4 GHz"
    ? [-1, 15, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]]
    : [30, 169, [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165]];
  const x = (ch) => pad.l + ((ch - lo) / (hi - lo)) * (W - pad.l - pad.r);
  const y = (dbm) => pad.t + (1 - (Math.max(-100, Math.min(-20, dbm)) + 100) / 80) * (H - pad.t - pad.b);
  const list = nets.filter((n) => n.band === band && n.channel != null && n.rssi != null);
  if (!list.length) {
    el.innerHTML = `<div class="empty">No ${band} networks in range${band === "5 GHz" ? " (or this Mac's last scan didn't include 5 GHz)" : ""}.</div>`;
    return;
  }
  let grid = "";
  for (const dbm of [-90, -80, -70, -60, -50, -40, -30]) {
    grid += `<line class="gridline" x1="${pad.l}" x2="${W - pad.r}" y1="${y(dbm)}" y2="${y(dbm)}"/><text class="axis-label" x="${pad.l - 6}" y="${y(dbm) + 4}" text-anchor="end">${dbm}</text>`;
  }
  for (const c of ticks) grid += `<text class="axis-label" x="${x(c)}" y="${H - 6}" text-anchor="middle">${c}</text>`;
  const halfWidth = (n) => (parseInt(n.width) || 20) / 10; // 20 MHz ≈ ±2 channel numbers
  // Strongest last so it draws on top; yours always on top.
  const drawn = [...list].sort((a, b) => (a === mine) - (b === mine) || a.rssi - b.rssi);
  const hills = drawn.map((n) => {
    const hw = halfWidth(n);
    const x0 = x(n.channel - hw), x1 = x(n.channel + hw), xm = x(n.channel);
    const base = y(-100), top = y(n.rssi);
    const k = (x1 - x0) * 0.18;
    const d = `M${x0},${base} C${x0 + k},${base} ${x0 + k},${top} ${x0 + 2 * k},${top} L${x1 - 2 * k},${top} C${x1 - k},${top} ${x1 - k},${base} ${x1},${base} Z`;
    const label = n === mine ? (mine.ssid || state.mifi?.ssid || "Your Wi-Fi") : n.ssid || "Hidden";
    return `<path class="hill ${n === mine ? "mine" : ""}" d="${d}" data-tip="${esc(`${label} · channel ${n.channel} · ${n.width || "20 MHz"} · ${n.rssi} dBm${n.security ? ` · ${n.security}` : ""}`)}"/>` +
      (n === mine || n.rssi > -75 ? `<text class="hill-label ${n === mine ? "mine" : ""}" x="${xm}" y="${top - 6}" text-anchor="middle">${esc(label)}</text>` : "");
  }).join("");
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(band)} Wi-Fi networks by channel and signal">${grid}${hills}
    <text class="axis-label" x="${pad.l}" y="${pad.t - 2}">dBm</text></svg>`;
}

function renderWifiAnalyzer() {
  const w = state.wifi;
  if (!w) {
    $("#wifi-tiles").innerHTML = "";
    $("#wifi24-chart").innerHTML = `<div class="empty">${/Mac/.test(navigator.userAgent) ? "Waiting for this Mac's Wi-Fi details (they refresh every minute)…" : "The Wi-Fi analyzer needs macOS."}</div>`;
    $("#wifi5-chart").innerHTML = "";
    $("#wifi-advice").innerHTML = "";
    return;
  }
  const c = w.current;
  const others = nearbyOthers(w);
  const mine = { ...c, mine: true };
  const nets = [...others, mine];
  const scores = [1, 6, 11].map((ch) => ({ ch, score: channelScore(ch, others) }));
  const best = scores.reduce((a, b) => (b.score < a.score ? b : a));
  const myScore = c.band === "2.4 GHz" && c.channel ? channelScore(c.channel, others) : null;
  const overlapping = others.filter((x) => overlaps(x, c)).length;
  $("#wifi-tiles").innerHTML = `
    <div class="tile"><div class="label">Your channel</div>${tileIcon("wifi")}<div class="value">${c.channel ?? "—"}</div><div class="sub">${esc([c.band, c.width].filter(Boolean).join(" · "))}</div></div>
    <div class="tile"><div class="label">Networks nearby</div>${tileIcon("router", "violet")}<div class="value">${others.length}</div><div class="sub">${overlapping} overlap your channel</div></div>
    <div class="tile"><div class="label">Best 2.4 GHz channel</div>${tileIcon("latency", "green")}<div class="value">${best.ch}</div><div class="sub">${c.band === "2.4 GHz" && c.channel === best.ch ? "You're already on it" : "Least crowded of 1, 6 and 11"}</div></div>
    <div class="tile"><div class="label">Signal</div>${tileIcon("wifi", signalQuality(c.rssi)?.[1] === "good" ? "green" : "amber")}<div class="value">${c.rssi ?? "—"}<span class="unit"> dBm</span></div><div class="sub">${signalQuality(c.rssi)?.[0] || ""}${c.noise != null && c.rssi != null ? ` · ${c.rssi - c.noise} dB above noise` : ""}</div></div>`;
  wifiChart($("#wifi24-chart"), nets, "2.4 GHz", mine);
  wifiChart($("#wifi5-chart"), nets, "5 GHz", mine);
  $("#wifi24-legend").innerHTML = '<span class="key"><i class="rk mine"></i>Your network</span><span class="key"><i class="rk other"></i>Others</span>';
  const tips = [];
  if (c.band === "2.4 GHz") {
    if (c.channel === best.ch || (myScore != null && myScore <= best.score * 1.1)) {
      tips.push(`Channel ${c.channel} is as good as it gets on 2.4 GHz right now.`);
    } else {
      tips.push(`Switching your router from channel ${c.channel} to channel ${best.ch} would put you on the least crowded part of the 2.4 GHz band. Set it in the router's Wi-Fi settings (you'll usually need to reconnect afterwards).`);
    }
    tips.push("On 2.4 GHz only channels 1, 6 and 11 don't overlap each other, so routers set to anything in between interfere with two neighbours at once.");
    tips.push("If your router supports 5 GHz, it has far more room and is usually much faster at short range.");
  } else {
    tips.push("You're on 5 GHz, which has many more non-overlapping channels than 2.4 GHz.");
  }
  $("#wifi-advice").innerHTML = `<div class="panel-head"><h2>Recommendation</h2></div>${tips.map((t) => `<p>${esc(t)}</p>`).join("")}
    <p class="muted small">Based on this Mac's last Wi-Fi scan (refreshed every minute).${c.ssid || others.some((x) => x.ssid) ? "" : " macOS hides network names unless NetWatch has Location access."}</p>
    ${c.ssid || others.some((x) => x.ssid) ? "" : locationNote()}`;
}

// ------------------------------------------------------------------ history

async function loadHistory() {
  try {
    state.historyData = await invoke("get_history", { range: state.histRange });
  } catch {
    state.historyData = [];
  }
  state.historyLoaded = Date.now();
  if (state.view === "history") render();
}

function renderHistory() {
  if (!state.historyLoaded || Date.now() - state.historyLoaded > 60_000 || state.historyFor !== state.histRange) {
    state.historyFor = state.histRange;
    loadHistory();
  }
  const span = { "24h": 86_400_000, "7d": 7 * 86_400_000, "30d": 30 * 86_400_000 }[state.histRange];
  const step = { "24h": 5 * 60_000, "7d": 30 * 60_000, "30d": 2 * 3_600_000 }[state.histRange];
  const now = Date.now();
  // Break lines where NetWatch wasn't running.
  const pts = [];
  for (const p of state.historyData || []) {
    const prev = pts[pts.length - 1];
    if (prev && p.t - prev.ts > step * 2.5) pts.push({ ts: prev.ts + step, inet: null, gw: null, loss: null, rx: null, tx: null });
    pts.push({ ts: p.t + step / 2, inet: p.inet_ms, gw: p.gateway_ms, loss: p.loss, rx: p.rx_bps, tx: p.tx_bps, rxb: p.rx, txb: p.tx });
  }
  const real = (state.historyData || []);
  const checks = real.filter((p) => p.loss != null);
  const uptime = checks.length ? 100 - checks.reduce((a, p) => a + p.loss, 0) / checks.length : null;
  const lat = real.filter((p) => p.inet_ms != null);
  const avgLat = lat.length ? lat.reduce((a, p) => a + p.inet_ms, 0) / lat.length : null;
  const outs = state.outages.filter((o) => o.start >= now - span);
  const downMs = outs.reduce((a, o) => a + ((o.end || now) - o.start), 0);
  const bytes = real.reduce((a, p) => a + p.rx + p.tx, 0);
  const label = { "24h": "24 hours", "7d": "7 days", "30d": "30 days" }[state.histRange];
  $("#hist-tiles").innerHTML = `
    <div class="tile"><div class="label">Uptime</div>${tileIcon("latency", uptime != null && uptime < 99 ? "amber" : "green")}<div class="value">${uptime != null ? `${uptime.toFixed(uptime >= 99.95 ? 0 : 2)}%` : "—"}</div><div class="sub">internet reachable, last ${label}</div></div>
    <div class="tile"><div class="label">Average latency</div>${tileIcon("latency", "violet")}<div class="value">${avgLat != null ? fmtMs(avgLat) : "—"}</div><div class="sub">to 1.1.1.1 / 8.8.8.8</div></div>
    <div class="tile"><div class="label">Outages</div>${tileIcon("alerts", outs.length ? "red" : "green")}<div class="value">${outs.length}</div><div class="sub">${outs.length ? `${fmtDuration(downMs / 1000)} offline in total` : "none recorded"}</div></div>
    <div class="tile"><div class="label">Data used</div>${tileIcon("data", "green")}<div class="value">${state.router?.counters ? fmtBytes(bytes) : "—"}</div><div class="sub">${state.router?.counters ? "whole network, from your router" : "needs router counters"}</div></div>`;
  const first = real[0]?.t;
  $("#hist-note").textContent = first ? `Recording since ${new Date(first).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}` : "";
  const ticksFor = (n) => timeTicks(now, span, n, (ms) => state.histRange === "24h" ? `-${Math.round(ms / 3_600_000)}h` : `-${Math.round(ms / 86_400_000)}d`);
  const bands = state.outages.map((o) => ({ start: o.start, end: o.end, label: o.kind === "router" ? "Router unreachable" : "Internet down" }));
  const empty = real.length < 2 ? "Collecting history… points appear every 5 minutes." : null;
  $("#hist-lat-legend").innerHTML = legend([{ cls: "s1", label: "Internet (average)" }, { cls: "s2", label: "Router" }]);
  lineChart($("#hist-lat-chart"), {
    points: pts, series: [{ key: "inet", label: "Internet", cls: "s1" }, { key: "gw", label: "Router", cls: "s2" }],
    span, now, fmt: (v) => `${Math.round(v)} ms`, minTop: 50, ticks: ticksFor(6), bands, emptyMsg: empty,
    aria: "Average latency over time",
  });
  lineChart($("#hist-loss-chart"), {
    points: pts, series: [{ key: "loss", label: "Packet loss", cls: "s2" }],
    span, now, fmt: (v) => `${Math.round(v)}%`, minTop: 5, ticks: ticksFor(6), bands, emptyMsg: empty,
    aria: "Packet loss over time",
  });
  $("#hist-tp-legend").innerHTML = legend([{ cls: "s1", label: "Download" }, { cls: "s2", label: "Upload" }]);
  lineChart($("#hist-tp-chart"), {
    points: pts, series: [{ key: "rx", label: "Download", cls: "s1" }, { key: "tx", label: "Upload", cls: "s2" }],
    span, now, fmt: fmtBits, minTop: 8000, ticks: ticksFor(6),
    emptyMsg: !state.router?.counters ? "Your router doesn't report traffic counters." : empty,
    aria: "Average whole-network throughput over time",
  });
  renderHistSpeed(span, now, ticksFor(6));
}

// Saved speed tests (the last 50) over the selected range, and the newest few
// of them in a table whatever the range.
function renderHistSpeed(span, now, ticks) {
  const tests = state.speedtests.filter((t) => t.ts >= now - span);
  $("#hist-sp-legend").innerHTML = legend([{ cls: "s1", label: "Download" }, { cls: "s2", label: "Upload" }]);
  const empty = tests.length >= 2 ? null
    : `${tests.length ? "Only one speed test" : "No speed tests"} in this range${state.histRange === "30d" ? "" : " · try a longer one"}`;
  // Mb/s as b/s, so the axis reads with fmtBits like the other charts.
  const pts = tests.map((t) => ({ ts: t.ts, down: t.down_mbps * 1e6, up: t.up_mbps * 1e6, lat: t.latency_ms }));
  lineChart($("#hist-sp-chart"), {
    points: pts, series: [{ key: "down", label: "Download", cls: "s1" }, { key: "up", label: "Upload", cls: "s2" }],
    span, now, fmt: fmtBits, minTop: 5e6, ticks, emptyMsg: empty,
    aria: "Speed test download and upload speeds over time",
  });
  lineChart($("#hist-spl-chart"), {
    points: pts, series: [{ key: "lat", label: "Latency", cls: "s1" }],
    span, now, fmt: (v) => `${Math.round(v)} ms`, minTop: 50, ticks, emptyMsg: empty,
    aria: "Speed test latency over time",
  });
  const recent = [...state.speedtests].reverse().slice(0, 8);
  $("#hist-sp-table").innerHTML = recent.length
    ? `<table class="table compact"><thead><tr><th>When</th><th class="num">Download</th><th class="num">Upload</th><th class="num">Latency</th><th class="num">Data used</th></tr></thead><tbody>
      ${recent.map((r) => speedRow(r, `${shortDate(r.ts)} ${hhmm(r.ts)}`)).join("")}</tbody></table>`
    : '<p class="muted small">No speed tests yet. Run one on the Connection page, or schedule them in Settings → Data allowance.</p>';
}

// ------------------------------------------------------------------ privacy check

async function runLeakTest() {
  state.leak = { running: true };
  render();
  try {
    state.leak = { result: await invoke("run_leak_test") };
  } catch (e) {
    state.leak = { error: String(e) };
  }
  render();
}

function renderLeak() {
  const L = state.leak || {};
  const vpn = L.result?.vpn || state.vpn;
  const r = L.result;
  let verdict = "";
  if (r) {
    const orgs = [...new Set(r.resolvers.map((x) => x.org).filter(Boolean))];
    verdict = vpn?.active
      ? r.leak
        ? `<div class="banner bad-banner"><div class="grow"><b>DNS is leaking.</b> You're on a VPN, but your lookups are answered by your own provider (${esc(r.public?.org || "")}), so it can see the sites you visit. Turn on your VPN's DNS protection.</div></div>`
        : `<div class="banner flat"><div class="grow"><span class="dot good"></span><b>No leak found.</b> Your lookups go through ${esc(orgs.join(", ") || "the VPN")}, not your own provider.</div></div>`
      : `<div class="banner flat"><div class="grow"><span class="dot off"></span>You're not on a VPN, so this is just who answers your lookups: <b>${esc(orgs.join(", ") || "unknown")}</b>.</div></div>`;
  }
  $("#leak-box").innerHTML = `
    <dl class="facts compact">
      <dt>VPN</dt><dd>${vpn ? (vpn.active ? `<span class="chip">On</span> via <span class="mono">${esc(vpn.interface)}</span>` : vpn.tunnels.length ? `Not routing traffic <span class="muted small">· tunnels: ${esc(vpn.tunnels.join(", "))}</span>` : "Off") : "Checking…"}</dd>
      ${r?.public ? `<dt>Seen from outside as</dt><dd><span class="mono">${esc(r.public.ip)}</span> <span class="muted small">· ${esc([r.public.org, r.public.country].filter(Boolean).join(" · "))}</span></dd>` : ""}
    </dl>
    ${verdict}
    ${r?.resolvers?.length ? `<table class="table compact" style="margin-top:10px"><thead><tr><th>DNS resolver</th><th>Operator</th><th>Country</th></tr></thead><tbody>${r.resolvers.map((x) => `<tr><td class="mono">${esc(x.ip)}</td><td>${esc(x.org || "—")}</td><td>${esc(x.country || "—")}</td></tr>`).join("")}</tbody></table>` : ""}
    <div class="row" style="margin-top:12px">
      <button class="btn" data-action="leak-test" ${L.running ? "disabled" : ""}>${L.running ? "Testing…" : r ? "Test again" : "Run DNS leak test"}</button>
      <span class="muted small">${L.error ? esc(L.error) : "Looks up 10 unique names and asks bash.ws which resolvers fetched them."}</span>
    </div>`;
}

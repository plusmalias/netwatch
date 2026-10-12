"use strict";
// The Network page: connection quality, household data usage, the router,
// the internet side, Wi-Fi and the outage log. Shares helpers and `state`
// with app.js, which loads after this file.

const DAY_MS = 86_400_000;

function dayStart(ts) {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function addDays(ts, n) {
  const d = new Date(ts);
  d.setDate(d.getDate() + n);
  return d.getTime();
}

function usageTotal(since, until = Infinity) {
  let n = 0;
  for (const [h, [rx, tx]] of state.usage) if (h >= since && h < until) n += rx + tx;
  return n;
}

function usageSplit(since, until) {
  const out = [0, 0];
  for (const [h, [rx, tx]] of state.usage) if (h >= since && h < until) { out[0] += rx; out[1] += tx; }
  return out;
}

// Local midnight on the day the data allowance renews.
function cycleStartMs(day) {
  const now = new Date();
  let y = now.getFullYear();
  let m = now.getMonth();
  if (now.getDate() < day) {
    m -= 1;
    if (m < 0) { m = 11; y -= 1; }
  }
  return new Date(y, m, day).getTime();
}

const trackingSince = () => (state.usage.size ? Math.min(...state.usage.keys()) : null);

function cycleSummary() {
  const s = state.settings;
  const start = cycleStartMs(s?.cycle_day || 1);
  const used = usageTotal(start);
  const first = trackingSince();
  const since = first && first > start ? `since ${shortDate(first)}` : s?.cycle_day > 1 ? `since ${shortDate(start)}` : "this month";
  return s?.data_cap_gb ? `${fmtBytes(used)} of ${s.data_cap_gb} GB ${since}` : `${fmtBytes(used)} ${since}`;
}

// Where this billing cycle's data use is heading, from the monitor's forecast
// (usage::forecast). Null without an allowance, router counters or a current
// forecast. `f.projected` is null until two complete days have been recorded.
function forecastInfo() {
  const f = state.forecast;
  const capGb = state.settings?.data_cap_gb;
  if (!f || !capGb || !state.router?.counters || Math.abs(f.cap - capGb * 1e9) > 1000) return null;
  if (f.projected == null) return { f, level: "off", text: "Forecast after 2 days of data", delta: "" };
  const over = f.projected - f.cap;
  const level = over > 0 ? "bad" : f.projected >= f.cap * 0.9 ? "warn" : "good";
  return {
    f,
    level,
    // The cycle's last day is the one before the next begins.
    text: `On track for ${fmtBytes(f.projected)} of ${fmtBytes(f.cap)} by ${shortDate(f.cycle_end - 1)}`,
    delta: over > 0 ? `${fmtBytes(over)} over` : `${fmtBytes(-over)} to spare`,
  };
}

// A bar scaled to the larger of the allowance and the projection: used so
// far, the projected rest of the cycle, and a tick at the allowance.
function forecastBar({ f, level, text, delta }) {
  const scale = Math.max(f.cap, f.projected, f.used, 1);
  const pct = (v) => Math.min(100, (v / scale) * 100);
  const used = pct(f.used);
  const end = pct(Math.max(f.projected, f.used));
  const tip = `Used ${fmtBytes(f.used)} · projected ${fmtBytes(f.projected)} · allowance ${fmtBytes(f.cap)}`;
  return `<div class="fbar ${level === "good" ? "" : level}" data-tip="${esc(tip)}" role="img" aria-label="${esc(`${text}. ${delta}.`)}">
    <i class="used" style="width:${used.toFixed(1)}%"></i><i class="proj" style="left:${used.toFixed(1)}%;width:${(end - used).toFixed(1)}%"></i><b class="cap" style="left:${pct(f.cap).toFixed(1)}%"></b></div>`;
}

function forecastLine(fc) {
  const { f } = fc;
  if (f.projected == null) return `<div class="forecast-line muted small">${esc(fc.text)}</div>`;
  const chip = fc.level === "bad" ? "chip bad" : fc.level === "warn" ? "chip warn" : "chip";
  return `<div class="forecast-line small"><span class="dot ${fc.level}"></span><b>${esc(fc.text)}</b> <span class="${chip}">${esc(fc.delta)}</span>
    <span class="muted">· a typical day is ${esc(fmtBytes(f.daily))} (median of the last ${f.sample_days} complete days)${f.partial ? " · NetWatch began counting partway through this cycle, so the real total may be higher" : ""}</span></div>`;
}

// "tomorrow around 3:00 am", "Monday 27 Jul around 3:00 am"
function whenLabel(ts) {
  const d0 = dayStart(Date.now());
  const day = ts < addDays(d0, 1) ? "today" : ts < addDays(d0, 2) ? "tomorrow"
    : new Date(ts).toLocaleDateString([], { weekday: "long", day: "numeric", month: "short" });
  return `${day} around ${new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
}

// The note under the scheduled speed test settings: what it does, and what
// each size costs a month on each schedule (the most a test can use).
function speedtestNote(s) {
  const month = (perTest, weekly) => fmtBytes(perTest * (weekly ? 4.3 : 30));
  const costs = `Light tests (up to about 10 MB each) use up to ${month(10e6, false)} a month daily or ${month(10e6, true)} weekly; full tests (up to about 38 MB) up to ${month(38e6, false)} daily or ${month(38e6, true)} weekly. Less on slow links.`;
  if (!s || s.speedtest_schedule === "off") {
    return `Off. Tests only run when you press Run speed test on the Connection page, which always does the full test. ${costs}`;
  }
  const weekly = s.speedtest_schedule === "weekly";
  return `Runs ${weekly ? "on Monday" : "each day"} around 3 am, or at the next chance if this computer was asleep or the internet was down, never during an outage. ${costs} Light tests read a little low on fast connections, so they suit spotting trends. The Run speed test button always does the full test.`;
}

const speedTag = (r) => (r.scheduled ? (r.light ? "Scheduled · light" : "Scheduled") : "");

// One row of a speed test table; `when` is the first cell's text.
function speedRow(r, when) {
  const tag = speedTag(r);
  return `<tr title="${esc(fullTime(r.ts))}${r.server ? ` · server ${esc(r.server)}` : ""}">
    <td>${esc(when)}${tag ? ` <span class="muted small">· ${esc(tag)}</span>` : ""}</td><td class="num"><b>${r.down_mbps}</b> Mb/s</td><td class="num"><b>${r.up_mbps}</b> Mb/s</td>
    <td class="num">${fmtMs(r.latency_ms)}<span class="muted small"> ±${Math.round(r.jitter_ms)}</span></td><td class="num">${fmtBytes(r.bytes_used)}</td></tr>`;
}

function signalQuality(rssi) {
  if (rssi == null) return null;
  if (rssi >= -55) return ["Excellent", "good"];
  if (rssi >= -67) return ["Good", "good"];
  if (rssi >= -75) return ["Fair", "warn"];
  return ["Weak", "bad"];
}

function wifiGeneration(phy) {
  if (!phy) return null;
  if (/be/.test(phy)) return "Wi-Fi 7";
  if (/ax/.test(phy)) return "Wi-Fi 6";
  if (/ac/.test(phy)) return "Wi-Fi 5";
  if (/n/.test(phy)) return "Wi-Fi 4";
  return null;
}

const overlaps = (a, b) =>
  a.band === b.band && a.channel != null && b.channel != null &&
  (a.band === "2.4 GHz" ? Math.abs(a.channel - b.channel) <= 4 : a.channel === b.channel);

// Packet loss to the internet over the samples in the last hour.
function lossPct() {
  const recent = state.health.filter((h) => h.ts >= Date.now() - 3_600_000);
  if (!recent.length) return null;
  return (recent.filter((h) => h.internet_ms == null).length / recent.length) * 100;
}

function routerUptime() {
  const r = state.router;
  if (r?.status?.uptime_s == null || !r.updated) return null;
  return r.status.uptime_s + (Date.now() - r.updated) / 1000;
}

// macOS lists the network you're on among the "other" networks too. With
// names hidden we match it on channel, security, standard and signal.
function nearbyOthers(w) {
  const c = w.current;
  // With BSSIDs (Location permission) the access point we're on is known exactly.
  if (c.bssid) return w.nearby.filter((x) => x.bssid !== c.bssid);
  let dropped = false;
  return w.nearby.filter((x) => {
    const same = !dropped && x.channel === c.channel && x.band === c.band && x.security === c.security &&
      (x.ssid && c.ssid ? x.ssid === c.ssid : x.rssi != null && c.rssi != null && Math.abs(x.rssi - c.rssi) <= 4);
    if (same) dropped = true;
    return !same;
  });
}

// ------------------------------------------------------------------ Location Services

// Turns Location Services on in Settings; macOS then asks for permission.
async function allowLocation() {
  state.location = { ...(state.location || {}), status: "checking" };
  render();
  state.settings = await call("set_settings", { settings: { ...state.settings, location: true } });
  render();
}

// Where Location permission stands, in words, and the button that helps:
// { text, button: { label, action } | null }, or null where it doesn't apply.
function locationHelp() {
  const st = state.location?.status;
  if (!st || st === "unavailable") return null;
  const open = { label: "Open System Settings", action: "location-settings" };
  return {
    off: { text: "Allow Location Services to see network names. NetWatch uses your location only for that and to spot unknown trackers; it never leaves this Mac.", button: { label: "Allow location", action: "allow-location" } },
    checking: { text: "Asking macOS for permission…", button: null },
    not_determined: { text: "Waiting for your answer to the macOS location prompt. If you can't see it, look behind other windows.", button: null },
    denied: { text: "macOS is blocking location for NetWatch. In System Settings → Privacy & Security → Location Services, make sure Location Services is on and switch on NetWatch.", button: open },
    restricted: { text: "A restriction on this Mac (Screen Time or a device profile) blocks location for NetWatch.", button: open },
    allowed: { text: "Location is allowed. Names appear with the next Wi-Fi scan, within a minute.", button: null },
  }[st] || null;
}

// A paragraph for where Wi-Fi names are hidden until Location is allowed.
function locationNote() {
  const h = locationHelp();
  if (!h) return "";
  return `<p class="muted small">${esc(h.text)}${h.button ? ` <button class="btn small" data-action="${h.button.action}">${esc(h.button.label)}</button>` : ""}</p>`;
}

// The Permission line in Settings → Location.
function renderLocationStatus() {
  const st = state.location?.status;
  const h = locationHelp();
  $("#location-status").innerHTML = !st || st === "off" ? '<span class="muted">Off</span>'
    : st === "unavailable" ? '<span class="muted">Location Services need macOS.</span>'
    : st === "allowed" ? `<span class="dot good"></span> Allowed <span class="muted small">${state.location.last_read ? `· position last checked ${esc(ago(state.location.last_read))}, only while an unknown tracker is near` : "· the position is only read while an unknown tracker is near"}</span>`
    : h ? `${esc(h.text)}${h.button ? ` <button class="btn small" data-action="${h.button.action}">${esc(h.button.label)}</button>` : ""}` : "";
}

const outageLabel = (o) => (o.kind === "router" ? "Router unreachable" : "Internet down");

// ------------------------------------------------------------------ sections

function renderNetTiles() {
  const h = state.health[state.health.length - 1];
  const loss = lossPct();
  const q = signalQuality(state.wifi?.current?.rssi);
  const up = routerUptime();
  const p = state.publicInfo;
  const inet = state.outage
    ? `<span class="dot bad"></span> ${esc(outageLabel(state.outage))}`
    : h ? esc(h.internet_ms != null ? fmtMs(h.internet_ms) : "No reply") : "—";
  $("#net-tiles").innerHTML = `
    <div class="tile"><div class="label">Internet latency</div>${tileIcon("latency", state.outage ? "red" : "violet")}<div class="value">${inet}</div>
      <div class="sub">${state.outage ? `since ${hhmm(state.outage.start)}` : loss == null ? "Checking…" : `${loss.toFixed(loss && loss < 1 ? 1 : 0)}% packet loss in the last hour`}</div></div>
    <div class="tile"><div class="label">Router</div>${tileIcon("router")}<div class="value">${h ? esc(fmtMs(h.gateway_ms)) : "—"}</div>
      <div class="sub">${[up != null ? `Up ${fmtDuration(up)}` : state.router?.identity?.model ? esc(state.router.identity.model) : "Latency from this computer", state.mifi?.connected ? esc(state.mifi.generation) : null].filter(Boolean).join(" · ")}</div></div>
    <div class="tile"><div class="label">Wi-Fi signal</div>${tileIcon("wifi", q && q[1] !== "good" ? "amber" : "green")}<div class="value">${state.wifi?.current?.rssi != null ? `${state.wifi.current.rssi} dBm` : "—"}</div>
      <div class="sub">${q ? `<span class="dot ${q[1]}"></span> ${q[0]}${state.wifi.rate_mbps ? ` · ${state.wifi.rate_mbps} Mb/s link` : ""}` : "Not on Wi-Fi"}</div></div>
    <div class="tile"><div class="label">Public IP</div>${tileIcon("globe", "violet")}<div class="value value-sm mono">${p ? esc(p.ip) : "—"}</div>
      <div class="sub truncate">${p?.org ? esc(p.org.replace(/^AS\d+\s+/, "")) : state.settings?.public_ip_lookup === false ? "Lookup turned off" : "Looking up…"}</div></div>`;
}

function renderHealthChart() {
  const el = $("#health-chart");
  const last = state.health[state.health.length - 1];
  $("#health-legend").innerHTML = legend([
    { cls: "s1", label: "Router", value: last ? fmtMs(last.gateway_ms) : null },
    { cls: "s2", label: "Internet", value: last ? fmtMs(last.internet_ms) : null },
  ]);
  const now = Date.now();
  const span = 3_600_000;
  const bands = [...state.outages, ...(state.outage ? [state.outage] : [])].map((o) => ({ start: o.start, end: o.end, label: outageLabel(o) }));
  lineChart(el, {
    points: state.health,
    series: [{ key: "gateway_ms", label: "Router", cls: "s1" }, { key: "internet_ms", label: "Internet", cls: "s2" }],
    span,
    now,
    fmt: (v) => `${Math.round(v)} ms`,
    minTop: 50,
    ticks: timeTicks(now, span, 6, (ms) => `-${Math.round(ms / 60000)}m`),
    bands,
    emptyMsg: !state.healthSupported
      ? "Latency checks need ICMP, which this system doesn't allow without privileges."
      : state.health.length < 2 ? "Measuring… the first readings appear within 20 seconds." : null,
    aria: "Ping time to the router and to the internet over the last hour",
  });
  const loss = lossPct();
  const down = state.outages.filter((o) => o.start >= now - 7 * DAY_MS);
  $("#health-foot").textContent = loss == null ? "" :
    `Packet loss ${loss.toFixed(loss && loss < 1 ? 1 : 0)}% in the last hour · ${down.length ? `${down.length} outage${down.length > 1 ? "s" : ""} in the last 7 days` : "no outages in the last 7 days"}`;
}

function renderUsage() {
  const r = state.router;
  const el = $("#usage-chart");
  if (!r?.counters) {
    $("#usage-summary").innerHTML = "";
    el.innerHTML = `<div class="empty">${!r?.checked ? "Asking your router for its data counters…" : r.upnp
      ? "Your router doesn't report data counters."
      : "Your router doesn't answer UPnP queries, so whole-network data usage isn't available. (Leaving UPnP off is the safer setting.)"}</div>`;
    return;
  }
  const now = Date.now();
  const today = dayStart(now);
  const s = state.settings;
  const cycleStart = cycleStartMs(s?.cycle_day || 1);
  const used = usageTotal(cycleStart);
  const first = trackingSince();
  let meter = "";
  const fc = forecastInfo();
  if (fc?.f.projected != null) {
    meter = forecastBar(fc);
  } else if (s?.data_cap_gb) {
    const pct = (used / (s.data_cap_gb * 1e9)) * 100;
    const level = pct >= 100 ? "bad" : pct >= 80 ? "warn" : "";
    meter = `<div class="meter ${level}" data-tip="${esc(`${pct.toFixed(1)}% of ${s.data_cap_gb} GB`)}"><i style="width:${Math.min(100, pct).toFixed(1)}%"></i></div>`;
  }
  $("#usage-summary").innerHTML = `
    <div class="stat"><span>Today</span><b>${fmtBytes(usageTotal(today))}</b></div>
    <div class="stat"><span>Yesterday</span><b>${fmtBytes(usageTotal(addDays(today, -1), today))}</b></div>
    <div class="stat grow"><span>${s?.data_cap_gb ? "This billing cycle" : "This month"}</span><b>${esc(cycleSummary())}</b>${meter}${fc ? forecastLine(fc) : ""}</div>
    ${first ? `<div class="muted small" style="align-self:end">Tracking since ${esc(shortDate(first))}${s?.data_cap_gb ? "" : ' · <button class="btn link small" data-goto="settings">Set a data allowance</button>'}</div>` : ""}`;

  const series = [{ label: "Download", cls: "s1" }, { label: "Upload", cls: "s2" }];
  if (state.usageView === "hours") {
    const h0 = new Date(); h0.setMinutes(0, 0, 0);
    const cols = Array.from({ length: 24 }, (_, i) => {
      const start = h0.getTime() - (23 - i) * 3_600_000;
      return { label: hhmm(start), tip: `${hhmm(start)}–${hhmm(start + 3_600_000)}`, values: state.usage.get(start) || [0, 0] };
    });
    columnChart(el, { cols, series, fmt: fmtBytes, every: 4, aria: "Data used per hour over the last 24 hours" });
  } else {
    const cols = Array.from({ length: 30 }, (_, i) => {
      const start = addDays(today, i - 29);
      const end = addDays(start, 1);
      return { label: i === 29 ? "Today" : shortDate(start), tip: new Date(start).toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" }), values: usageSplit(start, end) };
    });
    columnChart(el, { cols, series, fmt: fmtBytes, every: 5, aria: "Data used per day over the last 30 days" });
  }
  $("#usage-legend").innerHTML = legend(series);
}

function renderLive() {
  const el = $("#live-chart");
  if (!state.router?.counters) {
    $("#live-panel").hidden = true;
    return;
  }
  $("#live-panel").hidden = false;
  const pts = state.wan.map((w) => ({ ts: w.ts, rx: w.rx_bps, tx: w.tx_bps }));
  const last = pts[pts.length - 1];
  $("#live-legend").innerHTML = legend([
    { cls: "s1", label: "Download", value: fmtBits(last?.rx || 0) },
    { cls: "s2", label: "Upload", value: fmtBits(last?.tx || 0) },
  ]);
  const now = last?.ts || Date.now();
  const span = 10 * 60_000;
  lineChart(el, {
    points: pts,
    series: [{ key: "rx", label: "Download", cls: "s1" }, { key: "tx", label: "Upload", cls: "s2" }],
    span,
    now,
    fmt: fmtBits,
    minTop: 8000,
    ticks: timeTicks(now, span, 5, (ms) => `-${Math.round(ms / 60000)}m`),
    emptyMsg: pts.length < 2 ? "Waiting for the router's first readings…" : null,
    aria: "Whole-network download and upload over the last ten minutes",
  });
}

function renderRouter() {
  const r = state.router;
  const n = state.net;
  const h = state.health[state.health.length - 1];
  const fact = (k, v) => (v ? `<dt>${k}</dt><dd>${v}</dd>` : "");
  const id = r?.identity || {};
  const model = [id.manufacturer, id.model].filter(Boolean).join(" ");
  const st = r?.status || {};
  const up = routerUptime();
  const lease = n?.lease;
  let note = "";
  if (!r?.checked) note = '<p class="muted small">Looking for your router…</p>';
  else if (!r.upnp) note = `<p class="muted small">Your router doesn't answer UPnP queries, so its model, internet address and data usage aren't available. That's also the safer setting.</p>`;
  $("#router-facts").innerHTML = `
    ${fact("Model", model ? `${esc(model)}${id.description ? ` <span class="muted small">· ${esc(id.description)}</span>` : ""}` : "")}
    ${fact("Address", n?.gateway_ip ? `<span class="mono">${esc(n.gateway_ip)}</span>${id.admin_url ? ` · <button class="btn link" data-url="${esc(id.admin_url)}">Open admin page</button>` : ""}` : "")}
    ${fact("Connection", st.connection ? `${esc(st.connection)}${up != null ? ` · up ${fmtDuration(up)}` : ""}` : "")}
    ${fact("Internet address", st.external_ip ? `<span class="mono">${esc(st.external_ip)}</span>${st.cgnat ? ' <span class="chip">Carrier-grade NAT</span><div class="muted small">Your provider shares one public address between many customers, so devices here can\'t be reached directly from the internet.</div>' : ""}` : "")}
    ${fact("Latency", h?.gateway_ms != null ? fmtMs(h.gateway_ms) : "")}
    ${fact("UPnP", r?.upnp ? '<span class="chip warn">On</span> <span class="muted small">Devices can open ports on the router without asking.</span>' : r?.checked ? "Off or not answering" : "")}
    ${fact("DNS servers", n?.dns_servers?.length ? `<span class="mono">${n.dns_servers.map(esc).join(", ")}</span>` : "")}
    ${fact("DHCP lease", lease?.lease_s ? `${fmtDuration(lease.lease_s)}${lease.server ? ` from <span class="mono">${esc(lease.server)}</span>` : ""}${lease.domain ? ` · domain ${esc(lease.domain)}` : ""}` : "")}`;
  $("#router-note").innerHTML = note;

  const maps = r?.mappings;
  const names = new Map(state.devices.map((d) => [d.ip, deviceName(d)]));
  $("#forwards").innerHTML = !r?.upnp ? "" : maps == null
    ? '<p class="muted small">The router doesn\'t list its port forwards.</p>'
    : maps.length
      ? `<table class="table compact"><thead><tr><th>Port</th><th>Forwarded to</th><th>Description</th></tr></thead><tbody>${maps.map((m) => `<tr>
          <td class="mono">${esc(m.protocol)} ${m.external_port}</td>
          <td>${esc(names.get(m.internal_client) || m.internal_client)} <span class="muted small mono">${esc(m.internal_client)}:${m.internal_port}</span></td>
          <td>${esc(m.description || "—")}${m.enabled ? "" : ' <span class="muted small">(disabled)</span>'}</td></tr>`).join("")}</tbody></table>`
      : '<p class="muted small">None. No device has opened a port on your router. NetWatch alerts if one does.</p>';
}

function renderInternet() {
  const p = state.publicInfo;
  const h = state.health[state.health.length - 1];
  const loss = lossPct();
  const fact = (k, v) => (v ? `<dt>${k}</dt><dd>${v}</dd>` : "");
  const lookupOff = state.settings?.public_ip_lookup === false;
  const asn = p?.org?.match(/^AS\d+/)?.[0];
  $("#internet-facts").innerHTML = lookupOff
    ? `<dt>Public IP</dt><dd class="muted">Lookup is turned off in Settings</dd>`
    : `
    ${fact("Public IP", p ? `<span class="mono">${esc(p.ip)}</span> <button class="btn link small" data-action="refresh-public">Refresh</button>` : state.publicError ? `<span class="muted">Couldn't look it up: ${esc(state.publicError)}</span>` : '<span class="muted">Looking up…</span>')}
    ${fact("Provider", p?.org ? `${esc(p.org.replace(/^AS\d+\s+/, ""))}${asn ? ` <span class="muted small">· ${esc(asn)}</span>` : ""}` : "")}
    ${fact("Location", p ? `${esc([p.city, p.region, p.country].filter(Boolean).join(", "))} <span class="muted small">· approximate</span>` : "")}
    ${fact("Latency", h ? `${fmtMs(h.internet_ms)}${loss != null ? ` · ${loss.toFixed(loss && loss < 1 ? 1 : 0)}% loss in the last hour` : ""}` : "")}`;

  const sp = state.speed;
  const phase = { latency: "Measuring latency…", download: "Testing download…", upload: "Testing upload…" }[sp.phase] || "Starting…";
  const st = state.settings;
  const next = state.speedNext;
  const light = st?.speedtest_size === "light";
  const schedule = !st || st.speedtest_schedule === "off"
    ? 'Scheduled tests are off. <button class="btn link small" data-goto="settings">Schedule tests</button>'
    : next == null ? `Scheduled ${esc(st.speedtest_schedule)}`
      : next <= Date.now() ? "A scheduled test is due and will start once the connection is up."
        : `Next scheduled test ${esc(whenLabel(next))} · ${light ? "light, up to about 10 MB" : "full, up to about 38 MB"}`;
  $("#speed-box").innerHTML = `
    <div class="row">
      <button class="btn ${sp.running ? "" : "primary"}" data-action="speed-test" ${sp.running ? "disabled" : ""}>${sp.running ? "Testing…" : "Run speed test"}</button>
      <span class="muted small">${sp.running ? `${esc(phase)}${sp.mbps != null ? ` ${sp.mbps.toFixed(1)} Mb/s` : ""}` : "Uses up to about 38 MB of data, less on slow links. Runs against Cloudflare."}</span>
    </div>
    <div class="muted small" style="margin-top:8px">${schedule}</div>
    ${state.speedtests.length ? `<table class="table compact" style="margin-top:10px"><thead><tr><th>When</th><th class="num">Download</th><th class="num">Upload</th><th class="num">Latency</th><th class="num">Data used</th></tr></thead><tbody>
      ${[...state.speedtests].reverse().slice(0, 6).map((r) => speedRow(r, ago(r.ts))).join("")}
      </tbody></table>` : ""}`;
}

function renderWifi() {
  const w = state.wifi;
  const fact = (k, v) => (v ? `<dt>${k}</dt><dd>${v}</dd>` : "");
  const fw = state.firewall;
  const n = state.net;
  if (!w) {
    $("#wifi-facts").innerHTML = "";
    $("#wifi-note").innerHTML = `<p class="muted small">${/Mac/.test(navigator.userAgent) ? "This computer isn't on Wi-Fi, or the first reading is still coming in." : "Wi-Fi details are available on macOS."}</p>`;
    $("#nearby").innerHTML = "";
  } else {
    const c = w.current;
    const q = signalQuality(c.rssi);
    const snr = c.rssi != null && c.noise != null ? c.rssi - c.noise : null;
    const pct = c.rssi != null ? Math.max(4, Math.min(100, ((c.rssi + 90) / 60) * 100)) : 0;
    const weak = /^(Open|WEP|WPA Personal|WPA\/WPA2)/.test(c.security || "");
    const others = nearbyOthers(w);
    const neighbors = others.filter((x) => overlaps(x, c));
    const gen = wifiGeneration(c.phy);
    $("#wifi-facts").innerHTML = `
      ${fact("Network", c.ssid ? esc(c.ssid) : state.mifi?.ssid ? `${esc(state.mifi.ssid)} <span class="muted small">· from your hotspot</span>` : '<span class="muted">Name hidden by macOS</span> <span class="muted small">· apps need Location access to see it</span>')}
      ${fact("Access point", c.bssid ? `<span class="mono">${esc(c.bssid)}</span>` : "")}
      ${fact("Signal", c.rssi != null ? `${c.rssi} dBm · ${q[0]}${snr != null ? ` <span class="muted small">· ${snr} dB above noise</span>` : ""}<div class="meter ${q[1] === "good" ? "" : q[1]}" style="margin-top:6px"><i style="width:${pct}%"></i></div>` : "")}
      ${fact("Channel", c.channel != null ? `${c.channel}${c.band ? ` · ${esc(c.band)}` : ""}${c.width ? ` · ${esc(c.width)} wide` : ""}` : "")}
      ${fact("Standard", c.phy ? `${esc(c.phy)}${gen ? ` (${gen})` : ""}${w.rate_mbps ? ` · ${w.rate_mbps} Mb/s link` : ""}` : "")}
      ${fact("Security", c.security ? `${esc(c.security)}${weak ? ' <span class="chip warn">Outdated</span>' : ""}` : "")}
      ${fact("Nearby", `${others.length} other network${others.length === 1 ? "" : "s"}${neighbors.length ? ` · <b>${neighbors.length}</b> on an overlapping channel` : " · none on your channel"}`)}`;
    const tips = [];
    if (c.band === "2.4 GHz" && (w.rate_mbps || 0) < 200) tips.push("You're connected on 2.4 GHz. If the router also offers 5 GHz, that band is usually much faster at short range.");
    if (neighbors.length >= 3) tips.push(`${neighbors.length} nearby networks share or overlap channel ${c.channel}. On 2.4 GHz, channels 1, 6 and 11 don't overlap each other; picking the least crowded one in the router's settings can help.`);
    $("#wifi-note").innerHTML = tips.map((t) => `<p class="muted small">${esc(t)}</p>`).join("") + (c.ssid ? "" : locationNote());
    const rows = [...others].sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999)).slice(0, 8);
    $("#nearby").innerHTML = rows.length ? `<table class="table compact"><thead><tr><th>Nearby network</th><th>Channel</th><th class="num">Signal</th><th>Security</th></tr></thead><tbody>
      ${rows.map((x) => `<tr title="${esc(x.bssid || "")}"><td>${x.ssid ? esc(x.ssid) : '<span class="muted">Hidden name</span>'}${overlaps(x, c) ? ' <span class="chip">Overlaps yours</span>' : ""}</td>
        <td class="nowrap">${x.channel ?? "—"} <span class="muted small">${esc(x.band || "")}</span></td><td class="num">${x.rssi ?? "—"} dBm</td><td class="small">${esc(x.security || "—")}</td></tr>`).join("")}
      </tbody></table>` : "";
  }
  $("#this-computer").innerHTML = `
    ${fact("Interface", n ? `${esc(n.interface)} · <span class="mono">${esc(n.ip)}/${n.prefix}</span>` : "")}
    ${fact("MAC address", n?.mac ? `<span class="mono">${esc(n.mac)}</span>${isRandomMac(n.mac) ? ' <span class="muted small">· private Wi-Fi address</span>' : ""}` : "")}
    ${fact("Firewall", fw ? (fw.enabled ? `On${fw.block_all ? " · blocking all incoming connections" : ""}${fw.stealth ? " · stealth mode" : ""}` : '<span class="chip warn">Off</span> <span class="muted small">Turn it on in System Settings → Network → Firewall.</span>') : "")}`;
}

function renderOutages() {
  const list = [...(state.outage ? [state.outage] : []), ...[...state.outages].reverse()].slice(0, 30);
  const firstSample = state.health[0]?.ts;
  $("#outage-list").innerHTML = list.length
    ? list.map((o) => {
        const end = o.end ?? Date.now();
        const sameDay = new Date(o.start).toDateString() === new Date().toDateString();
        return `<div class="outage ${o.end ? "" : "ongoing"}">
          <span class="dot ${o.end ? "off" : "bad"}"></span>
          <div class="grow"><b>${esc(outageLabel(o))}</b> <span class="muted small">${o.end ? "" : "· ongoing"}</span>
            <div class="muted small">${sameDay ? "Today" : esc(shortDate(o.start))} ${hhmm(o.start)}–${o.end ? hhmm(o.end) : "now"}</div></div>
          <span class="num">${fmtDuration((end - o.start) / 1000)}</span></div>`;
      }).join("")
    : `<div class="empty">No outages recorded${firstSample ? ` since ${hhmm(firstSample)}` : ""}. Checks run every 10 seconds; three misses in a row count as an outage.</div>`;
}

// Share of today spent on each generation, from the change log.
function linkShareToday() {
  const m = state.mifi;
  if (!m) return null;
  const start = dayStart(Date.now());
  const log = state.linkLog.filter((c) => c.ts >= start);
  const before = [...state.linkLog].reverse().find((c) => c.ts < start);
  let cur = before ? before.to : log.length ? log[0].from : m.generation;
  let t = start;
  const spent = {};
  for (const c of log) {
    spent[cur] = (spent[cur] || 0) + (c.ts - t);
    cur = c.to;
    t = c.ts;
  }
  spent[cur] = (spent[cur] || 0) + (Date.now() - t);
  return spent;
}

function renderMobile() {
  const m = state.mifi;
  const panel = $("#mobile-panel");
  panel.hidden = !m;
  if (!m) return;
  const good = m.connected && (m.generation === "4G" || m.generation === "4G+");
  const share = linkShareToday();
  const total = Object.values(share || {}).reduce((a, b) => a + b, 0) || 1;
  const pct4 = Math.round((((share?.["4G"] || 0) + (share?.["4G+"] || 0)) / total) * 100);
  $("#mobile-now").innerHTML = `
    <div class="stat"><span>Network</span><b>${m.connected ? `<span class="dot ${good ? "good" : "warn"}"></span> ${esc(m.generation)}` : `<span class="dot bad"></span> ${esc(m.connect_label)}`}</b><span class="muted small">${esc(m.technology)}</span></div>
    <div class="stat"><span>SIM</span><b>${esc(m.sim_label)}</b></div>
    <div class="stat"><span>Devices on hotspot</span><b>${m.clients ?? "—"}</b></div>
    <div class="stat"><span>On 4G today</span><b>${pct4}%</b></div>
    <div class="stat grow"><span>Hotspot</span><b>${esc(m.model || "TP-Link")}</b><span class="muted small">${m.ssid ? `Wi-Fi "${esc(m.ssid)}"` : ""}</span></div>`;
  const recent = [...state.linkLog].reverse().slice(0, 8);
  $("#mobile-log").innerHTML = recent.length
    ? recent.map((c) => {
        const down = (["No service", "2G", "3G", "4G", "4G+"].indexOf(c.to)) < (["No service", "2G", "3G", "4G", "4G+"].indexOf(c.from));
        return `<div class="outage"><span class="dot ${down ? "warn" : "good"}"></span><div class="grow">${esc(c.from)} → <b>${esc(c.to)}</b></div><span class="muted small">${new Date(c.ts).toDateString() === new Date().toDateString() ? "" : esc(shortDate(c.ts)) + " "}${hhmm(c.ts)}</span></div>`;
      }).join("")
    : `<p class="muted small">No changes yet. NetWatch checks every 30 seconds and logs each switch between 4G, 3G and 2G.</p>`;
}

function renderNetwork() {
  renderNetTiles();
  renderMobile();
  renderHealthChart();
  renderUsage();
  renderLive();
  renderRouter();
  renderInternet();
  renderWifi();
  renderOutages();
  renderTrace();
  renderDnsCheck();
  renderWatch();
  renderLeak();
}

// ------------------------------------------------------------------ tools

function renderTrace() {
  const t = state.trace;
  const hops = t.hops || [];
  let prev = 0;
  const max = Math.max(1, ...hops.map((h) => h.rtt_ms || 0));
  $("#trace-result").innerHTML = t.running
    ? `<p class="muted small">Tracing the route to ${esc(t.target)}… this takes up to 20 seconds.</p>`
    : t.error
      ? `<p class="muted small">${esc(t.error)}</p>`
      : hops.length
        ? `<table class="table compact"><thead><tr><th class="num">Hop</th><th>Address</th><th class="num">Time</th><th class="bar-col"></th></tr></thead><tbody>${hops.map((h) => {
            const jump = h.rtt_ms != null && h.rtt_ms - prev >= 30 && h.n > 1 ? h.rtt_ms - prev : 0;
            if (h.rtt_ms != null) prev = Math.max(prev, h.rtt_ms);
            const who = h.n === 1 ? "your router" : h.ip?.startsWith("10.") || h.ip?.startsWith("100.") ? "provider's network" : "";
            return `<tr><td class="num">${h.n}</td>
              <td>${h.ip ? `<span class="mono">${esc(h.ip)}</span>${h.name ? ` <span class="muted small">${esc(h.name)}</span>` : ""}${who ? ` <span class="muted small">· ${who}</span>` : ""}` : '<span class="muted">No reply (normal for some routers)</span>'}</td>
              <td class="num">${h.rtt_ms != null ? fmtMs(h.rtt_ms) : "—"}${jump ? ` <span class="chip warn">+${Math.round(jump)} ms</span>` : ""}</td>
              <td><div class="share"><i style="width:${(((h.rtt_ms || 0) / max) * 100).toFixed(1)}%"></i></div></td></tr>`;
          }).join("")}</tbody></table>
          <p class="muted small" style="margin-top:8px">A big jump marks where delay is added. On 4G, the first hops after your router are the mobile network itself.</p>`
        : "";
  $("#trace-btn").disabled = t.running;
}

function renderDnsCheck() {
  const d = state.dnsCheck;
  const rows = d.results || [];
  const fastest = rows.filter((r) => r.cached_ms != null).sort((a, b) => a.cached_ms - b.cached_ms)[0];
  $("#dns-check-result").innerHTML = d.running
    ? '<p class="muted small">Asking each server a few questions…</p>'
    : d.error
      ? `<p class="muted small">${esc(d.error)}</p>`
      : rows.length
        ? `<table class="table compact"><thead><tr><th>Server</th><th class="num">Popular names</th><th class="num">New name</th><th class="num">Answered</th></tr></thead><tbody>${rows.map((r) => `<tr>
            <td><b>${esc(r.label)}</b> <span class="muted small mono">${esc(r.server)}</span>${r === fastest ? ' <span class="chip">Fastest</span>' : ""}${r.nxdomain_hijack ? ' <span class="chip warn">Redirects typos</span>' : ""}</td>
            <td class="num">${fmtMs(r.cached_ms)}</td><td class="num">${fmtMs(r.uncached_ms)}</td><td class="num">${r.answered}/${r.asked}</td></tr>`).join("")}</tbody></table>
          <p class="muted small" style="margin-top:8px">"Popular names" are usually cached, so they show the round trip. "New name" needs a full lookup. To change DNS for every device, set it in your router.</p>`
        : '<p class="muted small">Compares your DNS server with Cloudflare, Google and Quad9, and checks whether it redirects addresses that don\'t exist.</p>';
  $("#dns-check-btn").disabled = d.running;
}

// ------------------------------------------------------------------ watched hosts

// A tiny single-series sparkline of the last hour's round trips.
function sparkline(samples) {
  const W = 120, H = 26;
  const pts = samples.filter(([, v]) => v != null).map(([, v]) => v);
  if (samples.length < 2) return "";
  const max = Math.max(50, ...pts);
  const t0 = samples[0][0], t1 = samples[samples.length - 1][0] || t0 + 1;
  let d = "", pen = false, fails = "";
  for (const [ts, v] of samples) {
    const x = ((ts - t0) / Math.max(1, t1 - t0)) * (W - 2) + 1;
    if (v == null) { pen = false; fails += `<rect class="spark-fail" x="${x - 1}" y="0" width="2" height="${H}"/>`; continue; }
    const y = H - 2 - (v / max) * (H - 4);
    d += `${pen ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
    pen = true;
  }
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" aria-hidden="true">${fails}<path d="${d}"/></svg>`;
}

function renderWatch() {
  const rows = state.watch || [];
  const configured = state.settings?.watch_hosts || [];
  $("#watch-list").innerHTML = configured.length
    ? configured.map((t) => {
        const w = rows.find((r) => r.target === t) || { target: t, samples: [] };
        const ok = w.samples.filter(([, v]) => v != null).length;
        const uptime = w.samples.length ? Math.round((ok / w.samples.length) * 100) : null;
        const state_ = w.up == null ? ["off", "Checking…"] : w.up ? ["good", `Up for ${fmtDuration((Date.now() - w.since) / 1000)}`] : ["bad", `Down since ${hhmm(w.since)}`];
        return `<div class="watch-row">
          <span class="dot ${state_[0]}"></span>
          <div class="grow"><div><b>${esc(w.target)}</b>${w.address && w.address !== w.target.split(":")[0] ? ` <span class="muted small mono">${esc(w.address)}</span>` : ""}</div>
            <div class="muted small">${esc(state_[1])}${uptime != null ? ` · ${uptime}% answered in the last hour` : ""}${w.target.includes(":") ? " · TCP check" : " · ping"}</div></div>
          ${sparkline(w.samples || [])}
          <span class="num watch-rtt">${w.rtt_ms != null ? fmtMs(w.rtt_ms) : "—"}</span>
          <button class="icon-btn" data-unwatch="${esc(w.target)}" aria-label="Stop watching ${esc(w.target)}"><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
        </div>`;
      }).join("")
    : '<p class="muted small">Add a website, game server or anything else you rely on. NetWatch checks it every 15 seconds and alerts you when it stops answering. Use <span class="mono">host:port</span> for services that block ping, for example <span class="mono">example.com:443</span>.</p>';
}

async function addWatch() {
  const input = $("#watch-input");
  const v = input.value.trim().toLowerCase();
  if (!v) return;
  const next = { ...state.settings, watch_hosts: [...(state.settings?.watch_hosts || []), v] };
  state.settings = await call("set_settings", { settings: next });
  if (!state.settings.watch_hosts.includes(v)) {
    toast({ severity: "info", title: "Couldn't add that", detail: "Enter a host name or IP address, optionally with :port. You can watch up to 10." });
  } else {
    input.value = "";
  }
  render();
}

async function removeWatch(target) {
  const next = { ...state.settings, watch_hosts: (state.settings?.watch_hosts || []).filter((h) => h !== target) };
  state.settings = await call("set_settings", { settings: next });
  state.watch = (state.watch || []).filter((w) => w.target !== target);
  render();
}

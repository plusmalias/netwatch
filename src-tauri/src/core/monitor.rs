//! Monitors beyond the device list: the router (read-only UPnP), connection
//! health, Wi-Fi and firewall, the public address, per-app usage and the
//! speed test (on demand or scheduled).

use super::{describe, Core};
use crate::alerts::{AlertDraft, Severity};
use crate::apps::{self, AppUsage};
use crate::health::{self, HealthSample, Outage, OutageEvent, OutageTracker};
use crate::internet::{self, Gate, PublicInfo, SpeedResult};
use crate::mifi::{self, MifiStatus};
use crate::ping;
use crate::upnp::{self, Identity, Igd, PortMapping, WanStatus};
use crate::usage::{self, Forecast, Reading};
use crate::util::now_ms;
use crate::wifi::{self, FirewallInfo, WifiInfo};
use chrono::{Local, TimeZone};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const ROUTER_TICK: Duration = Duration::from_secs(3);
/// Router status every 20 ticks (1 min), port mappings every 100 (5 min).
const ROUTER_STATUS_EVERY: u32 = 20;
const ROUTER_MAPPINGS_EVERY: u32 = 100;
const ROUTER_REDISCOVER_MS: u64 = 10 * 60_000;
/// Consecutive failed status polls before we look for the router again.
const ROUTER_MAX_FAILURES: u32 = 5;
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const HEALTH_KEEP: usize = 360;
const WIFI_INTERVAL: Duration = Duration::from_secs(60);
const PUBLIC_INTERVAL_MS: u64 = 60 * 60_000;
const APPS_INTERVAL: Duration = Duration::from_secs(3);
const WAN_KEEP: usize = 200;
const MAX_OUTAGES: usize = 200;
const MAX_SPEEDTESTS: usize = 50;
/// Outages shorter than this are logged but don't alert.
const OUTAGE_ALERT_MIN_MS: u64 = 30_000;

#[derive(Serialize, Clone, Default)]
pub struct RouterInfo {
    /// Discovery has run at least once.
    pub checked: bool,
    /// The router answers UPnP IGD queries.
    pub upnp: bool,
    pub identity: Identity,
    pub status: WanStatus,
    /// `None` if the router won't list its port forwards.
    pub mappings: Option<Vec<PortMapping>>,
    /// The router reports WAN byte counters (household usage).
    pub counters: bool,
    pub updated: u64,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct LinkChange {
    pub ts: u64,
    pub from: String,
    pub to: String,
}

#[derive(Serialize, Clone)]
struct MifiEvent {
    status: Option<MifiStatus>,
    log: Vec<LinkChange>,
}

#[derive(Serialize, Clone, Default)]
pub struct WatchedHost {
    /// As the user entered it: "example.com" or "example.com:443".
    pub target: String,
    pub address: Option<String>,
    pub up: Option<bool>,
    pub rtt_ms: Option<f32>,
    /// When the current up/down state began.
    pub since: u64,
    /// The last hour of checks as (time, round trip or `None` if it failed).
    pub samples: VecDeque<(u64, Option<f32>)>,
    #[serde(skip)]
    fails: u32,
    #[serde(skip)]
    first_fail: u64,
}

const WATCH_INTERVAL: Duration = Duration::from_secs(15);
const WATCH_KEEP: usize = 240;
/// Failed checks in a row before a watched host counts as down.
const WATCH_FAILS_TO_DECLARE: u32 = 3;
/// The morning summary goes out at or after this local hour.
const SUMMARY_HOUR: u32 = 8;
/// How often to ask whether a scheduled speed test is due.
const SPEEDTEST_CHECK: Duration = Duration::from_secs(60);
/// A scheduled test needs a good connection check this recent: after waking
/// from sleep the last one is hours old, and Wi-Fi may still be rejoining.
const SPEEDTEST_LINK_FRESH_MS: u64 = 30_000;

/// Checks one watched host: TCP connect when a port is given, ping otherwise.
fn check_host(target: &str) -> (Option<String>, Option<f32>) {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (target, None),
    };
    let addr = (host, port.unwrap_or(0))
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.find(|s| s.is_ipv4()));
    let Some(addr) = addr else { return (None, None) };
    let ip = addr.ip().to_string();
    let rtt = match (port, addr) {
        (Some(_), a) => {
            let t = std::time::Instant::now();
            TcpStream::connect_timeout(&a, Duration::from_secs(3))
                .ok()
                .map(|_| t.elapsed().as_secs_f32() * 1000.0)
        }
        (None, SocketAddr::V4(a)) => ping::ping_many(&[*a.ip()], Duration::from_secs(2))
            .ok()
            .and_then(|r| r.get(a.ip()).map(|r| r.rtt_ms)),
        _ => None,
    };
    (Some(ip), rtt.map(|ms| (ms * 10.0).round() / 10.0))
}

const MIFI_INTERVAL: Duration = Duration::from_secs(30);
/// When the router isn't a hotspot that answers, look again this rarely.
const MIFI_RETRY: Duration = Duration::from_secs(10 * 60);
const MAX_LINK_LOG: usize = 300;

#[derive(Serialize, Clone, Copy)]
pub struct WanSample {
    pub ts: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Default)]
pub struct MonitorState {
    pub igd: Option<Igd>,
    pub router: RouterInfo,
    /// The gateway's IGD description URL, if SSDP turned it up.
    pub router_hint: Option<String>,
    /// The router's uptime as of a moment: (ts, uptime_s).
    uptime_at: Option<(u64, u64)>,
    router_failures: u32,
    /// Port mappings already seen, persisted so new ones alert even across restarts.
    known_mappings: Option<BTreeSet<String>>,
    pub wan: VecDeque<WanSample>,
    pub health: VecDeque<HealthSample>,
    pub health_supported: bool,
    tracker: OutageTracker,
    pub outages: Vec<Outage>,
    pub wifi: Option<WifiInfo>,
    pub firewall: Option<FirewallInfo>,
    pub public: Option<PublicInfo>,
    pub public_error: Option<String>,
    pub speed_running: bool,
    pub speedtests: Vec<SpeedResult>,
    /// When the scheduled speed test was switched on and last ran.
    speed_sched: SpeedSchedule,
    /// `None` where per-app usage isn't available (not macOS).
    pub apps: Option<Vec<AppUsage>>,
    /// The 4G hotspot's own status, when the router is a TP-Link mobile hotspot.
    pub mifi: Option<MifiStatus>,
    /// Mobile network type changes (4G → 3G…), newest last.
    pub link_log: Vec<LinkChange>,
    /// Hosts the user asked NetWatch to keep an eye on.
    pub watch: Vec<WatchedHost>,
}

/// Everything the monitors know, for the UI's initial load.
#[derive(Serialize)]
pub struct MonitorSnapshot {
    pub router: RouterInfo,
    pub wan: Vec<WanSample>,
    /// Hourly household usage for the last ~62 days, `[hour_start, rx, tx]`.
    pub usage: Vec<[u64; 3]>,
    /// Where this billing cycle's data use is heading. `None` without a
    /// data allowance or router counters.
    pub forecast: Option<Forecast>,
    pub health: Vec<HealthSample>,
    pub health_supported: bool,
    pub outage: Option<Outage>,
    pub outages: Vec<Outage>,
    pub wifi: Option<WifiInfo>,
    pub firewall: Option<FirewallInfo>,
    pub public: Option<PublicInfo>,
    pub public_error: Option<String>,
    pub speed_running: bool,
    pub speedtests: Vec<SpeedResult>,
    /// When the next scheduled speed test is due (ms), if one is scheduled.
    pub speedtest_next: Option<u64>,
    pub apps: Option<Vec<AppUsage>>,
    pub mifi: Option<MifiStatus>,
    pub link_log: Vec<LinkChange>,
    pub watch: Vec<WatchedHost>,
}

#[derive(Serialize, Clone)]
struct HealthEvent {
    sample: HealthSample,
    outage: Option<Outage>,
}

#[derive(Serialize, Clone)]
struct WifiEvent {
    wifi: Option<WifiInfo>,
    firewall: Option<FirewallInfo>,
}

#[derive(Serialize, Clone, Default)]
struct SpeedEvent {
    running: bool,
    phase: Option<String>,
    mbps: Option<f64>,
    result: Option<SpeedResult>,
    error: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Default)]
struct RouterFile {
    known_mappings: Option<BTreeSet<String>>,
}

/// What the speed test schedule remembers between runs (`speedtest-schedule.json`).
/// Kept out of the settings, which the window saves whole.
#[derive(Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
struct SpeedSchedule {
    /// When the schedule was switched on (or changed), so that the 03:00
    /// before that isn't counted as missed.
    anchor: Option<u64>,
    /// When the last scheduled test started.
    last_run: Option<u64>,
}

pub fn load_json<T: DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) {
    if let Ok(json) = serde_json::to_vec(value) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(tmp, path);
        }
    }
}

fn mapping_key(m: &PortMapping) -> String {
    format!("{}:{}:{}:{}", m.protocol, m.external_port, m.internal_client, m.internal_port)
}

fn local_clock(ts: u64) -> String {
    Local
        .timestamp_millis_opt(ts as i64)
        .earliest()
        .map_or_else(String::new, |t| t.format("%H:%M").to_string())
}

impl MonitorState {
    pub fn load(dir: &Path) -> Self {
        let router: RouterFile = load_json(&dir.join("router.json"));
        MonitorState {
            known_mappings: router.known_mappings,
            outages: load_json(&dir.join("outages.json")),
            speedtests: load_json(&dir.join("speedtests.json")),
            speed_sched: load_json(&dir.join("speedtest-schedule.json")),
            link_log: load_json(&dir.join("mobile-link.json")),
            health_supported: true,
            apps: cfg!(target_os = "macos").then(Vec::new),
            ..Default::default()
        }
    }
}

impl Core {
    pub(super) fn monitor_snapshot(&self) -> MonitorSnapshot {
        let usage = self.usage_hours(now_ms().saturating_sub(62 * 24 * 3_600_000));
        let forecast = self.forecast();
        let speedtest_next = self.speedtest_next();
        let m = self.mon.lock().unwrap();
        MonitorSnapshot {
            router: m.router.clone(),
            wan: m.wan.iter().copied().collect(),
            usage,
            forecast,
            health: m.health.iter().copied().collect(),
            health_supported: m.health_supported,
            outage: m.tracker.current().cloned(),
            outages: m.outages.clone(),
            wifi: m.wifi.clone(),
            firewall: m.firewall.clone(),
            public: m.public.clone(),
            public_error: m.public_error.clone(),
            speed_running: m.speed_running,
            speedtests: m.speedtests.clone(),
            speedtest_next,
            apps: m.apps.clone(),
            mifi: m.mifi.clone(),
            link_log: m.link_log.clone(),
            watch: m.watch.clone(),
        }
    }

    /// The kind of outage going on right now, if any.
    pub(super) fn monitor_snapshot_outage(&self) -> Option<String> {
        self.mon.lock().unwrap().tracker.current().map(|o| o.kind.clone())
    }

    pub(super) fn start_monitors(self: &Arc<Self>) {
        let core = self.clone();
        thread::spawn(move || core.router_loop());
        let core = self.clone();
        thread::spawn(move || core.health_loop());
        let core = self.clone();
        thread::spawn(move || core.wifi_loop());
        let core = self.clone();
        thread::spawn(move || core.public_loop());
        let core = self.clone();
        thread::spawn(move || core.apps_loop());
        let core = self.clone();
        thread::spawn(move || core.mifi_loop());
        let core = self.clone();
        thread::spawn(move || core.watch_loop());
        let core = self.clone();
        thread::spawn(move || core.summary_loop());
        let core = self.clone();
        thread::spawn(move || core.speedtest_loop());
    }

    /// Forgets the router after a network change so it's rediscovered.
    pub(super) fn reset_router(&self) {
        let mut m = self.mon.lock().unwrap();
        m.igd = None;
        m.router = RouterInfo::default();
        m.router_hint = None;
        m.uptime_at = None;
        m.wan.clear();
        drop(m);
        self.public_refresh.store(true, Ordering::SeqCst);
        self.emit("router", RouterInfo::default());
    }

    pub(super) fn set_router_hint(&self, url: String) {
        self.mon.lock().unwrap().router_hint = Some(url);
    }

    // ------------------------------------------------------------ router

    fn router_loop(self: &Arc<Self>) {
        let mut tick: u32 = 0;
        let mut last_discover = 0u64;
        // Let the first scan fill in the gateway (and maybe an SSDP hint).
        thread::sleep(Duration::from_secs(8));
        loop {
            let igd = self.mon.lock().unwrap().igd.clone();
            match igd {
                None => {
                    let gw = self.net.read().unwrap().as_ref().and_then(|n| n.gateway_ip);
                    if let Some(gw) = gw.filter(|_| now_ms() - last_discover >= ROUTER_REDISCOVER_MS) {
                        last_discover = now_ms();
                        tick = 0;
                        self.discover_router(gw);
                    }
                }
                Some(igd) => {
                    if tick % ROUTER_STATUS_EVERY == 0 {
                        self.poll_router_status(&igd);
                    }
                    if tick % ROUTER_MAPPINGS_EVERY == 0 {
                        self.poll_mappings(&igd);
                    }
                    if igd.has_counters() {
                        self.poll_counters(&igd);
                    }
                    if tick % ROUTER_STATUS_EVERY == ROUTER_STATUS_EVERY - 1 {
                        self.save_usage();
                    }
                    tick = tick.wrapping_add(1);
                }
            }
            thread::sleep(ROUTER_TICK);
        }
    }

    fn discover_router(&self, gw: Ipv4Addr) {
        let hint = self.mon.lock().unwrap().router_hint.clone();
        let igd = upnp::discover(gw, hint);
        {
            let mut m = self.mon.lock().unwrap();
            m.router.checked = true;
            m.router.upnp = igd.is_some();
            m.router.counters = igd.as_ref().is_some_and(|i| i.has_counters());
            m.router.identity = igd.as_ref().map(|i| i.identity.clone()).unwrap_or_default();
            m.router_failures = 0;
            m.igd = igd.clone();
        }
        if let Some(model) = igd.and_then(|i| i.identity.model) {
            let mut store = self.store.lock().unwrap();
            if let Some(d) = store.by_ip_mut(gw).filter(|d| d.model.is_none()) {
                d.model = Some(model);
                self.devices_dirty.store(true, Ordering::SeqCst);
            }
        }
        self.emit_router();
    }

    fn emit_router(&self) {
        let info = self.mon.lock().unwrap().router.clone();
        self.emit("router", info);
    }

    fn poll_router_status(&self, igd: &Igd) {
        let status = igd.status();
        let failed = status.connection.is_none() && status.external_ip.is_none();
        {
            let mut m = self.mon.lock().unwrap();
            if failed {
                m.router_failures += 1;
                if m.router_failures >= ROUTER_MAX_FAILURES {
                    m.igd = None;
                }
                return;
            }
            m.router_failures = 0;
            if let Some(up) = status.uptime_s {
                m.uptime_at = Some((now_ms(), up));
            }
            m.router.status = status;
            m.router.updated = now_ms();
        }
        self.emit_router();
    }

    fn poll_mappings(&self, igd: &Igd) {
        let Some(list) = igd.mappings() else { return };
        let keys: BTreeSet<String> = list.iter().map(mapping_key).collect();
        let (fresh, cgnat) = {
            let mut m = self.mon.lock().unwrap();
            let fresh: Vec<PortMapping> = match &m.known_mappings {
                // The first look at a router is the baseline.
                None => Vec::new(),
                Some(known) => list.iter().filter(|p| !known.contains(&mapping_key(p))).cloned().collect(),
            };
            if m.known_mappings.as_ref() != Some(&keys) {
                m.known_mappings = Some(keys.clone());
                save_json(
                    &self.dir.join("router.json"),
                    &RouterFile {
                        known_mappings: Some(keys),
                    },
                );
            }
            m.router.mappings = Some(list);
            (fresh, m.router.status.cgnat)
        };
        for p in fresh {
            let who = {
                let mut store = self.store.lock().unwrap();
                p.internal_client
                    .parse()
                    .ok()
                    .and_then(|ip| store.by_ip_mut(ip).map(|d| describe(d)))
                    .unwrap_or_else(|| "A device".into())
            };
            let what = if p.description.is_empty() {
                String::new()
            } else {
                format!(" (\"{}\")", p.description)
            };
            let reach = if cgnat {
                " Your ISP uses carrier-grade NAT, so it probably isn't reachable from the internet right now."
            } else {
                ""
            };
            self.alert(AlertDraft {
                severity: Severity::Medium,
                kind: "port_forward",
                key: mapping_key(&p),
                title: format!("New port forward to {who}"),
                detail: format!(
                    "{who} asked your router (over UPnP) to forward {} port {} from the internet to {}:{}{what}. Game consoles and media servers do this legitimately; if you don't recognize it, turn off UPnP in the router's settings.{reach}",
                    p.protocol, p.external_port, p.internal_client, p.internal_port
                ),
            });
        }
        self.emit_router();
    }

    fn poll_counters(&self, igd: &Igd) {
        let Some((rx, tx)) = igd.counters() else { return };
        let now = now_ms();
        let uptime_s = self
            .mon
            .lock()
            .unwrap()
            .uptime_at
            .map(|(ts, up)| up + now.saturating_sub(ts) / 1000);
        let router = self.net.read().unwrap().as_ref().and_then(|n| n.gateway_mac.clone());
        let delta = self.usage.lock().unwrap().record(Reading { ts: now, rx, tx, uptime_s, router });
        let Some((drx, dtx, dt)) = delta else { return };
        self.history.lock().unwrap().add_bytes(now, drx, dtx);
        let sample = WanSample {
            ts: now,
            rx_bps: drx * 8 * 1000 / dt,
            tx_bps: dtx * 8 * 1000 / dt,
        };
        {
            let mut m = self.mon.lock().unwrap();
            m.wan.push_back(sample);
            while m.wan.len() > WAN_KEEP {
                m.wan.pop_front();
            }
        }
        self.emit("wan", sample);
    }

    /// Recent hourly usage as `[hour_start, rx, tx]`, newest last.
    pub(super) fn usage_hours(&self, since: u64) -> Vec<[u64; 3]> {
        let usage = self.usage.lock().unwrap();
        usage
            .usage
            .hours
            .range(since..)
            .map(|(h, v)| [*h, v[0], v[1]])
            .collect()
    }

    fn save_usage(&self) {
        self.usage.lock().unwrap().save();
        let since = usage::hour_start(now_ms().saturating_sub(26 * 3_600_000));
        self.emit("usage", self.usage_hours(since));
        self.check_data_cap();
        self.check_forecast();
    }

    pub(super) fn check_data_cap(&self) {
        let (cap_gb, day) = {
            let s = self.settings.read().unwrap();
            (s.data_cap_gb, s.cycle_day)
        };
        let Some(cap_gb) = cap_gb else { return };
        let Some(start) = usage::cycle_start(Local::now(), day) else { return };
        let start_ms = start.timestamp_millis() as u64;
        let used = self.usage.lock().unwrap().total_since(start_ms);
        let cap = cap_gb * 1e9;
        for (pct, severity) in [(100u32, Severity::Medium), (80, Severity::Low)] {
            if (used as f64) < cap * pct as f64 / 100.0 {
                continue;
            }
            let key = format!("{}:{pct}", start.format("%Y-%m-%d"));
            if self.alerts.lock().unwrap().has("data_cap", &key) {
                break;
            }
            let title = if pct >= 100 {
                format!("Monthly data allowance used up ({:.1} GB)", used as f64 / 1e9)
            } else {
                format!("{pct}% of this month's data used")
            };
            self.alert(AlertDraft {
                severity,
                kind: "data_cap",
                key,
                title,
                detail: format!(
                    "Your network has used {:.1} GB of its {cap_gb} GB allowance since {}, according to your router. Check the Network page to see when it was used, and Traffic for which apps on this computer used the most.",
                    used as f64 / 1e9,
                    start.format("%-d %B")
                ),
            });
            break;
        }
    }

    /// Where this cycle's data use is heading, if there's an allowance to
    /// measure it against and the router reports usage.
    pub(super) fn forecast(&self) -> Option<Forecast> {
        let (cap_gb, day) = {
            let s = self.settings.read().unwrap();
            (s.data_cap_gb, s.cycle_day)
        };
        let cap_gb = cap_gb?;
        if !self.mon.lock().unwrap().router.counters {
            return None;
        }
        let usage = self.usage.lock().unwrap();
        usage::forecast(&usage.usage.hours, Local::now(), day, (cap_gb * 1e9) as u64)
    }

    /// Sends the forecast to the window, and warns once per cycle when the
    /// allowance won't last.
    pub(super) fn check_forecast(&self) {
        let f = self.forecast();
        self.emit("forecast", f.clone());
        let Some(f) = f.filter(Forecast::worth_alert) else { return };
        let at = |ms: u64| Local.timestamp_millis_opt(ms as i64).earliest();
        // The cycle's last day is the one before the next begins.
        let (Some(start), Some(last_day)) = (at(f.cycle_start), at(f.cycle_end.saturating_sub(1))) else { return };
        let key = start.format("%Y-%m-%d").to_string();
        if self.alerts.lock().unwrap().has("data_forecast", &key) {
            return;
        }
        // Decimal gigabytes to one place, without a trailing ".0".
        let gb = |bytes: u64| (bytes as f64 / 1e8).round() / 10.0;
        self.alert(AlertDraft {
            severity: Severity::Low,
            kind: "data_forecast",
            key,
            title: "On course to pass this month's data allowance".into(),
            detail: format!(
                "Your network has used {} GB of its {} GB allowance since {}, and a typical day lately is about {} GB. At that rate it will reach about {} GB by {} with {} days still to go. Check the Network page to see when the data was used, and Traffic for which apps on this computer used the most. Pausing large downloads, backups and video streaming now can keep you under.",
                gb(f.used),
                gb(f.cap),
                start.format("%-d %B"),
                gb(f.daily.unwrap_or(0)),
                gb(f.projected.unwrap_or(0)),
                last_day.format("%-d %B"),
                f.days_left.floor()
            ),
        });
    }

    // ------------------------------------------------------------ health

    fn health_loop(self: &Arc<Self>) {
        let interval_ms = HEALTH_INTERVAL.as_millis() as u64;
        loop {
            thread::sleep(HEALTH_INTERVAL);
            let Some(gw) = self.net.read().unwrap().as_ref().map(|n| n.gateway_ip) else {
                continue;
            };
            let internet: Vec<Ipv4Addr> = health::INTERNET_TARGETS.iter().map(|o| Ipv4Addr::from(*o)).collect();
            let mut targets = internet.clone();
            targets.extend(gw);
            let replies = match ping::ping_many(&targets, Duration::from_secs(2)) {
                Ok(r) => r,
                Err(_) => {
                    // No unprivileged ICMP on this system.
                    self.mon.lock().unwrap().health_supported = false;
                    return;
                }
            };
            let round = |ms: f32| (ms * 10.0).round() / 10.0;
            let sample = HealthSample {
                ts: now_ms(),
                gateway_ms: gw.and_then(|g| replies.get(&g)).map(|r| round(r.rtt_ms)),
                internet_ms: internet
                    .iter()
                    .filter_map(|ip| replies.get(ip))
                    .map(|r| round(r.rtt_ms))
                    .reduce(f32::min),
            };
            {
                let mut h = self.history.lock().unwrap();
                h.add_health(&sample);
                // Save about every five minutes.
                if sample.ts / 1000 % 300 < 10 {
                    h.save();
                }
            }
            let (event, outage) = {
                let mut m = self.mon.lock().unwrap();
                m.health.push_back(sample);
                while m.health.len() > HEALTH_KEEP {
                    m.health.pop_front();
                }
                let event = m.tracker.update(&sample, interval_ms);
                if let Some(OutageEvent::Ended(o)) = &event {
                    m.outages.push(o.clone());
                    if m.outages.len() > MAX_OUTAGES {
                        m.outages.remove(0);
                    }
                    save_json(&self.dir.join("outages.json"), &m.outages);
                }
                (event, m.tracker.current().cloned())
            };
            if let Some(OutageEvent::Ended(o)) = &event {
                self.outage_alert(o, gw);
                self.emit("outages", self.mon.lock().unwrap().outages.clone());
            }
            self.emit("health", HealthEvent { sample, outage });
        }
    }

    fn outage_alert(&self, o: &Outage, gw: Option<Ipv4Addr>) {
        let end = o.end.unwrap_or(o.start);
        let took = end.saturating_sub(o.start);
        if took < OUTAGE_ALERT_MIN_MS {
            return;
        }
        let (from, to, dur) = (local_clock(o.start), local_clock(end), health::fmt_duration(took));
        let (title, detail) = if o.kind == "router" {
            (
                format!("Lost connection to the router for {dur}"),
                format!(
                    "From {from} to {to} this computer couldn't reach your router{}. That's usually a Wi-Fi dropout or the router restarting.",
                    gw.map(|g| format!(" at {g}")).unwrap_or_default()
                ),
            )
        } else {
            (
                format!("Internet was down for {dur}"),
                format!(
                    "From {from} to {to} your router answered but the internet didn't (1.1.1.1 and 8.8.8.8 were unreachable). The problem was on the router's internet link or your provider's side."
                ),
            )
        };
        self.alert(AlertDraft {
            severity: Severity::Low,
            kind: "outage",
            key: o.start.to_string(),
            title,
            detail,
        });
    }

    // ------------------------------------------------------------ wifi

    fn wifi_loop(self: &Arc<Self>) {
        if !cfg!(target_os = "macos") {
            return;
        }
        loop {
            let iface = self.net.read().unwrap().as_ref().map(|n| n.interface.clone());
            let mut w = iface.as_deref().and_then(wifi::read);
            // With Location permission, CoreWLAN has the network names and BSSIDs
            // that system_profiler hides.
            if self.location_allowed() {
                w = w.map(|info| match crate::corewlan::scan(&info.interface) {
                    Some(cw) => wifi::merge_corewlan(info, cw),
                    None => info,
                });
            }
            let fw = wifi::firewall();
            {
                let mut m = self.mon.lock().unwrap();
                m.wifi = w.clone();
                m.firewall = fw.clone();
            }
            if let Some(label) = w.as_ref().and_then(|w| w.current.security.clone()) {
                self.wifi_security_alert(&label);
            }
            self.emit("wifi", WifiEvent { wifi: w, firewall: fw });
            // Look again early if Location permission changed, so names appear (or go) at once.
            let mut waited = Duration::ZERO;
            while waited < WIFI_INTERVAL && !self.wifi_refresh.swap(false, Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(1));
                waited += Duration::from_secs(1);
            }
        }
    }

    fn wifi_security_alert(&self, label: &str) {
        let weakness = wifi::security_weakness(label);
        if weakness == 0 || self.alerts.lock().unwrap().has("wifi_security", label) {
            return;
        }
        let (severity, title, detail) = if weakness >= 2 {
            (
                Severity::Medium,
                format!("Your Wi-Fi uses weak security ({label})"),
                "Anyone nearby can join or eavesdrop on this network. Set the router to WPA2 (AES) or WPA3 with a strong password.".to_string(),
            )
        } else {
            (
                Severity::Low,
                "Your Wi-Fi still allows old WPA security".to_string(),
                format!(
                    "This network is set to {label}, which keeps the outdated WPA/TKIP mode switched on for old devices. Changing the router's security to WPA2-PSK (AES) only, or WPA2/WPA3, closes that gap."
                ),
            )
        };
        self.alert(AlertDraft {
            severity,
            kind: "wifi_security",
            key: label.to_string(),
            title,
            detail,
        });
    }

    // ------------------------------------------------------------ public address

    fn public_loop(self: &Arc<Self>) {
        thread::sleep(Duration::from_secs(5));
        let mut last = 0u64;
        loop {
            let due = now_ms() - last >= PUBLIC_INTERVAL_MS || self.public_refresh.swap(false, Ordering::SeqCst);
            if due && self.settings.read().unwrap().public_ip_lookup {
                last = now_ms();
                let result = internet::lookup_public(now_ms());
                {
                    let mut m = self.mon.lock().unwrap();
                    match result {
                        Ok(p) => {
                            m.public = Some(p);
                            m.public_error = None;
                        }
                        Err(e) => m.public_error = Some(e),
                    }
                }
                self.emit_public();
            }
            thread::sleep(Duration::from_secs(5));
        }
    }

    pub(super) fn emit_public(&self) {
        let m = self.mon.lock().unwrap();
        let payload = (m.public.clone(), m.public_error.clone());
        drop(m);
        self.emit("public", payload);
    }

    /// History for a range ("24h", "7d", "30d"), merged to a sensible step.
    pub fn history(&self, range: &str) -> Vec<crate::history::Point> {
        let (span, step) = match range {
            "7d" => (7 * 86_400_000, 30 * 60_000),
            "30d" => (30 * 86_400_000, 2 * 3_600_000),
            _ => (86_400_000, 5 * 60_000),
        };
        self.history.lock().unwrap().points(now_ms().saturating_sub(span), step)
    }

    // ------------------------------------------------------------ watched hosts

    fn watch_loop(self: &Arc<Self>) {
        loop {
            let targets = self.settings.read().unwrap().watch_hosts.clone();
            {
                let mut m = self.mon.lock().unwrap();
                m.watch.retain(|w| targets.contains(&w.target));
                for t in &targets {
                    if !m.watch.iter().any(|w| &w.target == t) {
                        m.watch.push(WatchedHost {
                            target: t.clone(),
                            ..Default::default()
                        });
                    }
                }
            }
            if targets.is_empty() {
                thread::sleep(WATCH_INTERVAL);
                continue;
            }
            // Name lookups can be slow, so each host gets its own thread.
            let results: Vec<(String, (Option<String>, Option<f32>))> = targets
                .iter()
                .cloned()
                .map(|t| thread::spawn(move || (t.clone(), check_host(&t))))
                .collect::<Vec<_>>()
                .into_iter()
                .filter_map(|h| h.join().ok())
                .collect();
            let now = now_ms();
            let mut changes = Vec::new();
            {
                let mut m = self.mon.lock().unwrap();
                for (target, (address, rtt)) in results {
                    let Some(w) = m.watch.iter_mut().find(|w| w.target == target) else { continue };
                    w.address = address.or(w.address.take());
                    w.samples.push_back((now, rtt));
                    while w.samples.len() > WATCH_KEEP {
                        w.samples.pop_front();
                    }
                    w.rtt_ms = rtt;
                    match rtt {
                        Some(_) => {
                            w.fails = 0;
                            if w.up != Some(true) {
                                if w.up == Some(false) {
                                    changes.push((target.clone(), true, now.saturating_sub(w.since)));
                                }
                                w.up = Some(true);
                                w.since = now;
                            }
                        }
                        None => {
                            if w.fails == 0 {
                                w.first_fail = now;
                            }
                            w.fails += 1;
                            if w.fails >= WATCH_FAILS_TO_DECLARE && w.up != Some(false) {
                                w.up = Some(false);
                                w.since = w.first_fail;
                                changes.push((target.clone(), false, 0));
                            }
                        }
                    }
                }
            }
            for (target, up, down_for) in changes {
                let (kind, title, detail) = if up {
                    (
                        "host_up",
                        format!("{target} is reachable again"),
                        format!("{target} answered again after being unreachable for {}.", health::fmt_duration(down_for)),
                    )
                } else {
                    (
                        "host_down",
                        format!("{target} isn't responding"),
                        format!(
                            "NetWatch has had no answer from {target} for the last {} checks. If your internet is fine, the problem is likely on that service's side.",
                            WATCH_FAILS_TO_DECLARE
                        ),
                    )
                };
                self.alert(AlertDraft {
                    severity: Severity::Low,
                    kind,
                    key: format!("{target}:{now}"),
                    title,
                    detail,
                });
            }
            self.emit("watch", self.mon.lock().unwrap().watch.clone());
            thread::sleep(WATCH_INTERVAL);
        }
    }

    // ------------------------------------------------------------ morning summary

    fn summary_loop(self: &Arc<Self>) {
        loop {
            thread::sleep(Duration::from_secs(10 * 60));
            if !self.settings.read().unwrap().daily_summary {
                continue;
            }
            let now = Local::now();
            if chrono::Timelike::hour(&now) < SUMMARY_HOUR {
                continue;
            }
            let today = now.format("%Y-%m-%d").to_string();
            if self.alerts.lock().unwrap().has("daily_summary", &today) {
                continue;
            }
            self.send_summary(&today);
        }
    }

    /// Yesterday in a few lines: data, outages, mobile drops, new devices, alerts.
    fn send_summary(&self, today: &str) {
        let Some(t0) = Local::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .and_then(|d| Local.from_local_datetime(&d).earliest())
        else {
            return;
        };
        let t0 = t0.timestamp_millis() as u64;
        let y0 = t0.saturating_sub(24 * 3_600_000);
        let in_day = |ts: u64| ts >= y0 && ts < t0;
        let mut lines = Vec::new();
        {
            let usage = self.usage.lock().unwrap();
            let used = usage.total_since(y0).saturating_sub(usage.total_since(t0));
            if used > 0 {
                lines.push(format!("{:.2} GB of data used across your network", used as f64 / 1e9));
            }
        }
        {
            let m = self.mon.lock().unwrap();
            let outages: Vec<&Outage> = m.outages.iter().filter(|o| in_day(o.start)).collect();
            if outages.is_empty() {
                lines.push("No internet outages".into());
            } else {
                let total: u64 = outages.iter().map(|o| o.end.unwrap_or(o.start).saturating_sub(o.start)).sum();
                lines.push(format!(
                    "{} outage{} ({} offline in total)",
                    outages.len(),
                    if outages.len() == 1 { "" } else { "s" },
                    health::fmt_duration(total)
                ));
            }
            let drops = m
                .link_log
                .iter()
                .filter(|c| in_day(c.ts) && mifi::rank(&c.to) < mifi::rank(&c.from))
                .count();
            if drops > 0 {
                lines.push(format!("The 4G link dropped to an older network {drops} time{}", if drops == 1 { "" } else { "s" }));
            }
        }
        {
            let store = self.store.lock().unwrap();
            let new: Vec<String> = store.devices.values().filter(|d| in_day(d.first_seen)).map(describe).collect();
            if !new.is_empty() {
                lines.push(format!("{} new device{}: {}", new.len(), if new.len() == 1 { "" } else { "s" }, new.join(", ")));
            }
        }
        {
            let alerts = self.alerts.lock().unwrap();
            let worth: Vec<_> = alerts
                .alerts
                .iter()
                .filter(|a| in_day(a.ts) && a.severity > Severity::Info && a.kind != "daily_summary")
                .collect();
            let high = worth.iter().filter(|a| a.severity == Severity::High).count();
            lines.push(match (worth.len(), high) {
                (0, _) => "No alerts".into(),
                (n, 0) => format!("{n} alert{}", if n == 1 { "" } else { "s" }),
                (n, h) => format!("{n} alert{}, {h} high-severity", if n == 1 { "" } else { "s" }),
            });
        }
        self.alert(AlertDraft {
            severity: Severity::Info,
            kind: "daily_summary",
            key: today.to_string(),
            title: "Yesterday on your network".into(),
            detail: lines.join(". ") + ".",
        });
    }

    // ------------------------------------------------------------ 4G hotspot

    fn mifi_loop(self: &Arc<Self>) {
        thread::sleep(Duration::from_secs(10));
        loop {
            let gw = self.net.read().unwrap().as_ref().and_then(|n| n.gateway_ip);
            let status = gw.and_then(mifi::status);
            let Some(status) = status else {
                let had = self.mon.lock().unwrap().mifi.take().is_some();
                if had {
                    self.emit_mifi();
                }
                thread::sleep(MIFI_RETRY);
                continue;
            };
            let change = {
                let mut m = self.mon.lock().unwrap();
                let prev = m.mifi.replace(status.clone());
                match prev {
                    Some(p) if p.generation != status.generation => {
                        let c = LinkChange {
                            ts: now_ms(),
                            from: p.generation.clone(),
                            to: status.generation.clone(),
                        };
                        m.link_log.push(c.clone());
                        if m.link_log.len() > MAX_LINK_LOG {
                            m.link_log.remove(0);
                        }
                        save_json(&self.dir.join("mobile-link.json"), &m.link_log);
                        Some(c)
                    }
                    _ => None,
                }
            };
            if let Some(c) = change {
                // Alert when the link falls from 4G to something older.
                if mifi::rank(&c.to) < mifi::rank(&c.from) && mifi::rank(&c.from) >= 3 {
                    let (title, extra) = if c.to == "No service" {
                        ("Your hotspot lost mobile service".to_string(), "")
                    } else {
                        (
                            format!("Mobile connection dropped from {} to {}", c.from, c.to),
                            " Weak coverage or a busy tower usually causes this. If it happens often where 4G is normally strong, the times in the Network page's log can help your provider look into it.",
                        )
                    };
                    self.alert(AlertDraft {
                        severity: Severity::Low,
                        kind: "link_downgrade",
                        key: c.ts.to_string(),
                        title,
                        detail: format!(
                            "At {} your {} switched from {} to {}.{extra}",
                            local_clock(c.ts),
                            status.model.as_deref().unwrap_or("hotspot"),
                            c.from,
                            c.to
                        ),
                    });
                }
            }
            self.emit_mifi();
            thread::sleep(MIFI_INTERVAL);
        }
    }

    fn emit_mifi(&self) {
        let m = self.mon.lock().unwrap();
        let event = MifiEvent {
            status: m.mifi.clone(),
            log: m.link_log.clone(),
        };
        drop(m);
        self.emit("mifi", event);
    }

    // ------------------------------------------------------------ apps

    fn apps_loop(self: &Arc<Self>) {
        loop {
            let Some(rows) = apps::sample() else {
                self.mon.lock().unwrap().apps = None;
                return;
            };
            let list = {
                let mut tracker = self.apps.lock().unwrap();
                let mut sys = self.sys.lock().unwrap();
                tracker.update(rows, now_ms(), |pid, short| {
                    let p = sysinfo::Pid::from_u32(pid);
                    if sys.process(p).is_none() {
                        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[p]), false);
                    }
                    sys.process(p)
                        .and_then(|proc_| {
                            proc_
                                .exe()
                                .and_then(apps::app_name)
                                .or_else(|| Some(proc_.name().to_string_lossy().into_owned()))
                        })
                        .unwrap_or_else(|| short.to_string())
                });
                tracker.list()
            };
            self.mon.lock().unwrap().apps = Some(list.clone());
            self.emit("apps", list);
            thread::sleep(APPS_INTERVAL);
        }
    }

    // ------------------------------------------------------------ speed test

    /// The Run speed test button: always the full test.
    pub fn run_speed_test(self: &Arc<Self>) -> Result<(), String> {
        self.start_speed_test(false, false)
    }

    /// Starts a test in the background unless one is running. Progress and the
    /// result reach the window as "speedtest" events.
    fn start_speed_test(self: &Arc<Self>, light: bool, scheduled: bool) -> Result<(), String> {
        {
            let mut m = self.mon.lock().unwrap();
            if m.speed_running {
                return Err("A speed test is already running.".into());
            }
            m.speed_running = true;
        }
        let core = self.clone();
        thread::spawn(move || {
            let progress_core = core.clone();
            let result = internet::speed_test(now_ms(), light, |phase, mbps| {
                progress_core.emit(
                    "speedtest",
                    SpeedEvent {
                        running: true,
                        phase: Some(phase.into()),
                        mbps,
                        ..Default::default()
                    },
                );
            });
            let mut m = core.mon.lock().unwrap();
            m.speed_running = false;
            let event = match result {
                Ok(mut r) => {
                    r.scheduled = scheduled;
                    m.speedtests.push(r.clone());
                    if m.speedtests.len() > MAX_SPEEDTESTS {
                        m.speedtests.remove(0);
                    }
                    save_json(&core.dir.join("speedtests.json"), &m.speedtests);
                    SpeedEvent {
                        result: Some(r),
                        ..Default::default()
                    }
                }
                Err(e) => SpeedEvent {
                    error: Some(e),
                    ..Default::default()
                },
            };
            drop(m);
            core.emit("speedtest", event);
        });
        Ok(())
    }

    // ------------------------------------------------------------ scheduled speed test

    /// When the next scheduled test is due, if the schedule is on.
    fn speedtest_next(&self) -> Option<u64> {
        let schedule = self.settings.read().unwrap().speedtest_schedule.clone();
        let st = self.mon.lock().unwrap().speed_sched.clone();
        internet::next_scheduled(&schedule, st.anchor.or(Some(now_ms())), st.last_run)
    }

    /// Records a change to the schedule's memory, saves it and tells the window.
    fn update_speed_schedule(&self, change: impl FnOnce(&mut SpeedSchedule)) {
        {
            let mut m = self.mon.lock().unwrap();
            change(&mut m.speed_sched);
            save_json(&self.dir.join("speedtest-schedule.json"), &m.speed_sched);
        }
        self.emit("speedschedule", self.speedtest_next());
    }

    /// The schedule was switched on, off or between daily and weekly: count
    /// from now, so no test starts for a slot that passed before that.
    pub(super) fn speedtest_schedule_changed(&self, schedule: &str) {
        let anchor = (schedule != "off").then(now_ms);
        self.update_speed_schedule(|s| s.anchor = anchor);
    }

    fn speedtest_loop(self: &Arc<Self>) {
        // Let the first connection checks arrive after a launch.
        thread::sleep(Duration::from_secs(60));
        loop {
            self.scheduled_speed_test();
            thread::sleep(SPEEDTEST_CHECK);
        }
    }

    /// Starts the scheduled test if it's due and nothing is in the way.
    fn scheduled_speed_test(self: &Arc<Self>) {
        let (schedule, light) = {
            let s = self.settings.read().unwrap();
            (s.speedtest_schedule.clone(), s.speedtest_size == "light")
        };
        if schedule == "off" {
            return;
        }
        let now = now_ms();
        let st = self.mon.lock().unwrap().speed_sched.clone();
        if st.anchor.is_none() {
            // On from before anything was recorded: count from now.
            self.speedtest_schedule_changed(&schedule);
            return;
        }
        let has_net = self.net.read().unwrap().is_some();
        let gate = {
            let m = self.mon.lock().unwrap();
            // The outage tracker needs three misses and needs ICMP, so also
            // want a recent good reply: right after waking there isn't one.
            let fresh = m
                .health
                .back()
                .is_some_and(|h| now.saturating_sub(h.ts) <= SPEEDTEST_LINK_FRESH_MS && h.internet_ms.is_some());
            Gate {
                outage: m.tracker.current().is_some(),
                running: m.speed_running,
                online: has_net && (fresh || !m.health_supported),
            }
        };
        if !internet::is_due(&schedule, st.anchor, st.last_run, now, gate) {
            return;
        }
        // Only a test that really started uses up the slot (a manual one may have just begun).
        if self.start_speed_test(light, true).is_ok() {
            self.update_speed_schedule(|s| s.last_run = Some(now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs the internet: `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_watch_checks() {
        for t in ["1.1.1.1", "cloudflare.com:443", "no-such-host.invalid"] {
            println!("{t}: {:?}", check_host(t));
        }
    }

    #[test]
    fn speed_test_history_from_before_the_schedule_loads() {
        let dir = std::env::temp_dir().join(format!("netwatch-speedtests-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("speedtests.json");
        std::fs::write(
            &file,
            r#"[{"ts":1700000000000,"down_mbps":18.2,"up_mbps":3.9,"latency_ms":61.5,"jitter_ms":4.0,"bytes_used":31000000,"server":"SYD"}]"#,
        )
        .unwrap();
        let list: Vec<SpeedResult> = load_json(&file);
        assert_eq!(list.len(), 1);
        assert!(!list[0].scheduled && !list[0].light);
        // The schedule's memory starts empty when there's no file or an unreadable one.
        assert_eq!(load_json::<SpeedSchedule>(&dir.join("none.json")), SpeedSchedule::default());
        std::fs::write(dir.join("speedtest-schedule.json"), r#"{"last_run":5}"#).unwrap();
        assert_eq!(
            load_json::<SpeedSchedule>(&dir.join("speedtest-schedule.json")),
            SpeedSchedule { anchor: None, last_run: Some(5) }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

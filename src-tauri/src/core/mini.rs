//! The menu-bar dashboard's data: one compact summary, worked out here so the
//! popover only has to draw it. Also the text beside the menu-bar icon.

use super::Core;
use crate::alerts::{Alert, Severity};
use crate::capture::CaptureStatus;
use crate::health::HealthSample;
use crate::store::Device;
use crate::usage;
use crate::util::now_ms;
use chrono::{DateTime, Local, TimeZone};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

/// Answered nothing for this long: asleep. Keep in step with `isAsleep` in app.js.
const ASLEEP_AFTER_MS: u64 = 5 * 60_000;
/// How much connection history the popover's sparkline shows.
const LATENCY_WINDOW_MS: u64 = 10 * 60_000;
/// Connection checks run every 10 s; a reading older than this isn't "now".
const HEALTH_FRESH_MS: u64 = 60_000;
/// The router's counters are read every ~3 s.
const WAN_FRESH_MS: u64 = 30_000;
/// Capture reports once a second.
const TRAFFIC_FRESH_MS: u64 = 10_000;
const MINI_ALERTS: usize = 3;

#[derive(Serialize, Debug, PartialEq)]
pub struct DeviceCounts {
    /// Includes the asleep ones, like the Overview tile.
    pub online: usize,
    pub asleep: usize,
    pub total: usize,
}

#[derive(Serialize, Debug, PartialEq, Clone, Copy)]
pub struct Rates {
    pub down_bps: u64,
    pub up_bps: u64,
    /// From the router's counters (the whole network), not just this computer.
    pub household: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct CapUse {
    pub used_bytes: u64,
    pub cap_bytes: u64,
    pub pct: f64,
    /// Start of this billing cycle (ms since epoch).
    pub since: u64,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct MiniAlert {
    pub id: u64,
    pub severity: Severity,
    pub title: String,
    pub last_ts: u64,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct AlertDigest {
    /// Open alerts that need attention (not the info-level log).
    pub open: usize,
    pub high: bool,
    /// The newest few, most recently active first.
    pub newest: Vec<MiniAlert>,
}

#[derive(Serialize)]
pub struct MiniSummary {
    /// "good", "warn" or "bad": the colour of the status dot.
    pub level: &'static str,
    pub status: String,
    pub devices: DeviceCounts,
    pub router_ms: Option<f32>,
    pub internet_ms: Option<f32>,
    /// The last ~10 minutes of internet latency as (time, ms or `None` if unanswered).
    pub latency: Vec<(u64, Option<f32>)>,
    pub rates: Option<Rates>,
    /// Household data used today. `None` if the router doesn't report usage.
    pub today_bytes: Option<u64>,
    /// Progress through the monthly allowance, if one is set.
    pub cap: Option<CapUse>,
    pub open_alerts: usize,
    pub alerts: Vec<MiniAlert>,
    pub capture: CaptureStatus,
    pub scanning: bool,
    pub theme: String,
}

// ------------------------------------------------------------------ pure parts

/// The headline, most pressing thing first: no network, an outage, open
/// alerts, then blocked traffic monitoring.
fn status_line(
    has_net: bool,
    outage: Option<&str>,
    open_alerts: usize,
    high_alert: bool,
    needs_access: bool,
) -> (&'static str, String) {
    if !has_net {
        return ("bad", "Not connected to a network".into());
    }
    match outage {
        Some("router") => return ("bad", "Can't reach your router".into()),
        Some(_) => return ("bad", "Internet down".into()),
        None => {}
    }
    if open_alerts > 0 {
        let (s, v) = if open_alerts == 1 { ("", "s") } else { ("s", "") };
        let level = if high_alert { "bad" } else { "warn" };
        return (level, format!("{open_alerts} alert{s} need{v} attention"));
    }
    if needs_access {
        return ("warn", "Traffic monitoring needs access".into());
    }
    ("good", "All good".into())
}

fn count_devices<'a>(devices: impl Iterator<Item = &'a Device>, now: u64) -> DeviceCounts {
    let mut c = DeviceCounts { online: 0, asleep: 0, total: 0 };
    for d in devices {
        c.total += 1;
        if d.online {
            c.online += 1;
            if !d.is_self && !d.is_gateway && now.saturating_sub(d.last_reply) > ASLEEP_AFTER_MS {
                c.asleep += 1;
            }
        }
    }
    c
}

/// Throughput from the router's counters (the whole network) when they are
/// current, else this computer's capture. Each is `(time, rx_bps, tx_bps)`.
fn pick_rates(router: Option<(u64, u64, u64)>, computer: Option<(u64, u64, u64)>, now: u64) -> Option<Rates> {
    let fresh = |r: Option<(u64, u64, u64)>, max: u64| r.filter(|(ts, _, _)| now.saturating_sub(*ts) <= max);
    if let Some((_, rx, tx)) = fresh(router, WAN_FRESH_MS) {
        return Some(Rates { down_bps: rx, up_bps: tx, household: true });
    }
    fresh(computer, TRAFFIC_FRESH_MS).map(|(_, rx, tx)| Rates { down_bps: rx, up_bps: tx, household: false })
}

fn digest_alerts(alerts: &[Alert], n: usize) -> AlertDigest {
    let mut open: Vec<&Alert> = alerts
        .iter()
        .filter(|a| !a.acknowledged && a.severity > Severity::Info)
        .collect();
    open.sort_by_key(|a| std::cmp::Reverse((a.last_ts, a.id)));
    AlertDigest {
        open: open.len(),
        high: open.iter().any(|a| a.severity == Severity::High),
        newest: open
            .iter()
            .take(n)
            .map(|a| MiniAlert {
                id: a.id,
                severity: a.severity,
                title: a.title.clone(),
                last_ts: a.last_ts,
            })
            .collect(),
    }
}

/// The newest connection check as (router ms, internet ms), if it is recent.
fn latest_latency(health: &VecDeque<HealthSample>, now: u64) -> (Option<f32>, Option<f32>) {
    match health.back().filter(|s| now.saturating_sub(s.ts) <= HEALTH_FRESH_MS) {
        Some(s) => (s.gateway_ms, s.internet_ms),
        None => (None, None),
    }
}

fn latency_tail(health: &VecDeque<HealthSample>, now: u64) -> Vec<(u64, Option<f32>)> {
    let since = now.saturating_sub(LATENCY_WINDOW_MS);
    health
        .iter()
        .filter(|s| s.ts >= since)
        .map(|s| (s.ts, s.internet_ms))
        .collect()
}

fn cap_use(used_bytes: u64, cap_gb: f64, since: u64) -> CapUse {
    // Allowances count in decimal gigabytes, like `check_data_cap`.
    let cap_bytes = (cap_gb * 1e9) as u64;
    let pct = if cap_bytes == 0 { 0.0 } else { used_bytes as f64 / cap_bytes as f64 * 100.0 };
    CapUse { used_bytes, cap_bytes, pct, since }
}

/// Local midnight of `now`'s day, in ms since the epoch.
fn local_midnight_ms(now: DateTime<Local>) -> Option<u64> {
    let t0 = now.date_naive().and_hms_opt(0, 0, 0)?;
    Local
        .from_local_datetime(&t0)
        .earliest()
        .map(|t| t.timestamp_millis() as u64)
}

// ------------------------------------------------------------------ Core

impl Core {
    pub fn mini(&self) -> MiniSummary {
        let now = now_ms();
        let (cap_gb, cycle_day, theme) = {
            let s = self.settings.read().unwrap();
            (s.data_cap_gb, s.cycle_day, s.theme.clone())
        };
        let has_net = self.net.read().unwrap().is_some();
        let devices = count_devices(self.store.lock().unwrap().devices.values(), now);
        let digest = digest_alerts(&self.alerts.lock().unwrap().alerts, MINI_ALERTS);
        let outage = self.monitor_snapshot_outage();
        let capture = self.capture.lock().unwrap().0.clone();
        let (router_ms, internet_ms) = self.latest_latency(now);
        let (latency, counters) = {
            let m = self.mon.lock().unwrap();
            (latency_tail(&m.health, now), m.router.counters)
        };

        let local = Local::now();
        let today_bytes = local_midnight_ms(local)
            .map(|t0| self.usage.lock().unwrap().total_since(t0))
            .filter(|bytes| counters || *bytes > 0);
        let cap = cap_gb.and_then(|gb| {
            let since = usage::cycle_start(local, cycle_day)?.timestamp_millis() as u64;
            let used = self.usage.lock().unwrap().total_since(since);
            Some(cap_use(used, gb, since))
        });

        let needs_access = matches!(capture, CaptureStatus::NeedsPermission { .. });
        let (level, status) = status_line(has_net, outage.as_deref(), digest.open, digest.high, needs_access);
        MiniSummary {
            level,
            status,
            devices,
            router_ms,
            internet_ms,
            latency,
            rates: self.current_rates(now),
            today_bytes,
            cap,
            open_alerts: digest.open,
            alerts: digest.newest,
            capture,
            scanning: self.scanning.load(Ordering::SeqCst),
            theme,
        }
    }

    fn latest_latency(&self, now: u64) -> (Option<f32>, Option<f32>) {
        latest_latency(&self.mon.lock().unwrap().health, now)
    }

    /// Current throughput: the whole network from the router's counters if it
    /// reports them, else this computer's own traffic while capture runs.
    fn current_rates(&self, now: u64) -> Option<Rates> {
        let router = {
            let m = self.mon.lock().unwrap();
            let usable = m.router.counters && m.wan.len() > 1;
            m.wan.back().filter(|_| usable).map(|s| (s.ts, s.rx_bps, s.tx_bps))
        };
        let running = matches!(self.capture.lock().unwrap().0, CaptureStatus::Running { .. });
        let computer = running.then(|| {
            let t = self.traffic.lock().unwrap();
            (t.ts, t.rx_bps, t.tx_bps)
        });
        pick_rates(router, computer, now)
    }

    /// The text beside the menu-bar icon, per the "menu-bar text" setting.
    pub(super) fn tray_title(&self) -> Option<String> {
        let mode = self.settings.read().unwrap().tray_text.clone();
        if mode == "off" {
            return None;
        }
        let now = now_ms();
        let rates = self.current_rates(now).map(|r| (r.down_bps, r.up_bps));
        let online = self.store.lock().unwrap().devices.values().filter(|d| d.online).count();
        let (_, internet_ms) = self.latest_latency(now);
        let down = self.monitor_snapshot_outage().is_some();
        crate::tray::title_text(&mode, rates, online, internet_ms, down)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(online: bool, last_reply: u64) -> Device {
        Device { online, last_reply, ..Default::default() }
    }

    fn alert(id: u64, severity: Severity, last_ts: u64, acknowledged: bool) -> Alert {
        Alert {
            id,
            ts: last_ts,
            last_ts,
            count: 1,
            severity,
            kind: "test".into(),
            key: id.to_string(),
            title: format!("alert {id}"),
            detail: String::new(),
            acknowledged,
        }
    }

    fn sample(ts: u64, router: Option<f32>, internet: Option<f32>) -> HealthSample {
        HealthSample { ts, gateway_ms: router, internet_ms: internet }
    }

    #[test]
    fn status_line_puts_the_most_pressing_thing_first() {
        let line = |net, outage, open, high, access| status_line(net, outage, open, high, access);
        assert_eq!(line(true, None, 0, false, false), ("good", "All good".into()));
        assert_eq!(line(false, Some("internet"), 3, true, true), ("bad", "Not connected to a network".into()));
        assert_eq!(line(true, Some("internet"), 3, true, true), ("bad", "Internet down".into()));
        assert_eq!(line(true, Some("router"), 0, false, false), ("bad", "Can't reach your router".into()));
        assert_eq!(line(true, None, 1, false, true), ("warn", "1 alert needs attention".into()));
        assert_eq!(line(true, None, 4, false, false), ("warn", "4 alerts need attention".into()));
        assert_eq!(line(true, None, 2, true, false), ("bad", "2 alerts need attention".into()));
        assert_eq!(line(true, None, 0, false, true), ("warn", "Traffic monitoring needs access".into()));
    }

    #[test]
    fn counts_online_and_asleep_devices() {
        let now = 10_000_000;
        let mut me = device(true, 0);
        me.is_self = true;
        let mut router = device(true, 0);
        router.is_gateway = true;
        let devices = vec![
            me,
            router,
            device(true, now - 1_000),                    // answers pings
            device(true, now - ASLEEP_AFTER_MS - 1),      // only answers ARP: asleep
            device(true, 0),                              // never replied: asleep
            device(false, 0),                             // offline
        ];
        assert_eq!(count_devices(devices.iter(), now), DeviceCounts { online: 5, asleep: 2, total: 6 });
        assert_eq!(count_devices([].iter(), now), DeviceCounts { online: 0, asleep: 0, total: 0 });
    }

    #[test]
    fn prefers_the_routers_rates_while_they_are_current() {
        let now = 1_000_000;
        let router = Some((now - 3_000, 5_000_000, 1_000_000));
        let computer = Some((now - 500, 200_000, 50_000));
        let r = pick_rates(router, computer, now).unwrap();
        assert_eq!((r.down_bps, r.up_bps, r.household), (5_000_000, 1_000_000, true));
        // A router reading that went stale falls back to this computer.
        let stale = Some((now - WAN_FRESH_MS - 1, 5_000_000, 1_000_000));
        let r = pick_rates(stale, computer, now).unwrap();
        assert_eq!((r.down_bps, r.up_bps, r.household), (200_000, 50_000, false));
        // Nothing current at all.
        assert_eq!(pick_rates(stale, Some((now - TRAFFIC_FRESH_MS - 1, 1, 1)), now), None);
        assert_eq!(pick_rates(None, None, now), None);
    }

    #[test]
    fn picks_the_newest_open_alerts() {
        let alerts = vec![
            alert(1, Severity::High, 100, false),
            alert(2, Severity::Info, 900, false),   // a log entry, not an alert to act on
            alert(3, Severity::Low, 300, true),     // acknowledged
            alert(4, Severity::Medium, 500, false),
            alert(5, Severity::Low, 200, false),
            alert(6, Severity::Medium, 400, false),
        ];
        let d = digest_alerts(&alerts, 3);
        assert_eq!(d.open, 4);
        assert!(d.high);
        let ids: Vec<u64> = d.newest.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![4, 6, 5]);
        assert_eq!(d.newest[0].title, "alert 4");
        let quiet = digest_alerts(&alerts[1..3], 3);
        assert_eq!((quiet.open, quiet.high, quiet.newest.len()), (0, false, 0));
    }

    #[test]
    fn latency_uses_only_recent_checks() {
        let now = 10_000_000;
        let health: VecDeque<HealthSample> = [
            sample(now - LATENCY_WINDOW_MS - 10_000, Some(2.0), Some(20.0)),
            sample(now - 30_000, Some(2.5), None),
            sample(now - 10_000, Some(3.0), Some(24.0)),
        ]
        .into();
        assert_eq!(latest_latency(&health, now), (Some(3.0), Some(24.0)));
        assert_eq!(latency_tail(&health, now), vec![(now - 30_000, None), (now - 10_000, Some(24.0))]);
        // The computer slept: the last reading says nothing about now.
        assert_eq!(latest_latency(&health, now + HEALTH_FRESH_MS - 10_000), (Some(3.0), Some(24.0)));
        assert_eq!(latest_latency(&health, now + HEALTH_FRESH_MS - 9_999), (None, None));
        assert_eq!(latest_latency(&VecDeque::new(), now), (None, None));
    }

    #[test]
    fn works_out_allowance_progress() {
        let c = cap_use(25_000_000_000, 100.0, 7);
        assert_eq!((c.cap_bytes, c.since), (100_000_000_000, 7));
        assert!((c.pct - 25.0).abs() < 1e-9);
        assert_eq!(cap_use(5, 0.0, 0).pct, 0.0);
        assert!(cap_use(150_000_000_000, 100.0, 0).pct > 100.0);
    }

    #[test]
    fn finds_local_midnight() {
        let noon = Local.with_ymd_and_hms(2026, 10, 3, 12, 30, 0).unwrap();
        let midnight = Local.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap();
        assert_eq!(local_midnight_ms(noon), Some(midnight.timestamp_millis() as u64));
    }
}

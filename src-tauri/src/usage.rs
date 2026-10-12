//! Household data usage from the router's WAN byte counters. Totals are kept
//! per local hour, so the UI can show days and billing cycles in local time.

use chrono::{DateTime, Datelike, Days, Local, NaiveDate, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const HOUR_MS: u64 = 3_600_000;
const KEEP_MS: u64 = 120 * 24 * HOUR_MS;
/// Readings further apart than this (NetWatch was closed) can't be placed
/// in time reliably, and 32-bit counters may have wrapped more than once.
const MAX_GAP_MS: u64 = 12 * HOUR_MS;
/// Faster than this between two readings is a counter glitch, not traffic.
const MAX_PLAUSIBLE_BPS: u128 = 2_000_000_000;
/// A 32-bit counter only wraps from within this distance of the top to
/// within this distance of zero.
const WRAP_ZONE: u64 = 1 << 30;
/// Small drops are routers re-reporting a slightly stale value, not resets.
const JITTER: u64 = 64 << 20;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Reading {
    pub ts: u64,
    pub rx: u64,
    pub tx: u64,
    /// The router's uptime at `ts`, used to tell a reboot from a counter wrap.
    pub uptime_s: Option<u64>,
    /// Which router the counters came from (its MAC); readings from a
    /// different router can't be compared.
    #[serde(default)]
    pub router: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Usage {
    /// Local hour start (ms since epoch) → [received, sent] bytes.
    pub hours: BTreeMap<u64, [u64; 2]>,
    /// The last counter reading, so a restart can account for the gap.
    pub last: Option<Reading>,
}

pub struct UsageLog {
    path: PathBuf,
    pub usage: Usage,
}

/// What happened between two readings of one counter.
#[derive(Debug, PartialEq)]
pub enum Step {
    Bytes(u64),
    /// A slightly lower reading than before: ignore it and keep the old baseline.
    Jitter,
}

/// Bytes between two counter readings. A drop means a 32-bit counter
/// wrapped (from near the top to near zero), the counters were reset
/// (a big drop), or the router re-reported a slightly stale value (jitter).
pub fn counter_delta(prev: u64, cur: u64) -> Step {
    const TOP: u64 = 1 << 32;
    if cur >= prev {
        Step::Bytes(cur - prev)
    } else if prev < TOP && prev > TOP - WRAP_ZONE && cur < WRAP_ZONE {
        Step::Bytes(cur + TOP - prev)
    } else if prev - cur <= JITTER {
        Step::Jitter
    } else {
        Step::Bytes(cur)
    }
}

/// Start of the local hour containing `ts`.
pub fn hour_start(ts: u64) -> u64 {
    let Some(t) = Local.timestamp_millis_opt(ts as i64).earliest() else {
        return ts - ts % HOUR_MS;
    };
    let floored = t
        .with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0));
    floored.map_or(ts - ts % HOUR_MS, |t| t.timestamp_millis() as u64)
}

/// Local midnight starting the billing cycle that contains `now`, for a
/// plan that renews on `day` of each month (clamped to 1–28).
pub fn cycle_start(now: DateTime<Local>, day: u32) -> Option<DateTime<Local>> {
    let day = day.clamp(1, 28);
    let (mut y, mut m) = (now.year(), now.month());
    if now.day() < day {
        if m == 1 {
            y -= 1;
            m = 12;
        } else {
            m -= 1;
        }
    }
    let date = NaiveDate::from_ymd_opt(y, m, day)?.and_hms_opt(0, 0, 0)?;
    Local.from_local_datetime(&date).earliest()
}

impl UsageLog {
    pub fn load(path: PathBuf) -> Self {
        let usage = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        UsageLog { path, usage }
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_vec(&self.usage) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(tmp, &self.path);
            }
        }
    }

    /// Folds in a counter reading. Returns the bytes received and sent since
    /// the previous reading and the ms between them, or `None` if this
    /// reading only sets a new baseline.
    pub fn record(&mut self, r: Reading) -> Option<(u64, u64, u64)> {
        let prev = self.usage.last.replace(r.clone())?;
        if prev.router != r.router {
            return None;
        }
        let dt = r.ts.checked_sub(prev.ts).filter(|d| *d > 0 && *d <= MAX_GAP_MS)?;
        let rebooted = match (prev.uptime_s, r.uptime_s) {
            (Some(a), Some(b)) => b + 60 < a,
            _ => false,
        };
        let (rx, tx) = if rebooted {
            (r.rx, r.tx)
        } else {
            match (counter_delta(prev.rx, r.rx), counter_delta(prev.tx, r.tx)) {
                (Step::Bytes(rx), Step::Bytes(tx)) => (rx, tx),
                // Keep the higher baseline for the counter that jittered.
                (rx, tx) => {
                    let last = self.usage.last.as_mut().expect("just set");
                    if rx == Step::Jitter {
                        last.rx = prev.rx;
                    }
                    if tx == Step::Jitter {
                        last.tx = prev.tx;
                    }
                    let bytes = |s: Step| if let Step::Bytes(b) = s { b } else { 0 };
                    (bytes(rx), bytes(tx))
                }
            }
        };
        if (rx + tx) as u128 * 8 * 1000 / dt as u128 > MAX_PLAUSIBLE_BPS {
            return None;
        }
        self.add_spread(prev.ts, r.ts, rx, tx);
        Some((rx, tx, dt))
    }

    /// Spreads bytes evenly over the hours between `t0` and `t1`.
    fn add_spread(&mut self, t0: u64, t1: u64, rx: u64, tx: u64) {
        let span = (t1 - t0) as u128;
        let (mut left_rx, mut left_tx) = (rx, tx);
        let mut t = t0;
        while t < t1 {
            let h = hour_start(t);
            let next = (h + HOUR_MS).min(t1).max(t + 1);
            let (part_rx, part_tx) = if next >= t1 {
                (left_rx, left_tx)
            } else {
                let share = (next - t) as u128;
                ((rx as u128 * share / span) as u64, (tx as u128 * share / span) as u64)
            };
            let slot = self.usage.hours.entry(h).or_default();
            slot[0] += part_rx;
            slot[1] += part_tx;
            left_rx -= part_rx.min(left_rx);
            left_tx -= part_tx.min(left_tx);
            t = next;
        }
        let cutoff = t1.saturating_sub(KEEP_MS);
        self.usage.hours.retain(|h, _| *h >= cutoff);
    }

    /// Total bytes (received + sent) in hours starting at or after `since`.
    pub fn total_since(&self, since: u64) -> u64 {
        self.usage.hours.range(since..).map(|(_, v)| v[0] + v[1]).sum()
    }
}

// ------------------------------------------------------------------ forecast

const DAY_MS: u64 = 24 * HOUR_MS;
/// The forecast's "typical day" comes from this many local days before today.
const FORECAST_DAYS: u64 = 7;
/// Fewer complete days than this and there is no forecast yet.
pub const FORECAST_MIN_DAYS: usize = 2;
/// A day NetWatch missed more than this many hours of (it wasn't running)
/// is partial, and would drag the typical day down.
const FORECAST_MAX_MISSING_HOURS: usize = 2;
/// A projected overrun only earns an alert with at least this long left to act on it.
pub const FORECAST_ALERT_DAYS: f64 = 3.0;

/// Where this billing cycle's data use is heading.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Forecast {
    /// Bytes used so far this cycle, as counted since NetWatch began tracking.
    pub used: u64,
    pub cap: u64,
    /// Local midnight the cycle began, and the midnight the next one begins (ms).
    pub cycle_start: u64,
    pub cycle_end: u64,
    /// Time left in the cycle, in days (fractional).
    pub days_left: f64,
    /// How many complete days the typical day is based on.
    pub sample_days: usize,
    /// The median of those days, `None` until there are `FORECAST_MIN_DAYS`.
    pub daily: Option<u64>,
    /// `used` plus a typical day for every day left.
    pub projected: Option<u64>,
    /// NetWatch started tracking after the cycle began, so `used` may be low.
    pub partial: bool,
}

impl Forecast {
    /// On course to pass the allowance before the cycle ends.
    pub fn over(&self) -> bool {
        self.projected.is_some_and(|p| p > self.cap)
    }

    /// Worth an alert: heading over with time left to do something about it.
    /// Once the allowance is already used up, the 100% alert says so.
    pub fn worth_alert(&self) -> bool {
        self.over() && self.used < self.cap && self.days_left >= FORECAST_ALERT_DAYS
    }
}

/// Local midnight that starts the cycle after the one beginning at `start`.
pub fn next_cycle_start(start: DateTime<Local>) -> Option<DateTime<Local>> {
    let (y, m) = if start.month() == 12 { (start.year() + 1, 1) } else { (start.year(), start.month() + 1) };
    let date = NaiveDate::from_ymd_opt(y, m, start.day())?.and_hms_opt(0, 0, 0)?;
    Local.from_local_datetime(&date).earliest()
}

/// The middle value; with an even count, the mean of the two in the middle.
pub fn median(mut values: Vec<u64>) -> Option<u64> {
    values.sort_unstable();
    let n = values.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(values[n / 2]),
        _ => Some(((values[n / 2 - 1] as u128 + values[n / 2] as u128) / 2) as u64),
    }
}

fn local_midnight_ms(day: NaiveDate) -> Option<u64> {
    let t = Local.from_local_datetime(&day.and_hms_opt(0, 0, 0)?).earliest()?;
    Some(t.timestamp_millis() as u64)
}

/// Bytes used between `from` and `to` (one local day), or `None` if more
/// than a couple of its hours have no reading at all. `add_spread` makes an
/// entry for every hour it covers, even a silent one, so a missing hour means
/// NetWatch wasn't watching.
fn day_total(hours: &BTreeMap<u64, [u64; 2]>, from: u64, to: u64) -> Option<u64> {
    let (mut t, mut missing, mut sum) = (from, 0, 0u64);
    while t < to {
        let h = hour_start(t);
        match hours.get(&h) {
            Some(v) => sum += v[0] + v[1],
            None => missing += 1,
        }
        t = h + HOUR_MS;
    }
    (missing <= FORECAST_MAX_MISSING_HOURS).then_some(sum)
}

/// Bytes used on each of the last seven local days before today that
/// NetWatch watched (nearly) all of. Today is left out: it isn't over.
fn complete_days(hours: &BTreeMap<u64, [u64; 2]>, now: DateTime<Local>) -> Vec<u64> {
    let today = now.date_naive();
    (1..=FORECAST_DAYS)
        .filter_map(|back| {
            let day = today.checked_sub_days(Days::new(back))?;
            let from = local_midnight_ms(day)?;
            let to = local_midnight_ms(day.succ_opt()?)?;
            day_total(hours, from, to)
        })
        .collect()
}

/// Projects the current billing cycle's total: what's used so far plus a
/// typical day (the median of the complete days in the last week, so one odd
/// day doesn't dominate) for each day left. `None` only if the cycle's dates
/// can't be worked out; the projection itself waits for two complete days.
pub fn forecast(hours: &BTreeMap<u64, [u64; 2]>, now: DateTime<Local>, cycle_day: u32, cap: u64) -> Option<Forecast> {
    let start = cycle_start(now, cycle_day)?;
    let end = next_cycle_start(start)?;
    let ms = |t: DateTime<Local>| t.timestamp_millis() as u64;
    let (start_ms, end_ms, now_ms) = (ms(start), ms(end), ms(now));
    let used: u64 = hours.range(start_ms..).map(|(_, v)| v[0] + v[1]).sum();
    let days = complete_days(hours, now);
    let sample_days = days.len();
    let daily = if sample_days >= FORECAST_MIN_DAYS { median(days) } else { None };
    // Fractional, so the part of today still to come is counted once: today's
    // use so far is already in `used`.
    let days_left = end_ms.saturating_sub(now_ms) as f64 / DAY_MS as f64;
    Some(Forecast {
        used,
        cap,
        cycle_start: start_ms,
        cycle_end: end_ms,
        days_left,
        sample_days,
        daily,
        projected: daily.map(|d| used + (d as f64 * days_left).round() as u64),
        partial: hours.keys().next().is_some_and(|first| *first > start_ms),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> UsageLog {
        UsageLog {
            path: std::env::temp_dir().join("netwatch-usage-test.json"),
            usage: Usage::default(),
        }
    }

    fn reading(ts: u64, rx: u64, tx: u64, uptime_s: u64) -> Reading {
        Reading { ts, rx, tx, uptime_s: Some(uptime_s), router: Some("gw".into()) }
    }

    #[test]
    fn handles_wraps_resets_and_jitter() {
        assert_eq!(counter_delta(100, 250), Step::Bytes(150));
        // A 32-bit counter near the top wraps around.
        assert_eq!(counter_delta(4_294_967_000, 200), Step::Bytes(496));
        // A big drop that isn't a wrap means the counters were reset.
        assert_eq!(counter_delta(2_000_000_000, 300), Step::Bytes(300));
        // A slightly lower reading near the top is jitter, not a wrap.
        assert_eq!(counter_delta(4_000_000_000, 3_999_000_000), Step::Jitter);
    }

    #[test]
    fn jitter_near_the_top_adds_nothing() {
        let mut l = log();
        let t = 1_700_000_000_000;
        l.record(reading(t, 4_000_000_000, 0, 100));
        // The router briefly re-reports an older value…
        assert_eq!(l.record(reading(t + 60_000, 3_999_500_000, 0, 160)), Some((0, 0, 60_000)));
        // …then carries on from where it really was.
        assert_eq!(l.record(reading(t + 63_000, 4_000_100_000, 0, 163)), Some((100_000, 0, 3_000)));
        assert_eq!(l.total_since(0), 100_000);
    }

    #[test]
    fn a_different_router_starts_a_new_baseline() {
        let mut l = log();
        let t = 1_700_000_000_000;
        l.record(reading(t, 1_000, 0, 100));
        let mut other = reading(t + 3_000, 9_000_000_000, 0, 5);
        other.router = Some("other".into());
        assert_eq!(l.record(other), None);
    }

    #[test]
    fn first_reading_is_a_baseline() {
        let mut l = log();
        let t = 1_700_000_000_000;
        assert_eq!(l.record(reading(t, 1000, 500, 100)), None);
        assert_eq!(l.record(reading(t + 3000, 4000, 1500, 103)), Some((3000, 1000, 3000)));
        assert_eq!(l.total_since(0), 4000);
    }

    #[test]
    fn reboot_counts_from_zero() {
        let mut l = log();
        let t = 1_700_000_000_000;
        l.record(reading(t, 3_000_000_000, 10, 50_000));
        // Uptime went backwards: the router restarted, counters began again.
        assert_eq!(l.record(reading(t + 60_000, 7_000, 20, 30)), Some((7_000, 20, 60_000)));
    }

    #[test]
    fn long_gaps_reset_the_baseline() {
        let mut l = log();
        let t = 1_700_000_000_000;
        l.record(reading(t, 0, 0, 1));
        assert_eq!(l.record(reading(t + MAX_GAP_MS + 1, 9_999, 0, 50_000)), None);
        assert_eq!(l.record(reading(t + MAX_GAP_MS + 1001, 10_999, 0, 50_001)), Some((1000, 0, 1000)));
    }

    #[test]
    fn spreads_gaps_across_hours() {
        let mut l = log();
        let t0 = hour_start(1_700_000_000_000) + 30 * 60_000;
        l.record(reading(t0, 0, 0, 1));
        l.record(reading(t0 + 2 * HOUR_MS, 4_000, 0, 7201));
        let hours: Vec<u64> = l.usage.hours.values().map(|v| v[0]).collect();
        assert_eq!(hours, vec![1_000, 2_000, 1_000]);
        assert_eq!(l.total_since(0), 4_000);
    }

    #[test]
    fn computes_billing_cycle_start() {
        let at = |y, m, d| Local.from_local_datetime(&NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(12, 0, 0).unwrap()).unwrap();
        let s = cycle_start(at(2026, 10, 3), 15).unwrap();
        assert_eq!((s.year(), s.month(), s.day(), s.hour()), (2026, 9, 15, 0));
        let s = cycle_start(at(2026, 10, 20), 15).unwrap();
        assert_eq!((s.month(), s.day()), (10, 15));
        let s = cycle_start(at(2026, 1, 3), 10).unwrap();
        assert_eq!((s.year(), s.month()), (2025, 12));
        let s = cycle_start(at(2026, 3, 1), 31).unwrap();
        assert_eq!((s.month(), s.day()), (2, 28));
    }

    // ---- forecast. Dates sit in July/August, clear of daylight-saving
    // changes in nearly every time zone; hour buckets are made with the same
    // `hour_start` the code under test uses.

    const MB: u64 = 1_000_000;

    fn local(m: u32, d: u32, h: u32) -> DateTime<Local> {
        Local
            .from_local_datetime(&NaiveDate::from_ymd_opt(2026, m, d).unwrap().and_hms_opt(h, 0, 0).unwrap())
            .unwrap()
    }

    fn ms(t: DateTime<Local>) -> u64 {
        t.timestamp_millis() as u64
    }

    /// Gives every hour from `from` up to (not including) `to` the same use.
    fn fill(hours: &mut BTreeMap<u64, [u64; 2]>, from: DateTime<Local>, to: DateTime<Local>, per_hour: u64) {
        let mut t = ms(from);
        while t < ms(to) {
            let h = hour_start(t);
            hours.insert(h, [per_hour, 0]);
            t = h + HOUR_MS;
        }
    }

    /// One whole local day, `per_hour` bytes in each hour.
    fn day(hours: &mut BTreeMap<u64, [u64; 2]>, m: u32, d: u32, per_hour: u64) {
        fill(hours, local(m, d, 0), local(m, d + 1, 0), per_hour);
    }

    /// Days 13–19 July at `per_hour` MB, except `odd`, which gets `odd_mb`.
    fn week(odd: Option<(u32, u64)>, per_hour: u64) -> BTreeMap<u64, [u64; 2]> {
        let mut h = BTreeMap::new();
        for d in 13..=19 {
            let mb = odd.filter(|(od, _)| *od == d).map_or(per_hour, |(_, v)| v);
            day(&mut h, 7, d, mb * MB);
        }
        h
    }

    #[test]
    fn median_takes_the_middle() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![7]), Some(7));
        assert_eq!(median(vec![9, 1, 5]), Some(5));
        // Even counts average the middle pair.
        assert_eq!(median(vec![10, 2, 4, 100]), Some(7));
        assert_eq!(median(vec![u64::MAX, u64::MAX]), Some(u64::MAX));
    }

    #[test]
    fn next_cycle_is_the_same_day_next_month() {
        let s = next_cycle_start(cycle_start(local(7, 20, 12), 15).unwrap()).unwrap();
        assert_eq!((s.month(), s.day(), s.hour()), (8, 15, 0));
        // December rolls into January of the next year.
        let s = next_cycle_start(cycle_start(local(12, 20, 12), 1).unwrap()).unwrap();
        assert_eq!((s.year(), s.month(), s.day()), (2027, 1, 1));
    }

    #[test]
    fn forecast_is_used_plus_a_typical_day_per_day_left() {
        let mut hours = week(None, 1);
        // This morning, 00:00–11:59: twelve hours.
        fill(&mut hours, local(7, 20, 0), local(7, 20, 12), MB);
        let now = local(7, 20, 12);
        let f = forecast(&hours, now, 15, 10_000 * MB).unwrap();
        // Cycle 15 Jul – 15 Aug: used is 15–19 Jul (5 days) and this morning.
        assert_eq!((f.used, f.sample_days, f.daily), ((5 * 24 + 12) * MB, 7, Some(24 * MB)));
        assert_eq!(f.cycle_start, ms(local(7, 15, 0)));
        assert_eq!(f.cycle_end, ms(local(8, 15, 0)));
        let left = (ms(local(8, 15, 0)) - ms(now)) as f64 / DAY_MS as f64;
        assert!((f.days_left - left).abs() < 1e-9 && (24.9..=26.1).contains(&f.days_left));
        assert_eq!(f.projected, Some(f.used + (24.0 * MB as f64 * left).round() as u64));
        assert!(!f.partial && !f.over() && !f.worth_alert());
    }

    #[test]
    fn one_odd_day_does_not_move_the_typical_day() {
        // A counter glitch made one day 50 times too big.
        let odd = forecast(&week(Some((16, 50)), 1), local(7, 20, 12), 15, 1 << 50).unwrap();
        assert_eq!(odd.daily, Some(24 * MB));
        // The same shape with an even count averages the middle pair: 6 days.
        let mut hours = week(Some((16, 50)), 1);
        hours.retain(|h, _| *h >= ms(local(7, 14, 0)));
        assert_eq!(forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap().sample_days, 6);
        assert_eq!(forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap().daily, Some(24 * MB));
        let mut hours = BTreeMap::new();
        for (d, mb) in [(17, 1), (18, 3), (19, 2), (16, 90)] {
            day(&mut hours, 7, d, mb * MB);
        }
        // Days 16–19: sorted 1, 2, 3, 90 per hour → mean of 2 and 3 → 2.5 MB an hour.
        assert_eq!(forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap().daily, Some(60 * MB));
    }

    #[test]
    fn no_forecast_until_two_complete_days() {
        let mut hours = BTreeMap::new();
        let now = local(7, 20, 12);
        assert_eq!(forecast(&hours, now, 15, 100 * MB).unwrap().projected, None);
        // Today alone doesn't count: it isn't over.
        fill(&mut hours, local(7, 20, 0), local(7, 20, 12), MB);
        let f = forecast(&hours, now, 15, 100 * MB).unwrap();
        assert_eq!((f.sample_days, f.daily, f.projected, f.used), (0, None, None, 12 * MB));
        day(&mut hours, 7, 19, MB);
        let f = forecast(&hours, now, 15, 100 * MB).unwrap();
        assert_eq!((f.sample_days, f.projected), (1, None));
        assert!(!f.over() && !f.worth_alert());
        day(&mut hours, 7, 18, MB);
        let f = forecast(&hours, now, 15, 100 * MB).unwrap();
        assert_eq!(f.sample_days, 2);
        assert!(f.projected.is_some());
    }

    #[test]
    fn partial_days_and_partial_cycles_are_left_out() {
        // NetWatch started at 10:00 on the 17th, in the middle of the cycle.
        let mut hours = BTreeMap::new();
        fill(&mut hours, local(7, 17, 10), local(7, 20, 12), MB);
        let f = forecast(&hours, local(7, 20, 12), 15, 100_000 * MB).unwrap();
        // The 17th is only part watched; the 18th and 19th are whole.
        assert!(f.partial);
        assert_eq!((f.sample_days, f.daily), (2, Some(24 * MB)));
        assert_eq!(f.used, (14 + 24 + 24 + 12) * MB);
        // A cycle that began after tracking did is not partial.
        let f = forecast(&week(None, 1), local(7, 20, 12), 18, 100 * MB).unwrap();
        assert!(!f.partial);
        // A day with a long gap in it (NetWatch was closed) is skipped…
        let mut hours = week(None, 1);
        for d in [15, 17] {
            for h in 2..14 {
                hours.remove(&hour_start(ms(local(7, d, h))));
            }
        }
        assert_eq!(forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap().sample_days, 5);
        // …but one or two missing hours are forgiven, three are not.
        let mut hours = week(None, 1);
        hours.remove(&hour_start(ms(local(7, 18, 5))));
        hours.remove(&hour_start(ms(local(7, 18, 6))));
        let f = forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap();
        assert_eq!((f.sample_days, f.daily), (7, Some(24 * MB)));
        hours.remove(&hour_start(ms(local(7, 18, 7))));
        assert_eq!(forecast(&hours, local(7, 20, 12), 15, 1 << 50).unwrap().sample_days, 6);
    }

    #[test]
    fn a_new_cycle_starts_from_zero_but_keeps_the_typical_day() {
        // 2 am on the first: the cycle is two hours old, July was 31 days of 2 MB an hour.
        let mut hours = BTreeMap::new();
        fill(&mut hours, local(7, 1, 0), local(8, 1, 0), 2 * MB);
        fill(&mut hours, local(8, 1, 0), local(8, 1, 2), 3 * MB);
        let now = local(8, 1, 2);
        let f = forecast(&hours, now, 1, 100_000 * MB).unwrap();
        assert_eq!((f.cycle_start, f.cycle_end), (ms(local(8, 1, 0)), ms(local(9, 1, 0))));
        assert_eq!((f.used, f.sample_days, f.daily), (6 * MB, 7, Some(48 * MB)));
        assert!((29.9..=31.0).contains(&f.days_left));
        let left = (ms(local(9, 1, 0)) - ms(now)) as f64 / DAY_MS as f64;
        assert_eq!(f.projected, Some(6 * MB + (48.0 * MB as f64 * left).round() as u64));
        assert!(!f.partial);
    }

    #[test]
    fn over_and_under_the_allowance() {
        let hours = week(None, 1); // 24 MB a day; 5 cycle days used = 120 MB
        let now = local(7, 20, 0);
        let f = |cap_mb: u64| forecast(&hours, now, 15, cap_mb * MB).unwrap();
        // 120 MB + about 26 days × 24 MB ≈ 740 MB.
        let under = f(2_000);
        assert!(!under.over() && !under.worth_alert());
        let over = f(500);
        assert!(over.over() && over.worth_alert());
        // Already past the allowance: the 100% alert covers it.
        let spent = f(100);
        assert!(spent.over() && !spent.worth_alert());
        // Exactly on the allowance is not over it.
        let p = under.projected.unwrap();
        assert!(!forecast(&hours, now, 15, p).unwrap().over());
        assert!(forecast(&hours, now, 15, p - 1).unwrap().over());
    }

    #[test]
    fn alerts_need_three_days_left() {
        let f = |used, days_left, projected| Forecast {
            used,
            cap: 100,
            cycle_start: 0,
            cycle_end: 0,
            days_left,
            sample_days: 7,
            daily: Some(1),
            projected,
            partial: false,
        };
        assert!(f(50, 3.0, Some(101)).worth_alert());
        assert!(!f(50, 2.9, Some(101)).worth_alert());
        assert!(!f(50, 10.0, Some(100)).worth_alert());
        assert!(!f(100, 10.0, Some(150)).worth_alert());
        assert!(!f(50, 10.0, None).worth_alert());
    }
}

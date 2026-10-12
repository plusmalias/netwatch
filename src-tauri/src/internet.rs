//! The internet side: public address and ISP lookup, and the speed test
//! (on demand or on a schedule) against Cloudflare. Both are the only places
//! NetWatch talks to a third party besides the threat-feed downloads.

use chrono::{Datelike, Days, Local, TimeZone, Weekday};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::{Duration, Instant};

const SPEED_HOST: &str = "https://speed.cloudflare.com";

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PublicInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    /// ISP as "AS1234 Name".
    pub org: Option<String>,
    pub checked: u64,
}

pub fn lookup_public(now: u64) -> Result<PublicInfo, String> {
    let body = ureq::get("https://ipinfo.io/json")
        .timeout(Duration::from_secs(6))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(String::from);
    Ok(PublicInfo {
        ip: s("ip").ok_or("no address in reply")?,
        hostname: s("hostname"),
        city: s("city"),
        region: s("region"),
        country: s("country"),
        org: s("org"),
        checked: now,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SpeedResult {
    pub ts: u64,
    pub down_mbps: f64,
    pub up_mbps: f64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    /// Data the test used, which matters on metered connections.
    pub bytes_used: u64,
    /// Cloudflare data centre, e.g. "SYD".
    pub server: Option<String>,
    /// Started by the schedule rather than by the user. (The fields from here
    /// on are newer than the saved history, which lacks them.)
    #[serde(default)]
    pub scheduled: bool,
    /// Ran the light test, which moves less data and reads a little less exactly.
    #[serde(default)]
    pub light: bool,
}

fn mbps(bytes: u64, d: Duration) -> f64 {
    bytes as f64 * 8.0 / d.as_secs_f64().max(1e-3) / 1e6
}

fn download(agent: &ureq::Agent, bytes: u64) -> Result<(u64, Duration), String> {
    let resp = agent
        .get(&format!("{SPEED_HOST}/__down?bytes={bytes}"))
        .timeout(Duration::from_secs(60))
        .call()
        .map_err(|e| e.to_string())?;
    let mut reader = resp.into_reader();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0u64;
    let mut start = None;
    loop {
        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        // Time from the first byte, so connection setup doesn't count.
        start.get_or_insert_with(Instant::now);
        got += n as u64;
    }
    Ok((got, start.map_or(Duration::ZERO, |s| s.elapsed())))
}

fn upload(agent: &ureq::Agent, bytes: u64) -> Result<Duration, String> {
    let body = vec![b'0'; bytes as usize];
    let t = Instant::now();
    agent
        .post(&format!("{SPEED_HOST}/__up"))
        .timeout(Duration::from_secs(60))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&body)
        .map_err(|e| e.to_string())?;
    Ok(t.elapsed())
}

/// Sizes the main transfer to take about `secs` at the rate a small probe saw.
fn sized(probe_mbps: f64, secs: f64, min: u64, max: u64) -> u64 {
    ((probe_mbps * 1e6 / 8.0 * secs) as u64).clamp(min, max)
}

/// What a speed test moves: a small probe to gauge the link, then one main
/// transfer sized to take about `secs` at the probed rate, kept within
/// `min..=max` bytes. Each direction has its own.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Plan {
    down_probe: u64,
    down_secs: f64,
    down_min: u64,
    down_max: u64,
    up_probe: u64,
    up_secs: f64,
    up_min: u64,
    up_max: u64,
}

/// The on-demand test: at most ~37 MB.
pub const FULL: Plan = Plan {
    down_probe: 1_000_000,
    down_secs: 6.0,
    down_min: 2_000_000,
    down_max: 25_000_000,
    up_probe: 500_000,
    up_secs: 5.0,
    up_min: 1_000_000,
    up_max: 10_000_000,
};

/// For scheduled tests on a metered link: at most ~10 MB. Shorter transfers
/// finish before the link has fully ramped up, so it reads a little low.
pub const LIGHT: Plan = Plan {
    down_probe: 500_000,
    down_secs: 2.0,
    down_min: 1_000_000,
    down_max: 6_000_000,
    up_probe: 250_000,
    up_secs: 2.0,
    up_min: 500_000,
    up_max: 3_000_000,
};

impl Plan {
    pub fn new(light: bool) -> Plan {
        if light {
            LIGHT
        } else {
            FULL
        }
    }
}

/// Measures latency, download and upload. Calls `progress(phase, mbps)` as
/// it goes. A full test uses at most ~38 MB and a light one ~10 MB, and
/// both use less on slow links.
pub fn speed_test(now: u64, light: bool, mut progress: impl FnMut(&str, Option<f64>)) -> Result<SpeedResult, String> {
    let plan = Plan::new(light);
    let agent = ureq::AgentBuilder::new().build();
    let mut used = 0u64;

    progress("latency", None);
    let trace = agent
        .get(&format!("{SPEED_HOST}/cdn-cgi/trace"))
        .timeout(Duration::from_secs(8))
        .call()
        .map_err(|e| format!("Can't reach the speed test server: {e}"))?
        .into_string()
        .unwrap_or_default();
    let server = trace
        .lines()
        .find_map(|l| l.strip_prefix("colo="))
        .map(String::from);
    // The connection is warm now, so each tiny request costs about one round trip.
    let mut rtts = Vec::new();
    for _ in 0..6 {
        let t = Instant::now();
        if download(&agent, 0).is_ok() {
            rtts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
    }
    if rtts.is_empty() {
        return Err("The speed test server didn't respond.".into());
    }
    let jitter = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (rtts.len().max(2) - 1) as f64;
    rtts.sort_by(|a, b| a.total_cmp(b));
    let latency = rtts[rtts.len() / 2];

    progress("download", None);
    let (b, d) = download(&agent, plan.down_probe)?;
    used += b;
    let mut down = mbps(b, d);
    progress("download", Some(down));
    let size = sized(down, plan.down_secs, plan.down_min, plan.down_max);
    let (b, d) = download(&agent, size)?;
    used += b;
    down = mbps(b, d);
    progress("download", Some(down));

    progress("upload", None);
    let probe = plan.up_probe;
    let d = upload(&agent, probe)?;
    used += probe;
    let mut up = mbps(probe, d);
    progress("upload", Some(up));
    let size = sized(up, plan.up_secs, plan.up_min, plan.up_max);
    let d = upload(&agent, size)?;
    used += size;
    up = mbps(size, d);
    progress("upload", Some(up));

    Ok(SpeedResult {
        ts: now,
        down_mbps: (down * 10.0).round() / 10.0,
        up_mbps: (up * 10.0).round() / 10.0,
        latency_ms: (latency * 10.0).round() / 10.0,
        jitter_ms: (jitter * 10.0).round() / 10.0,
        bytes_used: used,
        server,
        scheduled: false,
        light,
    })
}

// ------------------------------------------------------------------ schedule

/// Scheduled tests run at this local hour, so they don't compete with anyone online.
const SLOT_HOUR: u32 = 3;
/// A weekly test runs on this day.
const WEEKLY_DAY: Weekday = Weekday::Mon;

/// How often a schedule ("daily" or "weekly") runs, or `None` for "off" and anything else.
fn period_ms(schedule: &str) -> Option<u64> {
    match schedule {
        "daily" => Some(24 * 3_600_000),
        "weekly" => Some(7 * 24 * 3_600_000),
        _ => None,
    }
}

/// The first 03:00 local (on Mondays only, for "weekly") strictly after `after`.
fn slot_after(schedule: &str, after: u64) -> Option<u64> {
    let first = Local.timestamp_millis_opt(after as i64).earliest()?.date_naive();
    (0..=8u64).find_map(|i| {
        let day = first.checked_add_days(Days::new(i))?;
        if schedule == "weekly" && day.weekday() != WEEKLY_DAY {
            return None;
        }
        // A day whose 03:00 doesn't exist (a clock change) is skipped.
        let at = Local.from_local_datetime(&day.and_hms_opt(SLOT_HOUR, 0, 0)?).earliest()?;
        Some(at.timestamp_millis() as u64).filter(|t| *t > after)
    })
}

/// When the next scheduled test is due, in ms since the epoch (wall-clock
/// time, so a sleeping Mac still finds it due when it wakes). `anchor` is
/// when the schedule was switched on, so turning it on at 15:00 doesn't
/// count this morning's 03:00 as missed. `last_run` is when the last test
/// started; the next one waits at least half a period after it, so a late
/// catch-up isn't followed by the regular slot minutes later.
pub fn next_scheduled(schedule: &str, anchor: Option<u64>, last_run: Option<u64>) -> Option<u64> {
    let gap = period_ms(schedule)? / 2;
    let after = [anchor, last_run.map(|t| t + gap)].into_iter().flatten().max()?;
    slot_after(schedule, after)
}

/// What stops a due test from starting.
#[derive(Clone, Copy, Debug, Default)]
pub struct Gate {
    /// The internet or the router is down.
    pub outage: bool,
    /// Another speed test is in progress.
    pub running: bool,
    /// The connection is known to be up right now (not just after waking).
    pub online: bool,
}

/// Whether a scheduled test should start now.
pub fn is_due(schedule: &str, anchor: Option<u64>, last_run: Option<u64>, now: u64, gate: Gate) -> bool {
    gate.online && !gate.outage && !gate.running && next_scheduled(schedule, anchor, last_run).is_some_and(|t| now >= t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Timelike};

    #[test]
    fn sizes_transfers_to_the_link() {
        // 8 Mb/s for 6 s is 6 MB.
        assert_eq!(sized(8.0, 6.0, 2_000_000, 25_000_000), 6_000_000);
        assert_eq!(sized(0.1, 6.0, 2_000_000, 25_000_000), 2_000_000);
        assert_eq!(sized(900.0, 6.0, 2_000_000, 25_000_000), 25_000_000);
    }

    #[test]
    fn computes_megabits() {
        assert_eq!(mbps(1_000_000, Duration::from_secs(1)), 8.0);
    }

    #[test]
    fn full_test_keeps_its_sizes() {
        assert_eq!(Plan::new(false), FULL);
        assert_eq!(
            (FULL.down_probe, FULL.down_secs, FULL.down_min, FULL.down_max),
            (1_000_000, 6.0, 2_000_000, 25_000_000)
        );
        assert_eq!((FULL.up_probe, FULL.up_secs, FULL.up_min, FULL.up_max), (500_000, 5.0, 1_000_000, 10_000_000));
        assert_eq!(max_bytes(FULL), 36_500_000);
        assert!(max_bytes(FULL) <= 38_000_000);
    }

    #[test]
    fn light_test_stays_within_ten_megabytes() {
        assert_eq!(Plan::new(true), LIGHT);
        assert_eq!(max_bytes(LIGHT), 9_750_000);
        assert!(max_bytes(LIGHT) <= 10_000_000);
        assert!(max_bytes(LIGHT) * 3 < max_bytes(FULL));
        // Every piece is smaller than the full test's, and the main transfers
        // are sized the same way, only shorter.
        assert!(LIGHT.down_probe < FULL.down_probe && LIGHT.up_probe < FULL.up_probe);
        assert!(LIGHT.down_max < FULL.down_max && LIGHT.up_max < FULL.up_max);
        assert!(LIGHT.down_min <= LIGHT.down_max && LIGHT.up_min <= LIGHT.up_max);
        // Whatever the link does, a light transfer stays inside its limits.
        for mbps in [0.01, 1.0, 10.0, 50.0, 900.0] {
            let d = sized(mbps, LIGHT.down_secs, LIGHT.down_min, LIGHT.down_max);
            let u = sized(mbps, LIGHT.up_secs, LIGHT.up_min, LIGHT.up_max);
            assert!((LIGHT.down_min..=LIGHT.down_max).contains(&d) && (LIGHT.up_min..=LIGHT.up_max).contains(&u));
        }
        // 10 Mb/s for 2 s is 2.5 MB.
        assert_eq!(sized(10.0, LIGHT.down_secs, LIGHT.down_min, LIGHT.down_max), 2_500_000);
    }

    #[test]
    fn saved_speed_tests_from_before_the_schedule_still_load() {
        let old = r#"[{"ts":1,"down_mbps":20.5,"up_mbps":4.1,"latency_ms":55.0,"jitter_ms":3.0,"bytes_used":30000000,"server":"SYD"}]"#;
        let list: Vec<SpeedResult> = serde_json::from_str(old).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].down_mbps, list[0].scheduled, list[0].light), (20.5, false, false));
    }

    // ---- schedule. July dates, clear of clock changes in nearly every zone.
    // 2026-07-20 is a Monday.

    fn on(month: u32, d: u32, h: u32, m: u32) -> u64 {
        let t = NaiveDate::from_ymd_opt(2026, month, d).unwrap().and_hms_opt(h, m, 0).unwrap();
        Local.from_local_datetime(&t).unwrap().timestamp_millis() as u64
    }

    /// A time in July.
    fn at(d: u32, h: u32, m: u32) -> u64 {
        on(7, d, h, m)
    }

    /// The most data a plan can use (the transfers, not the small requests around them).
    fn max_bytes(p: Plan) -> u64 {
        p.down_probe + p.down_max + p.up_probe + p.up_max
    }

    const OK: Gate = Gate { outage: false, running: false, online: true };

    #[test]
    fn slots_are_at_three_in_the_morning() {
        assert_eq!(Local.timestamp_millis_opt(at(20, 0, 0) as i64).unwrap().weekday(), Weekday::Mon);
        let next = |after| Local.timestamp_millis_opt(slot_after("daily", after).unwrap() as i64).unwrap();
        assert_eq!((next(at(20, 2, 59)).day(), next(at(20, 2, 59)).hour()), (20, 3));
        // Strictly after: at 03:00 sharp the next slot is tomorrow's.
        assert_eq!(next(at(20, 3, 0)).day(), 21);
        assert_eq!(next(at(20, 15, 0)).day(), 21);
        // Month ends are no trouble.
        assert_eq!(slot_after("daily", at(31, 4, 0)), Some(on(8, 1, 3, 0)));
    }

    #[test]
    fn daily_runs_once_a_day() {
        // Turned on Monday afternoon: nothing until Tuesday 03:00.
        let anchor = Some(at(20, 15, 0));
        assert_eq!(next_scheduled("daily", anchor, None), Some(at(21, 3, 0)));
        assert!(!is_due("daily", anchor, None, at(21, 2, 59), OK));
        assert!(is_due("daily", anchor, None, at(21, 3, 0), OK));
        // It ran at 03:01; Wednesday's slot is next, and not due before then.
        let last = Some(at(21, 3, 1));
        assert_eq!(next_scheduled("daily", anchor, last), Some(at(22, 3, 0)));
        assert!(!is_due("daily", anchor, last, at(21, 23, 59), OK));
        assert!(is_due("daily", anchor, last, at(22, 3, 0), OK));
    }

    #[test]
    fn a_missed_slot_runs_at_the_next_chance_once() {
        // The Mac slept through Wednesday's 03:00 and woke at 09:00.
        let anchor = Some(at(20, 15, 0));
        let last = Some(at(21, 3, 1));
        assert!(is_due("daily", anchor, last, at(22, 9, 0), OK));
        // It runs, so it isn't due again that day or at the next 03:00 minutes later…
        let last = Some(at(22, 9, 0));
        assert!(!is_due("daily", anchor, last, at(22, 9, 1), OK));
        assert!(!is_due("daily", anchor, last, at(22, 23, 0), OK));
        assert_eq!(next_scheduled("daily", anchor, last), Some(at(23, 3, 0)));
        // …even after several days asleep: one test, then back to the routine.
        let last = Some(at(21, 3, 1));
        assert!(is_due("daily", anchor, last, at(26, 18, 0), OK));
        assert_eq!(next_scheduled("daily", anchor, Some(at(26, 18, 0))), Some(at(28, 3, 0)));
    }

    #[test]
    fn a_catch_up_just_before_the_slot_is_not_followed_by_another() {
        let anchor = Some(at(20, 15, 0));
        // Woke at 02:50 and caught up; the 03:00 slot is ten minutes away.
        let last = Some(at(22, 2, 50));
        assert!(!is_due("daily", anchor, last, at(22, 3, 0), OK));
        assert!(!is_due("daily", anchor, last, at(22, 3, 30), OK));
        assert_eq!(next_scheduled("daily", anchor, last), Some(at(23, 3, 0)));
    }

    #[test]
    fn weekly_runs_on_monday_mornings() {
        // Turned on Wednesday 22 July: the first run is Monday 27 July.
        let anchor = Some(at(22, 10, 0));
        assert_eq!(next_scheduled("weekly", anchor, None), Some(at(27, 3, 0)));
        assert!(!is_due("weekly", anchor, None, at(26, 23, 0), OK));
        assert!(is_due("weekly", anchor, None, at(27, 3, 0), OK));
        // Then a week later, not the next day.
        let last = Some(at(27, 3, 1));
        assert!(!is_due("weekly", anchor, last, at(28, 3, 0), OK));
        assert_eq!(next_scheduled("weekly", anchor, last), Some(on(8, 3, 3, 0)));
        // Asleep on Monday, awake on Thursday: runs then, once.
        assert!(is_due("weekly", anchor, None, at(30, 12, 0), OK));
        assert!(!is_due("weekly", anchor, Some(at(30, 12, 0)), at(31, 12, 0), OK));
        // Switched on a Sunday night: the very next morning.
        assert_eq!(next_scheduled("weekly", Some(at(26, 22, 0)), None), Some(at(27, 3, 0)));
    }

    #[test]
    fn nothing_starts_during_an_outage_or_another_test() {
        let anchor = Some(at(20, 15, 0));
        let now = at(21, 4, 0);
        assert!(is_due("daily", anchor, None, now, OK));
        assert!(!is_due("daily", anchor, None, now, Gate { outage: true, ..OK }));
        assert!(!is_due("daily", anchor, None, now, Gate { running: true, ..OK }));
        // Not known to be online (just woke, no fresh reply yet).
        assert!(!is_due("daily", anchor, None, now, Gate { online: false, ..OK }));
        // The slot isn't used up by waiting: it runs once the outage is over.
        assert!(is_due("daily", anchor, None, at(21, 9, 30), OK));
    }

    #[test]
    fn off_and_unknown_schedules_never_run() {
        for s in ["off", "", "hourly"] {
            assert_eq!(next_scheduled(s, Some(0), None), None);
            assert!(!is_due(s, Some(0), None, at(30, 12, 0), OK));
        }
        // With nothing to count from there is no next time either.
        assert_eq!(next_scheduled("daily", None, None), None);
    }
}

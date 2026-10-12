//! Connection health: periodic latency to the router and the internet, and
//! an outage log built from consecutive failed checks.

use serde::{Deserialize, Serialize};

/// Internet targets: Cloudflare and Google DNS. Either answering counts.
pub const INTERNET_TARGETS: [[u8; 4]; 2] = [[1, 1, 1, 1], [8, 8, 8, 8]];
/// Failed checks in a row before the connection counts as down.
const FAILS_TO_DECLARE: u32 = 3;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct HealthSample {
    pub ts: u64,
    pub gateway_ms: Option<f32>,
    pub internet_ms: Option<f32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Outage {
    pub start: u64,
    /// `None` while it's still going on.
    pub end: Option<u64>,
    /// "internet" when the router answered but the internet didn't;
    /// "router" when the router didn't answer either.
    pub kind: String,
}

#[derive(Debug, PartialEq)]
pub enum OutageEvent {
    Started(Outage),
    Ended(Outage),
}

#[derive(Default)]
pub struct OutageTracker {
    fails: u32,
    first_fail: u64,
    last_ts: u64,
    open: Option<Outage>,
}

impl OutageTracker {
    /// Feeds one check. `interval_ms` is the normal gap between checks; a much
    /// longer gap means the computer slept, which isn't an outage.
    pub fn update(&mut self, s: &HealthSample, interval_ms: u64) -> Option<OutageEvent> {
        let slept = self.last_ts > 0 && s.ts.saturating_sub(self.last_ts) > interval_ms * 3;
        self.last_ts = s.ts;
        if slept {
            self.fails = 0;
        }
        if s.internet_ms.is_some() {
            self.fails = 0;
            let mut o = self.open.take()?;
            o.end = Some(s.ts);
            return Some(OutageEvent::Ended(o));
        }
        if self.fails == 0 {
            self.first_fail = s.ts;
        }
        self.fails += 1;
        if self.fails >= FAILS_TO_DECLARE && self.open.is_none() {
            let o = Outage {
                start: self.first_fail,
                end: None,
                kind: if s.gateway_ms.is_some() { "internet" } else { "router" }.into(),
            };
            self.open = Some(o.clone());
            return Some(OutageEvent::Started(o));
        }
        None
    }

    pub fn current(&self) -> Option<&Outage> {
        self.open.as_ref()
    }
}

/// `125_000` → `2m 5s`
pub fn fmt_duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: u64, gw: bool, inet: bool) -> HealthSample {
        HealthSample {
            ts,
            gateway_ms: gw.then_some(3.0),
            internet_ms: inet.then_some(30.0),
        }
    }

    #[test]
    fn declares_outage_after_three_failures_and_closes_it() {
        let mut t = OutageTracker::default();
        assert_eq!(t.update(&sample(0, true, true), 10_000), None);
        assert_eq!(t.update(&sample(10_000, true, false), 10_000), None);
        assert_eq!(t.update(&sample(20_000, true, false), 10_000), None);
        let started = t.update(&sample(30_000, true, false), 10_000);
        assert_eq!(
            started,
            Some(OutageEvent::Started(Outage { start: 10_000, end: None, kind: "internet".into() }))
        );
        assert_eq!(t.update(&sample(40_000, false, false), 10_000), None);
        match t.update(&sample(50_000, true, true), 10_000) {
            Some(OutageEvent::Ended(o)) => assert_eq!((o.start, o.end), (10_000, Some(50_000))),
            other => panic!("expected end, got {other:?}"),
        }
        assert!(t.current().is_none());
    }

    #[test]
    fn a_blip_or_sleep_is_not_an_outage() {
        let mut t = OutageTracker::default();
        t.update(&sample(0, true, false), 10_000);
        t.update(&sample(10_000, true, false), 10_000);
        assert_eq!(t.update(&sample(20_000, true, true), 10_000), None);
        t.update(&sample(30_000, false, false), 10_000);
        t.update(&sample(40_000, false, false), 10_000);
        // Woke from sleep 10 minutes later: the failure count starts over.
        assert_eq!(t.update(&sample(640_000, false, false), 10_000), None);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(fmt_duration(42_000), "42s");
        assert_eq!(fmt_duration(125_000), "2m 5s");
        assert_eq!(fmt_duration(3_720_000), "1h 2m");
    }
}

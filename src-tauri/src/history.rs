//! Long-term connection history: five-minute buckets of latency, packet
//! loss and whole-network traffic, kept for 30 days.

use crate::health::HealthSample;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;

const BUCKET_MS: u64 = 5 * 60_000;
const KEEP: usize = 30 * 24 * 12;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Bucket {
    /// Bucket start, ms since epoch.
    pub t: u64,
    /// Connection checks in the bucket, and how many reached the internet.
    pub checks: u32,
    pub ok: u32,
    pub inet_sum: f32,
    pub inet_max: f32,
    pub gw_sum: f32,
    pub gw_n: u32,
    /// Whole-network bytes from the router's counters.
    pub rx: u64,
    pub tx: u64,
}

/// A bucket summarised for charts: averages instead of sums.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Point {
    pub t: u64,
    pub inet_ms: Option<f32>,
    pub inet_max: Option<f32>,
    pub gateway_ms: Option<f32>,
    /// Share of checks that failed, 0–100.
    pub loss: Option<f32>,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub rx: u64,
    pub tx: u64,
}

pub struct History {
    path: PathBuf,
    buckets: VecDeque<Bucket>,
    dirty: bool,
}

impl History {
    pub fn load(path: PathBuf) -> Self {
        let buckets = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        History { path, buckets, dirty: false }
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        if let Ok(json) = serde_json::to_vec(&self.buckets) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(tmp, &self.path);
                self.dirty = false;
            }
        }
    }

    fn bucket(&mut self, ts: u64) -> &mut Bucket {
        let t = ts - ts % BUCKET_MS;
        if self.buckets.back().is_none_or(|b| b.t < t) {
            self.buckets.push_back(Bucket { t, ..Default::default() });
            while self.buckets.len() > KEEP {
                self.buckets.pop_front();
            }
        }
        self.dirty = true;
        // Late data for an older bucket lands in the newest one; it's at most seconds late.
        self.buckets.back_mut().expect("just pushed")
    }

    pub fn add_health(&mut self, s: &HealthSample) {
        let b = self.bucket(s.ts);
        b.checks += 1;
        if let Some(ms) = s.internet_ms {
            b.ok += 1;
            b.inet_sum += ms;
            b.inet_max = b.inet_max.max(ms);
        }
        if let Some(ms) = s.gateway_ms {
            b.gw_n += 1;
            b.gw_sum += ms;
        }
    }

    pub fn add_bytes(&mut self, ts: u64, rx: u64, tx: u64) {
        let b = self.bucket(ts);
        b.rx += rx;
        b.tx += tx;
    }

    /// Buckets since `since`, merged into steps of `step_ms` (a multiple of five minutes).
    pub fn points(&self, since: u64, step_ms: u64) -> Vec<Point> {
        let step = step_ms.max(BUCKET_MS);
        let mut out: Vec<(u64, Bucket)> = Vec::new();
        for b in self.buckets.iter().filter(|b| b.t >= since) {
            let t = b.t - b.t % step;
            match out.last_mut() {
                Some((lt, acc)) if *lt == t => {
                    acc.checks += b.checks;
                    acc.ok += b.ok;
                    acc.inet_sum += b.inet_sum;
                    acc.inet_max = acc.inet_max.max(b.inet_max);
                    acc.gw_sum += b.gw_sum;
                    acc.gw_n += b.gw_n;
                    acc.rx += b.rx;
                    acc.tx += b.tx;
                }
                _ => out.push((t, *b)),
            }
        }
        let secs = (step / 1000).max(1);
        out.into_iter()
            .map(|(t, b)| Point {
                t,
                inet_ms: (b.ok > 0).then(|| b.inet_sum / b.ok as f32),
                inet_max: (b.ok > 0).then_some(b.inet_max),
                gateway_ms: (b.gw_n > 0).then(|| b.gw_sum / b.gw_n as f32),
                loss: (b.checks > 0).then(|| (b.checks - b.ok) as f32 * 100.0 / b.checks as f32),
                rx_bps: b.rx * 8 / secs,
                tx_bps: b.tx * 8 / secs,
                rx: b.rx,
                tx: b.tx,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hist() -> History {
        History {
            path: std::env::temp_dir().join("netwatch-history-test.json"),
            buckets: VecDeque::new(),
            dirty: false,
        }
    }

    #[test]
    fn buckets_and_merges_samples() {
        let mut h = hist();
        let t0 = 1_700_000_100_000 - 1_700_000_100_000 % (2 * BUCKET_MS);
        h.add_health(&HealthSample { ts: t0 + 1_000, gateway_ms: Some(4.0), internet_ms: Some(40.0) });
        h.add_health(&HealthSample { ts: t0 + 11_000, gateway_ms: Some(6.0), internet_ms: None });
        h.add_bytes(t0 + 12_000, 3_000, 1_000);
        h.add_health(&HealthSample { ts: t0 + BUCKET_MS + 1_000, gateway_ms: Some(5.0), internet_ms: Some(60.0) });
        let p = h.points(0, BUCKET_MS);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].inet_ms, Some(40.0));
        assert_eq!(p[0].loss, Some(50.0));
        assert_eq!(p[0].gateway_ms, Some(5.0));
        assert_eq!(p[0].rx, 3_000);
        // Merged into one 10-minute step.
        let p = h.points(0, 2 * BUCKET_MS);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].inet_ms, Some(50.0));
        assert_eq!(p[0].inet_max, Some(60.0));
        assert!((p[0].loss.unwrap() - 33.33).abs() < 0.1);
    }
}

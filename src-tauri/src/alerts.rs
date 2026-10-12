use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Alert {
    pub id: u64,
    pub ts: u64,
    pub last_ts: u64,
    pub count: u32,
    pub severity: Severity,
    pub kind: String,
    /// What the alert is about (an IP, MAC, domain…); repeats with the same kind+key are merged.
    pub key: String,
    pub title: String,
    pub detail: String,
    pub acknowledged: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlertDraft {
    pub severity: Severity,
    pub kind: &'static str,
    pub key: String,
    pub title: String,
    pub detail: String,
}

const MERGE_WINDOW_MS: u64 = 15 * 60 * 1000;
const MAX_ALERTS: usize = 1000;

pub struct AlertLog {
    path: PathBuf,
    pub alerts: Vec<Alert>,
}

impl AlertLog {
    pub fn load(path: PathBuf) -> Self {
        let alerts = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        AlertLog { path, alerts }
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_vec(&self.alerts) {
            let _ = std::fs::write(&self.path, json);
        }
    }

    /// Records the alert, merging it into a recent unacknowledged one with the
    /// same kind and key. Returns the stored alert and whether it is new.
    pub fn push(&mut self, d: AlertDraft, now: u64) -> (Alert, bool) {
        if let Some(a) = self.alerts.iter_mut().rev().find(|a| {
            !a.acknowledged
                && a.kind == d.kind
                && a.key == d.key
                && now.saturating_sub(a.last_ts) < MERGE_WINDOW_MS
        }) {
            a.count += 1;
            a.last_ts = now;
            a.detail = d.detail;
            a.severity = a.severity.max(d.severity);
            return (a.clone(), false);
        }
        let id = self.alerts.iter().map(|a| a.id).max().unwrap_or(0) + 1;
        let alert = Alert {
            id,
            ts: now,
            last_ts: now,
            count: 1,
            severity: d.severity,
            kind: d.kind.to_string(),
            key: d.key,
            title: d.title,
            detail: d.detail,
            acknowledged: false,
        };
        self.alerts.push(alert.clone());
        if self.alerts.len() > MAX_ALERTS {
            let excess = self.alerts.len() - MAX_ALERTS;
            self.alerts.drain(..excess);
        }
        (alert, true)
    }

    /// Whether an alert with this kind and key was ever raised (and not cleared).
    pub fn has(&self, kind: &str, key: &str) -> bool {
        self.alerts.iter().any(|a| a.kind == kind && a.key == key)
    }

    pub fn acknowledge(&mut self, id: Option<u64>) {
        for a in self.alerts.iter_mut() {
            if id.is_none_or(|id| a.id == id) {
                a.acknowledged = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(key: &str) -> AlertDraft {
        AlertDraft {
            severity: Severity::Medium,
            kind: "port_scan",
            key: key.into(),
            title: "t".into(),
            detail: "d".into(),
        }
    }

    #[test]
    fn merges_repeats_until_acknowledged() {
        let mut log = AlertLog::load(std::env::temp_dir().join("netwatch-alerts-test-none.json"));
        log.alerts.clear();
        assert!(log.push(draft("1.2.3.4"), 1_000).1);
        let (a, new) = log.push(draft("1.2.3.4"), 2_000);
        assert!(!new);
        assert_eq!(a.count, 2);
        assert!(log.push(draft("5.6.7.8"), 3_000).1);
        log.acknowledge(Some(a.id));
        assert!(log.push(draft("1.2.3.4"), 4_000).1);
        assert!(log.push(draft("5.6.7.8"), 3_000 + MERGE_WINDOW_MS + 1).1);
    }
}

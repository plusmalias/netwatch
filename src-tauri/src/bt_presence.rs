//! When the user's own Bluetooth devices were nearby: paired devices (while
//! connected) and devices the user marked as theirs (while heard). Nothing
//! else is recorded: other people's devices are never logged over time.

use crate::bluetooth::PairedDevice;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Presence gaps shorter than this are merged into one session.
pub const SESSION_GAP_MS: u64 = 5 * 60_000;
/// How long sessions are kept.
pub const KEEP_MS: u64 = 30 * 86_400_000;
/// A paired device unused this long (and tracked this long) is worth a look.
pub const STALE_PAIRING_MS: u64 = 30 * 86_400_000;
/// How much of the history goes to the UI with every update.
const SNAPSHOT_MS: u64 = 48 * 3_600_000;

/// Adds "present at `now`": extends the last session when the gap is short,
/// otherwise starts a new one.
pub fn touch(sessions: &mut Vec<(u64, u64)>, now: u64) {
    match sessions.last_mut() {
        Some((_, end)) if now.saturating_sub(*end) < SESSION_GAP_MS => *end = (*end).max(now),
        _ => sessions.push((now, now)),
    }
}

/// Drops sessions older than the retention period, trimming one that straddles it.
pub fn expire(sessions: &mut Vec<(u64, u64)>, now: u64) {
    let cutoff = now.saturating_sub(KEEP_MS);
    sessions.retain(|s| s.1 >= cutoff);
    for s in sessions.iter_mut() {
        s.0 = s.0.max(cutoff);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Track {
    pub name: String,
    /// A paired device, as opposed to one the user marked as theirs.
    pub paired: bool,
    /// When NetWatch first saw it (paired devices: first in the paired list).
    pub first_tracked: u64,
    /// The last time it was connected (paired) or heard (marked as mine). 0 = never.
    pub last_present: u64,
    /// The last time a paired device appeared in the system's paired list.
    pub listed: u64,
    pub sessions: Vec<(u64, u64)>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PresenceEntry {
    pub key: String,
    pub name: String,
    /// "paired" or "mine".
    pub kind: &'static str,
    pub first_tracked: u64,
    pub last_present: u64,
    /// Sessions from the last 48 hours: [start, end] in ms.
    pub sessions: Vec<(u64, u64)>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct StalePaired {
    pub name: String,
    /// None: not connected once since NetWatch started tracking it.
    pub last_connected: Option<u64>,
    pub tracked_since: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct PresenceBook {
    tracks: BTreeMap<String, Track>,
}

impl PresenceBook {
    /// A device marked as mine was heard. The caller checks it is marked.
    pub fn touch_mine(&mut self, id: &str, name: &str, now: u64) {
        let t = self.tracks.entry(id.to_string()).or_insert_with(|| Track {
            first_tracked: now,
            ..Default::default()
        });
        t.name = name.to_string();
        t.paired = false;
        t.last_present = now;
        touch(&mut t.sessions, now);
    }

    /// Stops recording a device and deletes what was recorded.
    pub fn forget(&mut self, key: &str) {
        self.tracks.remove(key);
    }

    pub fn last_present(&self, key: &str) -> Option<u64> {
        self.tracks.get(key).map(|t| t.last_present).filter(|t| *t > 0)
    }

    /// Reads the paired list: starts tracking new devices and records those
    /// connected right now.
    pub fn record_paired(&mut self, paired: &[PairedDevice], now: u64) {
        for p in paired {
            let t = self.tracks.entry(p.key.clone()).or_insert_with(|| Track {
                first_tracked: now,
                ..Default::default()
            });
            t.name = p.name.clone();
            t.paired = true;
            t.listed = now;
            if p.connected {
                t.last_present = now;
                touch(&mut t.sessions, now);
            }
        }
    }

    /// A paired device was heard advertising nearby (matched by name).
    pub fn touch_paired(&mut self, key: &str, now: u64) {
        if let Some(t) = self.tracks.get_mut(key).filter(|t| t.paired) {
            t.last_present = now;
            touch(&mut t.sessions, now);
        }
    }

    /// Paired devices not connected for 30 days or more, once NetWatch has
    /// itself been tracking them for 30 days.
    pub fn stale_pairings(&self, paired: &[PairedDevice], now: u64) -> Vec<StalePaired> {
        paired
            .iter()
            .filter(|p| !p.connected)
            .filter_map(|p| {
                let t = self.tracks.get(&p.key).filter(|t| t.paired)?;
                let idle_since = if t.last_present > 0 { t.last_present } else { t.first_tracked };
                (now.saturating_sub(t.first_tracked) >= STALE_PAIRING_MS && now.saturating_sub(idle_since) >= STALE_PAIRING_MS).then(|| StalePaired {
                    name: p.name.clone(),
                    last_connected: (t.last_present > 0).then_some(t.last_present),
                    tracked_since: t.first_tracked,
                })
            })
            .collect()
    }

    /// Housekeeping: old sessions go, and so do devices no longer paired,
    /// or no longer marked as mine, for a month.
    pub fn prune(&mut self, now: u64, is_mine: impl Fn(&str) -> bool) {
        for t in self.tracks.values_mut() {
            expire(&mut t.sessions, now);
        }
        self.tracks.retain(|key, t| {
            if t.paired {
                now.saturating_sub(t.listed) < KEEP_MS
            } else {
                is_mine(key) && (!t.sessions.is_empty() || now.saturating_sub(t.first_tracked) < KEEP_MS)
            }
        });
    }

    /// What the UI shows. Paired devices that are no longer in the paired
    /// list (`paired` is the current list, when known) are left out.
    pub fn entries(&self, paired: Option<&[PairedDevice]>, now: u64) -> Vec<PresenceEntry> {
        let from = now.saturating_sub(SNAPSHOT_MS);
        self.tracks
            .iter()
            .filter(|(key, t)| !t.paired || paired.is_none_or(|l| l.iter().any(|p| &p.key == *key)))
            .map(|(key, t)| PresenceEntry {
                key: key.clone(),
                name: t.name.clone(),
                kind: if t.paired { "paired" } else { "mine" },
                first_tracked: t.first_tracked,
                last_present: t.last_present,
                sessions: t.sessions.iter().filter(|s| s.1 >= from).map(|s| (s.0.max(from), s.1)).collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;
    const DAY: u64 = 86_400_000;

    fn paired(key: &str, name: &str, connected: bool) -> PairedDevice {
        PairedDevice {
            key: key.into(),
            name: name.into(),
            connected,
            ..Default::default()
        }
    }

    #[test]
    fn short_gaps_merge_into_one_session() {
        let mut s = Vec::new();
        touch(&mut s, 1_000);
        touch(&mut s, 1_000 + MIN);
        touch(&mut s, 1_000 + 4 * MIN + 59_000);
        assert_eq!(s, vec![(1_000, 1_000 + 4 * MIN + 59_000)]);
    }

    #[test]
    fn gaps_of_five_minutes_start_a_new_session() {
        let mut s = Vec::new();
        touch(&mut s, 0);
        touch(&mut s, 2 * MIN);
        touch(&mut s, 2 * MIN + SESSION_GAP_MS);
        touch(&mut s, 2 * MIN + SESSION_GAP_MS + MIN);
        assert_eq!(s, vec![(0, 2 * MIN), (2 * MIN + SESSION_GAP_MS, 3 * MIN + SESSION_GAP_MS)]);
    }

    #[test]
    fn sessions_expire_after_thirty_days() {
        let now = 100 * DAY;
        let mut s = vec![(10 * DAY, 10 * DAY + MIN), (69 * DAY, 71 * DAY), (80 * DAY, 80 * DAY + MIN)];
        expire(&mut s, now);
        // The first is long gone; the second straddles the cutoff and is trimmed.
        assert_eq!(s, vec![(70 * DAY, 71 * DAY), (80 * DAY, 80 * DAY + MIN)]);
    }

    #[test]
    fn marked_devices_are_tracked_and_forgotten() {
        let mut b = PresenceBook::default();
        b.touch_mine("uuid-1", "Keys", 1_000);
        b.touch_mine("uuid-1", "Keys tag", 1_000 + MIN);
        let e = b.entries(None, 2_000 + MIN);
        assert_eq!(e.len(), 1);
        assert_eq!((e[0].kind, e[0].name.as_str(), e[0].last_present), ("mine", "Keys tag", 1_000 + MIN));
        assert_eq!(e[0].sessions, vec![(1_000, 1_000 + MIN)]);
        // Un-marking a device deletes its history.
        b.forget("uuid-1");
        assert!(b.entries(None, 3_000).is_empty());
        // Housekeeping drops anything that is no longer marked.
        b.touch_mine("uuid-2", "Tag", 5_000);
        b.prune(6_000, |_| false);
        assert!(b.entries(None, 6_000).is_empty());
    }

    #[test]
    fn only_connected_paired_devices_get_sessions() {
        let mut b = PresenceBook::default();
        let list = [paired("paired:a", "AirPods", true), paired("paired:b", "Old speaker", false)];
        b.record_paired(&list, 10 * MIN);
        b.record_paired(&list, 11 * MIN);
        let e = b.entries(Some(&list), 12 * MIN);
        assert_eq!(e.len(), 2);
        let a = e.iter().find(|x| x.key == "paired:a").unwrap();
        assert_eq!(a.sessions, vec![(10 * MIN, 11 * MIN)]);
        assert_eq!(a.kind, "paired");
        let s = e.iter().find(|x| x.key == "paired:b").unwrap();
        assert!(s.sessions.is_empty());
        assert_eq!(b.last_present("paired:b"), None);
        // A device that was unpaired no longer shows up.
        assert_eq!(b.entries(Some(&list[..1]), 12 * MIN).len(), 1);
    }

    #[test]
    fn pairings_go_stale_only_after_a_month_of_tracking_and_disuse() {
        let mut b = PresenceBook::default();
        let t0 = 50 * DAY;
        let used = paired("paired:a", "Headset", true);
        let idle = paired("paired:b", "Old speaker", false);
        b.record_paired(&[used.clone(), idle.clone()], t0);
        let list = |u: bool| [PairedDevice { connected: u, ..used.clone() }, idle.clone()];
        // Not tracked long enough yet, however idle.
        assert!(b.stale_pairings(&list(false), t0 + 29 * DAY).is_empty());
        // After 30 days the never-connected speaker is stale; the headset
        // (connected at t0, so idle 30 days too) is as well.
        let stale = b.stale_pairings(&list(false), t0 + 31 * DAY);
        let names: Vec<_> = stale.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Headset", "Old speaker"]);
        assert_eq!(stale[0].last_connected, Some(t0));
        assert_eq!(stale[1].last_connected, None);
        // Connecting the headset 5 days ago makes it fresh again.
        b.record_paired(&list(true), t0 + 26 * DAY);
        b.record_paired(&list(false), t0 + 31 * DAY);
        let stale = b.stale_pairings(&list(false), t0 + 31 * DAY);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].name, "Old speaker");
        // A device that is connected right now is never stale.
        assert!(b.stale_pairings(&[paired("paired:b", "Old speaker", true)], t0 + 31 * DAY).is_empty());
    }

    #[test]
    fn unpaired_devices_are_pruned_after_a_month() {
        let mut b = PresenceBook::default();
        let list = [paired("paired:a", "Headset", true)];
        b.record_paired(&list, DAY);
        b.prune(20 * DAY, |_| false);
        assert_eq!(b.entries(None, 20 * DAY).len(), 1);
        b.prune(DAY + KEEP_MS, |_| false);
        assert!(b.entries(None, DAY + KEEP_MS).is_empty());
    }

    #[test]
    fn the_snapshot_only_carries_recent_sessions() {
        let mut b = PresenceBook::default();
        let now = 10 * DAY;
        b.touch_mine("t", "Tag", 2 * DAY);
        let recent = 9 * DAY + 20 * 3_600_000;
        b.touch_mine("t", "Tag", recent);
        b.touch_mine("t", "Tag", recent + 4 * MIN);
        let e = b.entries(None, now);
        assert_eq!(e[0].sessions, vec![(recent, recent + 4 * MIN)]);
    }
}

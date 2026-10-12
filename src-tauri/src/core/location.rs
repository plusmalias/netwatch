//! Location Services: asks macOS for permission when the user turns the
//! setting on, keeps the permission status current, and runs the "unknown
//! tracker travelling with you" check. The rules and the CoreLocation wrapper
//! are in `location.rs`.
//!
//! This Mac's position is read only while the setting is on, permission is
//! granted, and an unknown tracker was heard in the last minute. It is held
//! in memory for the length of one check and never saved, logged, emitted to
//! the window, or put in an alert.

use super::bluetooth::NEARBY_KEEP_MS;
use super::Core;
use crate::alerts::{AlertDraft, Severity};
use crate::bluetooth::is_suspect_tracker;
use crate::location::{self, FollowWatch, Following};
use crate::util::now_ms;
use chrono::Local;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Read this Mac's position this often while an unknown tracker is nearby.
const FIX_EVERY_MS: u64 = 3 * 60_000;
/// After an attempt that got no usable position, wait this long.
const FIX_RETRY_MS: u64 = 60_000;
/// How long to wait for CoreLocation to deliver a position.
const FIX_WAIT: Duration = Duration::from_secs(25);
/// A tracker heard this recently counts as nearby right now.
const NEARBY_MS: u64 = 60_000;

#[derive(Default)]
pub struct LocationState {
    /// What macOS says about permission (`location::status_name`), once known.
    status: Option<&'static str>,
    /// When a position was last asked for, and when one last arrived.
    last_attempt: u64,
    last_read: Option<u64>,
    /// Where this Mac was when each unknown tracker was first heard.
    watch: FollowWatch,
}

/// What the window shows. Deliberately has no position in it.
#[derive(Serialize, Clone)]
pub struct LocationInfo {
    /// "off" (the setting is off), "checking", "not_determined", "denied",
    /// "restricted", "allowed" or "unavailable".
    pub status: String,
    /// When this Mac's position was last read, to show the check is working.
    pub last_read: Option<u64>,
}

impl Core {
    pub(super) fn location_info(&self) -> LocationInfo {
        let on = self.settings.read().unwrap().location;
        let l = self.loc.lock().unwrap();
        let status = if !cfg!(target_os = "macos") {
            "unavailable"
        } else if !on {
            "off"
        } else {
            l.status.unwrap_or("checking")
        };
        LocationInfo { status: status.into(), last_read: l.last_read.filter(|_| on) }
    }

    fn emit_location(&self) {
        self.emit("location", self.location_info());
    }

    /// Permission is granted and the user has the setting on.
    pub(super) fn location_allowed(&self) -> bool {
        self.settings.read().unwrap().location && self.loc.lock().unwrap().status == Some("allowed")
    }

    pub(super) fn start_location(self: &Arc<Self>) {
        if !cfg!(target_os = "macos") {
            return;
        }
        let core = self.clone();
        thread::spawn(move || core.location_loop());
    }

    /// Runs `f` on the main thread, which CoreLocation needs, and waits for
    /// the answer. Only for background threads: the main thread would
    /// wait for itself.
    fn on_main<R: Send + 'static>(&self, f: impl FnOnce() -> R + Send + 'static) -> Option<R> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.app.run_on_main_thread(move || drop(tx.send(f()))).ok()?;
        rx.recv_timeout(Duration::from_secs(5)).ok()
    }

    fn location_loop(self: &Arc<Self>) {
        let mut active = false;
        loop {
            if !self.settings.read().unwrap().location {
                if active {
                    active = false;
                    self.on_main(location::native::stop);
                    self.forget_location();
                    self.emit_location();
                }
                thread::sleep(Duration::from_secs(2));
                continue;
            }
            if !active {
                active = true;
                // The first call shows macOS's permission prompt, if the user hasn't been asked.
                self.on_main(location::native::start);
            }
            let status = self.on_main(location::native::status).unwrap_or("unavailable");
            let changed = {
                let mut l = self.loc.lock().unwrap();
                let changed = l.status != Some(status);
                l.status = Some(status);
                if status != "allowed" {
                    l.watch.clear();
                    l.last_read = None;
                }
                changed
            };
            if changed {
                // Names appear (or go) as soon as the permission does.
                self.wifi_refresh.store(true, Ordering::SeqCst);
                self.emit_location();
            }
            if status == "allowed" {
                self.check_tracker_travel();
            }
            thread::sleep(Duration::from_secs(if status == "not_determined" { 1 } else { 5 }));
        }
    }

    /// Drops everything held about this Mac's position.
    fn forget_location(&self) {
        let mut l = self.loc.lock().unwrap();
        *l = LocationState::default();
        drop(l);
        self.wifi_refresh.store(true, Ordering::SeqCst);
    }

    /// Unknown trackers still around: (id, last heard, kind of tracker). Ones not
    /// heard for as long as the nearby list keeps a device are gone, even if
    /// the scan has been stopped and the list hasn't been tidied since.
    fn suspect_trackers(&self) -> Vec<(String, u64, String)> {
        let now = now_ms();
        self.bt
            .lock()
            .unwrap()
            .nearby
            .values()
            .filter(|d| is_suspect_tracker(d) && now.saturating_sub(d.last_seen) < NEARBY_KEEP_MS)
            .map(|d| (d.id.clone(), d.last_seen, d.tracker.clone().unwrap_or_else(|| "item tracker".into())))
            .collect()
    }

    /// Reads this Mac's position once. Waits up to `FIX_WAIT` for a fresh,
    /// precise one, then stops location updates again.
    fn read_position(&self) -> Option<location::Fix> {
        // Even if starting seems to have timed out, it may still run: always stop again.
        let started = self.on_main(location::native::begin_updates).is_some();
        let deadline = Instant::now() + FIX_WAIT;
        let mut got = None;
        while started && got.is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_secs(1));
            got = self
                .on_main(location::native::read_fix)
                .flatten()
                .filter(|f| location::usable_fix(f, now_ms()));
        }
        self.on_main(location::native::end_updates);
        got
    }

    /// One pass of the travel check. Asks for this Mac's position only when an
    /// unknown tracker is near right now and one is due: every few minutes, or
    /// at once for a tracker with no first-heard position yet.
    fn check_tracker_travel(&self) {
        let now = now_ms();
        let suspects = self.suspect_trackers();
        let pairs: Vec<(String, u64)> = suspects.iter().map(|(id, seen, _)| (id.clone(), *seen)).collect();
        let nearby_now = |seen: u64| now.saturating_sub(seen) < NEARBY_MS;
        let due = {
            let mut l = self.loc.lock().unwrap();
            l.watch.keep_only(&pairs);
            pairs.iter().any(|(_, seen)| nearby_now(*seen))
                && now.saturating_sub(l.last_attempt) >= FIX_RETRY_MS
                && (l.last_read.is_none_or(|t| now.saturating_sub(t) >= FIX_EVERY_MS)
                    || pairs.iter().any(|(id, seen)| nearby_now(*seen) && !l.watch.has(id)))
        };
        if !due {
            return;
        }
        self.loc.lock().unwrap().last_attempt = now;
        let Some(fix) = self.read_position() else { return };
        // The wait took seconds; look at what is around now.
        let suspects = self.suspect_trackers();
        let pairs: Vec<(String, u64)> = suspects.iter().map(|(id, seen, _)| (id.clone(), *seen)).collect();
        let following = {
            let mut l = self.loc.lock().unwrap();
            l.last_read = Some(now_ms());
            l.watch.observe(&pairs, fix)
        };
        self.emit_location();
        let today = Local::now().format("%Y-%m-%d").to_string();
        for f in following {
            let key = format!("{}:{today}", f.id);
            if self.alerts.lock().unwrap().has("tracker_following", &key) {
                continue;
            }
            let tracker = suspects.iter().find(|(id, ..)| *id == f.id).map_or("item tracker", |(.., t)| t.as_str());
            let (title, detail) = following_text(tracker, &f);
            self.alert(AlertDraft { severity: Severity::High, kind: "tracker_following", key, title, detail });
        }
    }
}

/// "3.4 km", "12 km".
fn km(metres: f64) -> String {
    let k = metres / 1000.0;
    if k < 10.0 {
        format!("{k:.1} km")
    } else {
        format!("{k:.0} km")
    }
}

/// The alert's title and detail. Says how far and how long, never where.
fn following_text(tracker: &str, f: &Following) -> (String, String) {
    (
        format!("An unknown {tracker} has been travelling with you"),
        format!(
            "A {tracker} that isn't marked as yours was near this Mac {} minutes ago and is near it again now, after this Mac moved about {}. That is how someone can follow your movements. What to do: check your bags, jacket pockets and car. On an iPhone, open Find My and look under Items for \"Items Detected Near You\" (on Android, see Unknown tracker alerts in Safety settings). If you find a tag that isn't yours, take a photo and don't just throw it away; contact the police if you feel threatened. If it belongs to you or someone you live with, mark it as yours on the Bluetooth page.",
            f.minutes,
            km(f.distance_m)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_alert_says_how_far_and_how_long_but_not_where() {
        let f = Following { id: "tag-1".into(), distance_m: 3_440.0, minutes: 27 };
        let (title, detail) = following_text("Apple Find My", &f);
        assert_eq!(title, "An unknown Apple Find My has been travelling with you");
        assert!(detail.contains("27 minutes ago") && detail.contains("about 3.4 km"));
        // What to do is in the alert itself.
        for hint in ["bags", "Items Detected Near You", "police", "mark it as yours"] {
            assert!(detail.contains(hint), "{hint}");
        }
        // Nothing that identifies a place or the tracker's address.
        assert!(!detail.contains("tag-1"));
        assert_eq!(km(950.0), "0.9 km");
        assert_eq!(km(12_400.0), "12 km");
    }

    #[test]
    fn location_info_has_no_position_in_it() {
        let info = LocationInfo { status: "allowed".into(), last_read: Some(5) };
        let v = serde_json::to_value(&info).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"status") && keys.contains(&"last_read"));
    }
}

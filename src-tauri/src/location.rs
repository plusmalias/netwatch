//! Where this Mac is, for exactly two things: macOS only shows Wi-Fi network
//! names to apps with Location permission, and an unknown tracker that stays
//! within Bluetooth range while this Mac travels is following its owner.
//!
//! The position stays in memory on this Mac. It is never saved, put in an
//! alert, sent anywhere, or recorded alongside anyone else's Wi-Fi networks
//! or Bluetooth devices: the only thing kept is, for each unknown tracker
//! heard right now, where this Mac was when it was first heard.
//!
//! This file holds the rules as plain functions over plain data (testable)
//! and a thin CoreLocation wrapper (`native`); `core/location.rs` runs them.

use std::collections::{BTreeSet, HashMap};

/// An unknown tracker counts as travelling with this Mac once the Mac has
/// moved at least this far since the tracker was first heard…
pub const FOLLOW_MIN_DISTANCE_M: f64 = 1_000.0;
/// …and at least this long ago.
pub const FOLLOW_MIN_GAP_MS: u64 = 15 * 60_000;
/// A tracker only counts as heard at a fix if its last advertisement was no
/// older than this at the time of the fix (or newer than the fix).
pub const HEARD_SLACK_MS: u64 = 60_000;
/// Fixes less precise than this are ignored: Wi-Fi positioning that is off by
/// a kilometre would make a parked Mac look like it moved.
pub const MAX_FIX_ACCURACY_M: f64 = 500.0;
/// Fixes older than this are ignored (macOS can hand back a cached one).
pub const MAX_FIX_AGE_MS: u64 = 2 * 60_000;

/// This Mac's position at a moment.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
    /// Horizontal accuracy in metres (a radius), as CoreLocation reports it.
    pub accuracy_m: f64,
    pub ts: u64,
}

/// Great-circle distance in metres between two points given in degrees.
pub fn haversine_m(a: (f64, f64), b: (f64, f64)) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_008.8;
    let (lat1, lat2) = (a.0.to_radians(), b.0.to_radians());
    let dlat = lat2 - lat1;
    let dlon = (b.1 - a.1).to_radians();
    let h = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * h.sqrt().min(1.0).asin()
}

/// Whether a reading can be trusted for the travel rule: real coordinates, a
/// sane accuracy, and recent.
pub fn usable_fix(f: &Fix, now: u64) -> bool {
    f.lat.is_finite()
        && f.lon.is_finite()
        && f.lat.abs() <= 90.0
        && f.lon.abs() <= 180.0
        && f.accuracy_m >= 0.0
        && f.accuracy_m <= MAX_FIX_ACCURACY_M
        && now.saturating_sub(f.ts) <= MAX_FIX_AGE_MS
}

/// The travel rule. `Some(metres)` when `later` is at least 15 minutes after
/// `first` and at least 1 km from it.
pub fn travelled(first: &Fix, later: &Fix) -> Option<f64> {
    if later.ts.saturating_sub(first.ts) < FOLLOW_MIN_GAP_MS {
        return None;
    }
    let d = haversine_m((first.lat, first.lon), (later.lat, later.lon));
    (d >= FOLLOW_MIN_DISTANCE_M).then_some(d)
}

/// A tracker that was near this Mac before and after it moved.
#[derive(Clone, Debug, PartialEq)]
pub struct Following {
    pub id: String,
    pub distance_m: f64,
    pub minutes: u64,
}

/// Where this Mac was when each unknown tracker was first heard. Memory only.
#[derive(Default, Debug)]
pub struct FollowWatch {
    first: HashMap<String, Fix>,
}

impl FollowWatch {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.first.is_empty()
    }

    /// Whether a tracker already has its first-heard position.
    pub fn has(&self, id: &str) -> bool {
        self.first.contains_key(id)
    }

    pub fn clear(&mut self) {
        self.first.clear();
    }

    /// Forgets the position of every tracker that is no longer in `suspects`
    /// (gone, or marked as the user's own).
    pub fn keep_only(&mut self, suspects: &[(String, u64)]) {
        let around: BTreeSet<&str> = suspects.iter().map(|(id, _)| id.as_str()).collect();
        self.first.retain(|id, _| around.contains(id.as_str()));
    }

    /// Takes a new fix. `suspects` is every unknown tracker still around
    /// (id and when it was last heard). Trackers that are gone lose their
    /// first-heard position; ones heard around the time of the fix get one if
    /// they have none, and are checked against it if they do.
    pub fn observe(&mut self, suspects: &[(String, u64)], fix: Fix) -> Vec<Following> {
        self.keep_only(suspects);
        let mut found = Vec::new();
        for (id, last_heard) in suspects {
            if last_heard.saturating_add(HEARD_SLACK_MS) < fix.ts {
                continue;
            }
            match self.first.get(id) {
                None => {
                    self.first.insert(id.clone(), fix);
                }
                Some(first) => {
                    if let Some(distance_m) = travelled(first, &fix) {
                        found.push(Following { id: id.clone(), distance_m, minutes: (fix.ts - first.ts) / 60_000 });
                    }
                }
            }
        }
        found
    }
}

/// CoreLocation's authorization as the window sees it: "not_determined"
/// (never asked), "restricted" (a policy blocks it), "denied" (said no, or
/// Location Services is off), "allowed", or "unavailable" for anything else.
pub fn status_name(raw: i32) -> &'static str {
    match raw {
        0 => "not_determined",
        1 => "restricted",
        2 => "denied",
        // Always (3) is what macOS reports; When-in-use (4) is the same here.
        3 | 4 => "allowed",
        _ => "unavailable",
    }
}

#[cfg(target_os = "macos")]
pub mod native {
    //! Thin CoreLocation wrapper. Everything here must run on the main
    //! thread; `core/location.rs` hops there with `run_on_main_thread`.
    use super::{status_name, Fix};
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::{define_class, AllocAnyThread};
    use objc2_core_location::{kCLLocationAccuracyHundredMeters, CLLocation, CLLocationManager, CLLocationManagerDelegate};
    use objc2_foundation::{NSArray, NSObject, NSObjectProtocol};
    use std::cell::RefCell;
    use std::sync::Mutex;

    define_class!(
        /// Keeps the latest position CoreLocation delivers.
        #[unsafe(super(NSObject))]
        #[name = "NetWatchLocationDelegate"]
        struct Delegate;

        unsafe impl NSObjectProtocol for Delegate {}

        unsafe impl CLLocationManagerDelegate for Delegate {
            #[unsafe(method(locationManager:didUpdateLocations:))]
            fn did_update_locations(&self, _manager: &CLLocationManager, locations: &NSArray<CLLocation>) {
                if let Some(last) = locations.lastObject() {
                    *LATEST.lock().unwrap() = fix_of(&last);
                }
            }
        }
    );

    /// The newest position the delegate heard.
    static LATEST: Mutex<Option<Fix>> = Mutex::new(None);

    thread_local! {
        // The manager only keeps a weak reference to its delegate, so both live here.
        static STATE: RefCell<Option<(Retained<CLLocationManager>, Retained<Delegate>)>> = const { RefCell::new(None) };
    }

    fn fix_of(loc: &CLLocation) -> Option<Fix> {
        // SAFETY: plain property reads on a live CLLocation.
        let (c, accuracy_m, secs) = unsafe { (loc.coordinate(), loc.horizontalAccuracy(), loc.timestamp().timeIntervalSince1970()) };
        (secs > 0.0).then_some(Fix { lat: c.latitude, lon: c.longitude, accuracy_m, ts: (secs * 1000.0) as u64 })
    }

    /// Creates the manager if needed and, when the user hasn't been asked
    /// yet, asks: macOS shows its Location permission prompt.
    pub fn start() {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            if s.is_some() {
                return;
            }
            let delegate: Retained<Delegate> = {
                let this = Delegate::alloc().set_ivars(());
                // SAFETY: NSObject's init on a freshly allocated instance.
                unsafe { objc2::msg_send![super(this), init] }
            };
            // SAFETY: called on the main thread; the manager and delegate stay alive in STATE.
            let manager = unsafe {
                let m = CLLocationManager::new();
                m.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
                m.setDesiredAccuracy(kCLLocationAccuracyHundredMeters);
                if m.authorizationStatus().0 == 0 {
                    m.requestWhenInUseAuthorization();
                }
                m
            };
            *s = Some((manager, delegate));
        });
    }

    /// See [`status_name`].
    pub fn status() -> &'static str {
        STATE.with(|s| match &*s.borrow() {
            // SAFETY: a property read on a live manager.
            Some((m, _)) => status_name(unsafe { m.authorizationStatus() }.0),
            None => "unavailable",
        })
    }

    /// Starts location updates; call [`end_updates`] once a fix has arrived.
    pub fn begin_updates() {
        *LATEST.lock().unwrap() = None;
        STATE.with(|s| {
            if let Some((m, _)) = &*s.borrow() {
                // SAFETY: main thread, live manager.
                unsafe { m.startUpdatingLocation() };
            }
        });
    }

    /// Stops location updates and drops the position the delegate was holding.
    pub fn end_updates() {
        STATE.with(|s| {
            if let Some((m, _)) = &*s.borrow() {
                // SAFETY: main thread, live manager.
                unsafe { m.stopUpdatingLocation() };
            }
        });
        *LATEST.lock().unwrap() = None;
    }

    /// The latest position, from the delegate or the manager's own cache.
    pub fn read_fix() -> Option<Fix> {
        let delivered = *LATEST.lock().unwrap();
        delivered.or_else(|| {
            STATE.with(|s| {
                let s = s.borrow();
                let (m, _) = s.as_ref()?;
                // SAFETY: a property read on a live manager.
                unsafe { m.location() }.and_then(|l| fix_of(&l))
            })
        })
    }

    /// Stops everything and lets the manager go.
    pub fn stop() {
        end_updates();
        STATE.with(|s| *s.borrow_mut() = None);
    }
}

/// Stand-ins so the rest of the app builds where there is no CoreLocation.
#[cfg(not(target_os = "macos"))]
pub mod native {
    use super::Fix;

    pub fn start() {}
    pub fn status() -> &'static str {
        "unavailable"
    }
    pub fn begin_updates() {}
    pub fn end_updates() {}
    pub fn read_fix() -> Option<Fix> {
        None
    }
    pub fn stop() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    fn fix(lat: f64, lon: f64, ts: u64) -> Fix {
        Fix { lat, lon, accuracy_m: 30.0, ts }
    }

    #[test]
    fn haversine_matches_known_distances() {
        assert_eq!(haversine_m((51.5, -0.12), (51.5, -0.12)), 0.0);
        // One degree of latitude is about 111.2 km.
        let d = haversine_m((0.0, 0.0), (1.0, 0.0));
        assert!((d - 111_195.0).abs() < 100.0, "{d}");
        // London to Paris is about 344 km.
        let d = haversine_m((51.5074, -0.1278), (48.8566, 2.3522));
        assert!((d - 343_500.0).abs() < 2_000.0, "{d}");
        // Symmetric, and fine across the antimeridian and at the poles.
        assert_eq!(haversine_m((10.0, 179.9), (10.0, -179.9)), haversine_m((10.0, -179.9), (10.0, 179.9)));
        assert!(haversine_m((10.0, 179.9), (10.0, -179.9)) < 25_000.0);
        assert!((haversine_m((90.0, 0.0), (-90.0, 0.0)) - 20_015_087.0).abs() < 1_000.0);
    }

    #[test]
    fn travel_needs_both_distance_and_time() {
        let home = fix(51.5000, -0.1200, 0);
        // About 1.1 km north (0.01 degrees of latitude) after 20 minutes: yes.
        let d = travelled(&home, &fix(51.5100, -0.1200, 20 * MIN)).unwrap();
        assert!((d - 1_112.0).abs() < 5.0, "{d}");
        // Same place after an hour, or only 500 m away: no.
        assert_eq!(travelled(&home, &fix(51.5000, -0.1200, 60 * MIN)), None);
        assert_eq!(travelled(&home, &fix(51.5045, -0.1200, 60 * MIN)), None);
        // Far, but too soon (a fast car): no, until 15 minutes have passed.
        assert_eq!(travelled(&home, &fix(51.6000, -0.1200, 14 * MIN + 59_000)), None);
        assert!(travelled(&home, &fix(51.6000, -0.1200, 15 * MIN)).is_some());
        // Just under 1 km: no.
        assert_eq!(travelled(&home, &fix(51.5089, -0.1200, 30 * MIN)), None);
    }

    #[test]
    fn rejects_unusable_fixes() {
        let now = 10 * MIN;
        let good = fix(10.0, 20.0, now - MIN);
        assert!(usable_fix(&good, now));
        assert!(!usable_fix(&Fix { accuracy_m: -1.0, ..good }, now), "negative accuracy means invalid");
        assert!(!usable_fix(&Fix { accuracy_m: 501.0, ..good }, now));
        assert!(usable_fix(&Fix { accuracy_m: 500.0, ..good }, now));
        assert!(!usable_fix(&fix(10.0, 20.0, now - 3 * MIN), now), "stale");
        assert!(!usable_fix(&fix(f64::NAN, 20.0, now), now));
        assert!(!usable_fix(&fix(91.0, 20.0, now), now));
        assert!(!usable_fix(&fix(10.0, 181.0, now), now));
    }

    fn suspects(list: &[(&str, u64)]) -> Vec<(String, u64)> {
        list.iter().map(|(id, t)| (id.to_string(), *t)).collect()
    }

    #[test]
    fn a_tracker_heard_before_and_after_the_mac_moved_is_following() {
        let mut w = FollowWatch::default();
        // Heard at home at minute 0: that's its first-heard position, nothing to say yet.
        assert!(w.observe(&suspects(&[("tag", 0)]), fix(51.5, -0.12, 0)).is_empty());
        assert!(w.has("tag"));
        // Ten minutes later, 2 km away: moved, but not 15 minutes apart.
        assert!(w.observe(&suspects(&[("tag", 10 * MIN)]), fix(51.52, -0.12, 10 * MIN)).is_empty());
        // 20 minutes in and still 2 km away from where it was first heard: following.
        let f = w.observe(&suspects(&[("tag", 20 * MIN)]), fix(51.52, -0.12, 20 * MIN));
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].id.as_str(), f[0].minutes), ("tag", 20));
        assert!((f[0].distance_m - 2_224.0).abs() < 10.0, "{}", f[0].distance_m);
    }

    #[test]
    fn a_tracker_that_stayed_put_never_alerts() {
        // A neighbour's tag heard from a parked Mac for hours.
        let mut w = FollowWatch::default();
        for i in 0..20u64 {
            let t = i * 5 * MIN;
            assert!(w.observe(&suspects(&[("tag", t)]), fix(51.5, -0.12, t)).is_empty());
        }
        // The Mac drives off, the tag isn't heard any more (it is last heard at minute 95),
        // and the Mac is far away at minute 120: not heard at this fix, so no alert.
        assert!(w.observe(&suspects(&[("tag", 95 * MIN)]), fix(51.6, -0.12, 120 * MIN)).is_empty());
    }

    #[test]
    fn only_trackers_heard_around_the_fix_count() {
        let mut w = FollowWatch::default();
        w.observe(&suspects(&[("a", 0), ("b", 0)]), fix(51.5, -0.12, 0));
        // At minute 30 and 3 km away: "a" was heard 10 s before the fix, "b" 10 minutes before.
        let f = w.observe(&suspects(&[("a", 30 * MIN - 10_000), ("b", 20 * MIN)]), fix(51.53, -0.12, 30 * MIN));
        assert_eq!(f.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), ["a"]);
        // Heard just after the fix counts too.
        let f = w.observe(&suspects(&[("a", 31 * MIN)]), fix(51.53, -0.12, 30 * MIN));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn a_tracker_not_heard_at_the_first_fix_gets_no_position_until_it_is() {
        let mut w = FollowWatch::default();
        // Known (in range recently) but not heard within a minute of the fix: no position yet.
        assert!(w.observe(&suspects(&[("tag", 0)]), fix(51.5, -0.12, 10 * MIN)).is_empty());
        assert!(!w.has("tag"));
        assert!(w.is_empty());
    }

    #[test]
    fn positions_are_dropped_when_the_tracker_is_gone() {
        let mut w = FollowWatch::default();
        w.observe(&suspects(&[("a", 0), ("b", 0)]), fix(51.5, -0.12, 0));
        assert!(w.has("a") && w.has("b"));
        // "b" left (or was marked as the user's own): its position goes with it.
        w.observe(&suspects(&[("a", 5 * MIN)]), fix(51.5, -0.12, 5 * MIN));
        assert!(w.has("a") && !w.has("b"));
        // Nothing left: nothing kept.
        w.observe(&[], fix(51.5, -0.12, 10 * MIN));
        assert!(w.is_empty());
        // Coming back later starts over from the new position.
        assert!(w.observe(&suspects(&[("b", 40 * MIN)]), fix(51.7, -0.12, 40 * MIN)).is_empty());
        assert!(w.has("b"));
    }

    #[test]
    fn keep_only_drops_the_gone_without_a_fix() {
        let mut w = FollowWatch::default();
        w.observe(&suspects(&[("a", 0), ("b", 0)]), fix(51.5, -0.12, 0));
        w.keep_only(&suspects(&[("b", 0)]));
        assert!(!w.has("a") && w.has("b"));
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut w = FollowWatch::default();
        w.observe(&suspects(&[("a", 0)]), fix(51.5, -0.12, 0));
        w.clear();
        assert!(w.is_empty() && !w.has("a"));
    }

    #[test]
    fn names_the_authorization_states() {
        assert_eq!(status_name(0), "not_determined");
        assert_eq!(status_name(1), "restricted");
        assert_eq!(status_name(2), "denied");
        assert_eq!(status_name(3), "allowed");
        assert_eq!(status_name(4), "allowed");
        assert_eq!(status_name(99), "unavailable");
    }
}

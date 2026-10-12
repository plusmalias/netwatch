//! Bluetooth monitor: paired devices every minute (macOS), plus an opt-in,
//! passive scan of nearby advertisements that alerts on unknown item
//! trackers staying close (the same idea as phones' "tracker found moving
//! with you" warnings).

use super::monitor::{load_json, save_json};
use super::Core;
use crate::alerts::{AlertDraft, Severity};
use crate::bluetooth::{self, BleDevice, BtInfo};
use crate::bt_bands;
use crate::bt_presence::{PresenceBook, PresenceEntry, StalePaired};
use crate::util::now_ms;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const PAIRED_INTERVAL: Duration = Duration::from_secs(60);
/// Devices not heard from in this long drop off the nearby list.
pub(super) const NEARBY_KEEP_MS: u64 = 30 * 60_000;
/// An unknown tracker within range this long raises an alert.
const TRACKER_ALERT_AFTER_MS: u64 = 15 * 60_000;
const EMIT_INTERVAL_MS: u64 = 2_000;
/// Re-read a device's advertisement at most this often.
const REFRESH_MS: u64 = 1_000;
/// …except the device being located, which updates as fast as it can.
const LOCATE_REFRESH_MS: u64 = 150;
/// Presence history is written to disk at most this often.
const SAVE_EVERY_MS: u64 = 60_000;

#[derive(Default)]
pub struct BtState {
    pub info: Option<BtInfo>,
    pub nearby: HashMap<String, BleDevice>,
    /// "off", "starting", "scanning", "bluetooth_off", or an error message.
    pub scan_state: String,
    mine: BTreeSet<String>,
    stop: Option<Arc<AtomicBool>>,
    /// The device the user is locating, which gets fast updates.
    locate: Option<String>,
    spam: bluetooth::SpamDetector,
    /// The last spam burst: (when, type, devices in the burst).
    last_spam: Option<(u64, String, usize)>,
    /// When the user's own devices (paired, or marked as mine) were nearby.
    book: PresenceBook,
    /// Presence history changed since it was last saved, and when that was.
    dirty: bool,
    last_save: u64,
}

#[derive(Serialize, Clone)]
pub struct SpamInfo {
    pub ts: u64,
    pub kind: String,
    pub devices: usize,
}

#[derive(Serialize, Clone)]
pub struct BtSnapshot {
    pub info: Option<BtInfo>,
    pub nearby: Vec<BleDevice>,
    pub scan_state: String,
    pub spam: Option<SpamInfo>,
    pub locate: Option<String>,
    /// Sessions from the last 48 hours for the user's own devices.
    pub presence: Vec<PresenceEntry>,
    /// Paired devices that haven't connected for a month or more.
    pub stale_paired: Vec<StalePaired>,
}

#[derive(Serialize, Clone)]
struct LocateEvent {
    id: String,
    rssi: i16,
    distance_m: Option<f32>,
    ts: u64,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct BtFile {
    mine: BTreeSet<String>,
    presence: PresenceBook,
}

impl BtState {
    pub fn load(dir: &std::path::Path) -> Self {
        let f: BtFile = load_json(&dir.join("bluetooth.json"));
        BtState {
            mine: f.mine,
            book: f.presence,
            scan_state: "off".into(),
            ..Default::default()
        }
    }

    fn file(&self) -> BtFile {
        BtFile {
            mine: self.mine.clone(),
            presence: self.book.clone(),
        }
    }

    /// A device was heard. Only devices the user marked as theirs are recorded.
    fn touch_mine(&mut self, id: &str, name: &str, now: u64) {
        if self.mine.contains(id) {
            self.book.touch_mine(id, name, now);
            self.dirty = true;
        }
    }

    fn record_paired(&mut self, info: &BtInfo, now: u64) {
        self.book.record_paired(&info.paired, now);
        self.dirty = true;
    }

    /// Smooths every heard device's distance and settles its band. Runs on
    /// the scan loop's regular tick, so every device smooths at the same rate.
    fn smooth_nearby(&mut self, dt_ms: u64) {
        for d in self.nearby.values_mut() {
            if let Some(raw) = d.distance_m {
                let s = bt_bands::smooth_m(d.smooth_m, raw, dt_ms);
                d.smooth_m = Some(s);
                d.band = Some(bt_bands::band_for(d.band, s));
            }
        }
    }
}

impl Core {
    pub(super) fn bt_snapshot(&self) -> BtSnapshot {
        let bt = self.bt.lock().unwrap();
        let mut nearby: Vec<BleDevice> = bt.nearby.values().cloned().collect();
        nearby.sort_by_key(|d| std::cmp::Reverse(d.rssi.unwrap_or(-127)));
        let now = now_ms();
        let mut info = bt.info.clone();
        if let Some(i) = info.as_mut() {
            for p in &mut i.paired {
                p.last_connected = bt.book.last_present(&p.key);
            }
        }
        BtSnapshot {
            presence: bt.book.entries(info.as_ref().map(|i| i.paired.as_slice()), now),
            stale_paired: info.as_ref().map(|i| bt.book.stale_pairings(&i.paired, now)).unwrap_or_default(),
            info,
            nearby,
            scan_state: bt.scan_state.clone(),
            spam: bt.last_spam.as_ref().map(|(ts, kind, devices)| SpamInfo {
                ts: *ts,
                kind: kind.clone(),
                devices: *devices,
            }),
            locate: bt.locate.clone(),
        }
    }

    fn emit_bt(&self) {
        self.emit("bt", self.bt_snapshot());
    }

    pub(super) fn start_bluetooth(self: &Arc<Self>) {
        if cfg!(target_os = "macos") {
            let core = self.clone();
            thread::spawn(move || loop {
                let info = bluetooth::read_paired();
                {
                    let mut bt = core.bt.lock().unwrap();
                    if let Some(i) = &info {
                        bt.record_paired(i, now_ms());
                    }
                    bt.info = info.clone();
                }
                core.check_batteries(info.as_ref());
                core.save_presence(false);
                core.emit_bt();
                thread::sleep(PAIRED_INTERVAL);
            });
        }
        if self.settings.read().unwrap().ble_scan {
            let _ = self.set_ble_scan(true);
        }
    }

    pub fn set_ble_mine(&self, id: &str, mine: bool) {
        {
            let mut bt = self.bt.lock().unwrap();
            if mine {
                bt.mine.insert(id.to_string());
            } else {
                bt.mine.remove(id);
                // Unmarking a device stops recording it and deletes its history.
                bt.book.forget(id);
            }
            if let Some(d) = bt.nearby.get_mut(id) {
                d.mine = mine;
            }
            if mine {
                let heard = bt.nearby.get(id).map(|d| (bluetooth::ble_label(d), d.last_seen));
                if let Some((label, last_seen)) = heard {
                    bt.touch_mine(id, &label, last_seen);
                }
            }
            bt.dirty = false;
            bt.last_save = now_ms();
            save_json(&self.dir.join("bluetooth.json"), &bt.file());
        }
        self.emit_bt();
    }

    /// Writes presence history to disk, at most once a minute unless forced.
    fn save_presence(&self, force: bool) {
        let now = now_ms();
        let mut guard = self.bt.lock().unwrap();
        let bt = &mut *guard;
        if !bt.dirty || (!force && now.saturating_sub(bt.last_save) < SAVE_EVERY_MS) {
            return;
        }
        bt.book.prune(now, |k| bt.mine.contains(k));
        bt.dirty = false;
        bt.last_save = now;
        save_json(&self.dir.join("bluetooth.json"), &bt.file());
    }

    /// Alerts, once a day per device, when a connected accessory's battery is low.
    fn check_batteries(&self, info: Option<&BtInfo>) {
        let Some(info) = info else { return };
        let today = Local::now().format("%Y-%m-%d").to_string();
        for low in bluetooth::low_batteries(info) {
            let key = format!("{}:{today}", low.key);
            if self.alerts.lock().unwrap().has("bt_battery", &key) {
                continue;
            }
            let levels = match low.levels.as_slice() {
                [(label, pct)] if label == "Battery" => format!("{pct}%"),
                many => many.iter().map(|(l, p)| format!("{l} {p}%")).collect::<Vec<_>>().join(", "),
            };
            self.alert(AlertDraft {
                severity: Severity::Low,
                kind: "bt_battery",
                key,
                title: format!("{} battery is low ({levels})", low.name),
                detail: format!(
                    "{} reports {levels}. Charge it or swap its batteries soon. NetWatch mentions it once a day while it stays this low.",
                    low.name
                ),
            });
        }
    }

    /// Starts fast updates for one device (or stops them with `None`).
    pub fn set_ble_locate(&self, id: Option<String>) {
        self.bt.lock().unwrap().locate = id;
        self.emit_bt();
    }

    /// Turns the nearby scan on or off, and remembers the choice.
    pub fn set_ble_scan(self: &Arc<Self>, on: bool) -> Result<(), String> {
        {
            let mut s = self.settings.write().unwrap();
            if s.ble_scan != on {
                s.ble_scan = on;
                s.save(&self.dir.join("settings.json"))?;
            }
        }
        let mut bt = self.bt.lock().unwrap();
        if !on {
            if let Some(stop) = bt.stop.take() {
                stop.store(true, Ordering::SeqCst);
            }
            bt.scan_state = "off".into();
            drop(bt);
            self.emit_bt();
            return Ok(());
        }
        if bt.stop.is_some() {
            return Ok(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        bt.stop = Some(stop.clone());
        bt.scan_state = "starting".into();
        drop(bt);
        self.emit_bt();
        let core = self.clone();
        tauri::async_runtime::spawn(async move {
            let result = core.clone().ble_scan_loop(stop.clone()).await;
            let mut bt = core.bt.lock().unwrap();
            if bt.stop.as_ref().is_some_and(|s| Arc::ptr_eq(s, &stop)) {
                bt.stop = None;
                bt.scan_state = match result {
                    Ok(()) => "off".into(),
                    Err(e) => e,
                };
            }
            drop(bt);
            core.emit_bt();
        });
        Ok(())
    }

    async fn ble_scan_loop(self: Arc<Self>, stop: Arc<AtomicBool>) -> Result<(), String> {
        use btleplug::api::{Central, CentralEvent, CentralState, Manager as _, Peripheral as _, ScanFilter};
        use btleplug::platform::Manager;
        use futures::StreamExt;

        let err = |e: btleplug::Error| format!("Bluetooth error: {e}");
        let manager = Manager::new().await.map_err(err)?;
        let adapter = manager
            .adapters()
            .await
            .map_err(err)?
            .into_iter()
            .next()
            .ok_or("This computer has no Bluetooth adapter.")?;
        let mut events = adapter.events().await.map_err(err)?;
        let set_state = |s: &str| {
            self.bt.lock().unwrap().scan_state = s.to_string();
            self.emit_bt();
        };
        if matches!(adapter.adapter_state().await, Ok(CentralState::PoweredOff)) {
            set_state("bluetooth_off");
        }
        adapter.start_scan(ScanFilter::default()).await.map_err(err)?;
        if self.bt.lock().unwrap().scan_state != "bluetooth_off" {
            set_state("scanning");
        }
        let mut refreshed: HashMap<String, u64> = HashMap::new();
        let mut last_emit = 0u64;
        while !stop.load(Ordering::SeqCst) {
            let next = tokio::time::timeout(Duration::from_millis(500), events.next()).await;
            let id = match next {
                Ok(None) => break,
                Err(_) => None,
                Ok(Some(ev)) => match ev {
                    CentralEvent::StateUpdate(CentralState::PoweredOff) => {
                        set_state("bluetooth_off");
                        None
                    }
                    CentralEvent::StateUpdate(CentralState::PoweredOn) => {
                        let _ = adapter.start_scan(ScanFilter::default()).await;
                        set_state("scanning");
                        None
                    }
                    CentralEvent::DeviceDiscovered(id)
                    | CentralEvent::DeviceUpdated(id)
                    | CentralEvent::ManufacturerDataAdvertisement { id, .. }
                    | CentralEvent::ServiceDataAdvertisement { id, .. }
                    | CentralEvent::ServicesAdvertisement { id, .. }
                    | CentralEvent::RssiUpdate { id, .. } => Some(id),
                    _ => None,
                },
            };
            if let Some(id) = id {
                let key = id.to_string();
                let now = now_ms();
                let locating = self.bt.lock().unwrap().locate.as_deref() == Some(key.as_str());
                let every = if locating { LOCATE_REFRESH_MS } else { REFRESH_MS };
                if now.saturating_sub(*refreshed.get(&key).unwrap_or(&0)) >= every {
                    refreshed.insert(key.clone(), now);
                    if let Ok(p) = adapter.peripheral(&id).await {
                        if let Ok(Some(props)) = p.properties().await {
                            let rssi = props.rssi;
                            self.on_advert(key.clone(), props, now);
                            if let (true, Some(rssi)) = (locating, rssi) {
                                let distance_m = self.bt.lock().unwrap().nearby.get(&key).and_then(|d| d.distance_m);
                                self.emit("ble_locate", LocateEvent { id: key, rssi, distance_m, ts: now });
                            }
                        }
                    }
                }
            }
            let now = now_ms();
            if now - last_emit >= EMIT_INTERVAL_MS {
                let dt = (now - last_emit).min(10_000);
                last_emit = now;
                refreshed.retain(|_, t| now - *t < NEARBY_KEEP_MS);
                self.prune_nearby(now);
                self.bt.lock().unwrap().smooth_nearby(dt);
                self.check_trackers(now);
                self.save_presence(false);
                self.emit_bt();
            }
        }
        let _ = adapter.stop_scan().await;
        Ok(())
    }

    fn on_advert(&self, id: String, p: btleplug::api::PeripheralProperties, now: u64) {
        let mut c = bluetooth::classify(&p.manufacturer_data, &p.services, &p.service_data);
        let name = p.local_name.clone().or_else(|| p.advertisement_name.clone());
        let (brand, category) = bluetooth::identify(name.as_deref(), &mut c);
        let popup = c.popup;
        let mut bt = self.bt.lock().unwrap();
        let mine = bt.mine.contains(&id);
        let known_name = name.clone().or_else(|| bt.nearby.get(&id).and_then(|d| d.name.clone()));
        let paired = known_name.as_deref().and_then(|n| {
            let info = bt.info.as_ref()?;
            bluetooth::paired_match(n, &info.paired).map(|p| p.key.clone())
        });
        let is_new = !bt.nearby.contains_key(&id);
        let burst = match (is_new, popup) {
            (true, Some(class)) => bt.spam.record(class, now).map(|n| (class, n)),
            _ => None,
        };
        if let Some((class, n)) = burst {
            bt.last_spam = Some((now, class.to_string(), n));
        }
        let d = bt.nearby.entry(id.clone()).or_insert_with(|| BleDevice {
            id,
            first_seen: now,
            ..Default::default()
        });
        d.name = p.local_name.or(p.advertisement_name).or(d.name.take());
        d.maker = c.maker.or(d.maker.take());
        d.kind = c.kind.or(d.kind.take());
        d.brand = brand.or(d.brand.take());
        d.category = category.or(d.category.take());
        if !c.services.is_empty() {
            d.services = c.services;
        }
        if c.tracker.is_some() {
            d.tracker = c.tracker;
            d.separated = c.separated;
        }
        d.tx_power = p.tx_power_level.or(d.tx_power);
        if let Some(rssi) = p.rssi {
            d.rssi = Some(rssi);
            d.distance_m = Some((bluetooth::distance_m(rssi, d.tx_power) * 10.0).round() / 10.0);
        }
        d.last_seen = now;
        d.mine = mine;
        if paired.is_some() {
            d.paired = paired.clone();
        }
        let heard_mine = mine.then(|| (d.id.clone(), bluetooth::ble_label(d)));
        if let Some((id, label)) = heard_mine {
            bt.touch_mine(&id, &label, now);
        }
        if let Some(key) = &paired {
            bt.book.touch_paired(key, now);
        }
        drop(bt);
        if let Some((class, n)) = burst {
            self.alert(AlertDraft {
                severity: Severity::Medium,
                kind: "ble_spam",
                key: format!("{class}:{now}"),
                title: format!("Bluetooth pop-up spam nearby ({class})"),
                detail: format!(
                    "{n} new \"{class}\" devices appeared within 10 seconds. That's a spam tool (a Flipper Zero or ESP32 running \"BLE spam\" firmware, for example) inventing fake devices to flood phones with pairing pop-ups. It can't pair with or harm your devices, but it's annoying and can drain batteries; it stops when the sender moves out of range. Don't accept unexpected pairing requests."
                ),
            });
        }
    }

    fn prune_nearby(&self, now: u64) {
        self.bt
            .lock()
            .unwrap()
            .nearby
            .retain(|_, d| now.saturating_sub(d.last_seen) < NEARBY_KEEP_MS);
    }

    fn check_trackers(&self, now: u64) {
        let suspects: Vec<BleDevice> = self
            .bt
            .lock()
            .unwrap()
            .nearby
            .values()
            .filter(|d| {
                // Find My networks say whether a tag is away from its owner;
                // Tile and SmartTag don't, so any unknown one counts.
                let away = match d.tracker.as_deref() {
                    Some("Apple Find My" | "Google Find My Device") => d.separated,
                    Some(_) => true,
                    None => false,
                };
                away && !d.mine
                    && now.saturating_sub(d.last_seen) < 60_000
                    && d.last_seen.saturating_sub(d.first_seen) >= TRACKER_ALERT_AFTER_MS
            })
            .cloned()
            .collect();
        let today = Local::now().format("%Y-%m-%d").to_string();
        for d in suspects {
            let key = format!("{}:{today}", d.id);
            if self.alerts.lock().unwrap().has("ble_tracker", &key) {
                continue;
            }
            let tracker = d.tracker.clone().unwrap_or_else(|| "item tracker".into());
            let mins = d.last_seen.saturating_sub(d.first_seen) / 60_000;
            let near = d
                .distance_m
                .map(|m| format!(", roughly {m:.0} m away"))
                .unwrap_or_default();
            self.alert(AlertDraft {
                severity: Severity::Medium,
                kind: "ble_tracker",
                key,
                title: format!("Unknown {tracker} has been near you for {mins} minutes"),
                detail: format!(
                    "A {tracker} that isn't marked as yours has stayed in Bluetooth range for {mins} minutes (signal {} dBm{near}). If you didn't expect it, check your bags, car and belongings: open the Bluetooth page and watch its signal get stronger as you get closer. If it belongs to you or someone you live with, mark it as yours.",
                    d.rssi.unwrap_or(0)
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("netwatch-bt-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_marked_devices_are_ever_recorded() {
        let mut bt = BtState::default();
        // Someone else's device: heard, but never recorded.
        bt.touch_mine("stranger", "Stranger's phone", 1_000);
        assert!(bt.book.entries(None, 2_000).is_empty());
        assert!(!bt.dirty);
        // Once marked as mine it is.
        bt.mine.insert("mine-1".into());
        bt.touch_mine("mine-1", "My tag", 1_000);
        assert_eq!(bt.book.entries(None, 2_000).len(), 1);
        assert!(bt.dirty);
    }

    #[test]
    fn presence_survives_a_restart_and_old_files_still_load() {
        let dir = temp_dir("restart");
        let mut bt = BtState::default();
        bt.mine.insert("mine-1".into());
        bt.touch_mine("mine-1", "My tag", 5_000);
        save_json(&dir.join("bluetooth.json"), &bt.file());
        let back = BtState::load(&dir);
        assert!(back.mine.contains("mine-1"));
        assert_eq!(back.book.entries(None, 6_000)[0].name, "My tag");

        // A file from before presence history existed has only `mine`.
        std::fs::write(dir.join("bluetooth.json"), r#"{"mine":["a","b"]}"#).unwrap();
        let old = BtState::load(&dir);
        assert_eq!(old.mine.len(), 2);
        assert!(old.book.entries(None, 6_000).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nearby_distance_is_smoothed_and_banded_on_each_tick() {
        let mut bt = BtState::default();
        let dev = |m: f32| BleDevice {
            id: "d".into(),
            distance_m: Some(m),
            ..Default::default()
        };
        bt.nearby.insert("d".into(), dev(2.0));
        bt.smooth_nearby(2_000);
        let d = &bt.nearby["d"];
        assert_eq!((d.smooth_m, d.band), (Some(2.0), Some(1)));
        // Raw readings that hop over the 3 m line don't move the device.
        for m in [3.4, 2.6, 3.6, 2.8, 3.3] {
            bt.nearby.get_mut("d").unwrap().distance_m = Some(m);
            bt.smooth_nearby(2_000);
            assert_eq!(bt.nearby["d"].band, Some(1), "moved at {m} m");
        }
        // Staying far away for a while does move it.
        for _ in 0..20 {
            bt.nearby.get_mut("d").unwrap().distance_m = Some(6.0);
            bt.smooth_nearby(2_000);
        }
        assert_eq!(bt.nearby["d"].band, Some(2));
        // No distance (no signal reading yet): no band.
        bt.nearby.insert("x".into(), BleDevice::default());
        bt.smooth_nearby(2_000);
        assert_eq!(bt.nearby["x"].band, None);
    }

    #[test]
    fn paired_devices_are_recorded_when_the_list_is_read() {
        let mut bt = BtState::default();
        let info = BtInfo {
            controller: None,
            paired: vec![crate::bluetooth::PairedDevice {
                key: "paired:aa".into(),
                name: "Headset".into(),
                connected: true,
                ..Default::default()
            }],
        };
        bt.record_paired(&info, 10_000);
        let e = bt.book.entries(Some(&info.paired), 11_000);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].sessions, vec![(10_000, 10_000)]);
        assert_eq!(bt.book.last_present("paired:aa"), Some(10_000));
    }
}

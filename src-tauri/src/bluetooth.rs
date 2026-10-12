//! Bluetooth: this computer's paired devices (with battery levels) and what
//! nearby devices advertise. Everything here is passive: NetWatch reads the
//! advertisements devices broadcast to everyone, and never connects, pairs or
//! sends anything to them.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Controller {
    pub powered: bool,
    pub chipset: Option<String>,
    pub address: Option<String>,
    pub discoverable: bool,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct PairedDevice {
    pub name: String,
    pub address: Option<String>,
    /// Stable id for presence history: "paired:" plus the address (or the name).
    pub key: String,
    pub connected: bool,
    /// The last time NetWatch saw it connected (filled in from presence history).
    pub last_connected: Option<u64>,
    /// "Headphones", "Keyboard", "Mouse"…
    pub kind: Option<String>,
    /// e.g. [("Left", 80), ("Right", 75), ("Case", 40)] or [("Battery", 62)].
    pub battery: Vec<(String, u8)>,
    pub rssi: Option<i32>,
    pub firmware: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct BtInfo {
    pub controller: Option<Controller>,
    pub paired: Vec<PairedDevice>,
}

/// Default names that many strangers' devices share, so they never count
/// as one of yours.
const GENERIC_NAMES: &[&str] = &[
    "iphone", "ipad", "airpods", "airpods pro", "airpods max", "apple watch", "macbook",
    "macbook pro", "macbook air", "imac", "galaxy buds", "jbl", "bose", "beats", "pixel",
];

/// The paired device whose name this advertisement carries, if any. Names
/// must match exactly (ignoring case and surrounding spaces) and be distinctive.
pub fn paired_match<'a>(name: &str, paired: &'a [PairedDevice]) -> Option<&'a PairedDevice> {
    let n = name.trim().to_lowercase();
    if n.chars().count() < 3 || GENERIC_NAMES.contains(&n.as_str()) {
        return None;
    }
    paired.iter().find(|p| p.name.trim().to_lowercase() == n)
}

/// A device heard advertising nearby.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct BleDevice {
    /// The OS's identifier for it. macOS hides Bluetooth addresses and gives
    /// each device a UUID instead; many devices also rotate their address.
    pub id: String,
    pub name: Option<String>,
    pub maker: Option<String>,
    /// The brand, when the name or maker gives it away ("Apple", "Garmin").
    pub brand: Option<String>,
    pub kind: Option<String>,
    /// Icon key for the kind: "phone", "tracker", "garage"… (see `bt_types::Kind::key`).
    pub category: Option<String>,
    /// Set for item trackers: "Apple Find My", "Tile", "Samsung SmartTag",
    /// "Google Find My Device".
    pub tracker: Option<String>,
    /// The tracker says it's away from its owner (Find My networks only).
    pub separated: bool,
    pub rssi: Option<i16>,
    pub tx_power: Option<i16>,
    pub distance_m: Option<f32>,
    /// `distance_m` smoothed over time, and the proximity band it falls in
    /// (0 Touching, 1 Same room, 2 Nearby, 3 Far; see `bt_bands`).
    pub smooth_m: Option<f32>,
    pub band: Option<u8>,
    /// Advertised services, named from the Bluetooth SIG lists.
    pub services: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    /// The user marked it as theirs, so it never raises tracker alerts.
    pub mine: bool,
    /// Key of the paired device this advert matches by name (yours).
    pub paired: Option<String>,
}

/// An unknown tracker worth warning about: not marked as yours or paired, and
/// either a tag that says it is away from its owner (Apple Find My and Google
/// Find My Device) or one that can't say (Tile, SmartTag). The same test the
/// Bluetooth page applies (`isSuspectTracker` in bluetooth.js).
pub fn is_suspect_tracker(d: &BleDevice) -> bool {
    match d.tracker.as_deref() {
        None => false,
        _ if d.mine || d.paired.is_some() => false,
        Some("Apple Find My" | "Google Find My Device") => d.separated,
        Some(_) => true,
    }
}

// Bluetooth SIG assigned numbers (company identifiers, GATT services, and
// 16-bit UUIDs registered to member companies), shared with the Orca app.
// Each line is four hex digits followed by the name.
static COMPANIES: &str = include_str!("data/bt_companies.txt");
static SERVICES: &str = include_str!("data/bt_services.txt");
static MEMBERS: &str = include_str!("data/bt_members.txt");

fn parse_table(raw: &'static str) -> HashMap<u16, &'static str> {
    raw.lines()
        .filter_map(|l| Some((u16::from_str_radix(l.get(..4)?, 16).ok()?, l.get(4..)?.trim())))
        .filter(|(_, n)| !n.is_empty())
        .collect()
}

fn table(cell: &'static OnceLock<HashMap<u16, &'static str>>, raw: &'static str) -> &'static HashMap<u16, &'static str> {
    cell.get_or_init(|| parse_table(raw))
}

static COMPANY_MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
static SERVICE_MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
static MEMBER_MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();

/// "Samsung Electronics Co. Ltd." → "Samsung Electronics"
fn short_vendor(name: &str) -> String {
    let mut n = name.trim().trim_end_matches('.').to_string();
    loop {
        let before = n.len();
        for suffix in [
            ", Inc", " Inc", ", LLC", " LLC", " Ltd", ", Ltd", " Co.", " Co", " Corporation", " Corp", " GmbH",
            " AB", " A/S", " ASA", " AG", " Limited", " S.A", " SA", " B.V", " BV", " Oy", " Pty", " PTY",
            " S.r.l", " SRL", " SAS", " s.r.o", " KK", " Holdings", ",",
        ] {
            if n.len() > suffix.len() + 2 && n.ends_with(suffix) {
                n.truncate(n.len() - suffix.len());
                n = n.trim_end_matches(['.', ' ', ',']).to_string();
            }
        }
        if n.len() == before {
            return n;
        }
    }
}

/// The maker behind a Bluetooth SIG company identifier.
pub fn company_name(id: u16) -> Option<String> {
    curated_company(id)
        .map(String::from)
        .or_else(|| table(&COMPANY_MAP, COMPANIES).get(&id).map(|n| short_vendor(n)))
}

/// The company a vendor-registered 16-bit service UUID belongs to.
pub fn member_vendor(uuid: u16) -> Option<String> {
    table(&MEMBER_MAP, MEMBERS).get(&uuid).map(|n| short_vendor(n))
}

/// The standard GATT service name for a 16-bit UUID ("Heart Rate").
pub fn service_name(uuid: u16) -> Option<&'static str> {
    table(&SERVICE_MAP, SERVICES).get(&uuid).copied()
}

/// Short names for makers people know, so lists read "Apple", not "Apple, Inc.".
fn curated_company(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0002 => "Intel",
        0x0006 => "Microsoft",
        0x000F => "Broadcom",
        0x004C => "Apple",
        0x0059 => "Nordic Semiconductor",
        0x0075 => "Samsung",
        0x0087 => "Garmin",
        0x009E => "Bose",
        0x00E0 => "Google",
        0x012D => "Sony",
        0x0171 => "Amazon",
        0x01DA => "Logitech",
        0x038F => "Xiaomi",
        _ => return None,
    })
}

/// The 16-bit short form of a standard Bluetooth UUID.
pub fn short_uuid(u: &Uuid) -> Option<u16> {
    let b = u.as_bytes();
    const BASE_TAIL: [u8; 12] = [0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb];
    (b[0] == 0 && b[1] == 0 && b[4..] == BASE_TAIL).then(|| u16::from_be_bytes([b[2], b[3]]))
}

/// Fills in brand, kind and category from the name and maker, keeping
/// what the advertisement's structure already established (trackers, Apple types).
pub fn identify(name: Option<&str>, c: &mut Classified) -> (Option<String>, Option<String>) {
    use crate::bt_types::{self, Kind};
    let by_name = name.and_then(bt_types::from_name);
    let brand = by_name
        .and_then(|(b, _)| b.map(String::from))
        .or_else(|| c.maker.clone());
    let kind: Option<Kind> = if c.tracker.is_some() {
        Some(Kind::Tracker)
    } else {
        by_name
            .map(|(_, k)| k)
            .or_else(|| c.maker.as_deref().and_then(bt_types::from_maker))
            .or_else(|| match c.kind.as_deref() {
                Some("AirPods or Beats") => Some(Kind::Headphones),
                Some("Apple Watch") => Some(Kind::Watch),
                Some("AirPlay device") => Some(Kind::Tv),
                Some("HomeKit accessory") | Some("Xiaomi smart-home device") => Some(Kind::SmartHome),
                Some("Heart-rate monitor") | Some("Bike sensor") | Some("Running sensor") | Some("Fitness machine") => Some(Kind::Fitness),
                Some("Keyboard, mouse or controller") => Some(Kind::Computer),
                Some("Thermometer") | Some("Blood-pressure monitor") | Some("Pulse oximeter") | Some("Scale") => Some(Kind::Health),
                Some("Sensor") => Some(Kind::Sensor),
                Some("Fast Pair accessory") => Some(Kind::Headphones),
                _ => None,
            })
    };
    // A name-based kind is more specific than "iPhone, iPad or Mac".
    if let (Some((_, k)), false) = (by_name, c.tracker.is_some()) {
        c.kind = Some(k.label().to_string());
    } else if c.kind.is_none() {
        c.kind = kind.map(|k| k.label().to_string());
    }
    (brand, kind.map(|k| k.key().to_string()))
}

/// What a device's advertisement says about it.
#[derive(Debug, Default, PartialEq)]
pub struct Classified {
    pub maker: Option<String>,
    pub kind: Option<String>,
    pub tracker: Option<String>,
    pub separated: bool,
    pub services: Vec<String>,
    /// The advertisement type phones turn into a pairing pop-up, which spam
    /// tools flood with fake devices: "Apple", "Fast Pair" or "Swift Pair".
    pub popup: Option<&'static str>,
}

/// Apple Continuity messages are type-length-value records inside Apple's
/// manufacturer data.
fn apple_messages(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let (t, len) = (data[i], data[i + 1] as usize);
        let Some(payload) = data.get(i + 2..i + 2 + len) else { break };
        out.push((t, payload));
        i += 2 + len;
    }
    out
}

pub fn classify(
    manufacturer_data: &HashMap<u16, Vec<u8>>,
    services: &[Uuid],
    service_data: &HashMap<Uuid, Vec<u8>>,
) -> Classified {
    let mut c = Classified::default();
    if let Some((&id, _)) = manufacturer_data.iter().next() {
        c.maker = company_name(id);
    }
    if let Some(data) = manufacturer_data.get(&0x004C) {
        c.maker = Some("Apple".into());
        for (t, payload) in apple_messages(data) {
            match t {
                0x12 => {
                    c.kind = Some("Find My device".into());
                    c.tracker = Some("Apple Find My".into());
                    // A full 25-byte key means it has been away from its
                    // owner for a while; near its owner it sends 2 bytes.
                    c.separated = payload.len() >= 22;
                }
                0x07 => {
                    c.kind = c.kind.take().or(Some("AirPods or Beats".into()));
                    c.popup = Some("Apple");
                }
                0x0B => c.kind = c.kind.take().or(Some("Apple Watch".into())),
                0x09 => c.kind = c.kind.take().or(Some("AirPlay device".into())),
                0x06 => c.kind = c.kind.take().or(Some("HomeKit accessory".into())),
                0x0F => {
                    c.kind = c.kind.take().or(Some("iPhone, iPad or Mac".into()));
                    c.popup = Some("Apple");
                }
                0x10 | 0x0C | 0x05 => {
                    c.kind = c.kind.take().or(Some("iPhone, iPad or Mac".into()))
                }
                _ => {}
            }
        }
    }
    let shorts: Vec<u16> = services
        .iter()
        .chain(service_data.keys())
        .filter_map(short_uuid)
        .collect();
    for &u in &shorts {
        match u {
            0x180D => c.kind.get_or_insert_with(|| "Heart-rate monitor".into()),
            0x1812 => c.kind.get_or_insert_with(|| "Keyboard, mouse or controller".into()),
            0x1809 => c.kind.get_or_insert_with(|| "Thermometer".into()),
            0x1810 => c.kind.get_or_insert_with(|| "Blood-pressure monitor".into()),
            0x1822 => c.kind.get_or_insert_with(|| "Pulse oximeter".into()),
            0x181D | 0x181B => c.kind.get_or_insert_with(|| "Scale".into()),
            0x1816 | 0x1818 => c.kind.get_or_insert_with(|| "Bike sensor".into()),
            0x1814 => c.kind.get_or_insert_with(|| "Running sensor".into()),
            0x1826 => c.kind.get_or_insert_with(|| "Fitness machine".into()),
            0x181A | 0xFCD2 => c.kind.get_or_insert_with(|| "Sensor".into()),
            0xFE2C => c.kind.get_or_insert_with(|| "Fast Pair accessory".into()),
            0xFE95 => c.kind.get_or_insert_with(|| "Xiaomi smart-home device".into()),
            _ => continue,
        };
    }
    if c.maker.is_none() {
        c.maker = shorts.iter().find_map(|u| member_vendor(*u));
    }
    if service_data.keys().filter_map(short_uuid).any(|u| u == 0xFE2C) {
        c.popup.get_or_insert("Fast Pair");
    }
    // Microsoft Swift Pair beacons start with 03 00 80.
    if manufacturer_data.get(&0x0006).is_some_and(|d| d.starts_with(&[0x03, 0x00, 0x80])) {
        c.popup.get_or_insert("Swift Pair");
    }
    c.services = shorts
        .iter()
        .filter_map(|&u| {
            service_name(u)
                .map(String::from)
                .or_else(|| member_vendor(u).map(|v| format!("{v} service")))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if shorts.iter().any(|s| *s == 0xFEED || *s == 0xFEEC) {
        c.tracker = Some("Tile".into());
        c.kind = Some("Tile tracker".into());
        c.maker.get_or_insert_with(|| "Tile".into());
    }
    if shorts.contains(&0xFD5A) {
        c.tracker = Some("Samsung SmartTag".into());
        c.kind = Some("SmartTag tracker".into());
        c.maker = Some("Samsung".into());
    }
    // Google's Find My Device network uses Eddystone frames 0x40/0x41.
    if let Some(d) = service_data.iter().find(|(u, _)| short_uuid(u) == Some(0xFEAA)).map(|(_, d)| d) {
        if matches!(d.first(), Some(0x40 | 0x41)) {
            c.tracker = Some("Google Find My Device".into());
            c.kind = Some("Find My Device tracker".into());
            c.separated = d[0] == 0x41;
        }
    }
    c
}

/// Spots Bluetooth pop-up spam: tools like Flipper Zero's or ESP32 "BLE spam"
/// firmware invent dozens of fake devices a second, each with a new address,
/// so phones nearby keep showing pairing pop-ups. Real devices don't do that.
#[derive(Default)]
pub struct SpamDetector {
    recent: HashMap<&'static str, std::collections::VecDeque<u64>>,
    last_alert: HashMap<&'static str, u64>,
}

/// New pop-up devices within `SPAM_WINDOW_MS` before it counts as spam.
const SPAM_THRESHOLD: usize = 12;
const SPAM_WINDOW_MS: u64 = 10_000;
const SPAM_COOLDOWN_MS: u64 = 30 * 60_000;

impl SpamDetector {
    /// Records a newly heard device of a pop-up type. Returns the burst
    /// size when it crosses the threshold (at most once per cooldown).
    pub fn record(&mut self, class: &'static str, now: u64) -> Option<usize> {
        let q = self.recent.entry(class).or_default();
        q.push_back(now);
        while q.front().is_some_and(|t| now.saturating_sub(*t) > SPAM_WINDOW_MS) {
            q.pop_front();
        }
        if q.len() < SPAM_THRESHOLD {
            return None;
        }
        if self.last_alert.get(class).is_some_and(|t| now.saturating_sub(*t) < SPAM_COOLDOWN_MS) {
            return None;
        }
        self.last_alert.insert(class, now);
        Some(q.len())
    }
}

/// A rough distance from signal strength (log-distance path loss). Walls,
/// bodies and antennas easily make this off by a factor of two or more.
pub fn distance_m(rssi: i16, tx_power: Option<i16>) -> f32 {
    // Advertised TX power is at the antenna; at 1 m it's ~41 dB lower.
    let at_1m = tx_power.map_or(-59.0, |t| t as f32 - 41.0);
    let n = 2.2;
    10f32.powf((at_1m - rssi as f32) / (10.0 * n)).clamp(0.1, 100.0)
}

// ---------------------------------------------------------------- paired devices

#[cfg(target_os = "macos")]
pub fn read_paired() -> Option<BtInfo> {
    let out = crate::util::quiet_command("system_profiler")
        .args(["SPBluetoothDataType", "-json"])
        .output()
        .ok()?;
    let mut info = parse_system_profiler(&String::from_utf8_lossy(&out.stdout))?;
    // Apple's own mice, keyboards and trackpads report their charge to the
    // system rather than through system_profiler. Reading it is local only.
    if let Ok(io) = crate::util::quiet_command("ioreg").args(["-r", "-l", "-k", "BatteryPercent"]).output() {
        merge_ioreg_batteries(&mut info, &parse_ioreg_batteries(&String::from_utf8_lossy(&io.stdout)));
    }
    Some(info)
}

#[cfg(not(target_os = "macos"))]
pub fn read_paired() -> Option<BtInfo> {
    None
}

/// A battery level from `ioreg -r -l -k BatteryPercent`.
#[derive(Debug, Clone, PartialEq)]
pub struct IoregBattery {
    pub name: String,
    pub address: Option<String>,
    pub percent: u8,
}

/// Reads the registry objects that report `BatteryPercent` (Magic Mouse,
/// Keyboard, Trackpad). Each object starts with a `+-o` line and lists its
/// properties as `"Key" = value` lines; the first `Product` in an object is
/// the device's name.
pub fn parse_ioreg_batteries(text: &str) -> Vec<IoregBattery> {
    fn value(l: &str, key: &str) -> Option<String> {
        let rest = l.strip_prefix('"')?.strip_prefix(key)?.strip_prefix("\" = ")?;
        Some(rest.trim().trim_matches('"').to_string())
    }
    fn finish(out: &mut Vec<IoregBattery>, name: Option<String>, address: Option<String>, pct: Option<u8>) {
        if let (Some(name), Some(percent)) = (name.filter(|n| !n.is_empty()), pct) {
            if !out.iter().any(|b| b.name == name && b.address == address) {
                out.push(IoregBattery { name, address, percent });
            }
        }
    }
    let mut out = Vec::new();
    let (mut name, mut address, mut pct): (Option<String>, Option<String>, Option<u8>) = (None, None, None);
    for line in text.lines() {
        let l = line.trim_start_matches([' ', '|']);
        if l.starts_with("+-o ") {
            finish(&mut out, name.take(), address.take(), pct.take());
        } else if let Some(v) = value(l, "Product") {
            name.get_or_insert(v);
        } else if let Some(v) = value(l, "DeviceAddress") {
            address.get_or_insert(v);
        } else if let Some(v) = value(l, "BatteryPercent") {
            if let Ok(n) = v.parse::<u8>() {
                pct.get_or_insert(n.min(100));
            }
        }
    }
    finish(&mut out, name, address, pct);
    out
}

fn norm_address(a: &str) -> String {
    a.trim().to_lowercase().replace('-', ":")
}

/// Adds those levels to connected paired devices that have none from
/// system_profiler, matching by address or, failing that, by name.
pub fn merge_ioreg_batteries(info: &mut BtInfo, batteries: &[IoregBattery]) {
    for p in info.paired.iter_mut().filter(|p| p.connected && p.battery.is_empty()) {
        let by_address = batteries.iter().find(|b| {
            b.address.as_deref().zip(p.address.as_deref()).is_some_and(|(x, y)| norm_address(x) == norm_address(y))
        });
        let name = p.name.to_lowercase();
        let by_name = || {
            batteries.iter().find(|b| {
                let product = b.name.to_lowercase();
                product.len() >= 3 && name.len() >= 3 && (name.contains(&product) || product.contains(&name))
            })
        };
        if let Some(b) = by_address.or_else(by_name) {
            p.battery.push(("Battery".to_string(), b.percent));
        }
    }
}

/// Accessory batteries at or below this raise a "bt_battery" alert.
pub const LOW_BATTERY_PCT: u8 = 15;

#[derive(Debug, Clone, PartialEq)]
pub struct LowBattery {
    pub key: String,
    pub name: String,
    pub levels: Vec<(String, u8)>,
}

/// Connected devices with a battery at or below the alert level. Devices that
/// aren't connected can carry an old reading, so they're skipped.
pub fn low_batteries(info: &BtInfo) -> Vec<LowBattery> {
    info.paired
        .iter()
        .filter(|p| p.connected)
        .filter_map(|p| {
            let levels: Vec<(String, u8)> = p.battery.iter().filter(|(_, b)| *b <= LOW_BATTERY_PCT).cloned().collect();
            (!levels.is_empty()).then(|| LowBattery { key: p.key.clone(), name: p.name.clone(), levels })
        })
        .collect()
}

/// A nearby device's display name, like the UI's `bleLabel`.
pub fn ble_label(d: &BleDevice) -> String {
    if let Some(n) = &d.name {
        return n.clone();
    }
    match (&d.brand, &d.kind) {
        (Some(b), Some(k)) => format!("{b} {}", k.to_lowercase()),
        (_, Some(k)) => k.clone(),
        _ => match d.brand.as_ref().or(d.maker.as_ref()) {
            Some(m) => format!("{m} device"),
            None => "Unknown device".to_string(),
        },
    }
}

fn percent(v: &serde_json::Value) -> Option<u8> {
    v.as_str()?.trim_end_matches('%').trim().parse().ok()
}

pub fn parse_system_profiler(json: &str) -> Option<BtInfo> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let root = v.get("SPBluetoothDataType")?.get(0)?;
    let s = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).map(String::from);
    let controller = root.get("controller_properties").map(|c| Controller {
        powered: s(c, "controller_state").as_deref() == Some("attrib_on"),
        chipset: s(c, "controller_chipset"),
        address: s(c, "controller_address").filter(|a| a != "NULL"),
        discoverable: s(c, "controller_discoverable").as_deref() == Some("attrib_on"),
    });
    let mut paired = Vec::new();
    for (key, connected) in [("device_connected", true), ("device_not_connected", false)] {
        let Some(list) = root.get(key).and_then(|l| l.as_array()) else { continue };
        for entry in list {
            let Some(obj) = entry.as_object() else { continue };
            for (name, p) in obj {
                let battery = [
                    ("device_batteryLevelLeft", "Left"),
                    ("device_batteryLevelRight", "Right"),
                    ("device_batteryLevelCase", "Case"),
                    ("device_batteryLevelMain", "Battery"),
                    ("device_batteryLevel", "Battery"),
                ]
                .iter()
                .filter_map(|(k, label)| p.get(*k).and_then(percent).map(|b| (label.to_string(), b)))
                .collect();
                let address = s(p, "device_address");
                paired.push(PairedDevice {
                    name: name.clone(),
                    key: format!("paired:{}", address.as_deref().map_or_else(|| name.to_lowercase(), norm_address)),
                    address,
                    connected,
                    last_connected: None,
                    kind: s(p, "device_minorType"),
                    battery,
                    rssi: s(p, "device_rssi").and_then(|r| r.parse().ok()),
                    firmware: s(p, "device_firmwareVersion"),
                    vendor: s(p, "device_vendorID")
                        .and_then(|v| u16::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                        .and_then(curated_company)
                        .map(String::from),
                });
            }
        }
    }
    Some(BtInfo { controller, paired })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid16(s: u16) -> Uuid {
        Uuid::from_u128(((s as u128) << 96) | 0x0000_0000_0000_1000_8000_0080_5f9b_34fb)
    }

    #[test]
    fn recognizes_short_uuids() {
        assert_eq!(short_uuid(&uuid16(0xFEED)), Some(0xFEED));
        assert_eq!(short_uuid(&Uuid::from_u128(1)), None);
    }

    #[test]
    fn suspect_trackers_match_what_the_page_calls_unknown() {
        let tag = |tracker: Option<&str>, separated: bool| BleDevice { tracker: tracker.map(String::from), separated, ..Default::default() };
        // Find My tags only count when they say they're away from their owner.
        assert!(is_suspect_tracker(&tag(Some("Apple Find My"), true)));
        assert!(!is_suspect_tracker(&tag(Some("Apple Find My"), false)));
        assert!(is_suspect_tracker(&tag(Some("Google Find My Device"), true)));
        assert!(!is_suspect_tracker(&tag(Some("Google Find My Device"), false)));
        // Tile and SmartTag can't say, so any unknown one counts.
        assert!(is_suspect_tracker(&tag(Some("Tile"), false)));
        assert!(is_suspect_tracker(&tag(Some("Samsung SmartTag"), false)));
        // Not trackers at all.
        assert!(!is_suspect_tracker(&tag(None, true)));
        // Marked as the user's own, or matching a paired device: never.
        let mine = BleDevice { mine: true, ..tag(Some("Tile"), false) };
        assert!(!is_suspect_tracker(&mine));
        let paired = BleDevice { paired: Some("paired:aa".into()), ..tag(Some("Apple Find My"), true) };
        assert!(!is_suspect_tracker(&paired));
    }

    #[test]
    fn classifies_trackers() {
        let mut md = HashMap::new();
        // Find My, separated from owner: type 0x12 with a 25-byte payload.
        let mut separated = vec![0x12, 0x19];
        separated.extend([0u8; 25]);
        md.insert(0x004C, separated);
        let c = classify(&md, &[], &HashMap::new());
        assert_eq!(c.tracker.as_deref(), Some("Apple Find My"));
        assert!(c.separated);

        md.insert(0x004C, vec![0x12, 0x02, 0x00, 0x01]);
        assert!(!classify(&md, &[], &HashMap::new()).separated);

        let c = classify(&HashMap::new(), &[uuid16(0xFEED)], &HashMap::new());
        assert_eq!(c.tracker.as_deref(), Some("Tile"));
        let c = classify(&HashMap::new(), &[uuid16(0xFD5A)], &HashMap::new());
        assert_eq!(c.tracker.as_deref(), Some("Samsung SmartTag"));
        let sd = HashMap::from([(uuid16(0xFEAA), vec![0x41, 1, 2, 3])]);
        let c = classify(&HashMap::new(), &[], &sd);
        assert_eq!(c.tracker.as_deref(), Some("Google Find My Device"));
        assert!(c.separated);
    }

    #[test]
    fn classifies_apple_devices_and_makers() {
        let md = HashMap::from([(0x004C, vec![0x10, 0x05, 1, 2, 3, 4, 5])]);
        let c = classify(&md, &[], &HashMap::new());
        assert_eq!(c.kind.as_deref(), Some("iPhone, iPad or Mac"));
        assert_eq!(c.tracker, None);
        let md = HashMap::from([(0x0006, vec![1, 2])]);
        assert_eq!(classify(&md, &[], &HashMap::new()).maker.as_deref(), Some("Microsoft"));
    }

    #[test]
    fn names_makers_and_services_from_sig_lists() {
        assert_eq!(company_name(0x004C).as_deref(), Some("Apple"));
        assert_eq!(company_name(0x0499).as_deref(), Some("Ruuvi Innovations"));
        assert_eq!(member_vendor(0xFEED).as_deref(), Some("Tile"));
        assert_eq!(service_name(0x180D), Some("Heart Rate"));
        assert_eq!(short_vendor("Samsung Electronics Co. Ltd."), "Samsung Electronics");
        assert_eq!(short_vendor("Qualcomm Technologies International, Ltd. (QTIL)"), "Qualcomm Technologies International, Ltd. (QTIL)");
        // A heart-rate strap with no manufacturer data still gets a kind and services.
        let c = classify(&HashMap::new(), &[uuid16(0x180D), uuid16(0x180F)], &HashMap::new());
        assert_eq!(c.kind.as_deref(), Some("Heart-rate monitor"));
        assert_eq!(c.services, vec!["Battery".to_string(), "Heart Rate".to_string()]);
        // Unknown company in manufacturer data falls back to the full SIG list.
        let md = HashMap::from([(0x0499u16, vec![5u8])]);
        assert_eq!(classify(&md, &[], &HashMap::new()).maker.as_deref(), Some("Ruuvi Innovations"));
    }

    #[test]
    fn identifies_brand_and_category() {
        let md = HashMap::from([(0x004C, vec![0x10, 0x05, 1, 2, 3, 4, 5])]);
        let mut c = classify(&md, &[], &HashMap::new());
        let (brand, cat) = identify(Some("Jorden's iPhone"), &mut c);
        assert_eq!(brand.as_deref(), Some("Apple"));
        assert_eq!(cat.as_deref(), Some("phone"));
        assert_eq!(c.kind.as_deref(), Some("Phone"));
        // Trackers stay trackers whatever they're called.
        let mut c = classify(&HashMap::new(), &[uuid16(0xFEED)], &HashMap::new());
        let (_, cat) = identify(Some("Keys"), &mut c);
        assert_eq!(cat.as_deref(), Some("tracker"));
        // No name: the maker decides.
        let md = HashMap::from([(0x0087u16, vec![1u8])]);
        let mut c = classify(&md, &[], &HashMap::new());
        let (brand, cat) = identify(None, &mut c);
        assert_eq!(brand.as_deref(), Some("Garmin"));
        assert_eq!(cat.as_deref(), Some("watch"));
    }

    #[test]
    fn flags_popup_types() {
        let md = HashMap::from([(0x004C, vec![0x07, 0x02, 1, 2])]);
        assert_eq!(classify(&md, &[], &HashMap::new()).popup, Some("Apple"));
        let md = HashMap::from([(0x0006u16, vec![0x03, 0x00, 0x80, 1])]);
        assert_eq!(classify(&md, &[], &HashMap::new()).popup, Some("Swift Pair"));
        let sd = HashMap::from([(uuid16(0xFE2C), vec![1, 2, 3])]);
        assert_eq!(classify(&HashMap::new(), &[], &sd).popup, Some("Fast Pair"));
        let md = HashMap::from([(0x004C, vec![0x10, 0x05, 1, 2, 3, 4, 5])]);
        assert_eq!(classify(&md, &[], &HashMap::new()).popup, None);
    }

    #[test]
    fn detects_spam_bursts_once_per_cooldown() {
        let mut s = SpamDetector::default();
        // A few real AirPods over a minute: no spam.
        for i in 0..5 {
            assert_eq!(s.record("Apple", i * 15_000), None);
        }
        // Twenty fake devices in two seconds.
        let mut hit = None;
        for i in 0..20 {
            hit = hit.or(s.record("Apple", 100_000 + i * 100));
        }
        assert_eq!(hit, Some(SPAM_THRESHOLD));
        // More spam a minute later doesn't alert again.
        let again = (0..20).find_map(|i| s.record("Apple", 160_000 + i * 100));
        assert_eq!(again, None);
    }

    #[test]
    fn estimates_distance() {
        assert!((distance_m(-59, None) - 1.0).abs() < 0.01);
        assert!(distance_m(-80, None) > 5.0);
        assert!(distance_m(-30, None) < 1.0);
    }

    #[test]
    fn parses_paired_devices() {
        let json = r#"{"SPBluetoothDataType":[{"controller_properties":{"controller_address":"AA:BB:CC:DD:EE:FF","controller_chipset":"BCM_4364B3","controller_discoverable":"attrib_off","controller_state":"attrib_on"},
          "device_connected":[{"Jorden's AirPods Pro":{"device_address":"11:22:33:44:55:66","device_batteryLevelCase":"40%","device_batteryLevelLeft":"80%","device_batteryLevelRight":"75%","device_minorType":"Headphones","device_vendorID":"0x004C","device_rssi":"-52"}}],
          "device_not_connected":[{"MX Keys":{"device_address":"77:88:99:AA:BB:CC","device_minorType":"Keyboard","device_vendorID":"0x046D"}}]}]}"#;
        let b = parse_system_profiler(json).unwrap();
        let c = b.controller.unwrap();
        assert!(c.powered);
        assert_eq!(c.address.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(b.paired.len(), 2);
        let pods = &b.paired[0];
        assert!(pods.connected);
        assert_eq!(pods.battery, vec![("Left".into(), 80), ("Right".into(), 75), ("Case".into(), 40)]);
        assert_eq!(pods.vendor.as_deref(), Some("Apple"));
        assert_eq!(pods.rssi, Some(-52));
        assert!(!b.paired[1].connected);
        assert_eq!(b.paired[1].kind.as_deref(), Some("Keyboard"));
        // Paired devices get a stable key from their address.
        assert_eq!(pods.key, "paired:11:22:33:44:55:66");
    }

    #[test]
    fn reads_every_system_profiler_battery_key() {
        let json = r#"{"SPBluetoothDataType":[{"controller_properties":{"controller_state":"attrib_on"},
          "device_connected":[
            {"Magic Trackpad":{"device_address":"AA-BB-CC-00-11-22","device_batteryLevelMain":"85%","device_minorType":"Trackpad"}},
            {"Beats Fit Pro":{"device_address":"01:02:03:04:05:06","device_batteryLevelLeft":"9%","device_batteryLevelRight":" 100 %","device_batteryLevelCase":"N/A"}},
            {"Old Headset":{"device_address":"0A:0B:0C:0D:0E:0F","device_batteryLevel":"40%"}},
            {"Speaker":{"device_address":"10:20:30:40:50:60"}}
          ]}]}"#;
        let b = parse_system_profiler(json).unwrap();
        assert_eq!(b.paired[0].battery, vec![("Battery".to_string(), 85)]);
        assert_eq!(b.paired[0].key, "paired:aa:bb:cc:00:11:22");
        // Unreadable values ("N/A") are skipped, spaces tolerated.
        assert_eq!(b.paired[1].battery, vec![("Left".to_string(), 9), ("Right".to_string(), 100)]);
        assert_eq!(b.paired[2].battery, vec![("Battery".to_string(), 40)]);
        assert!(b.paired[3].battery.is_empty());
    }

    const IOREG: &str = r#"+-o BNBMouseDevice  <class BNBMouseDevice, id 0x1000004d2, registered, matched, active, busy 0 (3 ms), retain 14>
    {
      "Product" = "Magic Mouse"
      "DeviceAddress" = "d0-c0-50-aa-bb-cc"
      "BatteryPercent" = 12
      "Transport" = "Bluetooth"
      "ProductID" = 617
    }

+-o AppleBluetoothHIDKeyboard  <class AppleBluetoothHIDKeyboard, id 0x1000004f1, registered, matched, active, busy 0 (1 ms), retain 12>
  | {
  |   "Product" = "Magic Keyboard with Touch ID"
  |   "BatteryPercent" = 64
  |   "ProductID" = 666
  | }
  |
  +-o AppleDeviceManagementHIDEventService  <class AppleDeviceManagementHIDEventService, id 0x100000500, registered, matched, active, busy 0 (0 ms), retain 8>
      {
        "Product" = "Magic Keyboard with Touch ID"
        "BatteryPercent" = 64
      }

+-o Trackpad  <class AppleMultitouchDevice, id 0x100000510, retain 7>
    {
      "Product" = "No battery here"
    }
"#;

    #[test]
    fn parses_ioreg_battery_levels() {
        let b = parse_ioreg_batteries(IOREG);
        assert_eq!(
            b,
            vec![
                IoregBattery { name: "Magic Mouse".into(), address: Some("d0-c0-50-aa-bb-cc".into()), percent: 12 },
                // The child service repeats the keyboard; it's listed once.
                IoregBattery { name: "Magic Keyboard with Touch ID".into(), address: None, percent: 64 },
            ]
        );
        assert!(parse_ioreg_batteries("").is_empty());
        assert!(parse_ioreg_batteries("+-o X\n  | \"BatteryPercent\" = 50\n").is_empty());
    }

    fn paired_dev(name: &str, address: Option<&str>, connected: bool, battery: &[(&str, u8)]) -> PairedDevice {
        PairedDevice {
            name: name.into(),
            address: address.map(String::from),
            key: format!("paired:{name}"),
            connected,
            battery: battery.iter().map(|(l, b)| (l.to_string(), *b)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn merges_ioreg_levels_by_address_then_name() {
        let io = parse_ioreg_batteries(IOREG);
        let mut info = BtInfo {
            controller: None,
            paired: vec![
                // Matched by address, even though the names differ.
                paired_dev("Maka's mouse", Some("D0:C0:50:AA:BB:CC"), true, &[]),
                // Matched by name ("Jorden's Magic Keyboard with Touch ID" contains the product).
                paired_dev("Jorden's Magic Keyboard with Touch ID", Some("11:22:33:44:55:66"), true, &[]),
                // Already has a level from system_profiler: not overwritten or duplicated.
                paired_dev("Magic Mouse", None, true, &[("Battery", 80)]),
                // Not connected: nothing to read.
                paired_dev("Magic Mouse 2", None, false, &[]),
                paired_dev("AirPods", None, true, &[]),
                // A very short name must not match a longer product by accident.
                paired_dev("Ma", None, true, &[]),
            ],
        };
        merge_ioreg_batteries(&mut info, &io);
        assert_eq!(info.paired[0].battery, vec![("Battery".to_string(), 12)]);
        assert_eq!(info.paired[1].battery, vec![("Battery".to_string(), 64)]);
        assert_eq!(info.paired[2].battery, vec![("Battery".to_string(), 80)]);
        assert!(info.paired[3].battery.is_empty());
        assert!(info.paired[4].battery.is_empty());
        assert!(info.paired[5].battery.is_empty());
    }

    #[test]
    fn finds_low_batteries_on_connected_devices_only() {
        let info = BtInfo {
            controller: None,
            paired: vec![
                paired_dev("Mouse", None, true, &[("Battery", 15)]),
                paired_dev("Keyboard", None, true, &[("Battery", 16)]),
                paired_dev("Earbuds", None, true, &[("Left", 9), ("Right", 60), ("Case", 14)]),
                paired_dev("Unplugged", None, false, &[("Battery", 3)]),
                paired_dev("No battery", None, true, &[]),
            ],
        };
        let low = low_batteries(&info);
        assert_eq!(low.len(), 2);
        assert_eq!((low[0].name.as_str(), low[0].levels.clone()), ("Mouse", vec![("Battery".to_string(), 15)]));
        assert_eq!(low[1].name, "Earbuds");
        assert_eq!(low[1].levels, vec![("Left".to_string(), 9), ("Case".to_string(), 14)]);
    }

    #[test]
    fn labels_nearby_devices_like_the_ui_does() {
        let d = |name: Option<&str>, brand: Option<&str>, kind: Option<&str>, maker: Option<&str>| BleDevice {
            name: name.map(String::from),
            brand: brand.map(String::from),
            kind: kind.map(String::from),
            maker: maker.map(String::from),
            ..Default::default()
        };
        assert_eq!(ble_label(&d(Some("Keys"), Some("Apple"), None, None)), "Keys");
        assert_eq!(ble_label(&d(None, Some("Apple"), Some("Item tracker"), None)), "Apple item tracker");
        assert_eq!(ble_label(&d(None, None, Some("Heart-rate monitor"), None)), "Heart-rate monitor");
        assert_eq!(ble_label(&d(None, None, None, Some("Garmin"))), "Garmin device");
        assert_eq!(ble_label(&d(None, None, None, None)), "Unknown device");
    }
    #[test]
    fn matches_paired_devices_by_distinctive_name_only() {
        let paired = vec![
            PairedDevice { name: "Mak".into(), key: "mak".into(), ..Default::default() },
            PairedDevice { name: "AirPods".into(), key: "pods".into(), ..Default::default() },
        ];
        assert_eq!(paired_match(" mak ", &paired).map(|p| p.key.as_str()), Some("mak"));
        assert!(paired_match("AirPods", &paired).is_none(), "generic names never match");
        assert!(paired_match("Mak's TV", &paired).is_none());
        assert!(paired_match("Ma", &paired).is_none());
    }

}

//! Persistent inventory of devices seen on the LAN, keyed by MAC address.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Device {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    /// Name the user gave the device.
    pub label: Option<String>,
    pub model: Option<String>,
    pub friendly_name: Option<String>,
    pub services: BTreeSet<String>,
    /// How we learned about it: arp, mdns, ssdp, dhcp, capture, self, gateway.
    pub sources: BTreeSet<String>,
    pub open_ports: Option<Vec<u16>>,
    pub ports_checked_at: Option<u64>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub trusted: bool,
    pub is_self: bool,
    pub is_gateway: bool,
    /// Whether the device answered recently (see `ONLINE_WINDOW_MS`).
    pub online: bool,
    /// Round-trip time of the last ping or TCP probe that reached it.
    pub rtt_ms: Option<f32>,
    /// When it last answered a ping or TCP probe. Online devices that only
    /// answer ARP (most sleeping phones and laptops) have an old value here.
    pub last_reply: u64,
    /// IP TTL of its last ping reply, a hint at the OS family.
    pub ttl: Option<u8>,
    /// DHCP option 60 (vendor class), e.g. `MSFT 5.0` or `android-dhcp-14`.
    pub dhcp_vendor: Option<String>,
    /// DHCP option 55 (parameter request list), an OS fingerprint.
    pub dhcp_params: Option<String>,
    /// Alert when it joins or leaves the network.
    pub notify_presence: bool,
    /// The user's own notes and tags ("kids", "IoT", "guest"…).
    pub notes: Option<String>,
    pub tags: BTreeSet<String>,
    /// Periods it was online, as `[start, end]` in ms, oldest first.
    pub sessions: Vec<[u64; 2]>,
    /// Other MAC addresses this device has used. Phones and laptops pick a
    /// private address per network (and some rotate it), so a sighting of
    /// any of these counts as this device.
    pub aliases: BTreeSet<String>,
    /// MAC of the router of the network it was last seen on.
    pub network: Option<String>,
}

/// A device counts as online if it was seen within this window. Presence
/// checks run every minute, and a sleeping device's ARP answers can be a few
/// minutes apart, so this tolerates gaps without flapping.
pub const ONLINE_WINDOW_MS: u64 = 5 * 60_000;
const SESSION_KEEP_MS: u64 = 30 * 24 * 3_600_000;
const MAX_SESSIONS: usize = 1000;

/// Records a sighting at `now`, extending the current session or starting one.
fn extend_sessions(sessions: &mut Vec<[u64; 2]>, now: u64) {
    match sessions.last_mut() {
        Some(s) if now <= s[1] => {}
        Some(s) if now - s[1] <= ONLINE_WINDOW_MS => s[1] = now,
        _ => sessions.push([now, now]),
    }
    let cutoff = now.saturating_sub(SESSION_KEEP_MS);
    sessions.retain(|s| s[1] >= cutoff);
    if sessions.len() > MAX_SESSIONS {
        let excess = sessions.len() - MAX_SESSIONS;
        sessions.drain(..excess);
    }
}

pub struct DeviceStore {
    path: PathBuf,
    pub devices: BTreeMap<String, Device>,
}

pub struct Observed {
    pub is_new: bool,
    /// New device or an IP change — worth pushing to the UI right away.
    pub changed: bool,
}

impl DeviceStore {
    pub fn load(path: PathBuf) -> Self {
        let devices = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Device>>(&b).ok())
            .map(|v| v.into_iter().map(|d| (d.mac.clone(), d)).collect())
            .unwrap_or_default();
        DeviceStore { path, devices }
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_vec_pretty(&self.list()) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(tmp, &self.path);
            }
        }
    }

    pub fn list(&self) -> Vec<Device> {
        self.devices.values().cloned().collect()
    }

    pub fn observe(&mut self, mac: &str, ip: Ipv4Addr, source: &str, now: u64) -> Observed {
        let ip_s = ip.to_string();
        let rekeyed = self.adopt_alias(mac);
        let mut is_new = false;
        let dev = self.devices.entry(mac.to_string()).or_insert_with(|| {
            is_new = true;
            Device {
                mac: mac.to_string(),
                ip: ip_s.clone(),
                first_seen: now,
                ..Default::default()
            }
        });
        let changed = is_new || rekeyed || dev.ip != ip_s || !dev.online;
        dev.ip = ip_s;
        dev.last_seen = dev.last_seen.max(now);
        dev.online = true;
        extend_sessions(&mut dev.sessions, now);
        dev.sources.insert(source.to_string());
        Observed { is_new, changed }
    }

    /// Re-evaluates who is online. Returns the devices whose state flipped.
    pub fn update_online(&mut self, now: u64) -> Vec<Device> {
        let mut flipped = Vec::new();
        for d in self.devices.values_mut() {
            let online = d.is_self || now.saturating_sub(d.last_seen) < ONLINE_WINDOW_MS;
            if online != d.online {
                d.online = online;
                flipped.push(d.clone());
            }
        }
        flipped
    }

    /// The most recently seen device holding `ip`.
    pub fn by_ip_mut(&mut self, ip: Ipv4Addr) -> Option<&mut Device> {
        let ip_s = ip.to_string();
        self.devices
            .values_mut()
            .filter(|d| d.ip == ip_s)
            .max_by_key(|d| d.last_seen)
    }

    /// The key of the device that is or was using `mac`.
    pub fn resolve(&self, mac: &str) -> Option<String> {
        if self.devices.contains_key(mac) {
            return Some(mac.to_string());
        }
        self.devices
            .values()
            .find(|d| d.aliases.contains(mac))
            .map(|d| d.mac.clone())
    }

    /// When `mac` is an old address of a known device, re-files that device
    /// under `mac` (the address it uses now). Returns whether it did.
    fn adopt_alias(&mut self, mac: &str) -> bool {
        if self.devices.contains_key(mac) {
            return false;
        }
        let Some(old) = self.resolve(mac) else { return false };
        let mut d = self.devices.remove(&old).expect("resolved");
        d.aliases.remove(mac);
        d.aliases.insert(old);
        d.mac = mac.to_string();
        self.devices.insert(mac.to_string(), d);
        true
    }

    /// Folds device `other` into `keep`; `keep` stays filed under its own
    /// MAC and `other`'s MAC becomes one of its aliases.
    fn fold_into(&mut self, keep: &str, other: &str) -> bool {
        if keep == other || !self.devices.contains_key(keep) {
            return false;
        }
        let Some(from) = self.devices.remove(other) else { return false };
        let into = self.devices.get_mut(keep).expect("checked");
        let from_newer = from.last_seen > into.last_seen;
        into.first_seen = into.first_seen.min(from.first_seen);
        into.last_seen = into.last_seen.max(from.last_seen);
        macro_rules! fill {
            ($($f:ident),*) => { $( if into.$f.is_none() { into.$f = from.$f.clone(); } )* };
        }
        fill!(hostname, vendor, label, model, friendly_name, rtt_ms, ttl, dhcp_vendor, dhcp_params, notes, network);
        if from.ports_checked_at > into.ports_checked_at {
            into.open_ports = from.open_ports.clone();
            into.ports_checked_at = from.ports_checked_at;
        }
        if from_newer && from.last_reply > into.last_reply {
            into.rtt_ms = from.rtt_ms.or(into.rtt_ms);
        }
        into.last_reply = into.last_reply.max(from.last_reply);
        into.services.extend(from.services);
        into.sources.extend(from.sources);
        into.tags.extend(from.tags);
        into.aliases.extend(from.aliases);
        into.aliases.insert(from.mac);
        into.aliases.remove(keep);
        into.trusted |= from.trusted;
        into.notify_presence |= from.notify_presence;
        into.is_self |= from.is_self;
        into.online |= from.online;
        into.sessions = merge_sessions(std::mem::take(&mut into.sessions), from.sessions);
        true
    }

    /// Merges two records of the same device (the user's "Merge" action).
    /// The one seen most recently survives, since its MAC is the one in use.
    /// Returns the surviving key.
    pub fn merge(&mut self, a: &str, b: &str) -> Result<String, String> {
        let a = self.resolve(a).ok_or("unknown device")?;
        let b = self.resolve(b).ok_or("unknown device")?;
        if a == b {
            return Err("that's the same device".into());
        }
        let (da, db) = (&self.devices[&a], &self.devices[&b]);
        if da.is_gateway || db.is_gateway {
            return Err("routers can't be merged".into());
        }
        let (keep, other) = if db.last_seen > da.last_seen { (b, a) } else { (a, b) };
        self.fold_into(&keep, &other);
        Ok(keep)
    }

    /// Marks `mac` as this computer and folds in the records of addresses
    /// this computer used before. Returns whether any were merged.
    pub fn claim_self(&mut self, mac: &str) -> bool {
        let Some(d) = self.devices.get_mut(mac) else { return false };
        d.is_self = true;
        d.trusted = true;
        let old: Vec<String> = self
            .devices
            .values()
            .filter(|d| d.is_self && d.mac != mac)
            .map(|d| d.mac.clone())
            .collect();
        old.iter().fold(false, |any, o| self.fold_into(mac, o) | any)
    }

    /// Finds records that are really one phone or laptop that switched to a
    /// new private MAC address, and merges them. Two records count as one
    /// device when both use private addresses, share a distinctive hostname,
    /// don't contradict each other's DHCP fingerprint, and were never online
    /// at the same time (two real devices with one name would be). Returns
    /// the `(merged, into)` pairs.
    pub fn merge_rotated(&mut self) -> Vec<(String, String)> {
        let mut groups: BTreeMap<String, Vec<&Device>> = BTreeMap::new();
        for d in self.devices.values() {
            if d.is_self || d.is_gateway || !crate::util::is_randomized_mac(&d.mac) {
                continue;
            }
            if let Some(id) = d.hostname.as_deref().and_then(identity_name) {
                groups.entry(id).or_default().push(d);
            }
        }
        let mut pairs = Vec::new();
        for mut group in groups.into_values().filter(|g| g.len() > 1) {
            group.sort_by_key(|d| d.first_seen);
            let mut chain: Vec<Device> = vec![group[0].clone()];
            for d in &group[1..] {
                let last = chain.last().expect("non-empty");
                if same_device(last, d) {
                    pairs.push((last.mac.clone(), d.mac.clone()));
                    // Track the combined history for the next comparison.
                    let mut combined = (*d).clone();
                    combined.sessions = merge_sessions(last.sessions.clone(), d.sessions.clone());
                    combined.dhcp_params = d.dhcp_params.clone().or(last.dhcp_params.clone());
                    *chain.last_mut().expect("non-empty") = combined;
                } else {
                    chain.push((*d).clone());
                }
            }
        }
        // Pairs run oldest → newest, so each merge's survivor is the next
        // pair's older side.
        let mut renamed: BTreeMap<String, String> = BTreeMap::new();
        for (old, new) in &pairs {
            let old = renamed.get(old).cloned().unwrap_or_else(|| old.clone());
            self.fold_into(new, &old);
            renamed.insert(old, new.clone());
        }
        pairs
    }

    /// Fills in `network` for records saved before devices remembered it:
    /// the router whose address shares the device's /24, seen closest in time.
    pub fn assign_networks(&mut self) {
        let gateways: Vec<(String, String, u64)> = self
            .devices
            .values()
            .filter(|d| d.is_gateway)
            .map(|d| (d.mac.clone(), d.ip.clone(), d.last_seen))
            .collect();
        let prefix = |ip: &str| ip.rsplit_once('.').map(|(p, _)| p.to_string());
        for d in self.devices.values_mut().filter(|d| d.network.is_none()) {
            if d.is_gateway {
                d.network = Some(d.mac.clone());
                continue;
            }
            let p = prefix(&d.ip);
            d.network = gateways
                .iter()
                .filter(|(_, ip, _)| p.is_some() && prefix(ip) == p)
                .min_by_key(|(_, _, seen)| seen.abs_diff(d.last_seen))
                .map(|(mac, _, _)| mac.clone());
        }
    }

    /// Drops names this computer advertises from other devices' records. An
    /// earlier version took mDNS records relayed in other devices' queries as
    /// their own, which could label e.g. an iPad with this Mac's name.
    pub fn clear_borrowed_names(&mut self, own: &[String]) -> bool {
        let own: Vec<String> = own.iter().map(|n| n.to_lowercase()).collect();
        let mut any = false;
        for d in self.devices.values_mut().filter(|d| !d.is_self) {
            if d.friendly_name.as_ref().is_some_and(|n| own.contains(&n.to_lowercase())) {
                d.friendly_name = None;
                any = true;
            }
        }
        any
    }

    /// Drops Google Cast services from Apple devices. The same mDNS bug as
    /// in `clear_borrowed_names` filed a TV's Cast records under an iPad
    /// that listed them in its query; Apple devices never advertise Cast.
    pub fn clear_borrowed_services(&mut self) -> bool {
        const APPLE: &[&str] = &["companion-link", "remotepairing", "apple-mobdev2", "airplay", "raop"];
        let cast = |s: &str| {
            s == "googlecast" || s == "androidtvremote2" || (s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()))
        };
        let mut any = false;
        for d in self.devices.values_mut() {
            let host = d.hostname.as_deref().unwrap_or("").to_lowercase();
            let apple = d.services.iter().any(|s| APPLE.contains(&s.as_str()))
                || ["iphone", "ipad", "macbook", "imac"].iter().any(|k| host.contains(k));
            if apple && d.services.iter().any(|s| cast(s)) {
                d.services.retain(|s| !cast(s));
                any = true;
            }
        }
        any
    }
}

/// Hostnames that many unrelated devices share, so they don't identify one.
const GENERIC_NAMES: &[&str] = &[
    "android", "galaxy", "imac", "ipad", "iphone", "localhost", "mac", "macbook", "macbookair",
    "macbookpro", "phone", "pixel", "unknown", "windows", "desktop", "laptop", "espressif",
];

/// A hostname normalised for comparison (`Alexs-iPhone-2.local` →
/// `alexs-iphone`), or `None` when it's too generic to identify a device.
fn identity_name(host: &str) -> Option<String> {
    let mut h = host.trim().trim_end_matches('.').trim_end_matches(".local").to_lowercase();
    // mDNS conflict suffixes: "name-2", "name (2)".
    if let Some((base, n)) = h.rsplit_once(['-', ' ']) {
        let n = n.trim_matches(|c| c == '(' || c == ')');
        if !n.is_empty() && n.len() <= 2 && n.chars().all(|c| c.is_ascii_digit()) {
            h = base.trim().to_string();
        }
    }
    let squashed: String = h.chars().filter(|c| c.is_alphanumeric()).collect();
    (squashed.len() >= 3 && !GENERIC_NAMES.contains(&squashed.as_str())).then_some(h)
}

/// Whether `a` (older) and `b` look like one device under two addresses.
fn same_device(a: &Device, b: &Device) -> bool {
    let agree = |x: &Option<String>, y: &Option<String>| x.is_none() || y.is_none() || x == y;
    if !agree(&a.dhcp_params, &b.dhcp_params) || !agree(&a.dhcp_vendor, &b.dhcp_vendor) {
        return false;
    }
    // An old ARP entry can keep the previous address "online" for a few
    // minutes after the switch, so tolerate that much overlap.
    let overlap = |x: &[u64; 2], y: &[u64; 2]| {
        x[0].max(y[0]) + ONLINE_WINDOW_MS < x[1].min(y[1])
    };
    !a.sessions.iter().any(|x| b.sessions.iter().any(|y| overlap(x, y)))
}

/// Two session lists as one, oldest first, with touching periods joined.
fn merge_sessions(a: Vec<[u64; 2]>, b: Vec<[u64; 2]>) -> Vec<[u64; 2]> {
    let mut all: Vec<[u64; 2]> = a.into_iter().chain(b).collect();
    all.sort_by_key(|s| s[0]);
    let mut out: Vec<[u64; 2]> = Vec::with_capacity(all.len());
    for s in all {
        match out.last_mut() {
            Some(l) if s[0] <= l[1] + ONLINE_WINDOW_MS => l[1] = l[1].max(s[1]),
            _ => out.push(s),
        }
    }
    if out.len() > MAX_SESSIONS {
        let excess = out.len() - MAX_SESSIONS;
        out.drain(..excess);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_tracks_new_and_ip_changes() {
        let dir = std::env::temp_dir().join(format!("netwatch-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = DeviceStore::load(dir.join("devices.json"));
        let ip1 = Ipv4Addr::new(10, 0, 0, 5);
        let ip2 = Ipv4Addr::new(10, 0, 0, 6);
        let o = s.observe("aa:bb:cc:00:11:22", ip1, "arp", 1);
        assert!(o.is_new && o.changed);
        let o = s.observe("aa:bb:cc:00:11:22", ip1, "mdns", 2);
        assert!(!o.is_new && !o.changed);
        let o = s.observe("aa:bb:cc:00:11:22", ip2, "arp", 3);
        assert!(!o.is_new && o.changed);
        assert_eq!(s.by_ip_mut(ip2).unwrap().sources.len(), 2);
        s.save();
        let reloaded = DeviceStore::load(dir.join("devices.json"));
        assert_eq!(reloaded.devices["aa:bb:cc:00:11:22"].first_seen, 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sessions_merge_within_window_and_split_after() {
        let mut s = Vec::new();
        extend_sessions(&mut s, 1_000);
        extend_sessions(&mut s, 61_000);
        extend_sessions(&mut s, 61_000 + ONLINE_WINDOW_MS);
        assert_eq!(s, vec![[1_000, 61_000 + ONLINE_WINDOW_MS]]);
        extend_sessions(&mut s, 62_000 + 2 * ONLINE_WINDOW_MS);
        assert_eq!(s.len(), 2);
    }

    fn temp_store(tag: &str) -> (PathBuf, DeviceStore) {
        let dir = std::env::temp_dir().join(format!("netwatch-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = DeviceStore::load(dir.join("devices.json"));
        (dir, s)
    }

    const MIN: u64 = 60_000;

    #[test]
    fn this_computer_keeps_one_record_across_private_addresses() {
        let (dir, mut s) = temp_store("self");
        let home = Ipv4Addr::new(192, 168, 0, 110);
        let hotspot = Ipv4Addr::new(172, 20, 10, 12);
        s.observe("3a:00:00:00:a0:02", home, "self", 0);
        s.claim_self("3a:00:00:00:a0:02");
        s.devices.get_mut("3a:00:00:00:a0:02").unwrap().label = Some("Work Mac".into());
        // Joins the iPhone hotspot with another private address.
        s.observe("a2:00:00:00:a0:03", hotspot, "self", 60 * MIN);
        assert!(s.claim_self("a2:00:00:00:a0:03"));
        assert_eq!(s.devices.len(), 1);
        let d = &s.devices["a2:00:00:00:a0:03"];
        assert_eq!(d.label.as_deref(), Some("Work Mac"));
        assert_eq!(d.first_seen, 0);
        assert!(d.aliases.contains("3a:00:00:00:a0:02"));
        // Back home: the old address is re-adopted, not a new device.
        let o = s.observe("3a:00:00:00:a0:02", home, "self", 120 * MIN);
        assert!(!o.is_new && o.changed);
        assert_eq!(s.devices.len(), 1);
        assert!(s.devices["3a:00:00:00:a0:02"].aliases.contains("a2:00:00:00:a0:03"));
        assert_eq!(s.resolve("a2:00:00:00:a0:03").as_deref(), Some("3a:00:00:00:a0:02"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rotated_private_address_merges_but_two_real_macs_stay_apart() {
        let (dir, mut s) = temp_store("rotate");
        let ip = Ipv4Addr::new(192, 168, 0, 50);
        let host = |s: &mut DeviceStore, mac: &str, h: &str| s.devices.get_mut(mac).unwrap().hostname = Some(h.into());
        // One phone, new address the next day.
        s.observe("12:00:00:00:00:01", ip, "arp", 0);
        host(&mut s, "12:00:00:00:00:01", "Mak");
        s.observe("12:00:00:00:00:02", ip, "arp", 24 * 60 * MIN);
        host(&mut s, "12:00:00:00:00:02", "Mak.local");
        // Two MacBooks with the same default name, online together.
        for t in 0..30 {
            s.observe("22:00:00:00:00:01", ip, "arp", t * MIN);
            s.observe("22:00:00:00:00:02", ip, "arp", t * MIN + 1);
        }
        host(&mut s, "22:00:00:00:00:01", "alexs-MacBook-Pro");
        host(&mut s, "22:00:00:00:00:02", "alexs-MacBook-Pro-2");
        // Generic names never merge.
        s.observe("32:00:00:00:00:01", ip, "arp", 0);
        s.observe("32:00:00:00:00:02", ip, "arp", 9 * 24 * 60 * MIN);
        host(&mut s, "32:00:00:00:00:01", "iPhone");
        host(&mut s, "32:00:00:00:00:02", "iPhone");
        let pairs = s.merge_rotated();
        assert_eq!(pairs, vec![("12:00:00:00:00:01".to_string(), "12:00:00:00:00:02".to_string())]);
        assert_eq!(s.devices.len(), 5);
        assert!(s.devices["12:00:00:00:00:02"].aliases.contains("12:00:00:00:00:01"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn manual_merge_keeps_the_address_in_use_and_refuses_routers() {
        let (dir, mut s) = temp_store("merge");
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        s.observe("aa:00:00:00:00:01", ip, "arp", 0);
        s.observe("aa:00:00:00:00:02", ip, "arp", 10 * MIN);
        s.devices.get_mut("aa:00:00:00:00:01").unwrap().notes = Some("kitchen".into());
        assert_eq!(s.merge("aa:00:00:00:00:01", "aa:00:00:00:00:02").unwrap(), "aa:00:00:00:00:02");
        assert_eq!(s.devices["aa:00:00:00:00:02"].notes.as_deref(), Some("kitchen"));
        assert_eq!(s.devices["aa:00:00:00:00:02"].sessions, vec![[0, 0], [10 * MIN, 10 * MIN]]);
        s.observe("bb:00:00:00:00:01", Ipv4Addr::new(10, 0, 0, 1), "gateway", 0);
        s.devices.get_mut("bb:00:00:00:00:01").unwrap().is_gateway = true;
        assert!(s.merge("aa:00:00:00:00:02", "bb:00:00:00:00:01").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn old_records_get_their_network_and_lose_borrowed_names() {
        let (dir, mut s) = temp_store("nets");
        s.observe("a8:29:48:00:a0:05", Ipv4Addr::new(192, 168, 0, 1), "gateway", 0);
        s.observe("2a:00:00:00:a0:04", Ipv4Addr::new(172, 20, 10, 1), "gateway", 0);
        for d in s.devices.values_mut() {
            d.is_gateway = true;
        }
        s.observe("72:00:00:00:a0:01", Ipv4Addr::new(192, 168, 0, 103), "arp", 0);
        s.devices.get_mut("72:00:00:00:a0:01").unwrap().friendly_name = Some("Alex’s MacBook Pro".into());
        s.assign_networks();
        assert_eq!(s.devices["72:00:00:00:a0:01"].network.as_deref(), Some("a8:29:48:00:a0:05"));
        assert_eq!(s.devices["2a:00:00:00:a0:04"].network.as_deref(), Some("2a:00:00:00:a0:04"));
        assert!(s.clear_borrowed_names(&["Alex’s MacBook Pro".into()]));
        assert!(s.devices["72:00:00:00:a0:01"].friendly_name.is_none());
        let ipad = s.devices.get_mut("72:00:00:00:a0:01").unwrap();
        ipad.hostname = Some("Sams-iPad".into());
        ipad.services = ["C76FE7BD", "companion-link", "googlecast"].map(String::from).into();
        assert!(s.clear_borrowed_services());
        assert_eq!(s.devices["72:00:00:00:a0:01"].services, BTreeSet::from(["companion-link".to_string()]));
        assert!(!s.clear_borrowed_services());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn identity_names_ignore_suffixes_and_generic_names() {
        assert_eq!(identity_name("Alexs-iPhone-2.local").as_deref(), Some("alexs-iphone"));
        assert_eq!(identity_name("Living Room (3)").as_deref(), Some("living room"));
        assert_eq!(identity_name("MacBook-Pro"), None);
        assert_eq!(identity_name("iPhone"), None);
        assert_eq!(identity_name("P660").as_deref(), Some("p660"));
    }

    /// Dry run of the startup repairs on a copy of a real devices.json:
    /// `NETWATCH_DEVICES=/path/copy.json NETWATCH_OWN_NAMES="My Mac" cargo test live_tidy -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_tidy() {
        let path = std::env::var("NETWATCH_DEVICES").expect("NETWATCH_DEVICES");
        let mut s = DeviceStore::load(PathBuf::from(path));
        println!("before: {} records", s.devices.len());
        s.assign_networks();
        let newest = s.devices.values().filter(|d| d.is_self).max_by_key(|d| d.last_seen).map(|d| d.mac.clone());
        println!("self merged: {}", newest.is_some_and(|m| s.claim_self(&m)));
        // This computer's names, comma-separated (`scutil --get ComputerName`).
        let own: Vec<String> = std::env::var("NETWATCH_OWN_NAMES").unwrap_or_default().split(',').map(|n| n.trim().to_string()).collect();
        println!("names cleared: {}", s.clear_borrowed_names(&own));
        println!("services cleared: {}", s.clear_borrowed_services());
        println!("rotated: {:?}", s.merge_rotated());
        for d in s.devices.values() {
            println!("{} {:15} {:?} net={:?} self={} aliases={:?} fn={:?}", d.mac, d.ip, d.hostname, d.network, d.is_self, d.aliases, d.friendly_name);
        }
    }

    #[test]
    fn devices_go_offline_after_the_window() {
        let dir = std::env::temp_dir().join(format!("netwatch-online-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = DeviceStore::load(dir.join("devices.json"));
        s.observe("aa:bb:cc:00:11:22", Ipv4Addr::new(10, 0, 0, 5), "arp", 1_000);
        assert!(s.update_online(2_000).is_empty());
        let flipped = s.update_online(1_000 + ONLINE_WINDOW_MS);
        assert_eq!(flipped.len(), 1);
        assert!(!flipped[0].online);
        std::fs::remove_dir_all(dir).ok();
    }
}


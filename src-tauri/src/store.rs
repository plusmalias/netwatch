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
        let changed = is_new || dev.ip != ip_s || !dev.online;
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

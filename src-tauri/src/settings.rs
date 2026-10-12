use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// Lowest alert severity that gets a system notification: "high",
    /// "medium", "low", or "off". Join/leave alerts for watched devices
    /// always notify unless this is "off".
    pub notify: String,
    /// Keep monitoring from the menu bar / tray when the window is closed.
    pub keep_running: bool,
    /// Look up the public IP address and ISP (one request to ipinfo.io).
    pub public_ip_lookup: bool,
    /// Monthly data allowance in GB, for usage alerts.
    pub data_cap_gb: Option<f64>,
    /// Day of the month the data allowance renews (1–28).
    pub cycle_day: u32,
    /// Speed tests on a schedule, around 03:00 local time: "off", "daily" or "weekly".
    pub speedtest_schedule: String,
    /// How much data a scheduled test may use: "light" (about 10 MB) or "full"
    /// (about 38 MB, like the Run speed test button, which ignores this).
    pub speedtest_size: String,
    /// Listen for nearby Bluetooth devices (opt-in; macOS asks permission).
    pub ble_scan: bool,
    /// Hosts to keep an eye on: "example.com" (ping) or "example.com:443"
    /// (TCP connect), at most 10.
    pub watch_hosts: Vec<String>,
    /// A notification each morning summarising yesterday.
    pub daily_summary: bool,
    /// "light" (default), "dark" or "system".
    pub theme: String,
    /// Start quietly in the menu bar when you log in. Only the installed
    /// macOS app registers a login item; dev builds never touch it.
    pub launch_at_login: bool,
    /// Text beside the menu-bar icon: "off", "speed" or "devices".
    pub tray_text: String,
    /// Weekly check of the open ports on every device on the network.
    pub port_audit: bool,
    /// Alert when an app starts accepting connections from the network.
    pub listener_watch: bool,
    /// Alert when something is added to the startup items (launch agents, daemons).
    pub launch_watch: bool,
    /// Alert when this network's DNS or DHCP servers change.
    pub dns_watch: bool,
    /// Look for other Wi-Fi networks using your network's name.
    pub evil_twin_watch: bool,
    /// Certificate checks for watched sites and the HTTPS-interception check.
    pub cert_checks: bool,
    /// Expert mode: alert cards get ATT&CK details and the raw alert as JSON.
    pub expert_mode: bool,
    /// Use Location Services (macOS asks permission when this is turned on):
    /// real Wi-Fi network names, and a warning when an unknown tracker
    /// travels with this Mac. The position stays on this Mac, in memory.
    pub location: bool,
    /// Append every new alert as one JSON line to `alerts.jsonl` in the data folder.
    pub log_file: bool,
    /// Where to send each new alert as a syslog message over UDP: "host:port".
    /// Empty means off.
    pub siem_target: String,
    /// What the syslog message carries: "cef" or "json".
    pub siem_format: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            notify: "medium".into(),
            keep_running: true,
            public_ip_lookup: true,
            data_cap_gb: None,
            cycle_day: 1,
            speedtest_schedule: "off".into(),
            speedtest_size: "light".into(),
            ble_scan: false,
            watch_hosts: Vec::new(),
            daily_summary: true,
            theme: "light".into(),
            launch_at_login: true,
            tray_text: "off".into(),
            port_audit: true,
            listener_watch: true,
            launch_watch: true,
            dns_watch: true,
            evil_twin_watch: true,
            cert_checks: true,
            expert_mode: false,
            location: false,
            log_file: false,
            siem_target: String::new(),
            siem_format: "cef".into(),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn sanitized(mut self) -> Self {
        if !["high", "medium", "low", "off"].contains(&self.notify.as_str()) {
            self.notify = "medium".into();
        }
        self.cycle_day = self.cycle_day.clamp(1, 28);
        if !["off", "daily", "weekly"].contains(&self.speedtest_schedule.as_str()) {
            self.speedtest_schedule = "off".into();
        }
        if !["light", "full"].contains(&self.speedtest_size.as_str()) {
            self.speedtest_size = "light".into();
        }
        if !["light", "dark", "system"].contains(&self.theme.as_str()) {
            self.theme = "light".into();
        }
        if !["off", "speed", "devices"].contains(&self.tray_text.as_str()) {
            self.tray_text = "off".into();
        }
        // A target that isn't a plain host:port switches forwarding off.
        self.siem_target = self.siem_target.trim().to_lowercase();
        if !valid_siem_target(&self.siem_target) {
            self.siem_target.clear();
        }
        if !["cef", "json"].contains(&self.siem_format.as_str()) {
            self.siem_format = "cef".into();
        }
        self.data_cap_gb = self.data_cap_gb.filter(|g| g.is_finite() && *g > 0.0);
        let mut seen = std::collections::BTreeSet::new();
        self.watch_hosts = self
            .watch_hosts
            .iter()
            .map(|h| h.trim().to_lowercase())
            .filter(|h| valid_watch_host(h) && seen.insert(h.clone()))
            .take(10)
            .collect();
        self
    }
}

/// A host name or IPv4 address, optionally with `:port`.
pub fn valid_watch_host(h: &str) -> bool {
    let (host, port) = match h.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (h, None),
    };
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0))
}

/// A host name or IPv4 address with a required port (1-65535): "siem.lan:514".
/// IPv6 literals aren't supported.
pub fn valid_siem_target(t: &str) -> bool {
    t.contains(':') && valid_watch_host(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_watch_hosts() {
        assert!(valid_watch_host("example.com"));
        assert!(valid_watch_host("10.0.0.5:22"));
        assert!(!valid_watch_host("example.com:0"));
        assert!(!valid_watch_host("-rf"));
        assert!(!valid_watch_host("a b"));
        let s = Settings {
            watch_hosts: vec![" Example.com ".into(), "example.com".into(), "bad host".into()],
            ..Default::default()
        }
        .sanitized();
        assert_eq!(s.watch_hosts, vec!["example.com".to_string()]);
    }

    #[test]
    fn older_settings_files_get_the_new_defaults() {
        let s: Settings = serde_json::from_str(r#"{"notify":"high","keep_running":false}"#).unwrap();
        assert_eq!(s.notify, "high");
        assert!(!s.keep_running);
        assert!(s.launch_at_login);
        assert_eq!(s.tray_text, "off");
        // The security audits are on unless switched off.
        assert!(s.port_audit && s.listener_watch && s.launch_watch);
        assert!(s.dns_watch && s.evil_twin_watch && s.cert_checks);
        let s: Settings = serde_json::from_str(r#"{"port_audit":false,"cert_checks":false}"#).unwrap();
        assert!(!s.port_audit && !s.cert_checks && s.listener_watch);
    }

    #[test]
    fn location_is_off_until_turned_on() {
        assert!(!Settings::default().location);
        // Settings files from before Location support load with it off.
        let s: Settings = serde_json::from_str(r#"{"notify":"high","ble_scan":true}"#).unwrap();
        assert!(!s.location);
        let s: Settings = serde_json::from_str(r#"{"location":true}"#).unwrap();
        assert!(s.location && s.clone().sanitized().location);
    }

    #[test]
    fn sanitizes_tray_text() {
        for ok in ["off", "speed", "devices"] {
            let s = Settings { tray_text: ok.into(), ..Default::default() }.sanitized();
            assert_eq!(s.tray_text, ok);
        }
        let s = Settings { tray_text: "everything".into(), ..Default::default() }.sanitized();
        assert_eq!(s.tray_text, "off");
    }

    #[test]
    fn export_settings_default_off_and_sanitize() {
        let d = Settings::default();
        assert!(!d.expert_mode && !d.log_file);
        assert_eq!((d.siem_target.as_str(), d.siem_format.as_str()), ("", "cef"));
        // Settings files from before the export options still load.
        let s: Settings = serde_json::from_str(r#"{"notify":"low"}"#).unwrap();
        assert!(!s.expert_mode && !s.log_file && s.siem_target.is_empty() && s.siem_format == "cef");

        assert!(valid_siem_target("siem.lan:514"));
        assert!(valid_siem_target("10.0.0.9:6514"));
        assert!(valid_siem_target("127.0.0.1:1"));
        assert!(valid_siem_target("127.0.0.1:65535"));
        for bad in ["", "siem.lan", "siem.lan:", ":514", "siem.lan:0", "siem.lan:65536", "siem.lan:abc", "a b:514", "-x:514", "[::1]:514", "::1", "a:b:514", "udp://siem:514", "siem.lan:514/x"] {
            assert!(!valid_siem_target(bad), "{bad:?} should be rejected");
        }

        let s = Settings { siem_target: "  SIEM.lan:514 ".into(), siem_format: "json".into(), ..Default::default() }.sanitized();
        assert_eq!((s.siem_target.as_str(), s.siem_format.as_str()), ("siem.lan:514", "json"));
        let s = Settings { siem_target: "no port".into(), siem_format: "xml".into(), ..Default::default() }.sanitized();
        assert_eq!((s.siem_target.as_str(), s.siem_format.as_str()), ("", "cef"));
    }

    #[test]
    fn scheduled_speed_tests_default_off_and_sanitize() {
        let d = Settings::default();
        assert_eq!((d.speedtest_schedule.as_str(), d.speedtest_size.as_str()), ("off", "light"));
        // Settings files from before the schedule still load, with it off.
        let s: Settings = serde_json::from_str(r#"{"notify":"low","data_cap_gb":50.0}"#).unwrap();
        assert_eq!((s.speedtest_schedule.as_str(), s.speedtest_size.as_str()), ("off", "light"));
        for (sched, size) in [("daily", "full"), ("weekly", "light"), ("off", "full")] {
            let s = Settings { speedtest_schedule: sched.into(), speedtest_size: size.into(), ..Default::default() }.sanitized();
            assert_eq!((s.speedtest_schedule.as_str(), s.speedtest_size.as_str()), (sched, size));
        }
        let s = Settings { speedtest_schedule: "hourly".into(), speedtest_size: "huge".into(), ..Default::default() }.sanitized();
        assert_eq!((s.speedtest_schedule.as_str(), s.speedtest_size.as_str()), ("off", "light"));
    }
}

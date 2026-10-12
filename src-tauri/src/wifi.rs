//! This computer's Wi-Fi link and firewall. macOS only for now: the details
//! come from `system_profiler` and `socketfilterfw`, which need no privileges.

use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Network {
    /// `None` when macOS hides it (apps need Location Services to see SSIDs).
    pub ssid: Option<String>,
    /// The access point's address, lowercase `aa:bb:cc:dd:ee:ff`. Like the name,
    /// only available from CoreWLAN with Location permission.
    pub bssid: Option<String>,
    pub channel: Option<u32>,
    pub band: Option<String>,
    pub width: Option<String>,
    pub phy: Option<String>,
    pub security: Option<String>,
    pub rssi: Option<i32>,
    pub noise: Option<i32>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct WifiInfo {
    pub interface: String,
    pub current: Network,
    pub rate_mbps: Option<u32>,
    pub mcs: Option<u32>,
    pub country: Option<String>,
    /// Other networks in range from the last scan the OS did.
    pub nearby: Vec<Network>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct FirewallInfo {
    pub enabled: bool,
    /// "Block all incoming connections" is on.
    pub block_all: bool,
    pub stealth: bool,
}

#[cfg(target_os = "macos")]
pub fn read(interface: &str) -> Option<WifiInfo> {
    let out = crate::util::quiet_command("system_profiler")
        .args(["SPAirPortDataType", "-json"])
        .output()
        .ok()?;
    parse_system_profiler(&String::from_utf8_lossy(&out.stdout), interface)
}

#[cfg(not(target_os = "macos"))]
pub fn read(_interface: &str) -> Option<WifiInfo> {
    None
}

#[cfg(target_os = "macos")]
pub fn firewall() -> Option<FirewallInfo> {
    let out = crate::util::quiet_command("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .args(["--getglobalstate", "--getstealthmode"])
        .output()
        .ok()?;
    parse_firewall(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(not(target_os = "macos"))]
pub fn firewall() -> Option<FirewallInfo> {
    None
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_firewall(text: &str) -> Option<FirewallInfo> {
    let state: u8 = text.split("(State = ").nth(1)?.chars().next()?.to_digit(10)? as u8;
    Some(FirewallInfo {
        enabled: state >= 1,
        block_all: state == 2,
        stealth: text.contains("stealth mode is on"),
    })
}

/// `wpa2_personal_mixed` → `WPA/WPA2 Personal`
pub fn security_label(raw: &str) -> String {
    let key = raw
        .trim_start_matches("spairport_security_mode_")
        .trim_start_matches("pairport_security_mode_");
    match key {
        "none" => "Open (no password)".into(),
        "wep" => "WEP".into(),
        "wpa_personal" => "WPA Personal".into(),
        "wpa_personal_mixed" | "wpa2_personal_mixed" => "WPA/WPA2 Personal".into(),
        "wpa2_personal" => "WPA2 Personal".into(),
        "wpa3_transition" => "WPA2/WPA3 Personal".into(),
        "wpa3_personal" => "WPA3 Personal".into(),
        "wpa2_enterprise" => "WPA2 Enterprise".into(),
        "wpa3_enterprise" => "WPA3 Enterprise".into(),
        "owe" | "owe_transition" => "Enhanced Open".into(),
        other => other.replace('_', " "),
    }
}

/// How weak a Wi-Fi security mode is: 2 = no real protection, 1 = outdated.
pub fn security_weakness(label: &str) -> u8 {
    match label {
        "Open (no password)" | "WEP" => 2,
        "WPA Personal" | "WPA/WPA2 Personal" => 1,
        _ => 0,
    }
}

/// `A4:B1:C1:0:1:2` → `a4:b1:c1:00:01:02`. `None` unless it is six hex bytes,
/// or if it is the all-zero placeholder.
pub fn normalize_bssid(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::with_capacity(6);
    for p in parts {
        if p.is_empty() || p.len() > 2 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", p.to_lowercase()));
    }
    let bssid = out.join(":");
    (bssid != "00:00:00:00:00:00").then_some(bssid)
}

/// CoreWLAN's `CWChannelBand` as the labels above ("2.4 GHz").
pub fn band_label(raw: i64) -> Option<String> {
    Some(match raw {
        1 => "2.4 GHz",
        2 => "5 GHz",
        3 => "6 GHz",
        _ => return None,
    })
    .map(String::from)
}

/// CoreWLAN's `CWChannelWidth` as the labels above ("80 MHz").
pub fn width_label(raw: i64) -> Option<String> {
    Some(match raw {
        1 => "20 MHz",
        2 => "40 MHz",
        3 => "80 MHz",
        4 => "160 MHz",
        _ => return None,
    })
    .map(String::from)
}

/// CoreWLAN's `CWPHYMode` values a network supports (1 a, 2 b, 3 g, 4 n,
/// 5 ac, 6 ax) as system_profiler writes them: "802.11a/n/ac/ax".
pub fn phy_label(supported: &[i64]) -> Option<String> {
    let names: Vec<&str> = [(1, "a"), (2, "b"), (3, "g"), (4, "n"), (5, "ac"), (6, "ax")]
        .iter()
        .filter(|(v, _)| supported.contains(v))
        .map(|(_, n)| *n)
        .collect();
    (!names.is_empty()).then(|| format!("802.11{}", names.join("/")))
}

/// `CWSecurity` values, as CoreWLAN numbers them.
pub mod cw {
    pub const NONE: i64 = 0;
    pub const WEP: i64 = 1;
    pub const WPA_PERSONAL: i64 = 2;
    pub const WPA_PERSONAL_MIXED: i64 = 3;
    pub const WPA2_PERSONAL: i64 = 4;
    pub const DYNAMIC_WEP: i64 = 6;
    pub const WPA_ENTERPRISE: i64 = 7;
    pub const WPA_ENTERPRISE_MIXED: i64 = 8;
    pub const WPA2_ENTERPRISE: i64 = 9;
    pub const WPA3_PERSONAL: i64 = 11;
    pub const WPA3_ENTERPRISE: i64 = 12;
    pub const WPA3_TRANSITION: i64 = 13;
    pub const OWE: i64 = 14;
    pub const OWE_TRANSITION: i64 = 15;
    /// Every value worth asking a scanned network about. The generic
    /// "Personal" (5) and "Enterprise" (10) say too little to name a mode.
    pub const PROBE: [i64; 14] = [0, 1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14, 15];
}

/// The label for the `CWSecurity` values a network supports (one, for the
/// network you're connected to). Mixed modes are named after their weakest
/// and strongest member, like `security_label` does. `None` if nothing says
/// which mode it is.
pub fn cw_security_label(supported: &[i64]) -> Option<String> {
    let has = |v: i64| supported.contains(&v);
    let label = if has(cw::WPA3_TRANSITION) || (has(cw::WPA3_PERSONAL) && has(cw::WPA2_PERSONAL)) {
        "WPA2/WPA3 Personal"
    } else if has(cw::WPA3_PERSONAL) {
        "WPA3 Personal"
    } else if has(cw::WPA_PERSONAL_MIXED) || (has(cw::WPA_PERSONAL) && has(cw::WPA2_PERSONAL)) {
        "WPA/WPA2 Personal"
    } else if has(cw::WPA2_PERSONAL) {
        "WPA2 Personal"
    } else if has(cw::WPA_PERSONAL) {
        "WPA Personal"
    } else if has(cw::WPA3_ENTERPRISE) && !has(cw::WPA2_ENTERPRISE) {
        "WPA3 Enterprise"
    } else if has(cw::WPA2_ENTERPRISE) || has(cw::WPA3_ENTERPRISE) {
        "WPA2 Enterprise"
    } else if has(cw::WPA_ENTERPRISE) || has(cw::WPA_ENTERPRISE_MIXED) {
        "WPA Enterprise"
    // Before "Open": a transition-mode OWE network also answers for no security.
    } else if has(cw::OWE) || has(cw::OWE_TRANSITION) {
        "Enhanced Open"
    } else if has(cw::WEP) || has(cw::DYNAMIC_WEP) {
        "WEP"
    } else if has(cw::NONE) {
        "Open (no password)"
    } else {
        return None;
    };
    Some(label.into())
}

/// What CoreWLAN knows once macOS has authorised Location for NetWatch.
#[derive(Debug, Default, PartialEq)]
pub struct CwScan {
    /// The network this computer is connected to, with its name and BSSID.
    pub current: Option<Network>,
    /// Every network in the last scan, this computer's own included.
    pub nearby: Vec<Network>,
}

/// Puts CoreWLAN's names and BSSIDs into what system_profiler reported (which
/// keeps the link rate, MCS, standard and noise). The scan replaces the
/// nearby list when it found anything; the access point this computer is on
/// is taken out of it, as macOS does for the list it hands system_profiler.
pub fn merge_corewlan(mut base: WifiInfo, cw: CwScan) -> WifiInfo {
    let mut own = None;
    if let Some(c) = cw.current {
        own = c.bssid.clone();
        let cur = &mut base.current;
        cur.ssid = c.ssid.or(cur.ssid.take());
        cur.bssid = c.bssid;
        cur.channel = cur.channel.or(c.channel);
        cur.band = cur.band.take().or(c.band);
        cur.width = cur.width.take().or(c.width);
        cur.security = cur.security.take().or(c.security);
        cur.rssi = cur.rssi.or(c.rssi);
        cur.noise = cur.noise.or(c.noise);
    }
    if !cw.nearby.is_empty() {
        base.nearby = cw.nearby.into_iter().filter(|n| own.is_none() || n.bssid != own).collect();
    }
    base
}

fn parse_network(v: &serde_json::Value) -> Network {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    let channel_text = s("spairport_network_channel").unwrap_or_default();
    // "11 (2GHz, 20MHz)"
    let channel = channel_text.split_whitespace().next().and_then(|c| c.parse().ok());
    let inner: Vec<&str> = channel_text
        .split_once('(')
        .map(|(_, r)| r.trim_end_matches(')').split(", ").collect())
        .unwrap_or_default();
    let band = inner.first().map(|b| match *b {
        "2GHz" => "2.4 GHz".to_string(),
        "5GHz" => "5 GHz".to_string(),
        "6GHz" => "6 GHz".to_string(),
        other => other.to_string(),
    });
    let width = inner.get(1).map(|w| w.replace("MHz", " MHz"));
    // "-45 dBm / -96 dBm"
    let sn = s("spairport_signal_noise").unwrap_or_default();
    let mut nums = sn.split('/').map(|p| p.trim().trim_end_matches("dBm").trim().parse::<i32>().ok());
    let (rssi, noise) = (nums.next().flatten(), nums.next().flatten());
    Network {
        ssid: s("_name").filter(|n| n != "<redacted>" && !n.is_empty()),
        bssid: None,
        channel,
        band,
        width,
        phy: s("spairport_network_phymode"),
        security: s("spairport_security_mode").map(|m| security_label(&m)),
        rssi,
        noise,
    }
}

pub fn parse_system_profiler(json: &str, interface: &str) -> Option<WifiInfo> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let ifaces = v.get("SPAirPortDataType")?.get(0)?.get("spairport_airport_interfaces")?.as_array()?;
    let iface = ifaces
        .iter()
        .find(|i| i.get("_name").and_then(|n| n.as_str()) == Some(interface))?;
    let cur = iface.get("spairport_current_network_information")?;
    let num = |k: &str| cur.get(k).and_then(|x| x.as_u64()).map(|n| n as u32);
    let nearby = iface
        .get("spairport_airport_other_local_wireless_networks")
        .and_then(|n| n.as_array())
        .map(|a| a.iter().map(parse_network).collect())
        .unwrap_or_default();
    Some(WifiInfo {
        interface: interface.to_string(),
        current: parse_network(cur),
        rate_mbps: num("spairport_network_rate"),
        mcs: num("spairport_network_mcs"),
        country: cur
            .get("spairport_network_country_code")
            .and_then(|x| x.as_str())
            .map(String::from),
        nearby,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[
      {"_name":"en0","spairport_current_network_information":{"_name":"<redacted>",
        "spairport_network_channel":"11 (2GHz, 20MHz)","spairport_network_country_code":"AU",
        "spairport_network_mcs":15,"spairport_network_phymode":"802.11n","spairport_network_rate":144,
        "spairport_security_mode":"spairport_security_mode_wpa2_personal_mixed",
        "spairport_signal_noise":"-45 dBm / -96 dBm"},
       "spairport_airport_other_local_wireless_networks":[
        {"_name":"Neighbour","spairport_network_channel":"36 (5GHz, 80MHz)","spairport_network_phymode":"802.11a/n/ac/ax",
         "spairport_security_mode":"pairport_security_mode_wpa3_transition","spairport_signal_noise":"-72 dBm / -96 dBm"}]},
      {"_name":"awdl0"}]}]}"#;

    #[test]
    fn parses_current_and_nearby_networks() {
        let w = parse_system_profiler(SAMPLE, "en0").unwrap();
        assert_eq!(w.current.ssid, None);
        assert_eq!(w.current.channel, Some(11));
        assert_eq!(w.current.band.as_deref(), Some("2.4 GHz"));
        assert_eq!(w.current.width.as_deref(), Some("20 MHz"));
        assert_eq!(w.current.security.as_deref(), Some("WPA/WPA2 Personal"));
        assert_eq!((w.current.rssi, w.current.noise), (Some(-45), Some(-96)));
        assert_eq!(w.rate_mbps, Some(144));
        assert_eq!(w.nearby.len(), 1);
        assert_eq!(w.nearby[0].ssid.as_deref(), Some("Neighbour"));
        assert_eq!(w.nearby[0].band.as_deref(), Some("5 GHz"));
        assert_eq!(w.nearby[0].security.as_deref(), Some("WPA2/WPA3 Personal"));
        assert!(parse_system_profiler(SAMPLE, "en1").is_none());
    }

    #[test]
    fn rates_security_modes() {
        assert_eq!(security_weakness(&security_label("spairport_security_mode_none")), 2);
        assert_eq!(security_weakness(&security_label("spairport_security_mode_wpa2_personal_mixed")), 1);
        assert_eq!(security_weakness(&security_label("spairport_security_mode_wpa3_personal")), 0);
    }

    #[test]
    fn normalizes_bssids() {
        assert_eq!(normalize_bssid("AA:BB:CC:DD:EE:FF").as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(normalize_bssid("a4:b1:c1:0:1:2").as_deref(), Some("a4:b1:c1:00:01:02"));
        assert_eq!(normalize_bssid(" A4-B1-C1-00-01-02 ").as_deref(), Some("a4:b1:c1:00:01:02"));
        for bad in ["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "aa:bb:cc:dd:ee:gg", "aabbccddeeff", "aa:bb:cc:dd:ee:fff", "00:00:00:00:00:00", "0:0:0:0:0:0"] {
            assert_eq!(normalize_bssid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn corewlan_bands_widths_and_standards_use_the_existing_labels() {
        assert_eq!(band_label(1).as_deref(), Some("2.4 GHz"));
        assert_eq!(band_label(2).as_deref(), Some("5 GHz"));
        assert_eq!(band_label(3).as_deref(), Some("6 GHz"));
        assert_eq!(band_label(0), None);
        assert_eq!(width_label(1).as_deref(), Some("20 MHz"));
        assert_eq!(width_label(3).as_deref(), Some("80 MHz"));
        assert_eq!(width_label(4).as_deref(), Some("160 MHz"));
        assert_eq!(width_label(0), None);
        // The same text system_profiler gives for the same channel line.
        let n = parse_network(&serde_json::json!({"spairport_network_channel": "36 (5GHz, 80MHz)"}));
        assert_eq!((n.band, n.width), (band_label(2), width_label(3)));
        assert_eq!(phy_label(&[1, 4, 5, 6]).as_deref(), Some("802.11a/n/ac/ax"));
        assert_eq!(phy_label(&[2, 3, 4]).as_deref(), Some("802.11b/g/n"));
        assert_eq!(phy_label(&[]), None);
    }

    #[test]
    fn maps_corewlan_security_to_the_existing_labels() {
        use cw::*;
        let label = |v: &[i64]| cw_security_label(v);
        assert_eq!(label(&[NONE]).as_deref(), Some("Open (no password)"));
        assert_eq!(label(&[WEP]).as_deref(), Some("WEP"));
        assert_eq!(label(&[DYNAMIC_WEP]).as_deref(), Some("WEP"));
        assert_eq!(label(&[WPA_PERSONAL]).as_deref(), Some("WPA Personal"));
        assert_eq!(label(&[WPA_PERSONAL_MIXED]).as_deref(), Some("WPA/WPA2 Personal"));
        assert_eq!(label(&[WPA_PERSONAL, WPA2_PERSONAL]).as_deref(), Some("WPA/WPA2 Personal"));
        assert_eq!(label(&[WPA2_PERSONAL]).as_deref(), Some("WPA2 Personal"));
        assert_eq!(label(&[WPA3_PERSONAL]).as_deref(), Some("WPA3 Personal"));
        assert_eq!(label(&[WPA3_TRANSITION]).as_deref(), Some("WPA2/WPA3 Personal"));
        assert_eq!(label(&[WPA2_PERSONAL, WPA3_PERSONAL]).as_deref(), Some("WPA2/WPA3 Personal"));
        assert_eq!(label(&[WPA3_TRANSITION, WPA2_PERSONAL, WPA3_PERSONAL]).as_deref(), Some("WPA2/WPA3 Personal"));
        assert_eq!(label(&[WPA2_ENTERPRISE]).as_deref(), Some("WPA2 Enterprise"));
        assert_eq!(label(&[WPA3_ENTERPRISE]).as_deref(), Some("WPA3 Enterprise"));
        assert_eq!(label(&[WPA2_ENTERPRISE, WPA3_ENTERPRISE]).as_deref(), Some("WPA2 Enterprise"));
        assert_eq!(label(&[WPA_ENTERPRISE]).as_deref(), Some("WPA Enterprise"));
        assert_eq!(label(&[OWE]).as_deref(), Some("Enhanced Open"));
        // A transition-mode OWE network also answers for "no security": still Enhanced Open.
        assert_eq!(label(&[NONE, OWE_TRANSITION]).as_deref(), Some("Enhanced Open"));
        // The weakest personal mode a network accepts decides, as for system_profiler's "mixed".
        assert_eq!(label(&[WEP, WPA2_PERSONAL]).as_deref(), Some("WPA2 Personal"));
        // The generic values and "unknown" (NSIntegerMax) name nothing.
        assert_eq!(label(&[5]), None);
        assert_eq!(label(&[10]), None);
        assert_eq!(label(&[i64::MAX]), None);
        assert_eq!(label(&[]), None);
        // The labels agree with the weakness rating used for this network's own alert.
        assert_eq!(security_weakness(&label(&[NONE]).unwrap()), 2);
        assert_eq!(security_weakness(&label(&[WPA_PERSONAL_MIXED]).unwrap()), 1);
        assert_eq!(security_weakness(&label(&[WPA3_TRANSITION]).unwrap()), 0);
    }

    fn cw_net(ssid: &str, bssid: &str, channel: u32, rssi: i32) -> Network {
        Network {
            ssid: Some(ssid.into()),
            bssid: Some(bssid.into()),
            channel: Some(channel),
            band: Some("5 GHz".into()),
            security: Some("WPA2 Personal".into()),
            rssi: Some(rssi),
            ..Default::default()
        }
    }

    #[test]
    fn merges_corewlan_names_into_the_system_profiler_reading() {
        let base = parse_system_profiler(SAMPLE, "en0").unwrap();
        assert_eq!(base.current.ssid, None);
        let me = cw_net("Home", "aa:bb:cc:00:00:01", 11, -44);
        let scan = CwScan {
            current: Some(me.clone()),
            nearby: vec![me, cw_net("Neighbour", "11:22:33:44:55:66", 36, -72), cw_net("Home", "aa:bb:cc:00:00:02", 1, -60)],
        };
        let w = merge_corewlan(base, scan);
        // Name and BSSID are new; everything system_profiler knew stays.
        assert_eq!(w.current.ssid.as_deref(), Some("Home"));
        assert_eq!(w.current.bssid.as_deref(), Some("aa:bb:cc:00:00:01"));
        assert_eq!((w.current.channel, w.current.rssi, w.current.noise), (Some(11), Some(-45), Some(-96)));
        assert_eq!(w.current.security.as_deref(), Some("WPA/WPA2 Personal"));
        assert_eq!(w.rate_mbps, Some(144));
        // The access point we're on is not one of the "other" networks.
        let names: Vec<_> = w.nearby.iter().map(|n| (n.ssid.as_deref().unwrap(), n.bssid.as_deref().unwrap())).collect();
        assert_eq!(names, [("Neighbour", "11:22:33:44:55:66"), ("Home", "aa:bb:cc:00:00:02")]);
    }

    #[test]
    fn an_empty_corewlan_scan_keeps_the_system_profiler_list() {
        let base = parse_system_profiler(SAMPLE, "en0").unwrap();
        let scan = CwScan { current: Some(cw_net("Home", "aa:bb:cc:00:00:01", 11, -44)), nearby: vec![] };
        let w = merge_corewlan(base.clone(), scan);
        assert_eq!(w.nearby, base.nearby);
        assert_eq!(w.current.ssid.as_deref(), Some("Home"));
        // Nothing from CoreWLAN at all changes nothing.
        assert_eq!(merge_corewlan(base.clone(), CwScan::default()), base);
    }

    /// `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_wifi_and_firewall() {
        println!("{:?}", read("en0"));
        println!("{:?}", firewall());
    }

    #[test]
    fn parses_firewall_state() {
        let t = "Firewall is blocking all non-essential incoming connections. (State = 2)\nFirewall stealth mode is on\n";
        assert_eq!(parse_firewall(t), Some(FirewallInfo { enabled: true, block_all: true, stealth: true }));
        let t = "Firewall is disabled. (State = 0)\nFirewall stealth mode is off\n";
        assert_eq!(parse_firewall(t), Some(FirewallInfo { enabled: false, block_all: false, stealth: false }));
    }
}

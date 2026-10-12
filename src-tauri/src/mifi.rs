//! Status from TP-Link 4G mobile hotspots (M7350 and siblings). The
//! hotspot's web interface answers a basic status request without logging
//! in: connection state, mobile network type, SIM state, Wi-Fi name and how
//! many devices are connected. NetWatch only reads this; it never changes
//! any hotspot setting.

use base64::Engine;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct MifiStatus {
    pub model: Option<String>,
    pub connected: bool,
    pub connect_label: String,
    /// The hotspot's raw network type code (0 no service … 7 LTE+).
    pub network_type: u8,
    /// "4G+", "4G", "3G", "2G" or "No service".
    pub generation: String,
    /// The technology name, e.g. "LTE", "WCDMA", "GSM".
    pub technology: String,
    pub sim_label: String,
    pub sim_ready: bool,
    pub ssid: Option<String>,
    pub clients: Option<u32>,
}

/// (generation, technology) for the hotspot's network type code.
pub fn network_type(code: u8) -> (&'static str, &'static str) {
    match code {
        1 => ("2G", "GSM"),
        2 => ("3G", "WCDMA"),
        3 => ("4G", "LTE"),
        4 => ("3G", "TD-SCDMA"),
        5 => ("2G", "CDMA 1x"),
        6 => ("3G", "CDMA EV-DO"),
        7 => ("4G+", "LTE-A"),
        _ => ("No service", "None"),
    }
}

/// Orders generations so a drop can be detected: 4G+ > 4G > 3G > 2G > none.
pub fn rank(generation: &str) -> u8 {
    match generation {
        "4G+" => 4,
        "4G" => 3,
        "3G" => 2,
        "2G" => 1,
        _ => 0,
    }
}

fn connect_label(code: u64) -> &'static str {
    match code {
        0 => "Mobile data off",
        1 => "Disconnected",
        2 => "Connecting",
        3 => "Disconnecting",
        4 => "Connected",
        _ => "Unknown",
    }
}

fn sim_label(code: u64) -> &'static str {
    match code {
        0 => "SIM invalid",
        1 => "No SIM",
        2 => "SIM error",
        3 => "Ready",
        4 => "PIN required",
        5 => "PIN verified",
        6 => "PUK required",
        7 => "SIM locked",
        _ => "Unknown",
    }
}

pub fn parse_status(json: &str) -> Option<MifiStatus> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("result")?.as_i64()? != 0 {
        return None;
    }
    let wan = v.get("wan")?;
    let code = wan.get("networkType").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
    let connect = wan.get("connectStatus").and_then(|x| x.as_u64()).unwrap_or(99);
    let sim = wan.get("simStatus").and_then(|x| x.as_u64()).unwrap_or(99);
    let (generation, technology) = network_type(code);
    Some(MifiStatus {
        model: v
            .get("deviceInfo")
            .and_then(|d| d.get("model"))
            .and_then(|m| m.as_str())
            .map(String::from),
        connected: connect == 4,
        connect_label: connect_label(connect).into(),
        network_type: code,
        generation: generation.into(),
        technology: technology.into(),
        sim_label: sim_label(sim).into(),
        sim_ready: sim == 3 || sim == 5,
        ssid: v
            .get("wlan")
            .and_then(|w| w.get("ssid"))
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        clients: v
            .get("connectedDevices")
            .and_then(|c| c.get("number"))
            .and_then(|n| n.as_u64())
            .map(|n| n as u32),
    })
}

/// Asks the hotspot at `gateway` for its status. `None` if it isn't a
/// TP-Link hotspot or doesn't answer.
pub fn status(gateway: Ipv4Addr) -> Option<MifiStatus> {
    let b64 = base64::engine::general_purpose::STANDARD;
    // The web interface wraps requests and replies in base64.
    let body = format!(
        "{{\"data\":\"{}\"}}",
        b64.encode(r#"{"module":"webServer","action":6}"#)
    );
    let reply = ureq::post(&format!("http://{gateway}/cgi-bin/web_cgi"))
        .timeout(Duration::from_secs(3))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .ok()?
        .into_string()
        .ok()?;
    let decoded = b64.decode(reply.trim()).ok()?;
    parse_status(&String::from_utf8_lossy(&decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hotspot_status() {
        let json = "{\n\t\"factoryDefault\":\tfalse,\n\t\"deviceInfo\":\t{\"model\":\t\"M7350\"},\n\t\"wan\":\t{\"connectStatus\":\t4, \"networkType\":\t3, \"simStatus\":\t3},\n\t\"wlan\":\t{\"ssid\":\t\"TP_link1\", \"mode\": 1, \"bandType\": 0},\n\t\"connectedDevices\":\t{\"number\":\t5},\n\t\"result\":\t0\n}";
        let s = parse_status(json).unwrap();
        assert_eq!(s.model.as_deref(), Some("M7350"));
        assert!(s.connected);
        assert_eq!((s.generation.as_str(), s.technology.as_str()), ("4G", "LTE"));
        assert!(s.sim_ready);
        assert_eq!(s.ssid.as_deref(), Some("TP_link1"));
        assert_eq!(s.clients, Some(5));
        assert!(parse_status("{\"result\": 1}").is_none());
    }

    #[test]
    fn ranks_generations() {
        assert!(rank(network_type(3).0) > rank(network_type(2).0));
        assert!(rank(network_type(7).0) > rank(network_type(3).0));
        assert_eq!(rank(network_type(0).0), 0);
    }

    /// `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_hotspot_status() {
        println!("{:?}", status("192.168.0.1".parse().unwrap()));
    }
}

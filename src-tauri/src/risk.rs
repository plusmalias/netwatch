//! Device risk scoring and structured security incident report export.
//! Pure functions over plain data so the scoring model is unit-tested and
//! consistent across the backend, UI and incident exports.

use crate::alerts::{Alert, Severity};
use crate::audit::{is_risky_port, port_name};
use crate::expert;
use crate::store::Device;
use crate::upnp::PortMapping;
use crate::util::is_randomized_mac;
use serde::Serialize;
use std::collections::BTreeMap;

/// Open LAN ports that warrant attention even though they aren't as severe as
/// unencrypted remote-access ports (Telnet/FTP/RDP/VNC/ADB).
const SENSITIVE_PORTS: &[u16] = &[22, 139, 445, 554, 1883, 6379, 37777];

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRisk {
    pub score: u8,
    /// "none", "low", "medium" or "high".
    pub level: &'static str,
    pub reasons: Vec<String>,
}

/// Whether `alert` applies to `dev`, including compound keys such as
/// `mac:port` (`port_audit`), `ip:port` (`suspicious_port`) and `proc->ip`
/// (`c2_connection`).
pub fn alert_matches_device(alert: &Alert, dev: &Device) -> bool {
    let k = alert.key.as_str();
    let matches_id = |id: &str| {
        !id.is_empty()
            && (k == id
                || k.strip_prefix(id).is_some_and(|r| r.starts_with(':'))
                || k.strip_suffix(id).is_some_and(|l| l.ends_with("->")))
    };
    matches_id(&dev.mac)
        || matches_id(&dev.ip)
        || dev.aliases.iter().any(|a| matches_id(a))
}

fn is_exposed_forward_port(port: u16) -> bool {
    is_risky_port(port) || SENSITIVE_PORTS.contains(&port)
}

/// Scores how much security attention a single device deserves (0–100).
pub fn assess_device(
    dev: &Device,
    open_alerts: &[Alert],
    forwards: &[PortMapping],
    on_current_net: bool,
) -> DeviceRisk {
    if dev.is_self {
        return DeviceRisk {
            score: 0,
            level: "none",
            reasons: Vec::new(),
        };
    }
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let mut add = |pts: u32, why: String| {
        score += pts;
        reasons.push(why);
    };

    if let Some(open) = &dev.open_ports {
        for &p in open {
            let label = match port_name(p) {
                "" => format!("Port {p}"),
                n => format!("{n} (port {p})"),
            };
            let banner = dev
                .port_banners
                .get(&p)
                .map(|b| format!(" — {b}"))
                .unwrap_or_default();
            if is_risky_port(p) {
                add(
                    35,
                    format!("{label}{banner} is open; it's often unencrypted or a common target"),
                );
            } else if SENSITIVE_PORTS.contains(&p) {
                add(10, format!("{label}{banner} accepts connections"));
            }
        }
    }

    if on_current_net {
        let dev_fwds: Vec<&PortMapping> = forwards
            .iter()
            .filter(|m| m.internal_client == dev.ip)
            .collect();
        if !dev_fwds.is_empty() {
            let desc = dev_fwds
                .iter()
                .map(|m| format!("{} {}", m.protocol, m.external_port))
                .collect::<Vec<_>>()
                .join(", ");
            add(
                30,
                format!(
                    "Reachable from the internet through {} port forward{} ({desc})",
                    dev_fwds.len(),
                    if dev_fwds.len() == 1 { "" } else { "s" }
                ),
            );
            if dev_fwds
                .iter()
                .any(|m| is_exposed_forward_port(m.internal_port) || is_exposed_forward_port(m.external_port))
            {
                add(
                    20,
                    "A port forward exposes a sensitive or remote-access service directly to the internet"
                        .into(),
                );
            }
        }
    }

    for a in open_alerts
        .iter()
        .filter(|a| !a.acknowledged && a.severity > Severity::Info && alert_matches_device(a, dev))
    {
        let pts = match a.severity {
            Severity::High => 30,
            Severity::Medium if a.kind == "identity_change" => 25,
            Severity::Medium => 15,
            Severity::Low => 5,
            Severity::Info => 0,
        };
        if pts > 0 {
            add(pts, a.title.clone());
        }
    }

    if !dev.trusted && !dev.is_gateway {
        add(15, "Not marked as trusted yet".into());
    }
    let unidentified = dev.label.is_none()
        && dev.hostname.is_none()
        && dev.friendly_name.is_none()
        && dev.vendor.is_none()
        && dev.model.is_none()
        && dev.port_banners.is_empty();
    if unidentified {
        if !dev.trusted && is_randomized_mac(&dev.mac) {
            add(15, "Unidentified device using a private MAC address".into());
        } else {
            add(10, "NetWatch couldn't identify it".into());
        }
    }

    let score = score.min(100) as u8;
    let level = if score >= 50 {
        "high"
    } else if score >= 20 {
        "medium"
    } else if score > 0 {
        "low"
    } else {
        "none"
    };
    DeviceRisk {
        score,
        level,
        reasons,
    }
}

pub fn assess_all(
    devices: &[Device],
    alerts: &[Alert],
    forwards: &[PortMapping],
    current_gateway_mac: Option<&str>,
) -> BTreeMap<String, DeviceRisk> {
    devices
        .iter()
        .map(|d| {
            let on_cur = d.is_self
                || d.network.as_deref() == current_gateway_mac
                || (d.network.is_none() && current_gateway_mac.is_some());
            (d.mac.clone(), assess_device(d, alerts, forwards, on_cur))
        })
        .collect()
}

#[derive(Serialize)]
pub struct EnrichedAlert {
    #[serde(flatten)]
    pub alert: Alert,
    pub attack_techniques: Vec<String>,
    pub attack_tactic: String,
    pub why: String,
    pub recommended_steps: Vec<String>,
}

#[derive(Serialize)]
pub struct RiskyDeviceSummary {
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub vendor: Option<String>,
    pub trusted: bool,
    pub online: bool,
    pub open_ports: Option<Vec<u16>>,
    pub port_banners: BTreeMap<u16, String>,
    pub risk: DeviceRisk,
}

#[derive(Serialize)]
pub struct IncidentReport {
    pub generated_at: u64,
    pub netwatch_version: &'static str,
    pub open_alert_count: usize,
    pub high_alert_count: usize,
    pub risky_devices: Vec<RiskyDeviceSummary>,
    pub open_alerts: Vec<EnrichedAlert>,
    pub port_forwards: Vec<PortMapping>,
}

pub fn build_incident_report(
    now: u64,
    devices: &[Device],
    alerts: &[Alert],
    forwards: &[PortMapping],
    current_gateway_mac: Option<&str>,
    name_of: impl Fn(&Device) -> String,
) -> IncidentReport {
    let expert_map: BTreeMap<&str, expert::KindView> =
        expert::all().into_iter().map(|k| (k.kind, k)).collect();
    let open: Vec<EnrichedAlert> = alerts
        .iter()
        .filter(|a| !a.acknowledged && a.severity > Severity::Info)
        .rev()
        .map(|a| {
            let info = expert_map.get(a.kind.as_str());
            EnrichedAlert {
                alert: a.clone(),
                attack_techniques: info
                    .map(|i| {
                        i.techniques
                            .iter()
                            .map(|t| format!("{} ({})", t.id, t.name))
                            .collect()
                    })
                    .unwrap_or_default(),
                attack_tactic: info.map(|i| i.tactic.to_string()).unwrap_or_default(),
                why: info.map(|i| i.why.to_string()).unwrap_or_default(),
                recommended_steps: info
                    .map(|i| i.steps.iter().map(|s| s.to_string()).collect())
                    .unwrap_or_default(),
            }
        })
        .collect();
    let high_alert_count = open
        .iter()
        .filter(|a| a.alert.severity == Severity::High)
        .count();

    let risks = assess_all(devices, alerts, forwards, current_gateway_mac);
    let mut risky_devices: Vec<RiskyDeviceSummary> = devices
        .iter()
        .filter_map(|d| {
            let r = risks.get(&d.mac)?.clone();
            (r.score > 0).then(|| RiskyDeviceSummary {
                mac: d.mac.clone(),
                ip: d.ip.clone(),
                name: name_of(d),
                vendor: d.vendor.clone(),
                trusted: d.trusted,
                online: d.online,
                open_ports: d.open_ports.clone(),
                port_banners: d.port_banners.clone(),
                risk: r,
            })
        })
        .collect();
    risky_devices.sort_by(|a, b| b.risk.score.cmp(&a.risk.score));

    IncidentReport {
        generated_at: now,
        netwatch_version: env!("CARGO_PKG_VERSION"),
        open_alert_count: open.len(),
        high_alert_count,
        risky_devices,
        open_alerts: open,
        port_forwards: forwards.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(kind: &str, key: &str, severity: Severity) -> Alert {
        Alert {
            id: 1,
            ts: 1_000,
            last_ts: 1_000,
            count: 1,
            severity,
            kind: kind.into(),
            key: key.into(),
            title: format!("{kind} on {key}"),
            detail: "detail".into(),
            acknowledged: false,
        }
    }

    #[test]
    fn matches_compound_alert_keys_and_aliases() {
        let mut d = Device {
            mac: "aa:bb:cc:00:00:01".into(),
            ip: "192.168.0.20".into(),
            ..Default::default()
        };
        d.aliases.insert("22:33:44:00:00:99".into());

        assert!(alert_matches_device(&alert("port_audit", "aa:bb:cc:00:00:01:23", Severity::Medium), &d));
        assert!(alert_matches_device(&alert("suspicious_port", "192.168.0.20:4444", Severity::Medium), &d));
        assert!(alert_matches_device(&alert("c2_connection", "curl->192.168.0.20", Severity::High), &d));
        assert!(alert_matches_device(&alert("new_device", "22:33:44:00:00:99", Severity::Medium), &d));
        // Prefix collision must NOT match: .2 must not match .20
        assert!(!alert_matches_device(&alert("port_scan", "192.168.0.2", Severity::Medium), &d));
        assert!(!alert_matches_device(&alert("suspicious_port", "192.168.0.2:23", Severity::Medium), &d));
    }

    #[test]
    fn scores_risky_ports_forwarded_services_and_identity_change() {
        let mut dev = Device {
            mac: "aa:bb:cc:00:00:05".into(),
            ip: "192.168.0.50".into(),
            hostname: Some("cam-hall".into()),
            trusted: true,
            open_ports: Some(vec![554, 5555]),
            ..Default::default()
        };
        dev.port_banners.insert(554, "Hikvision/1.0".into());
        let fwd = PortMapping {
            protocol: "TCP".into(),
            external_port: 5555,
            internal_port: 5555,
            internal_client: "192.168.0.50".into(),
            description: "adb".into(),
            enabled: true,
            remote_host: String::new(),
            lease_s: 0,
        };
        let al = vec![
            alert("port_audit", "aa:bb:cc:00:00:05:5555", Severity::Medium),
            alert("identity_change", "aa:bb:cc:00:00:05", Severity::Medium),
        ];
        let r = assess_device(&dev, &al, &[fwd], true);
        // 35 (ADB) + 10 (RTSP) + 30 (fwd) + 20 (risky fwd) + 15 (port_audit) + 25 (identity) -> capped 100
        assert_eq!(r.score, 100);
        assert_eq!(r.level, "high");
        assert!(r.reasons.iter().any(|x| x.contains("Hikvision/1.0")));
        assert!(r.reasons.iter().any(|x| x.contains("port forward exposes a sensitive")));
    }

    #[test]
    fn self_is_zero_and_incident_report_includes_attack_metadata() {
        let self_dev = Device {
            mac: "02:00:00:00:00:01".into(),
            is_self: true,
            ..Default::default()
        };
        assert_eq!(assess_device(&self_dev, &[], &[], true).score, 0);

        let other = Device {
            mac: "12:00:00:00:00:09".into(),
            ip: "192.168.0.9".into(),
            trusted: false,
            ..Default::default()
        };
        let al = vec![alert("arp_spoof", "192.168.0.1", Severity::High)];
        let rep = build_incident_report(9_999, &[self_dev, other], &al, &[], None, |d| d.ip.clone());
        assert_eq!(rep.open_alert_count, 1);
        assert_eq!(rep.high_alert_count, 1);
        assert_eq!(rep.risky_devices.len(), 1);
        assert!(rep.open_alerts[0].attack_techniques[0].contains("T1557.002"));
    }
}

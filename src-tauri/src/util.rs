use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn fmt_mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Normalizes `0:1a:2B:3:4:5` / `00-1A-2B-03-04-05` to `00:1a:2b:03:04:05`.
pub fn norm_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(fmt_mac(&out))
}

fn first_octet(mac: &str) -> Option<u8> {
    u8::from_str_radix(mac.get(0..2)?, 16).ok()
}

/// A real device address: not broadcast, multicast or all-zero.
pub fn is_unicast_mac(mac: &str) -> bool {
    mac != "00:00:00:00:00:00" && first_octet(mac).is_some_and(|b| b & 0x01 == 0)
}

/// Locally administered bit set — phones and laptops use these for Wi-Fi privacy.
pub fn is_randomized_mac(mac: &str) -> bool {
    first_octet(mac).is_some_and(|b| b & 0x02 != 0)
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (seg & 0xfe00) == 0xfc00 // unique local
                || (seg & 0xffc0) == 0xfe80 // link local
        }
    }
}

pub fn ipv4_of(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// A `Command` that doesn't flash a console window on Windows.
pub fn quiet_command(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_macs() {
        assert_eq!(norm_mac("0:1a:2B:3:4:5").as_deref(), Some("00:1a:2b:03:04:05"));
        assert_eq!(norm_mac("00-1A-2B-03-04-05").as_deref(), Some("00:1a:2b:03:04:05"));
        assert_eq!(norm_mac("(incomplete)"), None);
        assert_eq!(norm_mac("00:11:22:33:44"), None);
    }

    #[test]
    fn classifies_macs() {
        assert!(is_unicast_mac("00:11:22:33:44:55"));
        assert!(!is_unicast_mac("ff:ff:ff:ff:ff:ff"));
        assert!(!is_unicast_mac("01:00:5e:00:00:fb"));
        assert!(is_randomized_mac("da:a1:19:00:00:01"));
        assert!(!is_randomized_mac("00:11:22:33:44:55"));
    }

    #[test]
    fn classifies_ips() {
        assert!(is_private_ip(&"192.168.1.4".parse().unwrap()));
        assert!(is_private_ip(&"100.72.0.1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"2606:4700::1111".parse().unwrap()));
    }
}

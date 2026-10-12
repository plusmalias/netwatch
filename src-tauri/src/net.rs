use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};

/// The interface this machine uses to reach the internet, and its LAN.
#[derive(Serialize, Clone, Debug)]
pub struct NetInfo {
    pub interface: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<String>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub gateway_mac: Option<String>,
    pub local_ips: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub lease: Option<Lease>,
}

/// What the DHCP server told this computer.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Lease {
    pub server: Option<String>,
    pub lease_s: Option<u64>,
    pub domain: Option<String>,
}

pub fn default_net() -> Result<NetInfo, String> {
    let iface = netdev::get_default_interface()?;
    let v4 = iface
        .ipv4
        .first()
        .ok_or_else(|| format!("{} has no IPv4 address", iface.name))?;
    let mut local_ips: Vec<IpAddr> = iface.ipv4.iter().map(|n| IpAddr::V4(n.addr())).collect();
    local_ips.extend(iface.ipv6.iter().map(|n| IpAddr::V6(n.addr())));
    let gateway_mac = iface
        .gateway
        .as_ref()
        .and_then(|g| crate::util::norm_mac(&g.mac_addr.to_string()))
        .filter(|m| crate::util::is_unicast_mac(m));
    Ok(NetInfo {
        interface: iface.name.clone(),
        ip: v4.addr(),
        prefix: v4.prefix_len(),
        mac: iface
            .mac_addr
            .and_then(|m| crate::util::norm_mac(&m.to_string())),
        gateway_ip: iface.gateway.as_ref().and_then(|g| g.ipv4.first().copied()),
        gateway_mac,
        local_ips,
        dns_servers: iface.dns_servers.clone(),
        lease: dhcp_lease(&iface.name),
    })
}

#[cfg(target_os = "macos")]
fn dhcp_lease(iface: &str) -> Option<Lease> {
    let out = crate::util::quiet_command("ipconfig")
        .args(["getpacket", iface])
        .output()
        .ok()?;
    parse_getpacket(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(not(target_os = "macos"))]
fn dhcp_lease(_iface: &str) -> Option<Lease> {
    None
}

/// macOS `ipconfig getpacket en0` output.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_getpacket(text: &str) -> Option<Lease> {
    let value = |key: &str| {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_once("): "))
            .map(|(_, v)| v.trim().to_string())
    };
    let lease = Lease {
        server: value("server_identifier"),
        lease_s: value("lease_time").and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()),
        domain: value("domain_name ("),
    };
    (lease != Lease::default()).then_some(lease)
}

/// Host addresses in our subnet, excluding ourselves. Large subnets are
/// narrowed to the /22 around our address so a sweep stays under ~1k hosts.
pub fn subnet_hosts(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let prefix = prefix.clamp(22, 30);
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(ip) & mask;
    let broadcast = net | !mask;
    (net + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|h| *h != ip)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_excludes_self_network_and_broadcast() {
        let hosts = subnet_hosts("192.168.0.110".parse().unwrap(), 24);
        assert_eq!(hosts.len(), 253);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(*hosts.last().unwrap(), Ipv4Addr::new(192, 168, 0, 254));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 0, 110)));
    }

    #[test]
    fn parses_dhcp_lease() {
        let text = "op = BOOTREPLY\nyiaddr = 192.168.0.110\noptions:\ndhcp_message_type (uint8): ACK 0x5\nserver_identifier (ip): 192.168.0.1\nlease_time (uint32): 0x1c20\ndomain_name (string): home\ndomain_name_server (ip_mult): {192.168.0.1}\n";
        let l = parse_getpacket(text).unwrap();
        assert_eq!(l.server.as_deref(), Some("192.168.0.1"));
        assert_eq!(l.lease_s, Some(7200));
        assert_eq!(l.domain.as_deref(), Some("home"));
        assert_eq!(parse_getpacket(""), None);
    }

    #[test]
    fn large_subnets_are_capped() {
        assert_eq!(subnet_hosts("10.1.2.3".parse().unwrap(), 8).len(), 1021);
    }
}

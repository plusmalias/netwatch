//! On-demand tools: Wake-on-LAN, traceroute and a DNS server check.

use serde::Serialize;
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, Question, CLASS, RCODE, TYPE};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- Wake-on-LAN

/// The magic packet: six 0xFF bytes, then the MAC address sixteen times.
pub fn magic_packet(mac: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = mac
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<_>>()?;
    if bytes.len() != 6 {
        return None;
    }
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend(&bytes);
    }
    Some(p)
}

/// Broadcasts a Wake-on-LAN packet for `mac` on the local subnet.
pub fn wake(mac: &str, local_ip: Ipv4Addr, prefix: u8) -> Result<(), String> {
    let packet = magic_packet(mac).ok_or("invalid MAC address")?;
    let sock = UdpSocket::bind((local_ip, 0)).map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    let subnet_bcast = Ipv4Addr::from(u32::from(local_ip) | !mask);
    let mut sent = false;
    for target in [subnet_bcast, Ipv4Addr::BROADCAST] {
        for port in [9, 7] {
            sent |= sock.send_to(&packet, (target, port)).is_ok();
        }
    }
    sent.then_some(()).ok_or_else(|| "couldn't send the wake packet".into())
}

// ---------------------------------------------------------------- traceroute

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Hop {
    pub n: u32,
    pub ip: Option<String>,
    pub name: Option<String>,
    pub rtt_ms: Option<f32>,
}

/// Parses `traceroute -n -q 1` (macOS/Linux) or `tracert -d` (Windows) output.
pub fn parse_traceroute(text: &str) -> Vec<Hop> {
    let mut hops = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let Some(n) = cols.first().and_then(|c| c.parse::<u32>().ok()) else { continue };
        let ip = cols.iter().skip(1).find_map(|c| c.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        // "3.123 ms" (traceroute) or "3 ms" / "<1 ms" (tracert): the number before the first "ms".
        let rtt_ms = cols
            .windows(2)
            .find(|w| w[1] == "ms")
            .and_then(|w| w[0].trim_start_matches('<').parse::<f32>().ok());
        hops.push(Hop {
            n,
            ip: ip.map(|i| i.to_string()),
            name: None,
            rtt_ms,
        });
    }
    hops
}

pub fn traceroute(target: &str) -> Result<Vec<Hop>, String> {
    let ok = !target.is_empty()
        && target.len() <= 253
        && target.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c))
        && !target.starts_with('-');
    if !ok {
        return Err("Enter a host name or IP address.".into());
    }
    #[cfg(windows)]
    let out = crate::util::quiet_command("tracert").args(["-d", "-h", "20", "-w", "1000", target]).output();
    #[cfg(not(windows))]
    let out = crate::util::quiet_command(if cfg!(target_os = "macos") { "/usr/sbin/traceroute" } else { "traceroute" })
        .args(["-n", "-q", "1", "-w", "1", "-m", "20", target])
        .output();
    let out = out.map_err(|e| format!("traceroute isn't available: {e}"))?;
    let mut hops = parse_traceroute(&String::from_utf8_lossy(&out.stdout));
    if hops.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() { "No route found.".into() } else { err });
    }
    let ips: Vec<Ipv4Addr> = hops.iter().filter_map(|h| h.ip.as_ref()?.parse().ok()).collect();
    let names = crate::discovery::reverse_lookup(ips, Duration::from_secs(3));
    for h in &mut hops {
        if let Some(ip) = h.ip.as_ref().and_then(|i| i.parse::<Ipv4Addr>().ok()) {
            h.name = names.get(&ip).cloned();
        }
    }
    Ok(hops)
}

// ---------------------------------------------------------------- DNS check

#[derive(Serialize, Clone, Debug, Default)]
pub struct DnsResult {
    pub server: String,
    pub label: String,
    /// Median time for popular names, which the server likely has cached.
    pub cached_ms: Option<f32>,
    /// Time for a name nobody has looked up before (a full lookup).
    pub uncached_ms: Option<f32>,
    pub answered: u32,
    pub asked: u32,
    /// It returned an address for a name that doesn't exist: the provider
    /// redirects mistyped addresses (usually to an ad or search page).
    pub nxdomain_hijack: bool,
}

const POPULAR: &[&str] = &["google.com", "apple.com", "cloudflare.com", "wikipedia.org", "amazon.com"];

fn query(server: IpAddr, name: &str, id: u16, timeout: Duration) -> Option<(Duration, RCODE, bool)> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut p = Packet::new_query(id);
    p.set_flags(simple_dns::PacketFlag::RECURSION_DESIRED);
    p.questions.push(Question::new(Name::new(name).ok()?, TYPE::A.into(), CLASS::IN.into(), false));
    let bytes = p.build_bytes_vec().ok()?;
    let t = Instant::now();
    sock.send_to(&bytes, (server, 53)).ok()?;
    let mut buf = [0u8; 1500];
    loop {
        let (n, _) = sock.recv_from(&mut buf).ok()?;
        let Ok(reply) = Packet::parse(&buf[..n]) else { continue };
        if reply.id() != id {
            continue;
        }
        let has_address = reply.answers.iter().any(|a| matches!(a.rdata, RData::A(_)));
        return Some((t.elapsed(), reply.rcode(), has_address));
    }
}

/// A name that can't exist, under a reserved TLD-like label nobody registers.
fn nonexistent_name(seed: u64) -> String {
    format!("netwatch-check-{seed:x}.invalid-tld-zz")
}

fn uncached_name(seed: u64) -> String {
    format!("nw{seed:x}.example.com")
}

/// Tests each server: popular (cached) names, one never-seen name, and a
/// name that doesn't exist to spot NXDOMAIN hijacking.
pub fn dns_check(servers: &[(IpAddr, String)], seed: u64) -> Vec<DnsResult> {
    let handles: Vec<_> = servers
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, (server, label))| {
            std::thread::spawn(move || {
                let timeout = Duration::from_secs(2);
                let mut r = DnsResult {
                    server: server.to_string(),
                    label,
                    ..Default::default()
                };
                let mut times = Vec::new();
                for (j, name) in POPULAR.iter().enumerate() {
                    r.asked += 1;
                    if let Some((t, _, _)) = query(server, name, (i * 64 + j) as u16 + 1, timeout) {
                        r.answered += 1;
                        times.push(t.as_secs_f32() * 1000.0);
                    }
                }
                times.sort_by(|a, b| a.total_cmp(b));
                r.cached_ms = times.get(times.len() / 2).copied();
                r.asked += 1;
                if let Some((t, _, _)) = query(server, &uncached_name(seed + i as u64), 900 + i as u16, timeout) {
                    r.answered += 1;
                    r.uncached_ms = Some(t.as_secs_f32() * 1000.0);
                }
                if let Some((_, rcode, has_address)) = query(server, &nonexistent_name(seed), 1800 + i as u16, timeout) {
                    r.nxdomain_hijack = rcode != RCODE::NameError && has_address;
                }
                r
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

// ---------------------------------------------------------------- VPN and DNS leaks

#[derive(Serialize, Clone, Debug, Default)]
pub struct VpnStatus {
    /// The default route goes through a tunnel interface.
    pub active: bool,
    pub interface: Option<String>,
    /// Tunnel interfaces that have an address (utun, ipsec, ppp, wg, tun).
    pub tunnels: Vec<String>,
}

fn is_tunnel(name: &str) -> bool {
    ["utun", "ipsec", "ppp", "wg", "tun", "tap"].iter().any(|p| name.starts_with(p))
}

pub fn vpn_status() -> VpnStatus {
    let default = netdev::get_default_interface().ok().map(|i| i.name);
    let tunnels: Vec<String> = netdev::get_interfaces()
        .into_iter()
        .filter(|i| is_tunnel(&i.name) && !i.ipv4.is_empty())
        .map(|i| i.name)
        .collect();
    let active = default.as_deref().is_some_and(is_tunnel);
    VpnStatus {
        active,
        interface: default.filter(|d| is_tunnel(d)),
        tunnels,
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct LeakEntry {
    pub ip: String,
    pub country: Option<String>,
    pub org: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct LeakResult {
    /// Your public address as the test server saw it.
    pub public: Option<LeakEntry>,
    /// The DNS resolvers that looked up the test names for you.
    pub resolvers: Vec<LeakEntry>,
    pub vpn: VpnStatus,
    /// On a VPN, a resolver from your own provider means lookups bypass the tunnel.
    pub leak: bool,
}

/// Looks up a handful of unique names and asks the bash.ws test service
/// which DNS resolvers asked for them.
pub fn dns_leak_test() -> Result<LeakResult, String> {
    let id = ureq::get("https://bash.ws/id")
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| format!("Couldn't reach the test service: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("The test service didn't return a test id.".into());
    }
    let handles: Vec<_> = (1..=10)
        .map(|i| {
            let name = format!("{i}.{id}.bash.ws");
            std::thread::spawn(move || {
                let _ = dns_lookup::lookup_host(&name);
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let body = ureq::get(&format!("https://bash.ws/dnsleak/test/{id}?json"))
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let mut r = parse_leak(&body)?;
    r.vpn = vpn_status();
    let isp = r.public.as_ref().and_then(|p| p.org.clone());
    r.leak = r.vpn.active && r.resolvers.iter().any(|x| x.org.is_some() && x.org == isp);
    Ok(r)
}

fn parse_leak(body: &str) -> Result<LeakResult, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let mut r = LeakResult::default();
    for e in v.as_array().ok_or("unexpected reply")? {
        let s = |k: &str| e.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(String::from);
        let entry = || LeakEntry {
            ip: s("ip").unwrap_or_default(),
            country: s("country_name"),
            org: s("org"),
        };
        match s("type").as_deref() {
            Some("ip") => r.public = Some(entry()),
            Some("dns") => r.resolvers.push(entry()),
            _ => {}
        }
    }
    Ok(r)
}

/// Friendly names for well-known public resolvers.
pub fn resolver_name(ip: &IpAddr) -> Option<&'static str> {
    let known: HashMap<&str, &str> = HashMap::from([
        ("1.1.1.1", "Cloudflare"),
        ("1.0.0.1", "Cloudflare"),
        ("8.8.8.8", "Google"),
        ("8.8.4.4", "Google"),
        ("9.9.9.9", "Quad9"),
        ("149.112.112.112", "Quad9"),
        ("208.67.222.222", "OpenDNS"),
        ("208.67.220.220", "OpenDNS"),
        ("94.140.14.14", "AdGuard"),
        ("94.140.15.15", "AdGuard"),
    ]);
    known.get(ip.to_string().as_str()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_magic_packets() {
        let p = magic_packet("00:11:22:33:44:55").unwrap();
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[6..12], &[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&p[96..102], &[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(magic_packet("nope").is_none());
    }

    #[test]
    fn parses_traceroute_output() {
        let mac = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 40 byte packets\n 1  192.168.0.1  4.693 ms\n 2  10.194.221.25  94.048 ms\n 4  *\n 8  1.1.1.1  92.795 ms\n";
        let h = parse_traceroute(mac);
        assert_eq!(h.len(), 4);
        assert_eq!(h[0], Hop { n: 1, ip: Some("192.168.0.1".into()), name: None, rtt_ms: Some(4.693) });
        assert_eq!(h[2].ip, None);
        assert_eq!(h[2].rtt_ms, None);
        let win = "\r\nTracing route to 1.1.1.1 over a maximum of 20 hops\r\n\r\n  1    <1 ms    <1 ms    <1 ms  192.168.0.1\r\n  2     *        *        *     Request timed out.\r\n  3    12 ms    11 ms    12 ms  1.1.1.1\r\n";
        let h = parse_traceroute(win);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].rtt_ms, Some(1.0));
        assert_eq!(h[0].ip.as_deref(), Some("192.168.0.1"));
        assert_eq!(h[1].ip, None);
        assert_eq!(h[2].rtt_ms, Some(12.0));
    }

    #[test]
    fn parses_leak_test_reply() {
        let body = r#"[{"ip":"211.30.37.204","country_name":"Australia","org":"Microplex Pty Ltd","type":"ip"},{"ip":"104.22.129.72","country_name":"Australia","org":"CloudFlare Inc","type":"dns"},{"ip":"DNS may be leaking.","type":"conclusion"}]"#;
        let r = parse_leak(body).unwrap();
        assert_eq!(r.public.unwrap().org.as_deref(), Some("Microplex Pty Ltd"));
        assert_eq!(r.resolvers.len(), 1);
        assert_eq!(r.resolvers[0].org.as_deref(), Some("CloudFlare Inc"));
    }

    #[test]
    fn rejects_unsafe_traceroute_targets() {
        assert!(traceroute("-n 1.1.1.1").is_err());
        assert!(traceroute("a;b").is_err());
        assert!(traceroute("").is_err());
    }

    /// `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_dns_check() {
        let servers = vec![("1.1.1.1".parse().unwrap(), "Cloudflare".to_string()), ("192.168.0.1".parse().unwrap(), "Router".to_string())];
        for r in dns_check(&servers, crate::util::now_ms()) {
            println!("{r:?}");
        }
    }
}

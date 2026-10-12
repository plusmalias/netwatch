//! Active discovery of devices on the local subnet. Nothing here needs
//! elevated privileges: we nudge the OS into resolving every neighbour, read
//! its ARP table, and ask devices to describe themselves over mDNS and SSDP.

use crate::util::{is_unicast_mac, norm_mac, quiet_command};
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, Question, CLASS, TYPE};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// macOS only: seconds until the OS stops considering the neighbour
    /// reachable ("Expire(I)"). It jumps back up whenever the device answers
    /// ARP, which sleeping laptops and phones still do via Wi-Fi offload.
    pub heard_expire_s: Option<u32>,
}

/// Remembers the last ARP table reading, to tell a device that just answered
/// from a cached entry. A cached entry can outlive a departed device by many
/// minutes, so only these changes count as evidence that a device is there.
#[derive(Default)]
pub struct ArpMemory {
    seen: HashMap<Ipv4Addr, (String, u64, Option<u32>)>,
    primed: bool,
}

impl ArpMemory {
    /// Addresses that answered ARP since the previous reading: a new or
    /// changed mapping, or (macOS) a reachability timer that was reset.
    /// The very first reading only sets the baseline.
    pub fn fresh(&mut self, table: &[ArpEntry], now: u64) -> HashSet<Ipv4Addr> {
        let mut out = HashSet::new();
        if self.primed {
            for e in table {
                let answered = match self.seen.get(&e.ip) {
                    None => true,
                    Some((mac, _, _)) if *mac != e.mac => true,
                    Some((_, ts, Some(prev))) => e.heard_expire_s.is_some_and(|cur| {
                        let elapsed = (now.saturating_sub(*ts) / 1000) as u32;
                        cur > prev.saturating_sub(elapsed) + 5
                    }),
                    _ => false,
                };
                if answered {
                    out.insert(e.ip);
                }
            }
        }
        self.primed = true;
        self.seen = table
            .iter()
            .map(|e| (e.ip, (e.mac.clone(), now, e.heard_expire_s)))
            .collect();
        out
    }
}

/// Sends one tiny UDP datagram to every host so the OS resolves its MAC
/// address via ARP. The discard port means nothing listens and nothing replies.
pub fn poke_hosts(hosts: &[Ipv4Addr]) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    for (i, h) in hosts.iter().enumerate() {
        let _ = sock.send_to(&[0], (*h, 9));
        if i % 64 == 63 {
            thread::sleep(Duration::from_millis(25));
        }
    }
}

pub fn read_arp_table(iface: &str, local_ip: Ipv4Addr) -> Vec<ArpEntry> {
    #[cfg(target_os = "linux")]
    {
        let _ = local_ip;
        std::fs::read_to_string("/proc/net/arp")
            .map(|t| parse_linux_arp(&t, iface))
            .unwrap_or_default()
    }
    #[cfg(windows)]
    {
        let _ = iface;
        quiet_command("arp")
            .arg("-a")
            .output()
            .map(|o| parse_windows_arp(&String::from_utf8_lossy(&o.stdout), local_ip))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = local_ip;
        quiet_command("arp")
            .arg("-anl")
            .output()
            .map(|o| parse_bsd_arp_long(&String::from_utf8_lossy(&o.stdout), iface))
            .unwrap_or_default()
    }
}

fn entry(ip: &str, mac: &str) -> Option<ArpEntry> {
    let ip = ip.parse().ok()?;
    let mac = norm_mac(mac).filter(|m| is_unicast_mac(m))?;
    Some(ArpEntry {
        ip,
        mac,
        heard_expire_s: None,
    })
}

/// `2m11s` → 131, `31s` → 31; `(none)` and `expired` → None.
fn parse_expiry(s: &str) -> Option<u32> {
    let mut total = 0u32;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u32 = num.parse().ok()?;
        num.clear();
        total += n * match c {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
    }
    num.is_empty().then_some(total)
}

/// macOS `arp -anl`:
/// `192.168.0.1   a8:29:48:68:53:3  2m25s  2m11s  en0  1`
/// (neighbour, link-layer address, Expire(O), Expire(I), interface, …)
#[cfg_attr(any(target_os = "linux", windows), allow(dead_code))]
pub fn parse_bsd_arp_long(text: &str, iface: &str) -> Vec<ArpEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 || cols[4] != iface {
                return None;
            }
            let mut e = entry(cols[0], cols[1])?;
            e.heard_expire_s = parse_expiry(cols[3]);
            Some(e)
        })
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// `/proc/net/arp`: `IP address  HW type  Flags  HW address  Mask  Device`
pub fn parse_linux_arp(text: &str, iface: &str) -> Vec<ArpEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 || cols[2] == "0x0" || cols[5] != iface {
                return None;
            }
            entry(cols[0], cols[3])
        })
        .collect()
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Windows `arp -a`, grouped by `Interface: <ip> --- 0x5` sections.
pub fn parse_windows_arp(text: &str, local_ip: Ipv4Addr) -> Vec<ArpEntry> {
    let mut in_section = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Interface:") {
            in_section = rest.split_whitespace().next() == Some(&local_ip.to_string());
            continue;
        }
        let cols: Vec<&str> = t.split_whitespace().collect();
        if in_section && cols.len() >= 3 && cols[2].eq_ignore_ascii_case("dynamic") {
            out.extend(entry(cols[0], cols[1]));
        }
    }
    out
}

/// Reverse DNS for each address, giving up on stragglers after `timeout`.
pub fn reverse_lookup(ips: Vec<Ipv4Addr>, timeout: Duration) -> HashMap<Ipv4Addr, String> {
    let (tx, rx) = mpsc::channel();
    for ip in ips {
        let tx = tx.clone();
        thread::spawn(move || {
            if let Ok(name) = dns_lookup::lookup_addr(&IpAddr::V4(ip)) {
                let name = name.trim_end_matches('.').to_string();
                if name.parse::<IpAddr>().is_err() {
                    let _ = tx.send((ip, name));
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut out = HashMap::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((ip, name)) => {
                out.insert(ip, name);
            }
            Err(_) => break,
        }
    }
    out
}

// ---------------------------------------------------------------- mDNS

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_QUERIES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_smb._tcp.local",
    "_ssh._tcp.local",
    "_http._tcp.local",
    "_companion-link._tcp.local",
    "_sonos._tcp.local",
    "_amzn-wplay._tcp.local",
];

#[derive(Debug, Default, Clone, PartialEq)]
pub struct MdnsInfo {
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub friendly_name: Option<String>,
    pub model: Option<String>,
    pub services: BTreeSet<String>,
}

/// Joins the mDNS group on our interface. Shares port 5353 with the OS's own
/// responder (mDNSResponder, avahi, Windows' DNS client).
pub fn mdns_socket(local_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353)).into())?;
    s.join_multicast_v4(&MDNS_GROUP, &local_ip)?;
    s.set_multicast_if_v4(&local_ip)?;
    s.set_multicast_loop_v4(false)?;
    Ok(s.into())
}

pub fn send_mdns_queries(sock: &UdpSocket) {
    // A few questions per packet keeps each query well under the MTU.
    for chunk in MDNS_QUERIES.chunks(4) {
        let mut p = Packet::new_query(0);
        for q in chunk {
            p.questions.push(Question::new(
                Name::new_unchecked(q),
                TYPE::PTR.into(),
                CLASS::IN.into(),
                false,
            ));
        }
        if let Ok(bytes) = p.build_bytes_vec() {
            let _ = sock.send_to(&bytes, (MDNS_GROUP, 5353));
        }
    }
}

/// `192.168.0.42` → `42.0.168.192.in-addr.arpa`
fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Asks devices for their own `.local` hostname with multicast reverse
/// lookups. Apple devices and most Linux boxes answer even when they
/// advertise no services.
pub fn send_reverse_queries(sock: &UdpSocket, ips: &[Ipv4Addr]) {
    for chunk in ips.chunks(8) {
        let mut p = Packet::new_query(0);
        let names: Vec<String> = chunk.iter().map(|ip| reverse_name(*ip)).collect();
        for n in &names {
            p.questions.push(Question::new(
                Name::new_unchecked(n),
                TYPE::PTR.into(),
                CLASS::IN.into(),
                false,
            ));
        }
        if let Ok(bytes) = p.build_bytes_vec() {
            let _ = sock.send_to(&bytes, (MDNS_GROUP, 5353));
        }
    }
}

fn strip_local(name: &str) -> String {
    name.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

/// What an mDNS response says about the device that sent it.
pub fn parse_mdns(src: Ipv4Addr, data: &[u8]) -> Option<MdnsInfo> {
    let pkt = Packet::parse(data).ok()?;
    let mut info = MdnsInfo {
        ip: Some(src),
        ..Default::default()
    };
    for rr in pkt.answers.iter().chain(&pkt.additional_records) {
        let owner = rr.name.to_string();
        match &rr.rdata {
            RData::A(a) if Ipv4Addr::from(a.address) == src => {
                info.hostname.get_or_insert_with(|| strip_local(&owner));
            }
            RData::PTR(ptr) if owner.ends_with(".in-addr.arpa") || owner.ends_with(".in-addr.arpa.") => {
                // Answer to a reverse lookup: `42.0.168.192.in-addr.arpa → host.local`.
                if reverse_name(src).trim_end_matches('.') == owner.trim_end_matches('.') {
                    info.hostname.get_or_insert_with(|| strip_local(&ptr.0.to_string()));
                }
            }
            RData::PTR(ptr) => {
                let target = ptr.0.to_string();
                if owner.starts_with("_services._dns-sd") {
                    if let Some(svc) = service_label(&target) {
                        info.services.insert(svc);
                    }
                } else if let Some(svc) = service_label(&owner) {
                    info.services.insert(svc);
                    let instance = target.split("._").next().unwrap_or("").trim();
                    if !instance.is_empty() && !instance.starts_with('_') {
                        info.friendly_name.get_or_insert_with(|| instance.replace("\\032", " "));
                    }
                }
            }
            RData::SRV(srv) => {
                info.hostname
                    .get_or_insert_with(|| strip_local(&srv.target.to_string()));
            }
            RData::TXT(txt) => {
                let attrs = txt.attributes();
                for key in ["md", "model", "usb_MDL", "ty"] {
                    if let Some(Some(v)) = attrs.get(key) {
                        if !v.is_empty() {
                            info.model.get_or_insert_with(|| v.clone());
                            break;
                        }
                    }
                }
                if let Some(Some(v)) = attrs.get("fn") {
                    info.friendly_name.get_or_insert_with(|| v.clone());
                }
            }
            _ => {}
        }
    }
    let empty = info.hostname.is_none()
        && info.friendly_name.is_none()
        && info.model.is_none()
        && info.services.is_empty();
    (!empty).then_some(info)
}

/// `_googlecast._tcp.local` → `googlecast`
fn service_label(name: &str) -> Option<String> {
    let first = name.split('.').next()?;
    let label = first.strip_prefix('_')?;
    (!label.is_empty() && (name.contains("._tcp") || name.contains("._udp")))
        .then(|| label.to_string())
}

// ---------------------------------------------------------------- SSDP / UPnP

#[derive(Debug, Clone)]
pub struct SsdpInfo {
    pub ip: Ipv4Addr,
    pub server: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// URL of its UPnP description document.
    pub location: Option<String>,
}

/// Broadcasts an SSDP M-SEARCH and collects UPnP devices' self-descriptions.
pub fn ssdp_search(local_ip: Ipv4Addr, listen_for: Duration) -> Vec<SsdpInfo> {
    let Ok(sock) = UdpSocket::bind((local_ip, 0)) else {
        return vec![];
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    for _ in 0..2 {
        let _ = sock.send_to(msg.as_bytes(), "239.255.255.250:1900");
    }
    let mut found: HashMap<Ipv4Addr, (Option<String>, Option<String>)> = HashMap::new();
    let deadline = Instant::now() + listen_for;
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) else {
            continue;
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let entry = found.entry(*from.ip()).or_default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim().to_string();
            match k.trim().to_ascii_lowercase().as_str() {
                "server" if entry.0.is_none() => entry.0 = Some(v),
                "location" if entry.1.is_none() => entry.1 = Some(v),
                _ => {}
            }
        }
    }
    let handles: Vec<_> = found
        .into_iter()
        .map(|(ip, (server, location))| {
            thread::spawn(move || {
                // Only follow description URLs that point back at the responder.
                let location = location.filter(|u| u.contains(&format!("//{ip}:")) || u.contains(&format!("//{ip}/")));
                let mut info = SsdpInfo {
                    ip,
                    server,
                    friendly_name: None,
                    manufacturer: None,
                    model: None,
                    location: location.clone(),
                };
                if let Some(url) = location {
                    if let Ok(xml) = ureq::get(&url)
                        .timeout(Duration::from_secs(2))
                        .call()
                        .and_then(|r| Ok(r.into_string()?))
                    {
                        info.friendly_name = xml_tag(&xml, "friendlyName");
                        info.manufacturer = xml_tag(&xml, "manufacturer");
                        info.model = xml_tag(&xml, "modelName");
                    }
                }
                info
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

/// The text of the first `<tag>…</tag>` in `xml`, trimmed, with `&amp;` decoded.
pub fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find(&format!("</{tag}>"))?;
    let v = xml[start..end].trim();
    (!v.is_empty()).then(|| v.replace("&amp;", "&"))
}

// ---------------------------------------------------------------- ports

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 139, 443, 445, 548, 554, 631, 1883, 3389, 5000, 5900, 7000, 8008,
    8009, 8080, 8443, 8883, 9100, 32400, 49152, 62078,
];

/// TCP connect check of a short list of well-known ports on one LAN device.
pub fn check_ports(ip: Ipv4Addr) -> Vec<u16> {
    let handles: Vec<_> = COMMON_PORTS
        .iter()
        .map(|&port| {
            thread::spawn(move || {
                let addr = SocketAddr::from((ip, port));
                TcpStream::connect_timeout(&addr, Duration::from_millis(800))
                    .is_ok()
                    .then_some(port)
            })
        })
        .collect();
    handles
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{A, PTR, SRV, TXT};
    use simple_dns::ResourceRecord;

    #[test]
    fn parses_macos_arp_with_expiry() {
        let text = "Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs\n\
192.168.0.1             0:11:22:33:44:55  2m25s     2m11s          en0    1\n\
192.168.0.7             (incomplete)      expired   expired        en0    1  3\n\
192.168.0.103           72:63:9f:6d:83:2b 1m3s      4s             en0    1\n\
192.168.0.255           ff:ff:ff:ff:ff:ff (none)    (none)         en0\n\
224.0.0.251             1:0:5e:0:0:fb     (none)    (none)         en0\n\
10.8.0.2                0:aa:bb:cc:dd:ee  1m0s      1m0s           utun3  1\n";
        assert_eq!(
            parse_bsd_arp_long(text, "en0"),
            vec![
                ArpEntry {
                    ip: Ipv4Addr::new(192, 168, 0, 1),
                    mac: "00:11:22:33:44:55".into(),
                    heard_expire_s: Some(131),
                },
                ArpEntry {
                    ip: Ipv4Addr::new(192, 168, 0, 103),
                    mac: "72:63:9f:6d:83:2b".into(),
                    heard_expire_s: Some(4),
                },
            ]
        );
        assert_eq!(parse_expiry("1h2m3s"), Some(3723));
        assert_eq!(parse_expiry("(none)"), None);
        assert_eq!(parse_expiry("12"), None);
    }

    #[test]
    fn arp_memory_spots_fresh_answers_only() {
        let e = |ip: u8, mac: &str, exp: Option<u32>| ArpEntry {
            ip: Ipv4Addr::new(10, 0, 0, ip),
            mac: mac.into(),
            heard_expire_s: exp,
        };
        let mut m = ArpMemory::default();
        // The first reading is a baseline, even for entries that look new.
        assert!(m.fresh(&[e(1, "aa", Some(120)), e(2, "bb", Some(90))], 0).is_empty());
        // 60 s later: .1's timer was reset (it answered), .2's just ran down,
        // and .3 is a new entry.
        let f = m.fresh(&[e(1, "aa", Some(150)), e(2, "bb", Some(30)), e(3, "cc", None)], 60_000);
        assert_eq!(f, HashSet::from([Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 3)]));
        // A different MAC on a known address counts too.
        let f = m.fresh(&[e(2, "dd", Some(10))], 70_000);
        assert_eq!(f, HashSet::from([Ipv4Addr::new(10, 0, 0, 2)]));
    }

    #[test]
    fn parses_linux_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         a4:91:b1:00:00:01     *        wlan0\n\
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n\
172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0\n";
        let e = parse_linux_arp(text, "wlan0");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].mac, "a4:91:b1:00:00:01");
    }

    #[test]
    fn parses_windows_arp_for_our_interface_only() {
        let text = "\r\nInterface: 192.168.0.110 --- 0x5\r\n  Internet Address      Physical Address      Type\r\n  192.168.0.1           a4-91-b1-00-00-01     dynamic   \r\n  192.168.0.255         ff-ff-ff-ff-ff-ff     static    \r\n\r\nInterface: 172.20.0.1 --- 0x9\r\n  172.20.0.5            00-15-5d-00-00-05     dynamic   \r\n";
        let e = parse_windows_arp(text, Ipv4Addr::new(192, 168, 0, 110));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].ip, Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn parses_mdns_announcement() {
        let src = Ipv4Addr::new(192, 168, 0, 42);
        let mut p = Packet::new_reply(0);
        p.answers.push(ResourceRecord::new(
            Name::new_unchecked("_googlecast._tcp.local"),
            CLASS::IN,
            120,
            RData::PTR(PTR(Name::new_unchecked("Living Room TV._googlecast._tcp.local"))),
        ));
        let mut txt = TXT::new();
        txt.add_string("md=Chromecast Ultra").unwrap();
        p.additional_records.push(ResourceRecord::new(
            Name::new_unchecked("Living Room TV._googlecast._tcp.local"),
            CLASS::IN,
            120,
            RData::TXT(txt),
        ));
        p.additional_records.push(ResourceRecord::new(
            Name::new_unchecked("Living Room TV._googlecast._tcp.local"),
            CLASS::IN,
            120,
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: 8009,
                target: Name::new_unchecked("chromecast-1234.local"),
            }),
        ));
        p.additional_records.push(ResourceRecord::new(
            Name::new_unchecked("chromecast-1234.local"),
            CLASS::IN,
            120,
            RData::A(A {
                address: u32::from(src),
            }),
        ));
        let info = parse_mdns(src, &p.build_bytes_vec().unwrap()).unwrap();
        assert_eq!(info.hostname.as_deref(), Some("chromecast-1234"));
        assert_eq!(info.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(info.model.as_deref(), Some("Chromecast Ultra"));
        assert_eq!(info.services, BTreeSet::from(["googlecast".to_string()]));
    }

    #[test]
    fn parses_reverse_lookup_answers() {
        let src = Ipv4Addr::new(192, 168, 0, 107);
        let mut p = Packet::new_reply(0);
        p.answers.push(ResourceRecord::new(
            Name::new_unchecked("107.0.168.192.in-addr.arpa"),
            CLASS::IN,
            120,
            RData::PTR(PTR(Name::new_unchecked("Jordens-iPhone.local"))),
        ));
        let info = parse_mdns(src, &p.build_bytes_vec().unwrap()).unwrap();
        assert_eq!(info.hostname.as_deref(), Some("Jordens-iPhone"));
        assert!(info.services.is_empty());
        // An answer about some other address is ignored.
        assert!(parse_mdns(Ipv4Addr::new(192, 168, 0, 9), &p.build_bytes_vec().unwrap()).is_none());
    }

    #[test]
    fn ignores_plain_queries() {
        let mut p = Packet::new_query(0);
        p.questions.push(Question::new(
            Name::new_unchecked("_airplay._tcp.local"),
            TYPE::PTR.into(),
            CLASS::IN.into(),
            false,
        ));
        assert!(parse_mdns(Ipv4Addr::new(10, 0, 0, 2), &p.build_bytes_vec().unwrap()).is_none());
    }

    #[test]
    fn extracts_upnp_description_tags() {
        let xml = "<root><device><friendlyName>NAS &amp; Media</friendlyName><manufacturer>Synology</manufacturer><modelName>DS220+</modelName></device></root>";
        assert_eq!(xml_tag(xml, "friendlyName").as_deref(), Some("NAS & Media"));
        assert_eq!(xml_tag(xml, "modelName").as_deref(), Some("DS220+"));
        assert_eq!(xml_tag(xml, "serialNumber"), None);
    }
}

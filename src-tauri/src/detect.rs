//! Passive traffic analysis. Turns captured Ethernet frames into device
//! sightings, DNS log entries, traffic stats and alerts. No I/O happens here,
//! so each detector is unit-tested with hand-built packets.

use crate::alerts::{AlertDraft, Severity};
use crate::blocklist::Blocklist;
use crate::util::{fmt_mac, ipv4_of, is_private_ip, is_unicast_mac};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::Serialize;
use simple_dns::rdata::RData;
use simple_dns::{Packet, QTYPE, RCODE};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

pub enum Event {
    Alert(AlertDraft),
    Device {
        mac: String,
        ip: Ipv4Addr,
        hostname: Option<String>,
        source: &'static str,
        /// DHCP option 60 and 55, when the sighting came from a DHCP request.
        fingerprint: Option<(Option<String>, Option<String>)>,
    },
    Dns(DnsEntry),
}

#[derive(Serialize, Clone, Debug)]
pub struct DnsEntry {
    pub ts: u64,
    pub client: String,
    pub name: String,
    pub qtype: String,
    pub answers: Vec<String>,
    pub blocked: bool,
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct HostStat {
    pub ip: String,
    pub name: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Service ports seen (the lower port of each flow), capped.
    pub ports: BTreeSet<u16>,
    pub lan: bool,
    pub flagged: bool,
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct TrafficSnapshot {
    pub ts: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub packets: u64,
    pub hosts: Vec<HostStat>,
}

pub struct Config {
    pub local_mac: Option<String>,
    pub local_ips: HashSet<IpAddr>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub gateway_mac: Option<String>,
}

const SCAN_WINDOW_MS: u64 = 15_000;
const SCAN_PORT_THRESHOLD: usize = 20;
/// Within this window, two MACs answering for one IP is a conflict rather
/// than a DHCP lease moving to a new device.
const IP_REASSIGN_GRACE_MS: u64 = 10 * 60_000;
const ARP_FLOOD_WINDOW_MS: u64 = 15_000;
const ARP_FLOOD_IP_THRESHOLD: usize = 8;
const BEACON_SAMPLES: usize = 10;
const BEACON_MIN_INTERVAL_MS: f64 = 15_000.0;
const BEACON_MAX_JITTER: f64 = 0.12;
const BEACON_SYN_DEDUP_MS: u64 = 2_000;
const DNS_TUNNEL_WINDOW_MS: u64 = 5 * 60_000;
const DNS_TUNNEL_SUB_THRESHOLD: usize = 12;
const DGA_WINDOW_MS: u64 = 2 * 60_000;
const DGA_NX_THRESHOLD: usize = 15;
const DNS_REBIND_WINDOW_MS: u64 = 30 * 60_000;
const SNI_LOG_DEDUP_MS: u64 = 10_000;
const MAX_HOST_PORTS: usize = 12;
const SUSPICIOUS_PORTS: &[(u16, &str)] = &[
    (23, "Telnet"),
    (1337, "backdoors"),
    (2323, "Mirai and IoT botnet Telnet"),
    (4444, "remote-access trojans and exploit kits"),
    (5555, "exposed Android Debug Bridge (ADB) and worms"),
    (6667, "IRC botnets"),
    (6668, "IRC botnets"),
    (6669, "IRC botnets"),
    (12345, "legacy backdoors (NetBus)"),
    (31337, "the Back Orifice trojan"),
    (50050, "Cobalt Strike command-and-control servers"),
];

pub struct Analyzer {
    cfg: Config,
    blocklist: Arc<RwLock<Blocklist>>,
    dns_names: Arc<RwLock<HashMap<IpAddr, String>>>,
    arp: HashMap<Ipv4Addr, (String, u64)>,
    /// Original gateway MAC baseline so router recovery after an ARP spoof
    /// doesn't falsely accuse the real router of spoofing the attacker.
    gateway_mac_baseline: Option<String>,
    /// Recent ARP replies per sender MAC to catch subnet-wide ARP poisoning floods.
    arp_claims: HashMap<String, VecDeque<(u64, Ipv4Addr)>>,
    dhcp_server: Option<Ipv4Addr>,
    syns: HashMap<IpAddr, VecDeque<(u64, u16)>>,
    conn_starts: HashMap<(IpAddr, u16), VecDeque<u64>>,
    /// High-entropy / long subdomains per (client, base_domain) for DNS tunneling detection.
    dns_tunnel: HashMap<(IpAddr, String), VecDeque<(u64, String)>>,
    /// High-entropy NXDOMAIN queries per client for DGA detection.
    dga_nx: HashMap<IpAddr, VecDeque<(u64, String)>>,
    /// Public domains recently observed resolving to public IPs, for DNS rebinding detection.
    dns_public_seen: HashMap<String, u64>,
    /// Deduplicates rapid parallel TLS ClientHello SNI log entries.
    sni_recent: HashMap<(IpAddr, String), u64>,
    hosts: HashMap<IpAddr, HostStat>,
    total_rx: u64,
    total_tx: u64,
    packets: u64,
    last_snap: (u64, u64, u64),
}

impl Analyzer {
    pub fn new(
        cfg: Config,
        blocklist: Arc<RwLock<Blocklist>>,
        dns_names: Arc<RwLock<HashMap<IpAddr, String>>>,
        now: u64,
    ) -> Self {
        let mut arp = HashMap::new();
        let gateway_mac_baseline = cfg.gateway_mac.clone();
        if let (Some(ip), Some(mac)) = (cfg.gateway_ip, &cfg.gateway_mac) {
            arp.insert(ip, (mac.clone(), now));
        }
        if let Some(mac) = &cfg.local_mac {
            for ip in &cfg.local_ips {
                if let IpAddr::V4(v4) = ip {
                    arp.insert(*v4, (mac.clone(), now));
                }
            }
        }
        Analyzer {
            cfg,
            blocklist,
            dns_names,
            arp,
            gateway_mac_baseline,
            arp_claims: HashMap::new(),
            dhcp_server: None,
            syns: HashMap::new(),
            conn_starts: HashMap::new(),
            dns_tunnel: HashMap::new(),
            dga_nx: HashMap::new(),
            dns_public_seen: HashMap::new(),
            sni_recent: HashMap::new(),
            hosts: HashMap::new(),
            total_rx: 0,
            total_tx: 0,
            packets: 0,
            last_snap: (now, 0, 0),
        }
    }

    fn is_local(&self, ip: &IpAddr) -> bool {
        self.cfg.local_ips.contains(ip)
    }

    fn name_of(&self, ip: &IpAddr) -> String {
        match self.dns_names.read().unwrap().get(ip) {
            Some(n) => format!("{ip} ({n})"),
            None => ip.to_string(),
        }
    }

    /// `wire_len` is the frame's length on the wire, which can exceed `frame.len()`.
    pub fn process(&mut self, now: u64, frame: &[u8], wire_len: u32) -> Vec<Event> {
        let mut out = Vec::new();
        if frame.len() < 14 {
            return out;
        }
        let (ethertype, offset) = ethertype(frame);
        if ethertype == 0x0806 {
            self.on_arp(now, &frame[offset..], &mut out);
            return out;
        }
        let Ok(pkt) = SlicedPacket::from_ethernet(frame) else {
            return out;
        };
        let (src, dst) = match &pkt.net {
            Some(NetSlice::Ipv4(v4)) => (
                IpAddr::V4(v4.header().source_addr()),
                IpAddr::V4(v4.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(v6)) => (
                IpAddr::V6(v6.header().source_addr()),
                IpAddr::V6(v6.header().destination_addr()),
            ),
            _ => return out,
        };
        let ports = match &pkt.transport {
            Some(TransportSlice::Udp(u)) => Some((u.source_port(), u.destination_port())),
            Some(TransportSlice::Tcp(t)) => Some((t.source_port(), t.destination_port())),
            _ => None,
        };
        self.account(now, src, dst, wire_len as u64, ports, &mut out);
        match &pkt.transport {
            Some(TransportSlice::Udp(udp)) => {
                let (sp, dp) = (udp.source_port(), udp.destination_port());
                if sp == 53 {
                    self.on_dns_response(now, dst, udp.payload(), &mut out);
                }
                if sp == 67 || dp == 67 {
                    self.on_dhcp(src, udp.payload(), &mut out);
                }
            }
            Some(TransportSlice::Tcp(tcp)) if tcp.syn() && !tcp.ack() => {
                self.on_syn(now, src, dst, tcp.destination_port(), &mut out);
            }
            Some(TransportSlice::Tcp(tcp))
                if !tcp.payload().is_empty() && self.is_local(&src) && !self.is_local(&dst) =>
            {
                self.on_tcp_payload(now, src, dst, tcp.payload(), &mut out);
            }
            _ => {}
        }
        out
    }

    fn account(
        &mut self,
        now: u64,
        src: IpAddr,
        dst: IpAddr,
        len: u64,
        ports: Option<(u16, u16)>,
        out: &mut Vec<Event>,
    ) {
        self.packets += 1;
        let (remote, outbound) = if self.is_local(&src) {
            (dst, true)
        } else if self.is_local(&dst) {
            (src, false)
        } else {
            return;
        };
        if outbound {
            self.total_tx += len;
        } else {
            self.total_rx += len;
        }
        if remote.is_multicast() || remote == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return;
        }
        let listed = self.blocklist.read().unwrap().match_ip(&remote);
        let flagged = listed.is_some();
        let h = self.hosts.entry(remote).or_insert_with(|| HostStat {
            ip: remote.to_string(),
            first_seen: now,
            lan: is_private_ip(&remote),
            ..Default::default()
        });
        if outbound {
            h.bytes_out += len;
        } else {
            h.bytes_in += len;
        }
        h.packets += 1;
        h.last_seen = now;
        if let Some((a, b)) = ports {
            if h.ports.len() < MAX_HOST_PORTS {
                h.ports.insert(a.min(b));
            }
        }
        let newly_flagged = flagged && !h.flagged;
        h.flagged |= flagged;
        if newly_flagged {
            out.push(Event::Alert(AlertDraft {
                severity: Severity::High,
                kind: "c2_traffic",
                key: remote.to_string(),
                title: format!("Traffic with blocklisted server {remote}"),
                detail: format!(
                    "This computer exchanged traffic with {}, which is on {}. Check Connections to see which app is talking to it.",
                    self.name_of(&remote),
                    listed.unwrap_or_default()
                ),
            }));
        }
    }

    fn on_arp(&mut self, now: u64, arp: &[u8], out: &mut Vec<Event>) {
        // Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4.
        if arp.len() < 28 || arp[0..6] != [0, 1, 0x08, 0x00, 6, 4] {
            return;
        }
        let op = u16::from_be_bytes([arp[6], arp[7]]);
        let sha = fmt_mac(&arp[8..14]);
        let spa = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
        if spa.is_unspecified() || !is_unicast_mac(&sha) || self.cfg.local_mac.as_ref() == Some(&sha)
        {
            return;
        }
        let kind = if op == 2 { "reply" } else { "request" };

        // Track subnet-wide ARP reply storms (one non-router MAC claiming many IPs quickly).
        if op == 2 && self.gateway_mac_baseline.as_deref() != Some(sha.as_str()) {
            let q = self.arp_claims.entry(sha.clone()).or_default();
            q.push_back((now, spa));
            while q.front().is_some_and(|(t, _)| now.saturating_sub(*t) > ARP_FLOOD_WINDOW_MS) {
                q.pop_front();
            }
            let distinct: HashSet<Ipv4Addr> = q.iter().map(|(_, ip)| *ip).collect();
            if distinct.len() >= ARP_FLOOD_IP_THRESHOLD {
                q.clear();
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::High,
                    kind: "arp_flood",
                    key: sha.clone(),
                    title: format!("ARP spoofing storm from {sha}"),
                    detail: format!(
                        "Device {sha} sent ARP replies claiming {} different IP addresses within {}s. That pattern matches a subnet-wide ARP poisoning tool trying to intercept traffic across your network.",
                        distinct.len(),
                        ARP_FLOOD_WINDOW_MS / 1000
                    ),
                }));
            }
            if self.arp_claims.len() > 2_000 {
                self.arp_claims.retain(|_, q| {
                    q.back().is_some_and(|(t, _)| now.saturating_sub(*t) < ARP_FLOOD_WINDOW_MS)
                });
            }
        }

        // Another device claiming THIS computer's own IP address.
        if self.is_local(&IpAddr::V4(spa)) {
            let mine = self.cfg.local_mac.as_deref().unwrap_or("this computer");
            out.push(Event::Alert(AlertDraft {
                severity: Severity::High,
                kind: "arp_spoof",
                key: spa.to_string(),
                title: "Another device is claiming this computer's IP — possible ARP spoofing".into(),
                detail: format!(
                    "An ARP {kind} from {sha} claims this computer's IP address {spa} (normally {mine}). Another device on the LAN may be impersonating this computer or poisoning the ARP cache."
                ),
            }));
            return;
        }

        out.push(Event::Device {
            mac: sha.clone(),
            ip: spa,
            hostname: None,
            source: "arp",
            fingerprint: None,
        });

        // Gateway protection: keep the original baseline MAC so the real router
        // answering again after an attack doesn't trigger a backwards alert.
        if Some(spa) == self.cfg.gateway_ip {
            let baseline = self.gateway_mac_baseline.get_or_insert_with(|| sha.clone()).clone();
            self.arp.insert(spa, (sha.clone(), now));
            if sha != baseline {
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::High,
                    kind: "arp_spoof",
                    key: spa.to_string(),
                    title: "Router's MAC address changed — possible ARP spoofing".into(),
                    detail: format!(
                        "An ARP {kind} says your router {spa} is now at {sha} (it was {baseline}). Unless you just replaced the router, another device may be impersonating it to intercept traffic."
                    ),
                }));
            }
            return;
        }

        let Some((old, seen)) = self.arp.insert(spa, (sha.clone(), now)) else {
            return;
        };
        if old == sha {
            return;
        }
        if now.saturating_sub(seen) < IP_REASSIGN_GRACE_MS {
            out.push(Event::Alert(AlertDraft {
                severity: Severity::Medium,
                kind: "ip_conflict",
                key: spa.to_string(),
                title: format!("Two devices are claiming {spa}"),
                detail: format!(
                    "{old} and {sha} both answered for {spa} within a few minutes. This is either an IP address conflict or ARP spoofing."
                ),
            }));
        }
    }

    fn on_dhcp(&mut self, src: IpAddr, payload: &[u8], out: &mut Vec<Event>) {
        let Some(d) = parse_dhcp(payload) else {
            return;
        };
        let device_mac = is_unicast_mac(&d.chaddr).then(|| d.chaddr.clone());
        match d.msg_type {
            // DISCOVER, REQUEST, INFORM: a client announcing itself.
            Some(1 | 3 | 8) => {
                let ip = d
                    .requested_ip
                    .or_else(|| (!d.ciaddr.is_unspecified()).then_some(d.ciaddr));
                if let (Some(mac), Some(ip)) = (device_mac, ip) {
                    out.push(Event::Device {
                        mac,
                        ip,
                        hostname: d.hostname,
                        source: "dhcp",
                        fingerprint: Some((d.vendor_class, d.params)),
                    });
                }
            }
            // OFFER, ACK: a server handing out an address.
            Some(2 | 5) => {
                if let Some(server) = d.server_id.or_else(|| ipv4_of(&src)) {
                    match self.dhcp_server {
                        None => self.dhcp_server = Some(server),
                        Some(known) if known != server => out.push(Event::Alert(AlertDraft {
                            severity: Severity::High,
                            kind: "rogue_dhcp",
                            key: server.to_string(),
                            title: format!("Unexpected DHCP server at {server}"),
                            detail: format!(
                                "Addresses on this network normally come from {known}, but {server} is also handing them out. A rogue DHCP server can route other devices' traffic through itself. If you added a second router or Pi-hole on purpose, acknowledge this."
                            ),
                        })),
                        _ => {}
                    }
                }
                if d.msg_type == Some(5) && !d.yiaddr.is_unspecified() {
                    if let Some(mac) = device_mac {
                        out.push(Event::Device {
                            mac,
                            ip: d.yiaddr,
                            hostname: None,
                            source: "dhcp",
                            fingerprint: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    fn on_dns_response(&mut self, now: u64, client: IpAddr, payload: &[u8], out: &mut Vec<Event>) {
        let Ok(pkt) = Packet::parse(payload) else {
            return;
        };
        let Some(q) = pkt.questions.first() else {
            return;
        };
        let name = q.qname.to_string().trim_end_matches('.').to_string();
        let qtype = match q.qtype {
            QTYPE::TYPE(t) => format!("{t:?}"),
            other => format!("{other:?}"),
        };
        let mut answers = Vec::new();
        let mut answer_ips = Vec::new();
        let mut checked = vec![name.clone()];
        {
            let mut names = self.dns_names.write().unwrap();
            if names.len() > 50_000 {
                names.clear();
            }
            for rr in &pkt.answers {
                let ip = match &rr.rdata {
                    RData::A(a) => IpAddr::V4(Ipv4Addr::from(a.address)),
                    RData::AAAA(a) => IpAddr::V6(Ipv6Addr::from(a.address)),
                    RData::CNAME(c) => {
                        let target = c.0.to_string().trim_end_matches('.').to_string();
                        answers.push(target.clone());
                        checked.push(target);
                        continue;
                    }
                    _ => continue,
                };
                answers.push(ip.to_string());
                answer_ips.push(ip);
                names.insert(ip, name.clone());
            }
        }
        let hit = {
            let bl = self.blocklist.read().unwrap();
            checked.iter().find_map(|n| bl.match_domain(n))
        };
        if let Some((entry, source)) = &hit {
            out.push(Event::Alert(AlertDraft {
                severity: Severity::High,
                kind: "malicious_domain",
                key: entry.clone(),
                title: format!("Lookup of blocklisted domain {name}"),
                detail: format!(
                    "{client} looked up {name}, which matches {entry} on {source}. Find the app that made the request in Connections, or scan that device for malware."
                ),
            }));
        }
        self.check_dns_rebinding(now, &name, &answer_ips, out);
        self.check_dns_tunnel(now, client, &name, &qtype, out);
        if pkt.rcode() == RCODE::NameError {
            self.check_dga(now, client, &name, out);
        }
        out.push(Event::Dns(DnsEntry {
            ts: now,
            client: client.to_string(),
            name,
            qtype,
            answers,
            blocked: hit.is_some(),
        }));
    }

    /// Passive TLS ClientHello SNI extraction: names HTTPS destinations and
    /// checks them against the domain blocklist even when browsers use DoH/DoT.
    fn on_tcp_payload(
        &mut self,
        now: u64,
        src: IpAddr,
        dst: IpAddr,
        payload: &[u8],
        out: &mut Vec<Event>,
    ) {
        let Some(sni) = parse_tls_sni(payload) else {
            return;
        };
        {
            let mut names = self.dns_names.write().unwrap();
            if names.len() > 50_000 {
                names.clear();
            }
            names.insert(dst, sni.clone());
        }
        let hit = {
            let bl = self.blocklist.read().unwrap();
            bl.match_domain(&sni)
        };
        if let Some((entry, source)) = &hit {
            out.push(Event::Alert(AlertDraft {
                severity: Severity::High,
                kind: "malicious_domain",
                key: entry.clone(),
                title: format!("HTTPS connection to blocklisted domain {sni}"),
                detail: format!(
                    "This computer started a TLS handshake to {sni} ({dst}), which matches {entry} on {source} (detected via TLS SNI, even if DNS was encrypted). Check Connections to see which app made it."
                ),
            }));
        }
        let dedup_key = (dst, sni.clone());
        let recently_logged = self
            .sni_recent
            .get(&dedup_key)
            .is_some_and(|t| now.saturating_sub(*t) < SNI_LOG_DEDUP_MS);
        if !recently_logged || hit.is_some() {
            self.sni_recent.insert(dedup_key, now);
            if self.sni_recent.len() > 5_000 {
                self.sni_recent
                    .retain(|_, t| now.saturating_sub(*t) < SNI_LOG_DEDUP_MS);
            }
            out.push(Event::Dns(DnsEntry {
                ts: now,
                client: src.to_string(),
                name: sni,
                qtype: "SNI".into(),
                answers: vec![dst.to_string()],
                blocked: hit.is_some(),
            }));
        }
    }

    /// Detects DNS rebinding: an external public domain resolving to our router
    /// IP, or flipping from a public IP to a private LAN IP within 30 minutes.
    /// Ad-blocker sinkholes (0.0.0.0, 127.0.0.1, ::, ::1) are ignored.
    fn check_dns_rebinding(
        &mut self,
        now: u64,
        name: &str,
        ips: &[IpAddr],
        out: &mut Vec<Event>,
    ) {
        if ips.is_empty() || is_local_domain(name) || is_rebinding_exempt(name) {
            return;
        }
        let lower = name.to_ascii_lowercase();
        let has_public = ips.iter().any(|ip| !is_private_ip(ip));
        if has_public {
            self.dns_public_seen.insert(lower.clone(), now);
            if self.dns_public_seen.len() > 10_000 {
                self.dns_public_seen
                    .retain(|_, t| now.saturating_sub(*t) < DNS_REBIND_WINDOW_MS);
            }
            return;
        }
        let gw_ip = self.cfg.gateway_ip.map(IpAddr::V4);
        let was_public = self
            .dns_public_seen
            .get(&lower)
            .is_some_and(|t| now.saturating_sub(*t) <= DNS_REBIND_WINDOW_MS);
        for ip in ips {
            if ip.is_unspecified() || ip.is_loopback() || !is_private_ip(ip) {
                continue;
            }
            if Some(*ip) == gw_ip {
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::High,
                    kind: "dns_rebinding",
                    key: format!("{lower}->{ip}"),
                    title: format!("Possible DNS rebinding to your router ({name})"),
                    detail: format!(
                        "Public domain {name} resolved to your router's LAN address {ip}. Attackers use DNS rebinding to let a web page reach your router's admin interface from your browser."
                    ),
                }));
                break;
            }
            if was_public {
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::High,
                    kind: "dns_rebinding",
                    key: format!("{lower}->{ip}"),
                    title: format!("DNS rebinding detected for {name}"),
                    detail: format!(
                        "Domain {name} recently resolved to a public internet address, and now points to private LAN address {ip}. That pattern is a classic DNS rebinding attack used to pivot from a web page into local devices."
                    ),
                }));
                break;
            }
        }
    }

    /// Detects DNS tunneling / data exfiltration: many distinct high-entropy or
    /// unusually long subdomains under one registrable domain in a short window.
    fn check_dns_tunnel(
        &mut self,
        now: u64,
        client: IpAddr,
        name: &str,
        qtype: &str,
        out: &mut Vec<Event>,
    ) {
        if is_local_domain(name) || is_benign_hash_domain(name) {
            return;
        }
        let Some((sub, base)) = registrable_domain(name) else {
            return;
        };
        if sub.is_empty() || sub.starts_with('_') {
            return;
        }
        let flat: String = sub.chars().filter(|c| *c != '.').collect();
        let ent = shannon_entropy(&flat);
        let suspicious = (flat.len() >= 24 && ent >= 3.5)
            || sub.len() >= 48
            || (matches!(qtype, "TXT" | "NULL" | "CNAME") && flat.len() >= 18 && ent >= 3.3);
        if !suspicious {
            return;
        }
        let q = self.dns_tunnel.entry((client, base.clone())).or_default();
        q.push_back((now, sub));
        while q.front().is_some_and(|(t, _)| now.saturating_sub(*t) > DNS_TUNNEL_WINDOW_MS) {
            q.pop_front();
        }
        let distinct: HashSet<&str> = q.iter().map(|(_, s)| s.as_str()).collect();
        if distinct.len() >= DNS_TUNNEL_SUB_THRESHOLD {
            let n = distinct.len();
            q.clear();
            out.push(Event::Alert(AlertDraft {
                severity: Severity::Medium,
                kind: "dns_tunnel",
                key: format!("{client}:{base}"),
                title: format!("Possible DNS tunneling to {base}"),
                detail: format!(
                    "{client} queried {n} distinct high-entropy or unusually long subdomains under {base} within {} minutes. Tools and malware can smuggle data or C2 commands through encoded DNS labels.",
                    DNS_TUNNEL_WINDOW_MS / 60_000
                ),
            }));
        }
        if self.dns_tunnel.len() > 5_000 {
            self.dns_tunnel.retain(|_, q| {
                q.back().is_some_and(|(t, _)| now.saturating_sub(*t) < DNS_TUNNEL_WINDOW_MS)
            });
        }
    }

    /// Detects Domain Generation Algorithm (DGA) activity: a burst of distinct
    /// high-entropy NXDOMAIN responses for one client.
    fn check_dga(&mut self, now: u64, client: IpAddr, name: &str, out: &mut Vec<Event>) {
        if is_local_domain(name) || is_benign_hash_domain(name) {
            return;
        }
        let lower = name.to_ascii_lowercase();
        if lower.contains("netwatch-check") {
            return;
        }
        let Some((sub, base)) = registrable_domain(&lower) else {
            return;
        };
        let sld = base.split('.').next().unwrap_or("");
        let candidate = if sld.len() >= 10 {
            sld
        } else {
            sub.split('.').next().unwrap_or("")
        };
        if candidate.len() < 10 || shannon_entropy(candidate) < 3.2 {
            return;
        }
        let q = self.dga_nx.entry(client).or_default();
        q.push_back((now, lower));
        while q.front().is_some_and(|(t, _)| now.saturating_sub(*t) > DGA_WINDOW_MS) {
            q.pop_front();
        }
        let distinct: HashSet<&str> = q.iter().map(|(_, n)| n.as_str()).collect();
        if distinct.len() >= DGA_NX_THRESHOLD {
            let n = distinct.len();
            q.clear();
            out.push(Event::Alert(AlertDraft {
                severity: Severity::High,
                kind: "dga_burst",
                key: client.to_string(),
                title: format!("Rapid lookups of random nonexistent domains from {client}"),
                detail: format!(
                    "{client} received NXDOMAIN for {n} distinct random-looking domains within {} minutes. Malware using a Domain Generation Algorithm (DGA) produces this pattern while hunting for its command-and-control server.",
                    DGA_WINDOW_MS / 60_000
                ),
            }));
        }
        if self.dga_nx.len() > 2_000 {
            self.dga_nx.retain(|_, q| {
                q.back().is_some_and(|(t, _)| now.saturating_sub(*t) < DGA_WINDOW_MS)
            });
        }
    }

    fn on_syn(&mut self, now: u64, src: IpAddr, dst: IpAddr, dport: u16, out: &mut Vec<Event>) {
        let (local_src, local_dst) = (self.is_local(&src), self.is_local(&dst));
        if local_dst && !local_src {
            let q = self.syns.entry(src).or_default();
            q.push_back((now, dport));
            while q.front().is_some_and(|(t, _)| now.saturating_sub(*t) > SCAN_WINDOW_MS) {
                q.pop_front();
            }
            let distinct: HashSet<u16> = q.iter().map(|(_, p)| *p).collect();
            if distinct.len() >= SCAN_PORT_THRESHOLD {
                let span = (now - q.front().map_or(now, |(t, _)| *t)) / 1000;
                q.clear();
                let origin = if is_private_ip(&src) { "a device on your network" } else { "the internet" };
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::Medium,
                    kind: "port_scan",
                    key: src.to_string(),
                    title: format!("Port scan from {src}"),
                    detail: format!(
                        "{src} ({origin}) probed {} different ports on this computer within {}s.",
                        distinct.len(),
                        span.max(1)
                    ),
                }));
            }
            if self.syns.len() > 10_000 {
                self.syns.retain(|_, q| q.back().is_some_and(|(t, _)| now - t < SCAN_WINDOW_MS));
            }
        } else if local_src && !local_dst && !is_private_ip(&dst) {
            if let Some((_, what)) = SUSPICIOUS_PORTS.iter().find(|(p, _)| *p == dport) {
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::Medium,
                    kind: "suspicious_port",
                    key: format!("{dst}:{dport}"),
                    title: format!("Outbound connection on port {dport}"),
                    detail: format!(
                        "This computer connected to {} on port {dport}, which is associated with {what}. Legitimate software rarely uses it.",
                        self.name_of(&dst)
                    ),
                }));
            }
            self.track_beacon(now, dst, dport, out);
        }
    }

    fn track_beacon(&mut self, now: u64, dst: IpAddr, port: u16, out: &mut Vec<Event>) {
        let q = self.conn_starts.entry((dst, port)).or_default();
        // Deduplicate rapid TCP SYN retransmissions or parallel browser sockets.
        if q.back().is_some_and(|last| now.saturating_sub(*last) < BEACON_SYN_DEDUP_MS) {
            return;
        }
        q.push_back(now);
        if q.len() > BEACON_SAMPLES {
            q.pop_front();
        }
        if q.len() == BEACON_SAMPLES {
            let gaps: Vec<f64> = q
                .iter()
                .zip(q.iter().skip(1))
                .map(|(a, b)| b.saturating_sub(*a) as f64)
                .collect();
            let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
            let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
            let jitter = if mean > 0.0 { var.sqrt() / mean } else { 1.0 };
            if mean >= BEACON_MIN_INTERVAL_MS && jitter <= BEACON_MAX_JITTER {
                out.push(Event::Alert(AlertDraft {
                    severity: Severity::Low,
                    kind: "beacon",
                    key: format!("{dst}:{port}"),
                    title: format!("Regular check-ins to {dst}"),
                    detail: format!(
                        "This computer opened {BEACON_SAMPLES} connections to {}:{port} at a steady ~{:.0}s interval ({:.0}% jitter). Malware often 'beacons' like this, but so do updaters and sync clients — check which app owns it in Connections.",
                        self.name_of(&dst),
                        mean / 1000.0,
                        jitter * 100.0
                    ),
                }));
            }
        }
        if self.conn_starts.len() > 20_000 {
            self.conn_starts
                .retain(|_, q| q.back().is_some_and(|t| now.saturating_sub(*t) < 3_600_000));
        }
    }

    pub fn snapshot(&mut self, now: u64) -> TrafficSnapshot {
        let (last_ts, last_rx, last_tx) = self.last_snap;
        let dt = now.saturating_sub(last_ts).max(1);
        let rx_bps = (self.total_rx - last_rx) * 8 * 1000 / dt;
        let tx_bps = (self.total_tx - last_tx) * 8 * 1000 / dt;
        self.last_snap = (now, self.total_rx, self.total_tx);
        if self.hosts.len() > 5_000 {
            self.hosts.retain(|_, h| now - h.last_seen < 3_600_000);
        }
        let names = self.dns_names.read().unwrap();
        let mut hosts: Vec<HostStat> = self
            .hosts
            .iter()
            .map(|(ip, h)| HostStat {
                name: names.get(ip).cloned(),
                ..h.clone()
            })
            .collect();
        hosts.sort_by_key(|h| std::cmp::Reverse(h.bytes_in + h.bytes_out));
        hosts.truncate(150);
        TrafficSnapshot {
            ts: now,
            rx_bps,
            tx_bps,
            total_rx: self.total_rx,
            total_tx: self.total_tx,
            packets: self.packets,
            hosts,
        }
    }
}

/// The EtherType after any VLAN tags, and where its payload starts.
fn ethertype(frame: &[u8]) -> (u16, usize) {
    let mut off = 12;
    let mut et = u16::from_be_bytes([frame[12], frame[13]]);
    while (et == 0x8100 || et == 0x88a8) && frame.len() >= off + 8 {
        off += 4;
        et = u16::from_be_bytes([frame[off], frame[off + 1]]);
    }
    (et, off + 2)
}

/// Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello
/// TCP payload. Pure bounds-checked parsing; returns `None` for non-TLS or ECH.
pub fn parse_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type 0x16 (Handshake), version 0x03 0x00..0x04, len(2).
    if data.len() < 43 || data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x04 {
        return None;
    }
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let rec = data.get(5..5 + rec_len.min(data.len() - 5))?;
    // Handshake header: type 0x01 (ClientHello), len(3), version(2), random(32).
    if rec.len() < 38 || rec[0] != 0x01 {
        return None;
    }
    let mut i = 38;
    // Session ID
    let sid_len = *rec.get(i)? as usize;
    i = i.checked_add(1 + sid_len)?;
    // Cipher suites
    let cs_len = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
    i = i.checked_add(2 + cs_len)?;
    // Compression methods
    let cm_len = *rec.get(i)? as usize;
    i = i.checked_add(1 + cm_len)?;
    // Extensions
    let ext_total = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
    i += 2;
    let end = i.checked_add(ext_total)?.min(rec.len());
    while i + 4 <= end {
        let ext_type = u16::from_be_bytes([rec[i], rec[i + 1]]);
        let ext_len = u16::from_be_bytes([rec[i + 2], rec[i + 3]]) as usize;
        i += 4;
        let ext_end = i.checked_add(ext_len)?;
        if ext_end > end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let list_len = u16::from_be_bytes([rec[i], rec[i + 1]]) as usize;
            let mut j = i + 2;
            let list_end = j.checked_add(list_len)?.min(ext_end);
            while j + 3 <= list_end {
                let name_type = rec[j];
                let name_len = u16::from_be_bytes([rec[j + 1], rec[j + 2]]) as usize;
                j += 3;
                let name_bytes = rec.get(j..j.checked_add(name_len)?)?;
                if name_type == 0x00 {
                    let s = std::str::from_utf8(name_bytes).ok()?.trim_end_matches('.');
                    let ok = !s.is_empty()
                        && s.len() <= 253
                        && s.contains('.')
                        && s.parse::<IpAddr>().is_err()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
                    return ok.then(|| s.to_ascii_lowercase());
                }
                j += name_len;
            }
        }
        i = ext_end;
    }
    None
}

/// Shannon entropy in bits per character. Random hex/base32/base64 payloads
/// typically score >= 3.5; ordinary English hostnames score ~2.3-3.1.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Splits `a.b.example.co.uk` into `("a.b", "example.co.uk")`.
/// Returns `None` for single-label names.
fn registrable_domain(name: &str) -> Option<(String, String)> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    let sld = parts[parts.len() - 2];
    let tld = parts[parts.len() - 1];
    let base_len = if parts.len() >= 3
        && tld.len() == 2
        && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "id")
    {
        3
    } else {
        2
    };
    let split = parts.len().saturating_sub(base_len);
    Some((parts[..split].join("."), parts[split..].join(".")))
}

fn is_local_domain(name: &str) -> bool {
    let l = name.trim_end_matches('.').to_ascii_lowercase();
    if !l.contains('.') {
        return true;
    }
    const LOCAL_SUFFIXES: &[&str] = &[
        ".local",
        ".lan",
        ".home",
        ".internal",
        ".arpa",
        ".localhost",
        ".localdomain",
        ".corp",
        ".home.arpa",
    ];
    LOCAL_SUFFIXES.iter().any(|s| l.ends_with(s))
}

/// Well-known cloud / CDN / OS domains that legitimately use long high-entropy
/// subdomain labels (hashing, cache sharding, telemetry).
fn is_benign_hash_domain(name: &str) -> bool {
    let l = name.trim_end_matches('.').to_ascii_lowercase();
    const SUFFIXES: &[&str] = &[
        "amazonaws.com",
        "cloudfront.net",
        "akamaiedge.net",
        "akamai.net",
        "akadns.net",
        "fastly.net",
        "googleusercontent.com",
        "icloud.com",
        "apple-dns.net",
        "windowsupdate.com",
        "azureedge.net",
        "cloudflare-dns.com",
        "1e100.net",
        "fbcdn.net",
        "cdninstagram.com",
        "nflxvideo.net",
        "plex.direct",
        "tailscale.com",
        "ts.net",
    ];
    SUFFIXES
        .iter()
        .any(|s| l == *s || l.ends_with(&format!(".{s}")))
}

/// Intentional LAN-resolution helper services that resolve to private IPs by design.
fn is_rebinding_exempt(name: &str) -> bool {
    let l = name.trim_end_matches('.').to_ascii_lowercase();
    const EXEMPT: &[&str] = &[
        "plex.direct",
        "nip.io",
        "sslip.io",
        "localtest.me",
        "lvh.me",
        "xip.io",
        "ts.net",
        "tailscale.net",
    ];
    EXEMPT
        .iter()
        .any(|s| l == *s || l.ends_with(&format!(".{s}")))
}

#[derive(Debug)]
pub struct Dhcp {
    pub msg_type: Option<u8>,
    pub chaddr: String,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    /// Option 60, e.g. `MSFT 5.0`, `android-dhcp-14`, `dhcpcd-9.4.1`.
    pub vendor_class: Option<String>,
    /// Option 55 as a comma-separated list of option codes.
    pub params: Option<String>,
}

pub fn parse_dhcp(p: &[u8]) -> Option<Dhcp> {
    if p.len() < 240 || p[1] != 1 || p[2] != 6 || p[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let ip_at = |o: usize| Ipv4Addr::new(p[o], p[o + 1], p[o + 2], p[o + 3]);
    let mut d = Dhcp {
        msg_type: None,
        chaddr: fmt_mac(&p[28..34]),
        ciaddr: ip_at(12),
        yiaddr: ip_at(16),
        server_id: None,
        requested_ip: None,
        hostname: None,
        vendor_class: None,
        params: None,
    };
    let mut i = 240;
    while i < p.len() {
        let code = p[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 || i + 1 >= p.len() {
            break;
        }
        let len = p[i + 1] as usize;
        let Some(v) = p.get(i + 2..i + 2 + len) else {
            break;
        };
        match (code, len) {
            (53, 1) => d.msg_type = Some(v[0]),
            (54, 4) => d.server_id = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            (50, 4) => d.requested_ip = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            (12, _) => {
                let h = String::from_utf8_lossy(v).trim_matches('\0').trim().to_string();
                d.hostname = (!h.is_empty()).then_some(h);
            }
            (60, 1..) => {
                let c = String::from_utf8_lossy(v).trim_matches('\0').trim().to_string();
                d.vendor_class = (!c.is_empty()).then_some(c);
            }
            (55, 1..) => {
                d.params = Some(v.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(","));
            }
            _ => {}
        }
        i += 2 + len;
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use simple_dns::rdata::A;
    use simple_dns::{Name, Question, ResourceRecord, CLASS, TYPE};

    const ME: [u8; 4] = [192, 168, 0, 110];
    const ME_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x6e];
    const GW: [u8; 4] = [192, 168, 0, 1];
    const GW_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x01];

    fn analyzer_with(bl: Blocklist) -> Analyzer {
        Analyzer::new(
            Config {
                local_mac: Some(fmt_mac(&ME_MAC)),
                local_ips: [IpAddr::from(ME)].into(),
                gateway_ip: Some(GW.into()),
                gateway_mac: Some(fmt_mac(&GW_MAC)),
            },
            Arc::new(RwLock::new(bl)),
            Arc::default(),
            0,
        )
    }

    fn analyzer() -> Analyzer {
        analyzer_with(Blocklist::default())
    }

    fn alerts(events: &[Event]) -> Vec<&AlertDraft> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Alert(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    fn syn(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, dst, 64)
            .tcp(sport, dport, 1, 1024)
            .syn();
        let mut buf = Vec::with_capacity(b.size(0));
        b.write(&mut buf, &[]).unwrap();
        buf
    }

    fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, dst, 64)
            .udp(sport, dport);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    fn arp_reply(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend(sender_mac);
        f.extend([0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        f.extend(sender_mac);
        f.extend(sender_ip);
        f.extend(ME_MAC);
        f.extend(ME);
        f
    }

    fn dhcp(msg_type: u8, chaddr: [u8; 6], yiaddr: [u8; 4], opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = if matches!(msg_type, 2 | 5) { 2 } else { 1 };
        p[1] = 1;
        p[2] = 6;
        p[16..20].copy_from_slice(&yiaddr);
        p[28..34].copy_from_slice(&chaddr);
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        p.extend([53, 1, msg_type]);
        for (code, val) in opts {
            p.push(*code);
            p.push(val.len() as u8);
            p.extend(*val);
        }
        p.push(255);
        p
    }

    fn dns_reply(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut p = Packet::new_reply(7);
        p.questions.push(Question::new(
            Name::new_unchecked(name),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
        p.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            60,
            RData::A(A {
                address: u32::from(Ipv4Addr::from(ip)),
            }),
        ));
        p.build_bytes_vec().unwrap()
    }

    #[test]
    fn detects_port_scan_but_not_normal_traffic() {
        let mut a = analyzer();
        let attacker = [192, 168, 0, 50];
        let mut found = Vec::new();
        for port in 1..=10u16 {
            let f = syn(attacker, ME, 40000, port);
            found.extend(a.process(port as u64 * 100, &f, f.len() as u32));
        }
        assert!(alerts(&found).is_empty(), "10 ports is not a scan");
        for port in 11..=30u16 {
            let f = syn(attacker, ME, 40000, port);
            found.extend(a.process(port as u64 * 100, &f, f.len() as u32));
        }
        let al = alerts(&found);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "port_scan");
        assert_eq!(al[0].key, "192.168.0.50");
    }

    #[test]
    fn slow_probes_outside_window_are_not_a_scan() {
        let mut a = analyzer();
        let mut found = Vec::new();
        for port in 1..=40u16 {
            let f = syn([192, 168, 0, 50], ME, 40000, port);
            found.extend(a.process(port as u64 * 5_000, &f, f.len() as u32));
        }
        assert!(alerts(&found).is_empty());
    }

    #[test]
    fn detects_gateway_arp_spoof() {
        let mut a = analyzer();
        let f = arp_reply(GW_MAC, GW);
        let ev = a.process(1_000, &f, f.len() as u32);
        assert!(alerts(&ev).is_empty(), "real router answering is fine");
        assert!(matches!(&ev[0], Event::Device { source: "arp", .. }));

        let f = arp_reply([0xde, 0xad, 0xbe, 0xef, 0, 1], GW);
        let ev = a.process(2_000, &f, f.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "arp_spoof");
        assert_eq!(al[0].severity, Severity::High);
    }

    #[test]
    fn ip_conflict_only_within_grace_window() {
        let mut a = analyzer();
        let ip = [192, 168, 0, 20];
        let f1 = arp_reply([0x00, 0xaa, 0, 0, 0, 1], ip);
        let f2 = arp_reply([0x00, 0xbb, 0, 0, 0, 2], ip);
        a.process(0, &f1, 42);
        assert_eq!(alerts(&a.process(60_000, &f2, 42))[0].kind, "ip_conflict");
        // Much later, the lease moving to another device is normal.
        assert!(alerts(&a.process(60_000 + IP_REASSIGN_GRACE_MS + 1, &f1, 42)).is_empty());
    }

    #[test]
    fn detects_rogue_dhcp_and_learns_hostnames() {
        let mut a = analyzer();
        let client = [0x00, 0x0c, 0x29, 1, 2, 3];
        let req = dhcp(
            3,
            client,
            [0; 4],
            &[(50, &[192, 168, 0, 77]), (12, b"living-room-tv"), (60, b"android-dhcp-14"), (55, &[1, 3, 6, 15])],
        );
        let f = udp([0; 4], [255; 4], 68, 67, &req);
        let ev = a.process(0, &f, f.len() as u32);
        match &ev[..] {
            [Event::Device { mac, ip, hostname, source, fingerprint }] => {
                assert_eq!(mac, "00:0c:29:01:02:03");
                assert_eq!(*ip, Ipv4Addr::new(192, 168, 0, 77));
                assert_eq!(hostname.as_deref(), Some("living-room-tv"));
                assert_eq!(*source, "dhcp");
                assert_eq!(
                    fingerprint,
                    &Some((Some("android-dhcp-14".into()), Some("1,3,6,15".into())))
                );
            }
            _ => panic!("expected one device event"),
        }

        let offer = |server: [u8; 4]| {
            let p = dhcp(2, client, [192, 168, 0, 77], &[(54, &server)]);
            udp(server, [255; 4], 67, 68, &p)
        };
        let f = offer(GW);
        assert!(alerts(&a.process(1, &f, 300)).is_empty());
        assert!(alerts(&a.process(2, &f, 300)).is_empty());
        let f = offer([192, 168, 0, 66]);
        let ev = a.process(3, &f, 300);
        assert_eq!(alerts(&ev)[0].kind, "rogue_dhcp");
    }

    #[test]
    fn flags_malicious_dns_and_maps_names() {
        let mut bl = Blocklist::default();
        bl.add_list("127.0.0.1 bad.example.com\n", "feed");
        let mut a = analyzer_with(bl);

        let f = udp(GW, ME, 53, 5555, &dns_reply("www.rust-lang.org", [151, 101, 1, 1]));
        let ev = a.process(10, &f, f.len() as u32);
        assert!(alerts(&ev).is_empty());
        assert!(matches!(&ev[..], [Event::Dns(d)] if !d.blocked && d.answers == ["151.101.1.1"]));

        let f = udp(GW, ME, 53, 5555, &dns_reply("cdn.bad.example.com", [203, 0, 113, 5]));
        let ev = a.process(20, &f, f.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "malicious_domain");
        assert_eq!(al[0].key, "bad.example.com");

        let snap = a.snapshot(1_000);
        assert!(snap.hosts.iter().all(|h| h.ip != "151.101.1.1"), "DNS server is the remote here");
        assert_eq!(
            a.dns_names.read().unwrap().get(&IpAddr::from([151, 101, 1, 1])).map(String::as_str),
            Some("www.rust-lang.org")
        );
    }

    #[test]
    fn flags_traffic_to_c2_ip_once() {
        let mut bl = Blocklist::default();
        bl.add_list("198.51.100.23\n", "feed");
        let mut a = analyzer_with(bl);
        let f = syn(ME, [198, 51, 100, 23], 50000, 443);
        assert_eq!(alerts(&a.process(0, &f, 60))[0].kind, "c2_traffic");
        assert!(alerts(&a.process(1, &f, 60)).is_empty());
    }

    #[test]
    fn detects_beaconing_but_not_irregular_traffic() {
        let mut a = analyzer();
        let f = syn(ME, [203, 0, 113, 9], 50000, 443);
        let mut found = Vec::new();
        for i in 0..BEACON_SAMPLES as u64 {
            let jitter = if i % 2 == 0 { 300 } else { 0 };
            found.extend(a.process(i * 60_000 + jitter, &f, 60));
        }
        let al = alerts(&found);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "beacon");

        let mut b = analyzer();
        let mut found = Vec::new();
        let times = [0u64, 5, 61, 62, 130, 300, 302, 420, 421, 600];
        for t in times {
            found.extend(b.process(t * 1000, &f, 60));
        }
        assert!(alerts(&found).is_empty());
    }

    #[test]
    fn flags_suspicious_outbound_ports() {
        let mut a = analyzer();
        let f = syn(ME, [198, 51, 100, 7], 50000, 4444);
        assert_eq!(alerts(&a.process(0, &f, 60))[0].kind, "suspicious_port");
        let f = syn(ME, [192, 168, 0, 9], 50000, 23);
        assert!(alerts(&a.process(0, &f, 60)).is_empty(), "LAN telnet is not outbound");
    }

    #[test]
    fn accounts_traffic_rates() {
        let mut a = analyzer();
        let out = syn(ME, [93, 184, 216, 34], 50000, 443);
        let inbound = syn([93, 184, 216, 34], ME, 443, 50000);
        a.process(0, &out, 1_000);
        a.process(0, &inbound, 3_000);
        let s = a.snapshot(1_000);
        assert_eq!(s.tx_bps, 8_000);
        assert_eq!(s.rx_bps, 24_000);
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].ports, BTreeSet::from([443]));
        assert!(!s.hosts[0].lan);
    }

    fn tcp_payload(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, dst, 64)
            .tcp(sport, dport, 10, 1024)
            .ack(1);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    /// Minimal valid TLS 1.2/1.3 ClientHello carrying a single SNI extension.
    fn tls_client_hello(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        // SNI extension body: list_len(2) + type(1=0) + name_len(2) + name
        let mut sni = Vec::new();
        sni.extend(((h.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend((h.len() as u16).to_be_bytes());
        sni.extend(h);
        // Extensions: ext_type(0x0000) + ext_len(2) + sni
        let mut exts = Vec::new();
        exts.extend(0x0000u16.to_be_bytes());
        exts.extend((sni.len() as u16).to_be_bytes());
        exts.extend(&sni);
        // ClientHello body
        let mut ch = Vec::new();
        ch.extend([0x03, 0x03]); // TLS 1.2 legacy version
        ch.extend([0x11; 32]); // random
        ch.push(0); // session_id_len
        ch.extend(2u16.to_be_bytes()); // cipher_suites_len
        ch.extend([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch.push(1); // compression_methods_len
        ch.push(0); // null compression
        ch.extend((exts.len() as u16).to_be_bytes());
        ch.extend(&exts);
        // Handshake header: type(1=ClientHello) + len(3)
        let mut hs = Vec::new();
        hs.push(0x01);
        let hl = ch.len() as u32;
        hs.extend([(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        hs.extend(&ch);
        // TLS record header: type(0x16) + version(0x03, 0x01) + len(2)
        let mut rec = Vec::new();
        rec.extend([0x16, 0x03, 0x01]);
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    fn dns_nxdomain(name: &str) -> Vec<u8> {
        let mut p = Packet::new_reply(9);
        *p.rcode_mut() = simple_dns::RCODE::NameError;
        p.questions.push(Question::new(
            Name::new_unchecked(name),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
        p.build_bytes_vec().unwrap()
    }

    #[test]
    fn extracts_tls_sni_and_flags_blocklisted_https_domains() {
        let mut bl = Blocklist::default();
        bl.add_list("127.0.0.1 evil-doh.example\n", "feed");
        let mut a = analyzer_with(bl);

        // Benign HTTPS site learned even without cleartext DNS (e.g. DoH).
        let ok_ip = [104, 16, 10, 20];
        let f = tcp_payload(ME, ok_ip, 51000, 443, &tls_client_hello("docs.rs"));
        let ev = a.process(1_000, &f, f.len() as u32);
        assert!(alerts(&ev).is_empty());
        assert_eq!(
            a.dns_names.read().unwrap().get(&IpAddr::from(ok_ip)).map(String::as_str),
            Some("docs.rs")
        );
        assert!(ev.iter().any(|e| matches!(e, Event::Dns(d) if d.name == "docs.rs" && d.qtype == "SNI" && !d.blocked)));

        // Malware domain reached over HTTPS while DNS was hidden by DoH.
        let bad_ip = [203, 0, 113, 88];
        let f = tcp_payload(ME, bad_ip, 51001, 443, &tls_client_hello("api.evil-doh.example"));
        let ev = a.process(2_000, &f, f.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "malicious_domain");
        assert_eq!(al[0].key, "evil-doh.example");
        assert_eq!(al[0].severity, Severity::High);
    }

    #[test]
    fn detects_self_ip_arp_spoof_and_preserves_gateway_baseline() {
        let mut a = analyzer();
        // Someone spoofing this computer's own IP must raise High arp_spoof.
        let spoof_self = arp_reply([0xde, 0xad, 0xbe, 0xef, 0x00, 0x02], ME);
        let ev = a.process(1_000, &spoof_self, spoof_self.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "arp_spoof");
        assert_eq!(al[0].severity, Severity::High);

        // Gateway spoof followed by the real router answering again:
        // only the attacker triggers arp_spoof, NOT the real router recovering.
        let spoof_gw = arp_reply([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], GW);
        assert_eq!(alerts(&a.process(2_000, &spoof_gw, 42)).len(), 1);
        let real_gw = arp_reply(GW_MAC, GW);
        assert!(alerts(&a.process(3_000, &real_gw, 42)).is_empty(), "real router recovery should not alert");
    }

    #[test]
    fn detects_arp_flood_subnet_poisoning() {
        let mut a = analyzer();
        let attacker = [0x00, 0xca, 0xfe, 0xba, 0xbe, 0x01];
        let mut found = Vec::new();
        for host in 10..20u8 {
            let f = arp_reply(attacker, [192, 168, 0, host]);
            found.extend(a.process(1_000 + host as u64 * 200, &f, 42));
        }
        let al: Vec<_> = alerts(&found).into_iter().filter(|x| x.kind == "arp_flood").collect();
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].severity, Severity::High);
    }

    #[test]
    fn detects_dns_tunneling_but_ignores_normal_and_cdn_domains() {
        let mut a = analyzer();
        let mut found = Vec::new();
        // 14 distinct high-entropy hex/base32 encoded subdomains under one domain.
        let payloads = [
            "a9f3k2m8p1x7q4v6w0z5n2c8b4d7",
            "b8e4j3l9o2w6r5u7y1a6m3d9c5e8",
            "c7d5h4k0n3v5s6t8x2b7l4e0d6f9",
            "d6c6g5j1m4u4t7s9w3c8k5f1e7g0",
            "e5b7f6i2l5t3u8r0v4d9j6g2f8h1",
            "f4a8e7h3k6s2v9q1u5e0i7h3g9i2",
            "g3z9d8g4j7r1w0p2t6f1h8i4h0j3",
            "h2y0c9f5i8q0x1o3s7g2g9j5i1k4",
            "i1x1b0e6h9p9y2n4r8h3f0k6j2l5",
            "j0w2a1d7g0o8z3m5q9i4e1l7k3m6",
            "k9v3z2c8f1n7a4l6p0j5d2m8l4n7",
            "l8u4y3b9e2m6b5k7o1k6c3n9m5o8",
            "m7t5x4a0d3l5c6j8n2l7b4o0n6p9",
            "n6s6w5z1c4k4d7i9m3m8a5p1o7q0",
        ];
        for (i, sub) in payloads.iter().enumerate() {
            let f = udp(GW, ME, 53, 5555, &dns_reply(&format!("{sub}.exfil-c2.example"), [198, 51, 100, 1]));
            found.extend(a.process(1_000 + i as u64 * 1_000, &f, f.len() as u32));
        }
        let al: Vec<_> = alerts(&found).into_iter().filter(|x| x.kind == "dns_tunnel").collect();
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].severity, Severity::Medium);

        // Normal CDN / cloud hash subdomains must NOT alert.
        let mut b = analyzer();
        let mut cdn_found = Vec::new();
        for (i, sub) in payloads.iter().enumerate() {
            let f = udp(GW, ME, 53, 5555, &dns_reply(&format!("{sub}.cloudfront.net"), [13, 32, 1, 1]));
            cdn_found.extend(b.process(1_000 + i as u64 * 1_000, &f, f.len() as u32));
        }
        assert!(alerts(&cdn_found).is_empty());
    }

    #[test]
    fn detects_dga_nxdomain_burst() {
        let mut a = analyzer();
        let mut found = Vec::new();
        let names = [
            "qx8f9m2v4k1z.com", "w7p3n9b2x5c8.net", "m4k8v2j9q6r1.org",
            "z9d2f7h4t1y6.com", "p5x1c8b3n7m2.info", "r3t6y9u2i5o8.biz",
            "k8j4h2g9f5d1.com", "v2b6n9m3q7w4.net", "c5x8z1l4k7j2.org",
            "f9g3h6j1k4l8.com", "t2y5u8i1o4p7.net", "s4d7f1g5h8j2.org",
            "q6w9e2r5t8y1.com", "b3n6m9v2c5x8.net", "l7k4j1h8g5f2.com",
            "n9m2b5v8c1x4.org",
        ];
        for (i, n) in names.iter().enumerate() {
            let f = udp(GW, ME, 53, 5555, &dns_nxdomain(n));
            found.extend(a.process(1_000 + i as u64 * 500, &f, f.len() as u32));
        }
        let al: Vec<_> = alerts(&found).into_iter().filter(|x| x.kind == "dga_burst").collect();
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].severity, Severity::High);
    }

    #[test]
    fn detects_dns_rebinding_but_ignores_adblock_sinkholes() {
        let mut a = analyzer();
        // Pi-hole / AdGuard sinkhole to 0.0.0.0 or 127.0.0.1 is NOT rebinding.
        let sink1 = udp(GW, ME, 53, 5555, &dns_reply("ads.tracker.example", [0, 0, 0, 0]));
        let sink2 = udp(GW, ME, 53, 5555, &dns_reply("ads2.tracker.example", [127, 0, 0, 1]));
        assert!(alerts(&a.process(1_000, &sink1, sink1.len() as u32)).is_empty());
        assert!(alerts(&a.process(2_000, &sink2, sink2.len() as u32)).is_empty());

        // Public domain resolving directly to our router IP -> High dns_rebinding.
        let gw_rebind = udp(GW, ME, 53, 5555, &dns_reply("rebind.evil.example", GW));
        let ev = a.process(3_000, &gw_rebind, gw_rebind.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "dns_rebinding");
        assert_eq!(al[0].severity, Severity::High);

        // Classic time-shifted DNS rebinding: public IP first, then private LAN IP.
        let pub_first = udp(GW, ME, 53, 5555, &dns_reply("flip.evil.example", [198, 51, 100, 42]));
        assert!(alerts(&a.process(4_000, &pub_first, pub_first.len() as u32)).is_empty());
        let lan_flip = udp(GW, ME, 53, 5555, &dns_reply("flip.evil.example", [192, 168, 0, 50]));
        let ev = a.process(20_000, &lan_flip, lan_flip.len() as u32);
        let al = alerts(&ev);
        assert_eq!(al.len(), 1);
        assert_eq!(al[0].kind, "dns_rebinding");
    }

    #[test]
    fn beacon_deduplicates_syn_retries_and_catches_jittered_beacons() {
        let mut a = analyzer();
        let f = syn(ME, [203, 0, 113, 55], 50000, 443);
        let mut found = Vec::new();
        // ~60s beacon with ~10% jitter and occasional 1s TCP SYN retries.
        let offsets = [0u64, 57, 123, 180, 244, 298, 362, 419, 483, 540];
        for (i, &sec) in offsets.iter().enumerate() {
            let t = sec * 1_000;
            found.extend(a.process(t, &f, 60));
            if i % 3 == 0 {
                // Retransmission 800ms later should be ignored, not ruin beacon stats.
                found.extend(a.process(t + 800, &f, 60));
            }
        }
        let al: Vec<_> = alerts(&found).into_iter().filter(|x| x.kind == "beacon").collect();
        assert_eq!(al.len(), 1);
    }
}

//! Reachability checks that need no special privileges: ICMP echo over an
//! unprivileged datagram socket (macOS, and Linux when `ping_group_range`
//! allows it), with a TCP fallback for devices that ignore ping.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reply {
    pub rtt_ms: f32,
    /// The reply's IP TTL, when the OS hands us the IP header (macOS does).
    pub ttl: Option<u8>,
}

/// Ports tried when a host ignores ping. A refused connection proves the host
/// is up just as well as an accepted one.
const TCP_PROBE_PORTS: &[u16] = &[80, 443, 62078, 22, 445, 7000, 8080, 5000];

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(id: u16, seq: u16, token: u32) -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0];
    p.extend(id.to_be_bytes());
    p.extend(seq.to_be_bytes());
    p.extend(b"NetWatch");
    p.extend(token.to_be_bytes());
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// Parses an echo reply, with or without a leading IPv4 header. Returns the
/// sequence number and TTL if the reply carries our token.
fn parse_reply(buf: &[u8], token: u32) -> Option<(u16, Option<u8>)> {
    let (icmp, ttl) = if buf.first().is_some_and(|b| b >> 4 == 4) && buf.len() >= 20 {
        let ihl = (buf[0] & 0x0f) as usize * 4;
        (buf.get(ihl..)?, Some(buf[8]))
    } else {
        (buf, None)
    };
    if icmp.len() < 20 || icmp[0] != 0 || &icmp[8..16] != b"NetWatch" {
        return None;
    }
    if icmp[16..20] != token.to_be_bytes() {
        return None;
    }
    Some((u16::from_be_bytes([icmp[6], icmp[7]]), ttl))
}

/// Pings every address (twice, for hosts that are slow to wake) and returns
/// the ones that answered within `timeout`.
pub fn ping_many(ips: &[Ipv4Addr], timeout: Duration) -> std::io::Result<HashMap<Ipv4Addr, Reply>> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let token: u32 = rand_u32();
    let id = (token >> 16) as u16;
    let mut sent: HashMap<u16, (Ipv4Addr, Instant)> = HashMap::new();
    let mut out = HashMap::new();
    let start = Instant::now();
    let resend_at = timeout / 2;
    let mut resent = false;
    let send_round = |sent: &mut HashMap<u16, (Ipv4Addr, Instant)>, out: &HashMap<Ipv4Addr, Reply>, base: u16| {
        for (i, ip) in ips.iter().enumerate() {
            if out.contains_key(ip) {
                continue;
            }
            let seq = base.wrapping_add(i as u16);
            let addr = SockAddr::from(SocketAddrV4::new(*ip, 0));
            if sock.send_to(&echo_request(id, seq, token), &addr).is_ok() {
                sent.insert(seq, (*ip, Instant::now()));
            }
            if i % 64 == 63 {
                thread::sleep(Duration::from_millis(15));
            }
        }
    };
    send_round(&mut sent, &out, 0);
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    while start.elapsed() < timeout && out.len() < ips.len() {
        if !resent && start.elapsed() >= resend_at {
            resent = true;
            send_round(&mut sent, &out, 0x8000);
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        // SAFETY: recv_from initialized the first `n` bytes.
        let data: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
        let Some((seq, ttl)) = parse_reply(&data, token) else { continue };
        let Some(&(ip, at)) = sent.get(&seq) else { continue };
        if from.as_socket_ipv4().map(|a| *a.ip()) != Some(ip) {
            continue;
        }
        out.entry(ip).or_insert(Reply {
            rtt_ms: at.elapsed().as_secs_f32() * 1000.0,
            ttl,
        });
    }
    Ok(out)
}

/// For hosts that ignore ping: tries a few common TCP ports in parallel and
/// counts the host as up if any port accepts or actively refuses.
pub fn tcp_probe_many(ips: &[Ipv4Addr], timeout: Duration) -> HashMap<Ipv4Addr, Reply> {
    let (tx, rx) = mpsc::channel();
    for &ip in ips {
        for &port in TCP_PROBE_PORTS {
            let tx = tx.clone();
            thread::spawn(move || {
                let t = Instant::now();
                let addr = SocketAddr::from((ip, port));
                let up = match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(_) => true,
                    Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
                };
                if up {
                    let _ = tx.send((ip, t.elapsed()));
                }
            });
        }
    }
    drop(tx);
    let mut out = HashMap::new();
    let deadline = Instant::now() + timeout + Duration::from_millis(200);
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((ip, rtt)) => {
                out.entry(ip).or_insert(Reply {
                    rtt_ms: rtt.as_secs_f32() * 1000.0,
                    ttl: None,
                });
            }
            Err(_) => break,
        }
    }
    out
}

fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(crate::util::now_ms());
    h.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_value() {
        // Echo request id=0x1234 seq=1, no payload.
        let p = [8, 0, 0, 0, 0x12, 0x34, 0, 1];
        assert_eq!(checksum(&p), 0xe5ca);
    }

    #[test]
    fn parses_replies_with_and_without_ip_header() {
        let token = 0xdeadbeef;
        let mut icmp = echo_request(7, 42, token);
        icmp[0] = 0; // echo reply
        assert_eq!(parse_reply(&icmp, token), Some((42, None)));
        let mut with_ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 57, 1, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2];
        with_ip.extend(&icmp);
        assert_eq!(parse_reply(&with_ip, token), Some((42, Some(57))));
        assert_eq!(parse_reply(&icmp, 1), None);
    }

    /// Needs a LAN: `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_ping_and_probe() {
        let gw: Ipv4Addr = std::env::var("NW_GW").unwrap_or("192.168.0.1".into()).parse().unwrap();
        let r = ping_many(&[gw, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(192, 0, 2, 1)], Duration::from_secs(2)).unwrap();
        println!("ping: {r:?}");
        assert!(r.contains_key(&gw));
        assert!(!r.contains_key(&Ipv4Addr::new(192, 0, 2, 1)));
        println!("tcp: {:?}", tcp_probe_many(&[gw], Duration::from_millis(900)));
    }
}

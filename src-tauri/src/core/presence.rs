//! Who is home: a light reachability check of known devices every minute,
//! online/offline transitions, and join/leave alerts for watched devices.

use super::{apply_reply, describe, Core};
use crate::alerts::{AlertDraft, Severity};
use crate::discovery;
use crate::ping;
use crate::util::now_ms;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const PRESENCE_INTERVAL: Duration = Duration::from_secs(60);
/// Devices seen this recently also get a TCP probe when they ignore ping, so
/// we notice when they leave. Older ones only get a ping.
const TCP_PROBE_RECENT_MS: u64 = 30 * 60_000;
const MAX_TARGETS: usize = 256;

struct Target {
    ip: Ipv4Addr,
    mac: String,
    recent: bool,
}

impl Core {
    pub(super) fn start_presence(self: &Arc<Self>) {
        let core = self.clone();
        thread::spawn(move || loop {
            thread::sleep(PRESENCE_INTERVAL);
            if !core.scanning.load(Ordering::SeqCst) {
                core.presence_check();
            }
        });
    }

    fn presence_check(&self) {
        let Some(net) = self.net.read().unwrap().clone() else { return };
        let now = now_ms();
        let targets: Vec<Target> = {
            let store = self.store.lock().unwrap();
            let mut v: Vec<_> = store
                .devices
                .values()
                .filter(|d| !d.is_self)
                .filter_map(|d| Some((d.ip.parse::<Ipv4Addr>().ok()?, d)))
                .filter(|(ip, _)| self.in_subnet(*ip))
                .collect();
            v.sort_by_key(|(_, d)| Reverse(d.last_seen));
            v.truncate(MAX_TARGETS);
            v.into_iter()
                .map(|(ip, d)| Target {
                    ip,
                    mac: d.mac.clone(),
                    recent: now.saturating_sub(d.last_seen) < TCP_PROBE_RECENT_MS,
                })
                .collect()
        };
        let ips: Vec<Ipv4Addr> = targets.iter().map(|t| t.ip).collect();
        let mut replies = ping::ping_many(&ips, Duration::from_secs(2)).unwrap_or_default();
        let probe: Vec<Ipv4Addr> = targets
            .iter()
            .filter(|t| t.recent && !replies.contains_key(&t.ip))
            .map(|t| t.ip)
            .collect();
        if !probe.is_empty() {
            replies.extend(ping::tcp_probe_many(&probe, Duration::from_millis(900)));
        }
        // The ARP table knows who holds each address right now, which beats
        // our records if a lease moved to another device.
        let table = discovery::read_arp_table(&net.interface, net.ip);
        let fresh = self.arp_memory.lock().unwrap().fresh(&table, now_ms());
        let arp: HashMap<Ipv4Addr, String> = table.iter().map(|e| (e.ip, e.mac.clone())).collect();
        for t in &targets {
            if let Some(reply) = replies.get(&t.ip) {
                let mac = arp.get(&t.ip).unwrap_or(&t.mac);
                self.observe_with(mac, t.ip, "ping", None, |d| apply_reply(d, Some(*reply)));
            }
        }
        // Devices that only answered ARP: usually asleep, but still here.
        for e in table.iter().filter(|e| fresh.contains(&e.ip) && !replies.contains_key(&e.ip)) {
            if self.in_subnet(e.ip) {
                self.observe(&e.mac, e.ip, "arp", None);
            }
        }
        if let Some(mac) = &net.mac {
            self.observe(mac, net.ip, "self", None);
        }
        self.update_presence();
        self.presence_armed.store(true, Ordering::SeqCst);
    }

    /// Re-evaluates who is online and alerts on watched devices that joined
    /// or left. Quiet until the first presence check after startup, so
    /// stale state from the last run doesn't fire alerts.
    pub(super) fn update_presence(&self) {
        let flipped = self.store.lock().unwrap().update_online(now_ms());
        if flipped.is_empty() {
            return;
        }
        self.devices_dirty.store(true, Ordering::SeqCst);
        if !self.presence_armed.load(Ordering::SeqCst) {
            return;
        }
        for d in flipped.iter().filter(|d| d.notify_presence) {
            let name = describe(d);
            let (verb, detail) = if d.online {
                ("joined", format!("{name} is back on the network at {}.", d.ip))
            } else {
                let mins = now_ms().saturating_sub(d.last_seen) / 60_000;
                (
                    "left",
                    format!("{name} stopped answering. It was last seen {mins} minutes ago at {}.", d.ip),
                )
            };
            self.alert(AlertDraft {
                severity: Severity::Info,
                kind: "presence",
                key: format!("{}:{verb}", d.mac),
                title: format!("{name} {verb} the network"),
                detail,
            });
        }
    }
}

//! Runs the security audits on a schedule: the weekly port audit, new
//! listening apps, startup items, DNS/DHCP changes, look-alike Wi-Fi networks
//! and certificate checks. The rules live in `crate::audit` and
//! `crate::certs`; this is the loops, the saved state and the alerts.
//! Locks are never held across slow work (port checks, handshakes, codesign).

use super::monitor::save_json;
use super::{describe, Core};
use crate::alerts::AlertDraft;
use crate::audit::{self as rules, AuditState, CertEntry, DeviceScan, InterceptCheck, LaunchAudit, Listener};
use crate::certs::{self, Handshake};
use crate::conns;
use crate::discovery;
use crate::util::now_ms;
use chrono::Local;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

const TICK: Duration = Duration::from_secs(60);
const LAUNCH_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How many devices the port audit probes at once.
const PORT_AUDIT_WORKERS: usize = 2;
/// An interception check that found no network is retried after this long.
const INTERCEPT_RETRY_MS: u64 = 10 * 60_000;

/// What the Audit page shows: the saved state plus when things run next.
#[derive(Serialize, Clone)]
pub struct AuditSnapshot {
    #[serde(flatten)]
    state: AuditState,
    ports_next: Option<u64>,
    certs_next: Option<u64>,
}

struct Target {
    mac: String,
    name: String,
    ip: Ipv4Addr,
}

fn mtime_ms(p: &Path) -> Option<u64> {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

impl Core {
    pub(super) fn audit_snapshot(&self) -> AuditSnapshot {
        let st = self.audit.lock().unwrap().clone();
        AuditSnapshot {
            ports_next: st.ports.last_run.map(|t| t + rules::PORT_AUDIT_EVERY_MS),
            certs_next: st.certs.last_run.map(|t| t + rules::CERT_CHECK_EVERY_MS),
            state: st,
        }
    }

    fn emit_audit(&self) {
        self.emit("audit", self.audit_snapshot());
    }

    fn save_audit(&self, st: &AuditState) {
        save_json(&self.dir.join("audit.json"), st);
    }

    /// Raises the alert unless this exact situation was already reported.
    fn alert_once(&self, d: AlertDraft) {
        if !self.alerts.lock().unwrap().has(d.kind, &d.key) {
            self.alert(d);
        }
    }

    pub(super) fn start_audits(self: &Arc<Self>) {
        let core = self.clone();
        thread::spawn(move || core.port_audit_loop());
        let core = self.clone();
        thread::spawn(move || core.listener_loop());
        let core = self.clone();
        thread::spawn(move || core.launch_loop());
        let core = self.clone();
        thread::spawn(move || core.integrity_loop());
        let core = self.clone();
        thread::spawn(move || core.cert_loop());
    }

    // ------------------------------------------------------------ port audit

    /// Marks a port audit as running. `false` if one already is.
    fn begin_ports(&self) -> bool {
        let mut st = self.audit.lock().unwrap();
        !std::mem::replace(&mut st.live.ports_running, true)
    }

    fn port_audit_loop(self: &Arc<Self>) {
        // Let the first scan find the devices.
        thread::sleep(Duration::from_secs(90));
        loop {
            let on = self.settings.read().unwrap().port_audit;
            let due = self
                .audit
                .lock()
                .unwrap()
                .ports
                .last_run
                .is_none_or(|t| now_ms().saturating_sub(t) >= rules::PORT_AUDIT_EVERY_MS);
            if on && due && self.port_audit_ready() && self.begin_ports() {
                self.run_port_audit_blocking();
            }
            thread::sleep(TICK);
        }
    }

    /// A scheduled audit waits for the first scan to finish and for someone to check.
    fn port_audit_ready(&self) -> bool {
        !self.scanning.load(Ordering::SeqCst) && self.net.read().unwrap().is_some() && !self.port_audit_targets().is_empty()
    }

    /// "Run audit now".
    pub fn run_port_audit(self: &Arc<Self>) -> Result<(), String> {
        if self.net.read().unwrap().is_none() {
            return Err("Not connected to a network".into());
        }
        if !self.begin_ports() {
            return Err("A port audit is already running.".into());
        }
        let core = self.clone();
        thread::spawn(move || core.run_port_audit_blocking());
        Ok(())
    }

    /// Every online device on the LAN, this computer included.
    fn port_audit_targets(&self) -> Vec<Target> {
        let own = self.net.read().unwrap().as_ref().map(|n| n.ip);
        let listed: Vec<(String, String, String)> = {
            let store = self.store.lock().unwrap();
            store
                .devices
                .values()
                .filter(|d| d.online)
                .map(|d| (d.mac.clone(), describe(d), d.ip.clone()))
                .collect()
        };
        listed
            .into_iter()
            .filter_map(|(mac, name, ip)| {
                let ip: Ipv4Addr = ip.parse().ok()?;
                (self.in_subnet(ip) || Some(ip) == own).then_some(Target { mac, name, ip })
            })
            .collect()
    }

    /// Runs the audit; the caller has already called `begin_ports`.
    fn run_port_audit_blocking(self: &Arc<Self>) {
        self.emit_audit();
        let targets = self.port_audit_targets();
        // At most two devices at a time; each check already opens its ports in parallel.
        let results = rules::run_pool(&targets, PORT_AUDIT_WORKERS, |t| discovery::check_ports(t.ip));
        // If the network went away mid-audit every device looks closed, and
        // recording that would turn the next audit into a false alarm.
        if crate::net::default_net().is_err() {
            self.audit.lock().unwrap().live.ports_running = false;
            self.emit_audit();
            return;
        }
        let now = now_ms();
        let scans: Vec<DeviceScan> = targets
            .iter()
            .zip(results)
            .map(|(t, open)| DeviceScan {
                mac: t.mac.clone(),
                name: t.name.clone(),
                ip: t.ip.to_string(),
                open,
            })
            .collect();
        let outcome = {
            let mut st = self.audit.lock().unwrap();
            let outcome = rules::apply_port_scan(&mut st.ports, scans.clone(), now);
            st.live.ports_running = false;
            self.save_audit(&st);
            outcome
        };
        // Keep the device drawers in step with what the audit found.
        {
            let mut store = self.store.lock().unwrap();
            for s in &scans {
                if let Some(d) = store.devices.get_mut(&s.mac) {
                    d.open_ports = Some(s.open.clone());
                    d.ports_checked_at = Some(now);
                }
            }
            store.save();
        }
        self.emit_devices();
        for (dev, port) in &outcome.opened {
            self.alert(rules::port_alert(dev, *port));
        }
        self.alert(rules::port_summary_alert(&outcome));
        self.emit_audit();
    }

    // ------------------------------------------------------------ listening apps

    fn listener_loop(self: &Arc<Self>) {
        thread::sleep(Duration::from_secs(20));
        loop {
            if self.settings.read().unwrap().listener_watch {
                self.check_listeners();
            }
            thread::sleep(TICK);
        }
    }

    fn check_listeners(&self) {
        let list = {
            let names = self.dns_names.read().unwrap();
            let bl = self.blocklist.read().unwrap();
            conns::list(&mut self.sys.lock().unwrap(), &names, &bl)
        };
        let Ok(list) = list else { return };
        let now_set: BTreeSet<Listener> = rules::listeners_from(&list);
        let (fresh, changed) = {
            let mut st = self.audit.lock().unwrap();
            let before = (st.listeners.baseline_at, st.listeners.known.len());
            let fresh = rules::update_listeners(&mut st.listeners, &now_set, now_ms());
            let saved = before != (st.listeners.baseline_at, st.listeners.known.len());
            let shown = st.live.listening != now_set;
            st.live.listening = now_set;
            if saved {
                self.save_audit(&st);
            }
            (fresh, saved || shown)
        };
        for l in &fresh {
            self.alert(rules::listener_alert(l));
        }
        if changed {
            self.emit_audit();
        }
    }

    // ------------------------------------------------------------ startup items

    fn launch_loop(self: &Arc<Self>) {
        if !cfg!(target_os = "macos") {
            return;
        }
        thread::sleep(Duration::from_secs(15));
        // plutil only runs again for plists that changed.
        let mut cache: HashMap<PathBuf, (u64, Option<rules::LaunchParsed>)> = HashMap::new();
        loop {
            if self.settings.read().unwrap().launch_watch {
                self.check_launch_items(&mut cache);
            }
            thread::sleep(LAUNCH_INTERVAL);
        }
    }

    fn check_launch_items(&self, cache: &mut HashMap<PathBuf, (u64, Option<rules::LaunchParsed>)>) {
        let dirs = rules::launch_dirs();
        let scanned = rules::scan_launch_items(&dirs, &mut |p: &Path| {
            let stamp = mtime_ms(p);
            if let (Some(t), Some((cached_t, parsed))) = (stamp, cache.get(p)) {
                if *cached_t == t {
                    return parsed.clone();
                }
            }
            let parsed = rules::read_launch_plist(p);
            if let Some(t) = stamp {
                cache.insert(p.to_path_buf(), (t, parsed.clone()));
            }
            parsed
        });
        // Only this loop changes the launch state, so work on a copy and the
        // lock isn't held while `codesign` runs for new items.
        let mut audit: LaunchAudit = self.audit.lock().unwrap().launch.clone();
        let findings = rules::update_launch(&mut audit, &scanned, now_ms(), &mut |p| rules::codesign_ok(p));
        {
            let mut st = self.audit.lock().unwrap();
            st.launch = audit;
            self.save_audit(&st);
        }
        for f in &findings {
            self.alert(rules::launch_alert(f));
        }
        self.emit_audit();
    }

    // ------------------------------------------------------------ DNS, DHCP and Wi-Fi look-alikes

    fn integrity_loop(self: &Arc<Self>) {
        thread::sleep(Duration::from_secs(25));
        loop {
            let (dns_on, twin_on) = {
                let s = self.settings.read().unwrap();
                (s.dns_watch, s.evil_twin_watch)
            };
            let mut changed = false;
            if dns_on {
                changed |= self.check_dns_dhcp();
            }
            if twin_on {
                changed |= self.check_wifi_lookalikes();
            }
            if changed {
                self.emit_audit();
            }
            thread::sleep(TICK);
        }
    }

    /// Returns whether anything worth redrawing changed.
    fn check_dns_dhcp(&self) -> bool {
        let Some(net) = self.net.read().unwrap().clone() else { return false };
        // One baseline per network, keyed by the router. Over a VPN the DNS
        // servers legitimately differ, and there's no router to key on.
        let Some(gateway_mac) = net.gateway_mac.clone() else { return false };
        if crate::tools::vpn_status().active {
            return false;
        }
        let dns: Vec<String> = net.dns_servers.iter().map(|d| d.to_string()).collect();
        let dhcp = net.lease.as_ref().and_then(|l| l.server.clone());
        let sig = |w: &rules::NetworkWatch| {
            w.networks
                .get(&gateway_mac)
                .map(|r| (r.dns_seen.clone(), r.dns_now.clone(), r.dhcp_last.clone()))
        };
        let (findings, changed) = {
            let mut st = self.audit.lock().unwrap();
            let before = sig(&st.network);
            let findings = rules::update_network(&mut st.network, &gateway_mac, net.gateway_ip.map(|g| g.to_string()), &dns, dhcp.as_deref(), now_ms());
            let changed = before != sig(&st.network);
            if changed {
                self.save_audit(&st);
            }
            (findings, changed)
        };
        for f in &findings {
            self.alert(rules::network_alert(&gateway_mac, f));
        }
        changed
    }

    fn check_wifi_lookalikes(&self) -> bool {
        let Some(wifi) = self.mon.lock().unwrap().wifi.clone() else { return false };
        let seen_count = |w: &rules::WifiAudit| w.seen.values().map(|m| m.len()).sum::<usize>();
        let (drafts, changed) = {
            let mut st = self.audit.lock().unwrap();
            let before = seen_count(&st.wifi);
            let (mut view, drafts) = rules::check_evil_twin(&wifi, &mut st.wifi, now_ms());
            let mut changed = st.live.wifi.as_ref().is_none_or(|prev| {
                view.checked_at = prev.checked_at;
                *prev != view
            });
            if changed {
                view.checked_at = now_ms();
            }
            st.live.wifi = Some(view);
            if before != seen_count(&st.wifi) {
                self.save_audit(&st);
                changed = true;
            }
            (drafts, changed)
        };
        for d in drafts {
            self.alert_once(d);
        }
        changed
    }

    // ------------------------------------------------------------ certificates

    /// Marks a certificate check as running. `false` if one already is.
    fn begin_certs(&self) -> bool {
        let mut st = self.audit.lock().unwrap();
        !std::mem::replace(&mut st.live.certs_running, true)
    }

    fn cert_loop(self: &Arc<Self>) {
        thread::sleep(Duration::from_secs(40));
        loop {
            if self.settings.read().unwrap().cert_checks {
                let now = now_ms();
                let watched = self.cert_targets();
                let (certs_due, intercept_due) = {
                    let st = self.audit.lock().unwrap();
                    let certs_due = st.certs.last_run.is_none_or(|t| now.saturating_sub(t) >= rules::CERT_CHECK_EVERY_MS)
                        || watched.iter().any(|(t, _, _)| !st.certs.entries.iter().any(|e| &e.target == t));
                    let intercept_due = st.certs.intercept.as_ref().is_none_or(|i| {
                        let age = now.saturating_sub(i.checked_at);
                        age >= rules::INTERCEPT_EVERY_MS || (i.verdict == "offline" && age >= INTERCEPT_RETRY_MS)
                    });
                    (certs_due, intercept_due)
                };
                if (certs_due || intercept_due) && self.begin_certs() {
                    self.run_cert_checks_blocking(certs_due, intercept_due);
                }
            }
            thread::sleep(TICK);
        }
    }

    /// "Check now": certificates and the interception check.
    pub fn run_cert_check(self: &Arc<Self>) -> Result<(), String> {
        if !self.begin_certs() {
            return Err("A certificate check is already running.".into());
        }
        let core = self.clone();
        thread::spawn(move || core.run_cert_checks_blocking(true, true));
        Ok(())
    }

    /// Watched hostnames as (entry as typed, host, port). IP addresses are left out.
    fn cert_targets(&self) -> Vec<(String, String, u16)> {
        self.settings
            .read()
            .unwrap()
            .watch_hosts
            .iter()
            .filter_map(|t| certs::cert_target(t).map(|(h, p)| (t.clone(), h, p)))
            .collect()
    }

    /// Runs the checks; the caller has already called `begin_certs`.
    fn run_cert_checks_blocking(self: &Arc<Self>, check_certs: bool, check_intercept: bool) {
        self.emit_audit();
        if check_certs {
            self.check_certificates();
        }
        if check_intercept {
            self.check_interception();
        }
        {
            let mut st = self.audit.lock().unwrap();
            st.live.certs_running = false;
            self.save_audit(&st);
        }
        self.emit_audit();
    }

    fn check_certificates(&self) {
        let targets = self.cert_targets();
        // Each site gets its own thread: lookups and handshakes can be slow.
        let handles: Vec<_> = targets
            .iter()
            .cloned()
            .map(|(entry, host, port)| thread::spawn(move || (entry, certs::handshake(&host, port))))
            .collect();
        let results: Vec<(String, Handshake)> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
        let now = now_ms();
        let mut drafts = Vec::new();
        {
            let mut st = self.audit.lock().unwrap();
            let mut entries = Vec::new();
            for (target, outcome) in results {
                let mut entry = st
                    .certs
                    .entries
                    .iter()
                    .find(|e| e.target == target)
                    .cloned()
                    .unwrap_or_else(|| CertEntry {
                        target: target.clone(),
                        ..Default::default()
                    });
                entry.checked_at = now;
                match outcome {
                    Handshake::Trusted(info) => {
                        drafts.extend(certs::cert_findings(&target, entry.info.as_ref(), &info, None, now));
                        rules::record_cert_change(&mut entry, &info, now);
                        entry.info = Some(info);
                        entry.untrusted = None;
                        entry.error = None;
                    }
                    Handshake::Untrusted { info, failure } => {
                        drafts.extend(certs::cert_findings(&target, entry.info.as_ref(), &info, Some(&failure), now));
                        rules::record_cert_change(&mut entry, &info, now);
                        entry.info = Some(info);
                        entry.untrusted = Some(failure.describe());
                        entry.error = None;
                    }
                    // No certificate to judge: say so, and keep what we knew.
                    Handshake::NoTls(why) | Handshake::Unreachable(why) => {
                        entry.error = Some(why);
                        entry.untrusted = None;
                    }
                }
                entries.push(entry);
            }
            st.certs.entries = entries;
            st.certs.last_run = Some(now);
            self.save_audit(&st);
        }
        for f in drafts {
            self.alert_once(f.draft);
        }
    }

    fn check_interception(&self) {
        let handles: Vec<_> = certs::INTERCEPT_HOSTS
            .iter()
            .map(|h| thread::spawn(move || certs::probe(h)))
            .collect();
        let probes: Vec<certs::Probe> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
        let verdict = certs::intercept_verdict(&probes);
        let draft = (verdict == certs::Verdict::Intercepted)
            .then(|| certs::intercept_alert(&Local::now().format("%Y-%m-%d").to_string(), &probes));
        {
            let mut st = self.audit.lock().unwrap();
            st.certs.intercept = Some(InterceptCheck {
                checked_at: now_ms(),
                verdict: verdict.as_str().to_string(),
                probes,
            });
            self.save_audit(&st);
        }
        if let Some(d) = draft {
            self.alert_once(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{DeviceScan, LaunchParsed, ScannedItem};
    use crate::certs::{CertInfo, Probe};
    use crate::wifi::{Network, WifiInfo};

    /// The page reads these field names; this pins the JSON shape of the
    /// `audit` event and snapshot. Set NETWATCH_DUMP_AUDIT_JSON=path to write a sample.
    #[test]
    fn snapshot_json_has_the_shape_the_page_reads() {
        let mut st = AuditState::default();
        let scan = |mac: &str, open: &[u16]| DeviceScan { mac: mac.into(), name: format!("Device {mac}"), ip: "192.168.0.7".into(), open: open.to_vec() };
        rules::apply_port_scan(&mut st.ports, vec![scan("aa", &[22, 80]), scan("bb", &[])], 1_000);
        rules::apply_port_scan(&mut st.ports, vec![scan("aa", &[22, 23]), scan("bb", &[])], 2_000);

        let now: BTreeSet<Listener> = BTreeSet::from([Listener { process: "ControlCenter".into(), port: 7000 }]);
        rules::update_listeners(&mut st.listeners, &now, 10);
        let more: BTreeSet<Listener> = BTreeSet::from([Listener { process: "ControlCenter".into(), port: 7000 }, Listener { process: "python3".into(), port: 8000 }]);
        rules::update_listeners(&mut st.listeners, &more, 20);
        st.live.listening = more;

        let item = |label: &str, program: &str| ScannedItem {
            path: format!("/Users/x/Library/LaunchAgents/{label}.plist"),
            scope: "your login items",
            parsed: LaunchParsed { label: label.into(), program: Some(program.into()), args: vec![], run_at_load: true },
        };
        rules::update_launch(&mut st.launch, &[item("com.a", "/Applications/A.app/a")], 10, &mut |_| Some(true));
        rules::update_launch(&mut st.launch, &[item("com.a", "/Applications/A.app/a"), item("com.b", "/tmp/b")], 20, &mut |_| Some(false));

        rules::update_network(&mut st.network, "aa:bb:cc:dd:ee:ff", Some("192.168.0.1".into()), &["192.168.0.1".to_string()], Some("192.168.0.1"), 5);

        let net = |ssid: &str, ch: u32, band: &str, sec: &str| Network { ssid: Some(ssid.into()), channel: Some(ch), band: Some(band.into()), security: Some(sec.into()), rssi: Some(-55), ..Default::default() };
        let w = WifiInfo { interface: "en0".into(), current: net("Home", 36, "5 GHz", "WPA2 Personal"), nearby: vec![net("Home", 6, "2.4 GHz", "Open (no password)")], ..Default::default() };
        let (view, _) = rules::check_evil_twin(&w, &mut st.wifi, 30);
        st.live.wifi = Some(view);

        st.certs.entries.push(CertEntry {
            target: "example.com".into(),
            checked_at: 40,
            info: Some(CertInfo { subject: "example.com".into(), issuer: "Let's Encrypt (R11)".into(), issuer_org: "Let's Encrypt".into(), not_before: 1, not_after: 4_000_000_000_000, fingerprint: "abcd".into() }),
            ..Default::default()
        });
        st.certs.last_run = Some(40);
        st.certs.intercept = Some(InterceptCheck {
            checked_at: 41,
            verdict: "ok".into(),
            probes: vec![Probe { host: "www.apple.com".into(), reachable: true, verified: true, ..Default::default() }],
        });

        let snap = AuditSnapshot { ports_next: st.ports.last_run.map(|t| t + rules::PORT_AUDIT_EVERY_MS), certs_next: Some(1), state: st };
        let v = serde_json::to_value(&snap).unwrap();
        assert_eq!(v["ports"]["devices"]["aa"]["opened"][0], 23);
        assert_eq!(v["ports"]["devices"]["aa"]["closed"][0], 80);
        assert_eq!(v["ports"]["runs"].as_array().unwrap().len(), 2);
        assert_eq!(v["ports_next"], 2_000 + rules::PORT_AUDIT_EVERY_MS);
        assert_eq!(v["listeners"]["known"]["python3:8000"]["new"], true);
        assert_eq!(v["live"]["listening"][1]["process"], "python3");
        assert_eq!(v["launch"]["items"][1]["risk"].as_str().is_some(), true);
        assert_eq!(v["launch"]["items"][1]["new"], true);
        assert_eq!(v["network"]["networks"]["aa:bb:cc:dd:ee:ff"]["dns_now"][0], "192.168.0.1");
        assert_eq!(v["live"]["wifi"]["names_visible"], true);
        assert_eq!(v["live"]["wifi"]["aps"][1]["flag"], "weaker");
        assert_eq!(v["certs"]["entries"][0]["info"]["issuer"], "Let's Encrypt (R11)");
        assert_eq!(v["certs"]["intercept"]["verdict"], "ok");
        assert_eq!(v["live"]["ports_running"], false);
        if let Ok(path) = std::env::var("NETWATCH_DUMP_AUDIT_JSON") {
            std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        }
    }
}

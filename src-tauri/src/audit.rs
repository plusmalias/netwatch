//! Defensive audits of this network and this computer: the weekly port audit,
//! new listening apps, startup items, DNS/DHCP changes and look-alike Wi-Fi
//! networks. This module holds the saved state and every rule as plain
//! functions over plain data, so each one is testable; `core/audit.rs` runs
//! them on a schedule. Everything here only looks at the user's own network
//! and computer.

use crate::alerts::{AlertDraft, Severity};
use crate::certs::{CertInfo, Probe};
use crate::conns::Conn;
use crate::wifi::{normalize_bssid, Network, WifiInfo};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const PORT_AUDIT_EVERY_MS: u64 = 7 * 24 * 3_600_000;
pub const CERT_CHECK_EVERY_MS: u64 = 6 * 3_600_000;
pub const INTERCEPT_EVERY_MS: u64 = 24 * 3_600_000;
const MAX_PORT_RUNS: usize = 12;
const MAX_DEVICES: usize = 300;
const MAX_LISTENERS: usize = 1000;
const MAX_NETWORKS: usize = 50;
const MAX_SSIDS: usize = 50;
const MAX_CERT_CHANGES: usize = 10;

/// Everything the audits remember, saved as `audit.json` in the data folder.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AuditState {
    pub ports: PortAudit,
    pub listeners: ListenerAudit,
    pub launch: LaunchAudit,
    pub network: NetworkWatch,
    pub wifi: WifiAudit,
    pub certs: CertAudit,
    /// Not saved: what is happening right now.
    #[serde(skip_deserializing)]
    pub live: Live,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Live {
    pub ports_running: bool,
    pub certs_running: bool,
    /// Apps listening at the last look.
    pub listening: BTreeSet<Listener>,
    /// The Wi-Fi look-alike check at its last look.
    pub wifi: Option<WifiView>,
}

// ------------------------------------------------------------ ports

/// Port number → what it usually is, for alert text.
pub fn port_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        139 => "NetBIOS",
        443 => "HTTPS",
        445 => "SMB file sharing",
        548 => "AFP file sharing",
        554 => "RTSP video",
        631 => "printing",
        1883 => "MQTT",
        3389 => "Remote Desktop",
        5000 => "UPnP/HTTP",
        5900 => "VNC screen sharing",
        7000 => "AirPlay",
        8008 => "HTTP alt",
        8009 => "Cast",
        8080 => "HTTP proxy",
        8443 => "HTTPS alt",
        8883 => "MQTT TLS",
        9100 => "printing",
        32400 => "Plex",
        49152 => "UPnP",
        62078 => "iOS sync",
        _ => "",
    }
}

/// Remote-access and file-transfer services that are often unencrypted or
/// weakly protected.
pub fn is_risky_port(port: u16) -> bool {
    matches!(port, 21 | 23 | 3389 | 5900)
}

pub fn port_severity(port: u16) -> Severity {
    if is_risky_port(port) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PortDiff {
    /// No earlier result: this one becomes the baseline.
    pub baseline: bool,
    pub opened: Vec<u16>,
    pub closed: Vec<u16>,
}

/// Compares a device's open ports with its previous result. The first result
/// for a device is a baseline and reports no changes.
pub fn diff_ports(prev: Option<&[u16]>, now: &[u16]) -> PortDiff {
    let Some(prev) = prev else {
        return PortDiff { baseline: true, opened: vec![], closed: vec![] };
    };
    let (a, b): (BTreeSet<u16>, BTreeSet<u16>) = (prev.iter().copied().collect(), now.iter().copied().collect());
    PortDiff {
        baseline: false,
        opened: b.difference(&a).copied().collect(),
        closed: a.difference(&b).copied().collect(),
    }
}

/// One device's result in the weekly audit.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct DevicePorts {
    pub mac: String,
    pub name: String,
    pub ip: String,
    pub open: Vec<u16>,
    /// Ports that appeared since the previous audit of this device.
    pub opened: Vec<u16>,
    pub closed: Vec<u16>,
    /// This was the device's first audit, so it is the baseline.
    pub baseline: bool,
    pub checked_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct PortRun {
    pub ts: u64,
    pub devices: usize,
    /// Ports that newly opened, and ports that closed, across all devices.
    pub opened: usize,
    pub closed: usize,
}

impl PortRun {
    pub fn changes(&self) -> usize {
        self.opened + self.closed
    }

    /// "Port audit: 7 devices checked, 1 change"
    pub fn summary(&self) -> String {
        let n = self.changes();
        format!(
            "Port audit: {} device{} checked, {} change{}",
            self.devices,
            if self.devices == 1 { "" } else { "s" },
            n,
            if n == 1 { "" } else { "s" }
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct PortAudit {
    pub last_run: Option<u64>,
    pub devices: BTreeMap<String, DevicePorts>,
    /// The last 12 runs, oldest first.
    pub runs: Vec<PortRun>,
}

/// A device to audit: its MAC (the key), name for alerts, and address.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceScan {
    pub mac: String,
    pub name: String,
    pub ip: String,
    pub open: Vec<u16>,
}

#[derive(Debug, PartialEq)]
pub struct PortOutcome {
    pub run: PortRun,
    /// (device, port) pairs that newly opened.
    pub opened: Vec<(DeviceScan, u16)>,
}

/// Folds a finished run into the saved state.
pub fn apply_port_scan(audit: &mut PortAudit, scans: Vec<DeviceScan>, now: u64) -> PortOutcome {
    let mut run = PortRun {
        ts: now,
        devices: scans.len(),
        ..Default::default()
    };
    let mut opened = Vec::new();
    for mut s in scans {
        s.open.sort_unstable();
        s.open.dedup();
        let diff = diff_ports(audit.devices.get(&s.mac).map(|d| d.open.as_slice()), &s.open);
        run.opened += diff.opened.len();
        run.closed += diff.closed.len();
        opened.extend(diff.opened.iter().map(|p| (s.clone(), *p)));
        audit.devices.insert(
            s.mac.clone(),
            DevicePorts {
                mac: s.mac,
                name: s.name,
                ip: s.ip,
                open: s.open,
                opened: diff.opened,
                closed: diff.closed,
                baseline: diff.baseline,
                checked_at: now,
            },
        );
    }
    while audit.devices.len() > MAX_DEVICES {
        let oldest = audit.devices.values().min_by_key(|d| d.checked_at).map(|d| d.mac.clone());
        match oldest {
            Some(m) => audit.devices.remove(&m),
            None => break,
        };
    }
    audit.last_run = Some(now);
    audit.runs.push(run.clone());
    if audit.runs.len() > MAX_PORT_RUNS {
        let excess = audit.runs.len() - MAX_PORT_RUNS;
        audit.runs.drain(..excess);
    }
    PortOutcome { run, opened }
}

pub fn port_alert(dev: &DeviceScan, port: u16) -> AlertDraft {
    let name = &dev.name;
    let what = match port_name(port) {
        "" => format!("port {port}"),
        n => format!("port {port} ({n})"),
    };
    let advice = if is_risky_port(port) {
        "Remote-access and file-transfer services like this are often unencrypted or weakly protected. Turn it off if you don't use it."
    } else {
        "If you didn't expect this, check what the device is running or whether it was just set up."
    };
    AlertDraft {
        severity: port_severity(port),
        kind: "port_audit",
        key: format!("{}:{port}", dev.mac),
        title: format!("New open port on {name}: {port}"),
        detail: format!("{name} ({}) now accepts connections on {what}; it was closed at the previous port audit. {advice}", dev.ip),
    }
}

pub fn port_summary_alert(outcome: &PortOutcome) -> AlertDraft {
    let run = &outcome.run;
    let mut bits = Vec::new();
    if run.opened > 0 {
        bits.push(format!("{} port{} newly opened", run.opened, if run.opened == 1 { "" } else { "s" }));
    }
    if run.closed > 0 {
        bits.push(format!("{} port{} closed", run.closed, if run.closed == 1 { "" } else { "s" }));
    }
    AlertDraft {
        severity: Severity::Info,
        kind: "port_audit_summary",
        key: run.ts.to_string(),
        title: run.summary(),
        detail: if bits.is_empty() {
            "Every device has the same open ports as at the previous audit (or this was its first look).".into()
        } else {
            format!("{}.", bits.join(", "))
        },
    }
}

/// Runs `f` over `items` on at most `workers` threads at once, keeping order.
pub fn run_pool<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: std::sync::Mutex<Vec<Option<R>>> = std::sync::Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1).min(items.len().max(1)) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(item) = items.get(i) else { break };
                let r = f(item);
                results.lock().unwrap()[i] = Some(r);
            });
        }
    });
    results.into_inner().unwrap().into_iter().flatten().collect()
}

// ------------------------------------------------------------ listening apps

/// An app accepting connections on a port.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    pub process: String,
    pub port: u16,
}

impl Listener {
    fn key(&self) -> String {
        format!("{}:{}", self.process, self.port)
    }
}

/// The (app, port) pairs listening for TCP connections on a non-loopback
/// address, IPv4 and IPv6 merged. Like the Security checkup's own list.
pub fn listeners_from(conns: &[Conn]) -> BTreeSet<Listener> {
    conns
        .iter()
        .filter(|c| c.proto == "TCP" && c.state == "Listen")
        .filter(|c| c.local_ip.parse::<std::net::IpAddr>().is_ok_and(|ip| !ip.is_loopback()))
        .map(|c| Listener {
            process: c.process.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "unknown".into()),
            port: c.local_port,
        })
        .collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KnownListener {
    pub process: String,
    pub port: u16,
    pub first_seen: u64,
    /// Appeared after the baseline was taken.
    pub new: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ListenerAudit {
    /// When the baseline was taken; `None` until the first look.
    pub baseline_at: Option<u64>,
    /// Everything ever seen listening (so an app that toggles a port, or
    /// restarts, doesn't alert twice).
    pub known: BTreeMap<String, KnownListener>,
}

/// Updates the known set from what's listening now and returns the pairs that
/// are new since the baseline. The first call takes the baseline and returns none.
pub fn update_listeners(audit: &mut ListenerAudit, now_set: &BTreeSet<Listener>, now: u64) -> Vec<Listener> {
    let baseline = audit.baseline_at.is_none();
    // Apps like Spotify or Zoom pick a new random port each launch, so only an
    // app that has never listened before alerts; new ports are just recorded.
    let mut known_apps: BTreeSet<String> = audit.known.values().map(|k| k.process.clone()).collect();
    let mut fresh = Vec::new();
    for l in now_set {
        if audit.known.contains_key(&l.key()) {
            continue;
        }
        audit.known.insert(
            l.key(),
            KnownListener {
                process: l.process.clone(),
                port: l.port,
                first_seen: now,
                new: !baseline,
            },
        );
        if !baseline && known_apps.insert(l.process.clone()) {
            fresh.push(l.clone());
        }
    }
    audit.baseline_at.get_or_insert(now);
    while audit.known.len() > MAX_LISTENERS {
        let oldest = audit.known.iter().min_by_key(|(_, k)| (k.new, k.first_seen)).map(|(k, _)| k.clone());
        match oldest {
            Some(k) => audit.known.remove(&k),
            None => break,
        };
    }
    fresh
}

pub fn listener_alert(l: &Listener) -> AlertDraft {
    AlertDraft {
        severity: Severity::Low,
        kind: "new_listener",
        key: l.process.clone(),
        title: format!("{} started accepting connections (port {})", l.process, l.port),
        detail: format!(
            "{} is now listening on port {}, so other devices on your network can try to connect to it. That's normal for sharing, media and developer apps. If you didn't expect it, quit the app, or turn on the firewall in System Settings → Network.",
            l.process, l.port
        ),
    }
}

// ------------------------------------------------------------ startup items

/// What a launchd plist says about what it runs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct LaunchParsed {
    pub label: String,
    pub program: Option<String>,
    pub args: Vec<String>,
    pub run_at_load: bool,
}

/// Reads `plutil -convert json` output for a launch plist.
pub fn parse_launch_json(json: &str, fallback_label: &str) -> Option<LaunchParsed> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = v.as_object()?;
    let strings = |k: &str| -> Vec<String> {
        obj.get(k)
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let argv = strings("ProgramArguments");
    let program = obj
        .get("Program")
        .and_then(|p| p.as_str())
        .map(String::from)
        .or_else(|| argv.first().cloned())
        .filter(|p| !p.is_empty());
    Some(LaunchParsed {
        label: obj
            .get("Label")
            .and_then(|l| l.as_str())
            .filter(|l| !l.is_empty())
            .unwrap_or(fallback_label)
            .to_string(),
        program,
        args: argv.into_iter().skip(1).collect(),
        run_at_load: obj.get("RunAtLoad").and_then(|r| r.as_bool()).unwrap_or(false),
    })
}

/// Places a program shouldn't normally run from: temporary folders, the
/// shared folder every user can write to, or a hidden directory.
pub fn risky_location(path: &str) -> Option<&'static str> {
    const TEMP: [&str; 5] = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/Users/Shared"];
    if TEMP.iter().any(|t| path == *t || path.strip_prefix(t).is_some_and(|r| r.starts_with('/'))) {
        return Some(if path.starts_with("/Users/Shared") {
            "runs from the shared folder every user can write to"
        } else {
            "runs from a temporary folder"
        });
    }
    Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::Normal(n) if n.to_string_lossy().starts_with('.')))
        .then_some("runs from a hidden folder")
}

/// Why a startup item looks risky: where its program (or an absolute path it
/// is given, as in `/bin/sh /tmp/x.sh`) lives, or a failed signature check.
/// `signed` is `Some(false)` when `codesign -v` rejected the program.
pub fn launch_risk(item: &LaunchParsed, signed: Option<bool>) -> Option<String> {
    let paths = item.program.iter().chain(item.args.iter().filter(|a| a.starts_with('/')));
    for p in paths {
        if let Some(why) = risky_location(p) {
            return Some(format!("{why} ({p})"));
        }
    }
    (signed == Some(false)).then(|| "has a missing or invalid code signature".to_string())
}

/// A launch plist found on disk.
#[derive(Clone, Debug, PartialEq)]
pub struct ScannedItem {
    pub path: String,
    /// "your login items", "all users' login items" or "system service".
    pub scope: &'static str,
    pub parsed: LaunchParsed,
}

pub struct LaunchDir {
    pub dir: PathBuf,
    pub scope: &'static str,
}

/// NetWatch's own "open at login" agent, which is not a finding.
pub const OWN_PLIST: &str = "NetWatch.plist";

/// Lists the plists in `dirs`. `read` turns a plist into its contents
/// (`plutil` in the app); unreadable ones are skipped.
pub fn scan_launch_items(dirs: &[LaunchDir], read: &mut dyn FnMut(&Path) -> Option<LaunchParsed>) -> Vec<ScannedItem> {
    let mut out = Vec::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d.dir) else { continue };
        let mut files: Vec<PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name.ends_with(".plist") && !name.starts_with('.') && !name.eq_ignore_ascii_case(OWN_PLIST)
            })
            .collect();
        files.sort();
        for path in files {
            if let Some(parsed) = read(&path) {
                out.push(ScannedItem {
                    path: path.display().to_string(),
                    scope: d.scope,
                    parsed,
                });
            }
        }
    }
    out
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KnownLaunch {
    pub first_seen: u64,
    pub new: bool,
    /// `codesign -v` result for items that appeared after the baseline.
    pub signed: Option<bool>,
}

/// A startup item as the page shows it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct LaunchItem {
    pub label: String,
    pub path: String,
    pub program: Option<String>,
    pub run_at_load: bool,
    pub scope: String,
    pub new: bool,
    pub first_seen: u64,
    /// Why it looks risky, if it does.
    pub risk: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct LaunchAudit {
    pub baseline_at: Option<u64>,
    /// Everything ever seen, by label (or file name).
    pub known: BTreeMap<String, KnownLaunch>,
    /// The last scan.
    pub items: Vec<LaunchItem>,
    pub scanned_at: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct LaunchFinding {
    pub item: LaunchItem,
}

/// Folds a scan into the saved state and returns the items that are new since
/// the baseline. `signer` runs `codesign -v` and is only asked about those.
pub fn update_launch(audit: &mut LaunchAudit, scanned: &[ScannedItem], now: u64, signer: &mut dyn FnMut(&str) -> Option<bool>) -> Vec<LaunchFinding> {
    let baseline = audit.baseline_at.is_none();
    let mut findings = Vec::new();
    let mut items = Vec::new();
    for s in scanned {
        let key = s.parsed.label.clone();
        let is_new = !audit.known.contains_key(&key);
        if is_new {
            let signed = if baseline { None } else { s.parsed.program.as_deref().and_then(|p| signer(p)) };
            audit.known.insert(
                key.clone(),
                KnownLaunch {
                    first_seen: now,
                    new: !baseline,
                    signed,
                },
            );
        }
        let known = &audit.known[&key];
        let item = LaunchItem {
            label: s.parsed.label.clone(),
            path: s.path.clone(),
            program: s.parsed.program.clone(),
            run_at_load: s.parsed.run_at_load,
            scope: s.scope.to_string(),
            new: known.new,
            first_seen: known.first_seen,
            risk: launch_risk(&s.parsed, known.signed),
        };
        if is_new && !baseline {
            findings.push(LaunchFinding { item: item.clone() });
        }
        items.push(item);
    }
    audit.items = items;
    audit.scanned_at = Some(now);
    audit.baseline_at.get_or_insert(now);
    findings
}

pub fn launch_alert(f: &LaunchFinding) -> AlertDraft {
    let i = &f.item;
    let program = i.program.as_deref().unwrap_or("an unknown program");
    let risk = i.risk.as_ref().map(|r| format!(" Warning: it {r}.")).unwrap_or_default();
    AlertDraft {
        severity: if i.risk.is_some() { Severity::High } else { Severity::Medium },
        kind: "launch_item",
        key: i.path.clone(),
        title: format!("New startup item: {}", i.label),
        detail: format!(
            "{} was added to {} and will run {program}{}.{risk} Malware often installs itself this way to survive a restart. If you didn't just install something that does this, remove it ({}) and run a malware scan.",
            i.label,
            i.scope,
            if i.run_at_load { " every time you log in or start up" } else { " when launchd decides to" },
            i.path
        ),
    }
}

/// Reads a launch plist with `plutil`, which also handles binary plists.
#[cfg(target_os = "macos")]
pub fn read_launch_plist(path: &Path) -> Option<LaunchParsed> {
    let out = crate::util::quiet_command("plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let stem = path.file_stem()?.to_str()?;
    parse_launch_json(&String::from_utf8_lossy(&out.stdout), stem)
}

#[cfg(not(target_os = "macos"))]
pub fn read_launch_plist(_path: &Path) -> Option<LaunchParsed> {
    None
}

/// `codesign -v`: whether `program` has a valid code signature. `None` when
/// it can't be judged (the file is missing, or this isn't macOS).
#[cfg(target_os = "macos")]
pub fn codesign_ok(program: &str) -> Option<bool> {
    if !Path::new(program).exists() {
        return None;
    }
    let out = crate::util::quiet_command("codesign").args(["-v", program]).output().ok()?;
    Some(out.status.success())
}

#[cfg(not(target_os = "macos"))]
pub fn codesign_ok(_program: &str) -> Option<bool> {
    None
}

/// The folders macOS runs startup items from.
pub fn launch_dirs() -> Vec<LaunchDir> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(LaunchDir {
            dir: PathBuf::from(home).join("Library/LaunchAgents"),
            scope: "your login items",
        });
    }
    dirs.push(LaunchDir {
        dir: PathBuf::from("/Library/LaunchAgents"),
        scope: "all users' login items",
    });
    dirs.push(LaunchDir {
        dir: PathBuf::from("/Library/LaunchDaemons"),
        scope: "system services",
    });
    dirs
}

// ------------------------------------------------------------ DNS and DHCP

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct NetworkRecord {
    pub gateway_mac: String,
    pub gateway_ip: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Every DNS server this network has ever handed out.
    pub dns_seen: BTreeSet<String>,
    pub dns_now: Vec<String>,
    /// The DHCP server that answered last time.
    pub dhcp_last: Option<String>,
}

/// One baseline per network, keyed by the router's MAC address.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NetworkWatch {
    pub networks: BTreeMap<String, NetworkRecord>,
}

#[derive(Debug, PartialEq)]
pub enum NetFinding {
    /// DNS servers this network never used before.
    NewDns { added: Vec<String>, previous: Vec<String> },
    DhcpChanged { from: String, to: String },
}

/// Records this network's DNS and DHCP servers and reports what changed.
/// First sight of a network (or of its DNS, if the lease wasn't ready) is a
/// baseline. DNS counts as changed only when a server appears that this
/// network never used; DHCP when it differs from last time.
pub fn update_network(watch: &mut NetworkWatch, gateway_mac: &str, gateway_ip: Option<String>, dns: &[String], dhcp: Option<&str>, now: u64) -> Vec<NetFinding> {
    let rec = watch.networks.entry(gateway_mac.to_string()).or_insert_with(|| NetworkRecord {
        gateway_mac: gateway_mac.to_string(),
        first_seen: now,
        ..Default::default()
    });
    rec.last_seen = now;
    rec.gateway_ip = gateway_ip.or(rec.gateway_ip.take());
    let mut out = Vec::new();
    let mut dns: Vec<String> = dns.to_vec();
    dns.sort();
    dns.dedup();
    if !dns.is_empty() {
        if !rec.dns_seen.is_empty() {
            let added: Vec<String> = dns.iter().filter(|d| !rec.dns_seen.contains(*d)).cloned().collect();
            if !added.is_empty() {
                out.push(NetFinding::NewDns {
                    added,
                    previous: rec.dns_now.clone(),
                });
            }
        }
        rec.dns_seen.extend(dns.iter().cloned());
        rec.dns_now = dns;
    }
    if let Some(d) = dhcp {
        if let Some(prev) = rec.dhcp_last.as_ref().filter(|p| p.as_str() != d) {
            out.push(NetFinding::DhcpChanged {
                from: prev.clone(),
                to: d.to_string(),
            });
        }
        rec.dhcp_last = Some(d.to_string());
    }
    while watch.networks.len() > MAX_NETWORKS {
        let oldest = watch.networks.values().min_by_key(|n| n.last_seen).map(|n| n.gateway_mac.clone());
        match oldest {
            Some(m) => watch.networks.remove(&m),
            None => break,
        };
    }
    out
}

pub fn network_alert(gateway_mac: &str, f: &NetFinding) -> AlertDraft {
    match f {
        NetFinding::NewDns { added, previous } => AlertDraft {
            severity: Severity::Medium,
            kind: "dns_change",
            key: format!("{gateway_mac}:{}", added.join(",")),
            title: "Your DNS servers changed: possible DNS hijack".into(),
            detail: format!(
                "This computer is now using DNS server{} {}{}. DNS decides where every website name leads, so a changed server can silently send you to fake sites. If you or your internet provider didn't change this, check the DNS settings on your router and in System Settings → Network.",
                if added.len() == 1 { "" } else { "s" },
                added.join(", "),
                if previous.is_empty() { String::new() } else { format!(" (before: {})", previous.join(", ")) }
            ),
        },
        NetFinding::DhcpChanged { from, to } => AlertDraft {
            severity: Severity::Low,
            kind: "dhcp_change",
            key: format!("{gateway_mac}:{to}"),
            title: "A different device is handing out network settings".into(),
            detail: format!(
                "The DHCP server on this network changed from {from} to {to}. That's normal after you swap or reconfigure a router, but a rogue device can use it to point your DNS and gateway somewhere else. If you didn't change anything, look for an unfamiliar device in the Devices list."
            ),
        },
    }
}

// ------------------------------------------------------------ look-alike Wi-Fi

/// How strong a Wi-Fi security mode is, in tiers coarse enough that ordinary
/// mixed-mode setups don't compare as "weaker": a mesh can legitimately offer
/// WPA2/WPA3 on one band and WPA3 on another. `None` when unknown.
pub fn security_tier(label: Option<&str>) -> Option<u8> {
    Some(match label? {
        "Open (no password)" | "Enhanced Open" | "WEP" => 0,
        "WPA Personal" | "WPA/WPA2 Personal" | "WPA Enterprise" => 1,
        "WPA2 Personal" | "WPA2/WPA3 Personal" | "WPA3 Personal" | "WPA2 Enterprise" | "WPA3 Enterprise" => 2,
        _ => return None,
    })
}

/// What tells one access point from another: its BSSID when macOS gives it
/// (CoreWLAN, with Location permission), otherwise its channel and band,
/// "36@5 GHz".
fn ap_key(n: &Network) -> Option<String> {
    if let Some(b) = n.bssid.as_deref().and_then(normalize_bssid) {
        return Some(b);
    }
    Some(format!("{}@{}", n.channel?, n.band.as_deref().unwrap_or("?")))
}

fn is_bssid_key(k: &str) -> bool {
    k.contains(':')
}

/// Most access points remembered for one network name, so a campus or an
/// enterprise network can't grow the file without end.
const MAX_APS_PER_SSID: usize = 64;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ApRecord {
    pub first_seen: u64,
    /// Seen when this network name was first looked at.
    pub baseline: bool,
    /// Where it was when first seen (the key is its BSSID, when there is one).
    pub channel: Option<u32>,
    pub band: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct WifiAudit {
    /// Network name → the access points seen using it, by BSSID or by
    /// channel and band (see `ap_key`).
    pub seen: BTreeMap<String, BTreeMap<String, ApRecord>>,
}

/// An access point with your network's name, for the page.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct ApView {
    /// The one this computer is connected to.
    pub ours: bool,
    pub bssid: Option<String>,
    pub channel: Option<u32>,
    pub band: Option<String>,
    pub security: Option<String>,
    pub rssi: Option<i32>,
    /// "weaker" or "new" (an access point not seen before).
    pub flag: Option<String>,
    pub first_seen: u64,
    pub baseline: bool,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct WifiView {
    /// macOS shows network names only to apps with Location permission.
    pub names_visible: bool,
    pub ssid: Option<String>,
    pub aps: Vec<ApView>,
    pub checked_at: u64,
}

fn bssid_of(n: &Network) -> Option<String> {
    n.bssid.as_deref().and_then(normalize_bssid)
}

/// Notes an access point, unless this name already has the most it keeps.
fn remember(seen: &mut BTreeMap<String, ApRecord>, key: &str, n: &Network, now: u64, baseline: bool) {
    if seen.len() < MAX_APS_PER_SSID && !seen.contains_key(key) {
        seen.insert(key.to_string(), ApRecord { first_seen: now, baseline, channel: n.channel, band: n.band.clone() });
    }
}

/// Looks for other access points using this network's name. One with weaker
/// or no security is High (a classic evil twin), whether or not it was around
/// before. One with the same or better security from a BSSID never seen
/// before (or, without BSSIDs, on a channel or band never seen before) is Low
/// (fine for a mesh or extender). The access point this computer is on is
/// never a look-alike. Needs visible names; without them it reports
/// `names_visible: false` and no findings.
pub fn check_evil_twin(w: &WifiInfo, audit: &mut WifiAudit, now: u64) -> (WifiView, Vec<AlertDraft>) {
    let cur = &w.current;
    let visible = cur.ssid.is_some() && (w.nearby.is_empty() || w.nearby.iter().any(|n| n.ssid.is_some()));
    let mut view = WifiView {
        names_visible: visible,
        ssid: cur.ssid.clone(),
        aps: Vec::new(),
        checked_at: now,
    };
    let (true, Some(ssid)) = (visible, cur.ssid.as_ref()) else {
        return (view, Vec::new());
    };
    let ours_bssid = bssid_of(cur);
    let twins: Vec<&Network> = w
        .nearby
        .iter()
        .filter(|n| n.ssid.as_ref() == Some(ssid))
        .filter(|n| ours_bssid.is_none() || bssid_of(n) != ours_bssid)
        .collect();
    let by_bssid = ours_bssid.is_some() || twins.iter().any(|n| bssid_of(n).is_some());
    let mut alerts = Vec::new();
    // Records made before BSSIDs were available are keyed by channel and band.
    // The first look with BSSIDs starts a new baseline, so upgrading doesn't
    // flag every access point of an existing mesh as new.
    let mut migrating = false;
    if let (true, Some(m)) = (by_bssid, audit.seen.get_mut(ssid)) {
        if !m.is_empty() && m.keys().all(|k| !is_bssid_key(k)) {
            m.clear();
            migrating = true;
        }
    }
    let first_look = !audit.seen.contains_key(ssid) || migrating;
    if first_look && audit.seen.len() >= MAX_SSIDS {
        if let Some(oldest) = audit.seen.iter().min_by_key(|(_, m)| m.values().map(|r| r.first_seen).min()).map(|(k, _)| k.clone()) {
            audit.seen.remove(&oldest);
        }
    }
    let seen = audit.seen.entry(ssid.clone()).or_default();
    // Records keyed by BSSID and a scan without BSSIDs (or the reverse) can't
    // be compared: nothing is called new or added then.
    let comparable = seen.is_empty() || seen.keys().any(|k| is_bssid_key(k)) == by_bssid;
    let ours = ap_key(cur);
    if let (true, Some(k)) = (comparable, &ours) {
        remember(seen, k, cur, now, first_look);
    }
    let record = |seen: &BTreeMap<String, ApRecord>, k: &Option<String>| k.as_ref().and_then(|k| seen.get(k)).cloned().unwrap_or_default();
    let r = record(seen, &ours);
    view.aps.push(ApView {
        ours: true,
        bssid: ours_bssid,
        channel: cur.channel,
        band: cur.band.clone(),
        security: cur.security.clone(),
        rssi: cur.rssi,
        flag: None,
        first_seen: r.first_seen,
        baseline: r.baseline,
    });
    for n in twins {
        let key = ap_key(n);
        let weaker = matches!(
            (security_tier(cur.security.as_deref()), security_tier(n.security.as_deref())),
            (Some(mine), Some(theirs)) if theirs < mine
        );
        let unseen = comparable && key.as_ref().is_some_and(|k| !seen.contains_key(k));
        if let (true, Some(k)) = (comparable, &key) {
            remember(seen, k, n, now, first_look);
        }
        let where_ = match (n.channel, n.band.as_deref()) {
            (Some(c), Some(b)) => format!("channel {c} ({b})"),
            (Some(c), None) => format!("channel {c}"),
            _ => "another channel".to_string(),
        };
        let who = bssid_of(n).map(|b| format!(" (address {b})")).unwrap_or_default();
        let sec = n.security.clone().unwrap_or_else(|| "unknown security".into());
        let mine = cur.security.clone().unwrap_or_else(|| "your security setting".into());
        let id = format!("{ssid}|{}|{sec}", key.clone().unwrap_or_default());
        if weaker {
            alerts.push(AlertDraft {
                severity: Severity::High,
                kind: "evil_twin",
                key: id,
                title: format!("Another Wi-Fi network is pretending to be \"{ssid}\""),
                detail: format!(
                    "An access point{who} on {where_} is broadcasting your network's name with {sec}, weaker than your {mine}. Attackers copy a network's name this way (an \"evil twin\") so devices join them and expose their traffic. Don't connect to it. If it's one of your own devices, such as an old router or a guest network, fix its security or give it a different name."
                ),
            });
        } else if unseen && !first_look {
            // On the first look everything is a baseline, so only later arrivals alert.
            alerts.push(AlertDraft {
                severity: Severity::Low,
                kind: "evil_twin",
                key: id,
                title: format!("Another access point is broadcasting \"{ssid}\""),
                detail: format!(
                    "An access point{who} on {where_} is using your network's name, and NetWatch hasn't seen it before. That's fine if you have a mesh system or Wi-Fi extender; if you don't, it could be someone copying your network's name."
                ),
            });
        }
        let r = record(seen, &key);
        let known = key.as_ref().is_some_and(|k| seen.contains_key(k));
        view.aps.push(ApView {
            ours: false,
            bssid: bssid_of(n),
            channel: n.channel,
            band: n.band.clone(),
            security: n.security.clone(),
            rssi: n.rssi,
            // Anything first seen after the baseline stays marked on the page.
            flag: if weaker {
                Some("weaker".to_string())
            } else {
                (known && !r.baseline).then(|| "new".to_string())
            },
            first_seen: r.first_seen,
            baseline: r.baseline,
        });
    }
    (view, alerts)
}

// ------------------------------------------------------------ certificates

/// A renewal or change of a watched site's certificate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct CertChange {
    pub ts: u64,
    pub old_issuer: String,
    pub new_issuer: String,
    pub issuer_changed: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct CertEntry {
    /// As in the watch list: "example.com" or "example.com:8443".
    pub target: String,
    pub checked_at: u64,
    /// The leaf certificate from the last handshake that got one.
    pub info: Option<CertInfo>,
    /// Why the chain didn't verify, in words.
    pub untrusted: Option<String>,
    /// Why the last check couldn't get a certificate at all.
    pub error: Option<String>,
    pub changes: Vec<CertChange>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct InterceptCheck {
    pub checked_at: u64,
    /// "ok", "intercepted", "inconclusive" or "offline".
    pub verdict: String,
    pub probes: Vec<Probe>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct CertAudit {
    pub last_run: Option<u64>,
    pub entries: Vec<CertEntry>,
    pub intercept: Option<InterceptCheck>,
}

/// Records a renewal when the certificate changed, and keeps the last few.
pub fn record_cert_change(entry: &mut CertEntry, new: &CertInfo, now: u64) {
    if let Some(old) = entry.info.as_ref().filter(|o| o.fingerprint != new.fingerprint) {
        entry.changes.push(CertChange {
            ts: now,
            old_issuer: old.issuer.clone(),
            new_issuer: new.issuer.clone(),
            issuer_changed: old.issuer_org != new.issuer_org,
        });
        if entry.changes.len() > MAX_CERT_CHANGES {
            let excess = entry.changes.len() - MAX_CERT_CHANGES;
            entry.changes.drain(..excess);
        }
    }
}

// ------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ports

    #[test]
    fn port_diff_baseline_then_changes() {
        let d = diff_ports(None, &[22, 80]);
        assert_eq!(d, PortDiff { baseline: true, opened: vec![], closed: vec![] });
        let d = diff_ports(Some(&[22, 80]), &[22, 80]);
        assert_eq!(d, PortDiff { baseline: false, opened: vec![], closed: vec![] });
        let d = diff_ports(Some(&[22, 80, 8080]), &[22, 21, 443]);
        assert_eq!(d.opened, vec![21, 443]);
        assert_eq!(d.closed, vec![80, 8080]);
        // An empty previous result is still a baseline that exists.
        assert_eq!(diff_ports(Some(&[]), &[80]).opened, vec![80]);
    }

    #[test]
    fn port_severity_follows_the_risky_list() {
        for p in [21, 23, 3389, 5900] {
            assert_eq!(port_severity(p), Severity::Medium, "{p}");
        }
        for p in [22, 80, 443, 8080, 9100] {
            assert_eq!(port_severity(p), Severity::Low, "{p}");
        }
    }

    fn scan(mac: &str, open: &[u16]) -> DeviceScan {
        DeviceScan { mac: mac.into(), name: format!("Device {mac}"), ip: "192.168.0.5".into(), open: open.to_vec() }
    }

    #[test]
    fn port_runs_baseline_then_alert_on_new_ports() {
        let mut a = PortAudit::default();
        // First run: baselines only.
        let o = apply_port_scan(&mut a, vec![scan("aa", &[80, 22]), scan("bb", &[])], 1_000);
        assert!(o.opened.is_empty());
        assert_eq!(o.run, PortRun { ts: 1_000, devices: 2, opened: 0, closed: 0 });
        assert!(a.devices["aa"].baseline && a.devices["bb"].baseline);
        assert_eq!(a.devices["aa"].open, vec![22, 80]);

        // Second run: aa opened Telnet and closed 80, bb unchanged, cc is new (its own baseline).
        let o = apply_port_scan(&mut a, vec![scan("aa", &[22, 23]), scan("bb", &[]), scan("cc", &[3389])], 2_000);
        assert_eq!(o.opened.len(), 1);
        assert_eq!((o.opened[0].0.mac.as_str(), o.opened[0].1), ("aa", 23));
        assert_eq!(o.run, PortRun { ts: 2_000, devices: 3, opened: 1, closed: 1 });
        assert_eq!(a.devices["aa"].opened, vec![23]);
        assert_eq!(a.devices["aa"].closed, vec![80]);
        assert!(!a.devices["aa"].baseline);
        assert!(a.devices["cc"].baseline && a.devices["cc"].opened.is_empty());
        assert_eq!(a.last_run, Some(2_000));

        let alert = port_alert(&o.opened[0].0, 23);
        assert_eq!((alert.severity, alert.kind), (Severity::Medium, "port_audit"));
        assert_eq!(alert.key, "aa:23");
        assert!(alert.detail.contains("Telnet"));
        let low = port_alert(&o.opened[0].0, 8080);
        assert_eq!(low.severity, Severity::Low);

        let s = port_summary_alert(&o);
        assert_eq!((s.severity, s.kind), (Severity::Info, "port_audit_summary"));
        assert_eq!(s.title, "Port audit: 3 devices checked, 2 changes");
    }

    #[test]
    fn summary_wording_and_run_history() {
        let r = PortRun { ts: 1, devices: 7, opened: 1, closed: 0 };
        assert_eq!(r.summary(), "Port audit: 7 devices checked, 1 change");
        assert_eq!(PortRun { devices: 1, ..Default::default() }.summary(), "Port audit: 1 device checked, 0 changes");
        let mut a = PortAudit::default();
        for i in 0..15 {
            apply_port_scan(&mut a, vec![scan("aa", &[80])], i);
        }
        assert_eq!(a.runs.len(), 12);
        assert_eq!(a.runs[0].ts, 3);
        assert_eq!(a.runs[11].ts, 14);
    }

    #[test]
    fn pool_runs_two_at_a_time_in_order() {
        use std::sync::atomic::AtomicUsize;
        let (now, peak) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let items: Vec<u32> = (0..9).collect();
        let out = run_pool(&items, 2, |i| {
            let n = now.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(15));
            now.fetch_sub(1, Ordering::SeqCst);
            i * 10
        });
        assert_eq!(out, vec![0, 10, 20, 30, 40, 50, 60, 70, 80]);
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert!(run_pool::<u32, u32>(&[], 2, |i| *i).is_empty());
    }

    // ---- listeners

    fn conn(proto: &'static str, ip: &str, port: u16, state: &str, process: Option<&str>) -> Conn {
        Conn {
            proto,
            local_ip: ip.into(),
            local_port: port,
            remote_ip: None,
            remote_port: None,
            remote_name: None,
            state: state.into(),
            pid: Some(1),
            process: process.map(String::from),
            scope: "listen",
            flagged: false,
        }
    }

    fn lis(p: &str, port: u16) -> Listener {
        Listener { process: p.into(), port }
    }

    #[test]
    fn listeners_ignore_loopback_udp_and_established_and_merge_families() {
        let conns = vec![
            conn("TCP", "0.0.0.0", 7000, "Listen", Some("ControlCenter")),
            conn("TCP", "::", 7000, "Listen", Some("ControlCenter")),
            conn("TCP", "127.0.0.1", 631, "Listen", Some("cupsd")),
            conn("TCP", "::1", 8888, "Listen", Some("jupyter")),
            conn("TCP", "192.168.0.110", 5900, "Listen", None),
            conn("TCP", "192.168.0.110", 50000, "Established", Some("Safari")),
            conn("UDP", "0.0.0.0", 5353, "Bound", Some("mDNSResponder")),
        ];
        let set = listeners_from(&conns);
        assert_eq!(set, BTreeSet::from([lis("ControlCenter", 7000), lis("unknown", 5900)]));
    }

    #[test]
    fn listener_baseline_then_new_apps_alert_once() {
        let mut a = ListenerAudit::default();
        let first = BTreeSet::from([lis("ControlCenter", 7000), lis("rapportd", 49152)]);
        assert!(update_listeners(&mut a, &first, 100).is_empty());
        assert_eq!(a.baseline_at, Some(100));
        assert_eq!(a.known.len(), 2);
        assert!(a.known.values().all(|k| !k.new));

        // Same set, and a baseline app moving away and back: nothing.
        assert!(update_listeners(&mut a, &first, 200).is_empty());
        assert!(update_listeners(&mut a, &BTreeSet::new(), 250).is_empty());
        assert!(update_listeners(&mut a, &first, 260).is_empty());

        // A new app alerts; a known app on a new (random) port is only recorded.
        let next = BTreeSet::from([lis("ControlCenter", 7000), lis("python3", 8000), lis("rapportd", 49153)]);
        let fresh = update_listeners(&mut a, &next, 300);
        assert_eq!(fresh, vec![lis("python3", 8000)]);
        assert!(a.known.contains_key("rapportd:49153"));
        assert!(a.known["python3:8000"].new);
        assert_eq!(a.known["python3:8000"].first_seen, 300);
        // Seen once, never alerted again.
        assert!(update_listeners(&mut a, &next, 400).is_empty());

        let alert = listener_alert(&fresh[0]);
        assert_eq!((alert.severity, alert.kind), (Severity::Low, "new_listener"));
        assert_eq!(alert.key, "python3");
        assert!(alert.title.contains("python3") && alert.title.contains("8000"));
    }

    #[test]
    fn an_empty_first_look_is_still_a_baseline() {
        let mut a = ListenerAudit::default();
        assert!(update_listeners(&mut a, &BTreeSet::new(), 10).is_empty());
        assert_eq!(a.baseline_at, Some(10));
        let fresh = update_listeners(&mut a, &BTreeSet::from([lis("x", 1)]), 20);
        assert_eq!(fresh.len(), 1);
    }

    // ---- startup items

    #[test]
    fn parses_plutil_json() {
        let j = r#"{"Label":"com.example.agent","ProgramArguments":["/Applications/Ex.app/Contents/MacOS/ex","--background"],"RunAtLoad":true,"KeepAlive":true}"#;
        let p = parse_launch_json(j, "fallback").unwrap();
        assert_eq!(p.label, "com.example.agent");
        assert_eq!(p.program.as_deref(), Some("/Applications/Ex.app/Contents/MacOS/ex"));
        assert_eq!(p.args, vec!["--background"]);
        assert!(p.run_at_load);

        let p = parse_launch_json(r#"{"Program":"/usr/bin/true","ProgramArguments":["true","x"]}"#, "from-file").unwrap();
        assert_eq!(p.label, "from-file");
        assert_eq!(p.program.as_deref(), Some("/usr/bin/true"));
        assert_eq!(p.args, vec!["x"]);
        assert!(!p.run_at_load);

        assert_eq!(parse_launch_json("[]", "x"), None);
        assert_eq!(parse_launch_json("not json", "x"), None);
    }

    #[test]
    fn risky_locations() {
        for p in [
            "/tmp/payload",
            "/private/tmp/a/b",
            "/var/tmp/x",
            "/private/var/tmp/x",
            "/Users/Shared/helper",
            "/Users/user/.hidden/agent",
            "/Users/user/Library/.cache/x",
            "/opt/.stash/run",
        ] {
            assert!(risky_location(p).is_some(), "{p}");
        }
        for p in [
            "/Applications/Foo.app/Contents/MacOS/foo",
            "/usr/local/bin/tool",
            "/opt/homebrew/bin/node",
            "/Library/PrivilegedHelperTools/com.x.helper",
            "/Users/user/Library/Application Support/Foo/bar",
            "/tmpfoo/x",
            "/Users/SharedStuff/x",
            "/System/Library/CoreServices/x",
        ] {
            assert!(risky_location(p).is_none(), "{p}");
        }
        assert_eq!(risky_location("/tmp/x"), Some("runs from a temporary folder"));
        assert_eq!(risky_location("/Users/Shared/x"), Some("runs from the shared folder every user can write to"));
    }

    fn parsed(label: &str, program: &str, args: &[&str]) -> LaunchParsed {
        LaunchParsed {
            label: label.into(),
            program: Some(program.into()),
            args: args.iter().map(|a| a.to_string()).collect(),
            run_at_load: true,
        }
    }

    #[test]
    fn launch_risk_rules() {
        let ok = parsed("a", "/Applications/Foo.app/Contents/MacOS/foo", &["--bg", "/Users/x/Library/Foo/conf"]);
        assert_eq!(launch_risk(&ok, None), None);
        assert_eq!(launch_risk(&ok, Some(true)), None);
        assert!(launch_risk(&ok, Some(false)).unwrap().contains("signature"));
        let tmp = parsed("b", "/tmp/updater", &[]);
        assert!(launch_risk(&tmp, Some(true)).unwrap().contains("temporary folder"));
        // A shell running a script from a risky place.
        let sh = parsed("c", "/bin/sh", &["-c", "/Users/Shared/run.sh"]);
        assert!(launch_risk(&sh, Some(true)).unwrap().contains("shared folder"));
        let hidden = parsed("d", "/bin/zsh", &["/Users/x/.local/bin/x"]);
        assert!(launch_risk(&hidden, None).unwrap().contains("hidden folder"));
        // Non-path arguments don't count.
        let flags = parsed("e", "/usr/bin/tool", &["--dir=/tmp/x", "-v"]);
        assert_eq!(launch_risk(&flags, None), None);
    }

    fn item(label: &str, program: &str) -> ScannedItem {
        ScannedItem { path: format!("/Users/x/Library/LaunchAgents/{label}.plist"), scope: "your login items", parsed: parsed(label, program, &[]) }
    }

    #[test]
    fn launch_baseline_then_new_items() {
        let mut a = LaunchAudit::default();
        let asked = std::cell::RefCell::new(Vec::new());
        let mut signer = |p: &str| {
            asked.borrow_mut().push(p.to_string());
            Some(!p.contains("unsigned"))
        };
        // Baseline: nothing alerts, nothing is run through codesign, but a
        // risky-path item is still marked on the page.
        let base = vec![item("com.a", "/Applications/A.app/a"), item("com.b", "/tmp/old")];
        assert!(update_launch(&mut a, &base, 10, &mut signer).is_empty());
        assert_eq!(a.baseline_at, Some(10));
        assert!(a.items.iter().all(|i| !i.new));
        assert!(a.items[1].risk.as_ref().unwrap().contains("temporary"));
        assert!(a.items[0].risk.is_none());

        // Later: one clean new item (Medium), one in /var/tmp (High), one that fails codesign (High).
        let mut next = base.clone();
        next.push(item("com.c", "/Applications/C.app/c"));
        next.push(item("com.d", "/var/tmp/d"));
        next.push(item("com.e", "/usr/local/unsigned/e"));
        let found = update_launch(&mut a, &next, 20, &mut signer);
        let labels: Vec<_> = found.iter().map(|f| f.item.label.as_str()).collect();
        assert_eq!(labels, vec!["com.c", "com.d", "com.e"]);
        let alerts: Vec<_> = found.iter().map(launch_alert).collect();
        assert_eq!(alerts[0].severity, Severity::Medium);
        assert_eq!(alerts[1].severity, Severity::High);
        assert_eq!(alerts[2].severity, Severity::High);
        assert!(alerts[2].detail.contains("signature"));
        assert!(alerts.iter().all(|a| a.kind == "launch_item"));
        assert_eq!(alerts[0].key, "/Users/x/Library/LaunchAgents/com.c.plist");
        assert!(alerts[0].title.contains("com.c") && alerts[0].detail.contains("/Applications/C.app/c"));
        // codesign only ran for the new items.
        assert_eq!(*asked.borrow(), vec!["/Applications/C.app/c", "/var/tmp/d", "/usr/local/unsigned/e"]);
        // They stay marked new and flagged on the page; nothing re-alerts.
        assert!(a.items.iter().filter(|i| i.new).count() == 3);
        assert!(a.items.iter().find(|i| i.label == "com.e").unwrap().risk.is_some());
        assert!(update_launch(&mut a, &next, 30, &mut signer).is_empty());
        // Removing and re-adding a known item isn't new.
        assert!(update_launch(&mut a, &base, 40, &mut signer).is_empty());
        assert!(update_launch(&mut a, &next, 50, &mut signer).is_empty());
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netwatch-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn scans_plists_in_a_folder_and_skips_netwatchs_own() {
        let dir = temp_dir("scan");
        let other = temp_dir("scan-missing").join("nope");
        for (name, body) in [
            ("com.good.plist", r#"{"Label":"com.good","ProgramArguments":["/usr/bin/true"],"RunAtLoad":true}"#),
            ("NetWatch.plist", r#"{"Label":"NetWatch","ProgramArguments":["/Applications/NetWatch.app/Contents/MacOS/netwatch","--hidden"]}"#),
            ("notes.txt", "hello"),
            (".hidden.plist", r#"{"Label":"x"}"#),
            ("broken.plist", "garbage"),
        ] {
            std::fs::write(dir.join(name), body).unwrap();
        }
        let dirs = [
            LaunchDir { dir: dir.clone(), scope: "your login items" },
            LaunchDir { dir: other, scope: "system service" },
        ];
        // Sample plists hold JSON here; the app turns real plists into JSON with plutil.
        let mut read = |p: &Path| {
            let stem = p.file_stem()?.to_str()?.to_string();
            parse_launch_json(&std::fs::read_to_string(p).ok()?, &stem)
        };
        let items = scan_launch_items(&dirs, &mut read);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].parsed.label, "com.good");
        assert_eq!(items[0].scope, "your login items");
        assert!(items[0].path.ends_with("com.good.plist"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_real_plists_with_plutil_and_checks_signatures() {
        let dir = temp_dir("plutil");
        let xml = |label: &str, prog: &str| {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{prog}</string><string>--go</string></array><key>RunAtLoad</key><true/></dict></plist>\n"
            )
        };
        std::fs::write(dir.join("com.sample.plist"), xml("com.sample", "/tmp/sample-helper")).unwrap();
        std::fs::write(dir.join("NetWatch.plist"), xml("NetWatch", "/Applications/NetWatch.app/x")).unwrap();
        std::fs::write(dir.join("bad.plist"), "not a plist").unwrap();
        let dirs = [LaunchDir { dir: dir.clone(), scope: "your login items" }];
        let items = scan_launch_items(&dirs, &mut |p| read_launch_plist(p));
        assert_eq!(items.len(), 1);
        let p = &items[0].parsed;
        assert_eq!((p.label.as_str(), p.program.as_deref(), p.run_at_load), ("com.sample", Some("/tmp/sample-helper"), true));
        assert_eq!(p.args, vec!["--go"]);
        assert!(launch_risk(p, None).unwrap().contains("temporary"));

        // codesign: a system binary is signed, a plain file isn't, a missing one can't be judged.
        assert_eq!(codesign_ok("/bin/ls"), Some(true));
        assert_eq!(codesign_ok(dir.join("com.sample.plist").to_str().unwrap()), Some(false));
        assert_eq!(codesign_ok("/no/such/program"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- DNS and DHCP

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dns_and_dhcp_baseline_per_network() {
        let mut w = NetworkWatch::default();
        let home = "aa:aa:aa:aa:aa:aa";
        let cafe = "bb:bb:bb:bb:bb:bb";
        // First sight of each network is a baseline.
        assert!(update_network(&mut w, home, Some("192.168.0.1".into()), &s(&["192.168.0.1"]), Some("192.168.0.1"), 1).is_empty());
        assert!(update_network(&mut w, cafe, None, &s(&["10.0.0.1"]), Some("10.0.0.1"), 2).is_empty());
        // The same values again: quiet. Order doesn't matter.
        assert!(update_network(&mut w, home, None, &s(&["192.168.0.1"]), Some("192.168.0.1"), 3).is_empty());
        // The café's DNS is not "new" at home, and vice versa: each has its own history.
        assert!(update_network(&mut w, cafe, None, &s(&["10.0.0.1"]), Some("10.0.0.1"), 4).is_empty());

        // Home DNS switches to a server never used on this network.
        let f = update_network(&mut w, home, None, &s(&["6.6.6.6", "192.168.0.1"]), Some("192.168.0.1"), 5);
        assert_eq!(f, vec![NetFinding::NewDns { added: s(&["6.6.6.6"]), previous: s(&["192.168.0.1"]) }]);
        let a = network_alert(home, &f[0]);
        assert_eq!((a.severity, a.kind), (Severity::Medium, "dns_change"));
        assert!(a.title.contains("DNS hijack") && a.detail.contains("6.6.6.6"));
        // Seen now, so going back or staying isn't a change.
        assert!(update_network(&mut w, home, None, &s(&["6.6.6.6", "192.168.0.1"]), Some("192.168.0.1"), 6).is_empty());
        assert!(update_network(&mut w, home, None, &s(&["192.168.0.1"]), Some("192.168.0.1"), 7).is_empty());
        // Using the café's DNS at home would be new, though.
        let f = update_network(&mut w, home, None, &s(&["10.0.0.1"]), None, 8);
        assert_eq!(f.len(), 1);

        // DHCP server change: Low.
        let f = update_network(&mut w, home, None, &[], Some("192.168.0.77"), 9);
        assert_eq!(f, vec![NetFinding::DhcpChanged { from: "192.168.0.1".into(), to: "192.168.0.77".into() }]);
        let a = network_alert(home, &f[0]);
        assert_eq!((a.severity, a.kind), (Severity::Low, "dhcp_change"));
        assert!(a.detail.contains("192.168.0.1") && a.detail.contains("192.168.0.77"));
        // Going back is a change from the last one (the spec compares with last time).
        assert_eq!(update_network(&mut w, home, None, &[], Some("192.168.0.1"), 10).len(), 1);
        // A missing lease doesn't reset or alert.
        assert!(update_network(&mut w, home, None, &[], None, 11).is_empty());
        assert_eq!(w.networks[home].dhcp_last.as_deref(), Some("192.168.0.1"));
    }

    #[test]
    fn dns_that_wasnt_ready_at_first_sight_is_a_baseline_not_a_change() {
        let mut w = NetworkWatch::default();
        let gw = "cc:cc:cc:cc:cc:cc";
        assert!(update_network(&mut w, gw, None, &[], None, 1).is_empty());
        assert!(update_network(&mut w, gw, None, &s(&["1.1.1.1"]), Some("192.168.1.1"), 2).is_empty());
        assert_eq!(update_network(&mut w, gw, None, &s(&["8.8.8.8"]), Some("192.168.1.1"), 3).len(), 1);
    }

    // ---- Wi-Fi look-alikes

    fn net(ssid: Option<&str>, channel: u32, band: &str, sec: &str) -> Network {
        Network {
            ssid: ssid.map(String::from),
            channel: Some(channel),
            band: Some(band.into()),
            security: Some(sec.into()),
            rssi: Some(-60),
            ..Default::default()
        }
    }

    fn wifi(cur: Network, nearby: Vec<Network>) -> WifiInfo {
        WifiInfo { interface: "en0".into(), current: cur, nearby, ..Default::default() }
    }

    #[test]
    fn security_tiers_are_coarse() {
        assert_eq!(security_tier(Some("Open (no password)")), Some(0));
        assert_eq!(security_tier(Some("Enhanced Open")), Some(0));
        assert_eq!(security_tier(Some("WEP")), Some(0));
        assert_eq!(security_tier(Some("WPA/WPA2 Personal")), Some(1));
        assert_eq!(security_tier(Some("WPA2 Personal")), security_tier(Some("WPA3 Personal")));
        assert_eq!(security_tier(Some("WPA2/WPA3 Personal")), security_tier(Some("WPA3 Personal")));
        assert_eq!(security_tier(Some("something new")), None);
        assert_eq!(security_tier(None), None);
    }

    #[test]
    fn evil_twin_needs_visible_names() {
        let mut a = WifiAudit::default();
        let hidden = wifi(net(None, 11, "2.4 GHz", "WPA2 Personal"), vec![net(None, 6, "2.4 GHz", "Open (no password)")]);
        let (view, alerts) = check_evil_twin(&hidden, &mut a, 1);
        assert!(!view.names_visible && alerts.is_empty() && view.aps.is_empty());
        assert!(a.seen.is_empty());
        // Our name visible but every neighbour hidden also counts as hidden.
        let partial = wifi(net(Some("Home"), 11, "2.4 GHz", "WPA2 Personal"), vec![net(None, 6, "2.4 GHz", "Open (no password)")]);
        assert!(!check_evil_twin(&partial, &mut a, 2).0.names_visible);
        // Alone on the air is fine and visible.
        let alone = wifi(net(Some("Home"), 11, "2.4 GHz", "WPA2 Personal"), vec![]);
        let (view, alerts) = check_evil_twin(&alone, &mut a, 3);
        assert!(view.names_visible && alerts.is_empty());
    }

    #[test]
    fn evil_twin_weaker_security_is_high_and_open_too() {
        let mut a = WifiAudit::default();
        let mine = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        // Baseline look, nothing else around.
        check_evil_twin(&wifi(mine.clone(), vec![]), &mut a, 1);
        let twin = net(Some("Home"), 6, "2.4 GHz", "Open (no password)");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![twin.clone(), net(Some("Neighbour"), 1, "2.4 GHz", "WPA2 Personal")]), &mut a, 2);
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].severity, alerts[0].kind), (Severity::High, "evil_twin"));
        assert!(alerts[0].detail.contains("Open (no password)") && alerts[0].detail.contains("channel 6"));
        assert_eq!(view.aps.len(), 2);
        assert_eq!(view.aps[1].flag.as_deref(), Some("weaker"));
        // The same AP again gives the same alert key (the caller dedupes on it).
        let (_, again) = check_evil_twin(&wifi(mine.clone(), vec![twin]), &mut a, 3);
        assert_eq!(again[0].key, alerts[0].key);
        // WPA vs WPA2 is weaker too; WPA2 vs WPA3 is not.
        let wpa = net(Some("Home"), 1, "2.4 GHz", "WPA Personal");
        assert_eq!(check_evil_twin(&wifi(mine.clone(), vec![wpa]), &mut a, 4).1[0].severity, Severity::High);
        let wpa3 = net(Some("Home"), 37, "6 GHz", "WPA3 Personal");
        assert!(check_evil_twin(&wifi(mine, vec![wpa3]), &mut a, 5).1.iter().all(|x| x.severity != Severity::High));
    }

    #[test]
    fn evil_twin_new_channel_is_low_once_after_the_baseline() {
        let mut a = WifiAudit::default();
        let mine = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        let node = net(Some("Home"), 1, "2.4 GHz", "WPA2 Personal");
        // First look: your mesh node is already there, so it's part of the baseline.
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![node.clone()]), &mut a, 1);
        assert!(alerts.is_empty());
        assert!(view.aps[1].baseline && view.aps[1].flag.is_none());
        assert_eq!(a.seen["Home"].len(), 2);
        // Later, another AP appears on a band not seen before.
        let extra = net(Some("Home"), 149, "5 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![node.clone(), extra.clone()]), &mut a, 2);
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].severity, alerts[0].kind), (Severity::Low, "evil_twin"));
        assert!(alerts[0].detail.contains("mesh"));
        assert_eq!(view.aps[2].flag.as_deref(), Some("new"));
        // It's known now: no repeat, but the page keeps showing it as new since baseline.
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![node, extra]), &mut a, 3);
        assert!(alerts.is_empty());
        assert_eq!(view.aps[2].flag.as_deref(), Some("new"));
        assert!(!view.aps[2].baseline);
        // Another network name has its own baseline.
        let other = net(Some("Office"), 11, "2.4 GHz", "WPA2 Personal");
        let stray = net(Some("Office"), 6, "2.4 GHz", "WPA2 Personal");
        assert!(check_evil_twin(&wifi(other, vec![stray]), &mut a, 4).1.is_empty());
    }

    #[test]
    fn evil_twin_ignores_other_names_and_unknown_security() {
        let mut a = WifiAudit::default();
        let mine = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        check_evil_twin(&wifi(mine.clone(), vec![]), &mut a, 1);
        let mut unknown = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        unknown.security = None;
        // Same channel as ours (a BSSID on the same band) and security unknown: nothing to say.
        let (_, alerts) = check_evil_twin(&wifi(mine, vec![unknown, net(Some("Cafe"), 1, "2.4 GHz", "Open (no password)")]), &mut a, 2);
        assert!(alerts.is_empty());
    }

    // ---- Wi-Fi look-alikes by BSSID

    fn ap(ssid: &str, bssid: &str, channel: u32, band: &str, sec: &str) -> Network {
        Network { bssid: Some(bssid.into()), ..net(Some(ssid), channel, band, sec) }
    }

    const MINE: &str = "aa:bb:cc:00:00:01";
    const NODE: &str = "aa:bb:cc:00:00:02";

    #[test]
    fn evil_twin_by_bssid_ignores_our_own_access_point() {
        let mut a = WifiAudit::default();
        let mine = ap("Home", MINE, 36, "5 GHz", "WPA2 Personal");
        // macOS lists the access point you're on in the scan too; it is not a look-alike.
        let own_in_scan = ap("Home", "AA:BB:CC:0:0:1", 36, "5 GHz", "WPA2 Personal");
        let node = ap("Home", NODE, 1, "2.4 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![own_in_scan, node.clone()]), &mut a, 1);
        assert!(alerts.is_empty());
        assert_eq!(view.aps.len(), 2, "own access point must not appear twice");
        assert_eq!(view.aps[0].bssid.as_deref(), Some(MINE));
        assert_eq!(view.aps[1].bssid.as_deref(), Some(NODE));
        assert!(view.aps.iter().all(|x| x.baseline && x.flag.is_none()));
        assert_eq!(a.seen["Home"].keys().cloned().collect::<Vec<_>>(), [MINE, NODE]);
    }

    #[test]
    fn a_known_bssid_changing_channel_is_not_new_but_an_unknown_one_is() {
        let mut a = WifiAudit::default();
        let mine = ap("Home", MINE, 36, "5 GHz", "WPA2 Personal");
        let node = ap("Home", NODE, 1, "2.4 GHz", "WPA2 Personal");
        check_evil_twin(&wifi(mine.clone(), vec![node.clone()]), &mut a, 1);
        // The mesh node's radio moves to another channel: same BSSID, so same access point.
        let moved = ap("Home", NODE, 11, "2.4 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![moved]), &mut a, 2);
        assert!(alerts.is_empty());
        assert!(view.aps[1].flag.is_none());
        // A BSSID never seen before with the same security: Low, once.
        let stranger = ap("Home", "de:ad:be:ef:00:01", 6, "2.4 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![stranger.clone()]), &mut a, 3);
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].severity, alerts[0].kind), (Severity::Low, "evil_twin"));
        assert!(alerts[0].key.contains("de:ad:be:ef:00:01") && alerts[0].detail.contains("address de:ad:be:ef:00:01"));
        assert_eq!(view.aps[1].flag.as_deref(), Some("new"));
        // Seen now: no more Low alerts for it, though the page keeps marking it.
        let (view, alerts) = check_evil_twin(&wifi(mine, vec![stranger]), &mut a, 4);
        assert!(alerts.is_empty());
        assert_eq!(view.aps[1].flag.as_deref(), Some("new"));
    }

    #[test]
    fn a_weaker_bssid_is_high_even_if_it_was_there_at_the_baseline() {
        let mut a = WifiAudit::default();
        let mine = ap("Home", MINE, 36, "5 GHz", "WPA2 Personal");
        let twin = ap("Home", "de:ad:be:ef:00:02", 6, "2.4 GHz", "Open (no password)");
        // Even on the very first look, when everything else is only a baseline.
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![twin.clone()]), &mut a, 1);
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].severity, alerts[0].kind), (Severity::High, "evil_twin"));
        assert_eq!(view.aps[1].flag.as_deref(), Some("weaker"));
        // The same twin later: same alert key, so the caller doesn't repeat it.
        let (_, again) = check_evil_twin(&wifi(mine, vec![twin]), &mut a, 2);
        assert_eq!(again[0].key, alerts[0].key);
    }

    #[test]
    fn records_from_before_bssids_start_a_new_baseline() {
        let mut a = WifiAudit::default();
        // The old scheme: no BSSIDs, access points told apart by channel and band.
        let old_mine = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        let old_node = net(Some("Home"), 1, "2.4 GHz", "WPA2 Personal");
        check_evil_twin(&wifi(old_mine.clone(), vec![old_node]), &mut a, 1);
        assert!(a.seen["Home"].keys().all(|k| k.contains('@')));
        // After the upgrade the same mesh shows up with BSSIDs: no alerts.
        let mine = ap("Home", MINE, 36, "5 GHz", "WPA2 Personal");
        let node = ap("Home", NODE, 1, "2.4 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), vec![node.clone()]), &mut a, 2);
        assert!(alerts.is_empty());
        assert!(view.aps.iter().all(|x| x.baseline && x.flag.is_none()));
        assert!(a.seen["Home"].keys().all(|k| k.contains(':')));
        // Later arrivals are judged by BSSID as usual.
        let extra = ap("Home", "aa:bb:cc:00:00:03", 149, "5 GHz", "WPA2 Personal");
        assert_eq!(check_evil_twin(&wifi(mine, vec![node, extra]), &mut a, 3).1.len(), 1);
    }

    #[test]
    fn bssid_records_and_scans_without_bssids_are_not_compared() {
        let mut a = WifiAudit::default();
        let mine = ap("Home", MINE, 36, "5 GHz", "WPA2 Personal");
        check_evil_twin(&wifi(mine, vec![ap("Home", NODE, 1, "2.4 GHz", "WPA2 Personal")]), &mut a, 1);
        let before = a.seen.clone();
        // A scan that lacks BSSIDs (say, Location was switched off) can't tell what is new.
        let plain = net(Some("Home"), 36, "5 GHz", "WPA2 Personal");
        let stray = net(Some("Home"), 6, "2.4 GHz", "WPA2 Personal");
        let (view, alerts) = check_evil_twin(&wifi(plain.clone(), vec![stray]), &mut a, 2);
        assert!(alerts.is_empty());
        assert_eq!(a.seen, before);
        assert!(view.aps[1].flag.is_none());
        // Weaker security is still High without any history.
        let open = net(Some("Home"), 6, "2.4 GHz", "Open (no password)");
        assert_eq!(check_evil_twin(&wifi(plain, vec![open]), &mut a, 3).1[0].severity, Severity::High);
    }

    #[test]
    fn remembers_a_bounded_number_of_access_points_per_name() {
        let mut a = WifiAudit::default();
        let mine = ap("Campus", MINE, 36, "5 GHz", "WPA2 Enterprise");
        let nearby: Vec<Network> = (0..100).map(|i| ap("Campus", &format!("aa:bb:cc:01:00:{i:02x}"), 36, "5 GHz", "WPA2 Enterprise")).collect();
        let (view, alerts) = check_evil_twin(&wifi(mine.clone(), nearby.clone()), &mut a, 1);
        assert!(alerts.is_empty());
        assert_eq!(view.aps.len(), 101);
        assert_eq!(a.seen["Campus"].len(), MAX_APS_PER_SSID);
        // Past the cap nothing is called "new" on a guess.
        let (view, _) = check_evil_twin(&wifi(mine, nearby), &mut a, 2);
        assert!(view.aps.iter().all(|x| x.flag.is_none()));
    }

    #[test]
    fn every_label_the_corewlan_mapping_can_give_has_a_security_tier() {
        use crate::wifi::{cw, cw_security_label};
        // Every combination of the values worth probing, up to three at a time.
        let mut labels = std::collections::BTreeSet::new();
        let probe = cw::PROBE;
        for (i, &a) in probe.iter().enumerate() {
            labels.extend(cw_security_label(&[a]));
            for (j, &b) in probe.iter().enumerate().skip(i + 1) {
                labels.extend(cw_security_label(&[a, b]));
                for &c in probe.iter().skip(j + 1) {
                    labels.extend(cw_security_label(&[a, b, c]));
                }
            }
        }
        assert!(labels.len() >= 10, "{labels:?}");
        for l in &labels {
            assert!(security_tier(Some(l)).is_some(), "{l:?} has no tier");
        }
    }

    // ---- certificate records

    #[test]
    fn records_renewals() {
        let old = CertInfo { fingerprint: "aa".into(), issuer: "LE (R10)".into(), issuer_org: "LE".into(), ..Default::default() };
        let mut e = CertEntry { target: "x.com".into(), info: Some(old.clone()), ..Default::default() };
        record_cert_change(&mut e, &old, 5);
        assert!(e.changes.is_empty());
        let renewed = CertInfo { fingerprint: "bb".into(), issuer: "LE (R11)".into(), issuer_org: "LE".into(), ..Default::default() };
        record_cert_change(&mut e, &renewed, 6);
        assert_eq!(e.changes, vec![CertChange { ts: 6, old_issuer: "LE (R10)".into(), new_issuer: "LE (R11)".into(), issuer_changed: false }]);
        let other = CertInfo { fingerprint: "cc".into(), issuer: "Evil".into(), issuer_org: "Evil".into(), ..Default::default() };
        e.info = Some(renewed);
        record_cert_change(&mut e, &other, 7);
        assert!(e.changes[1].issuer_changed);
    }

    #[test]
    fn state_round_trips_and_ignores_transient_data() {
        let mut st = AuditState::default();
        st.live.ports_running = true;
        st.ports.last_run = Some(5);
        let json = serde_json::to_string(&st).unwrap();
        let back: AuditState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ports.last_run, Some(5));
        assert!(!back.live.ports_running);
        // An older or partial file loads with defaults.
        let back: AuditState = serde_json::from_str(r#"{"ports":{"last_run":9}}"#).unwrap();
        assert_eq!(back.ports.last_run, Some(9));
        assert!(back.listeners.baseline_at.is_none());
    }
}

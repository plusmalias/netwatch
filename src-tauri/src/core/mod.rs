//! Shared app state and the background workers: periodic scans, the mDNS
//! listener, packet capture, the connection watcher and feed updates.

mod audit;
mod bluetooth;
mod location;
mod mini;
mod monitor;
mod presence;

pub use audit::AuditSnapshot;
pub use bluetooth::BtSnapshot;
pub use location::LocationInfo;
pub use mini::MiniSummary;
pub use monitor::MonitorSnapshot;

use crate::alerts::{Alert, AlertDraft, AlertLog, Severity};
use crate::apps::AppTracker;
use crate::settings::Settings;
use crate::usage::UsageLog;
use monitor::MonitorState;
use crate::blocklist::{self, Blocklist, BlocklistInfo};
use crate::capture::{self, CaptureStatus};
use crate::conns::{self, Conn};
use crate::detect::{self, Analyzer, DnsEntry, Event, TrafficSnapshot};
use crate::export::{self, ExportConfig, Exporter};
use crate::discovery::{self, MdnsInfo, SsdpInfo};
use crate::net::{self, NetInfo};
use crate::oui::{self, Oui};
use crate::ping;
use crate::store::{Device, DeviceStore};
use crate::util::{is_randomized_mac, now_ms};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

const SCAN_INTERVAL: Duration = Duration::from_secs(5 * 60);
const CONN_WATCH_INTERVAL: Duration = Duration::from_secs(15);
/// How often to look for a network when NetWatch started without one.
const NET_POLL: Duration = Duration::from_secs(5);
const VENDOR_DB_MAX_AGE_MS: u64 = 30 * 24 * 3_600_000;
const DNS_LOG_LEN: usize = 500;
const DEVICE_SAVE_INTERVAL_MS: u64 = 30_000;
/// Open ports that usually shouldn't be reachable on a home device.
const RISKY_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (23, "Telnet"),
    (3389, "Remote Desktop"),
    (5900, "VNC"),
];

pub struct Core {
    app: AppHandle,
    dir: PathBuf,
    net: RwLock<Option<NetInfo>>,
    store: Mutex<DeviceStore>,
    alerts: Mutex<AlertLog>,
    /// Writes new alerts to the log file and forwards them to a SIEM, off the alert path.
    export: Exporter,
    blocklist: Arc<RwLock<Blocklist>>,
    oui: RwLock<Oui>,
    dns_names: Arc<RwLock<HashMap<IpAddr, String>>>,
    dns_log: Mutex<VecDeque<DnsEntry>>,
    dns_pending: Mutex<Vec<DnsEntry>>,
    traffic: Mutex<TrafficSnapshot>,
    capture: Mutex<(CaptureStatus, Option<Arc<AtomicBool>>)>,
    pending_mdns: Mutex<HashMap<Ipv4Addr, MdnsInfo>>,
    mdns_sock: Mutex<Option<UdpSocket>>,
    mdns_generation: AtomicU64,
    sys: Mutex<sysinfo::System>,
    scanning: AtomicBool,
    feeds_updating: AtomicBool,
    feeds_error: Mutex<Option<String>>,
    /// Whether "new device" alerts are armed. Off until the first scan
    /// finishes, so a fresh install doesn't alert on every existing device.
    baseline: AtomicBool,
    /// Whether join/leave alerts are armed (after the first presence check).
    presence_armed: AtomicBool,
    devices_dirty: AtomicBool,
    arp_memory: Mutex<discovery::ArpMemory>,
    settings: RwLock<Settings>,
    mon: Mutex<MonitorState>,
    /// What the security audits remember (see `audit.rs`).
    audit: Mutex<crate::audit::AuditState>,
    usage: Mutex<UsageLog>,
    apps: Mutex<AppTracker>,
    bt: Mutex<bluetooth::BtState>,
    /// Location permission, and where this Mac was when each unknown tracker was first heard.
    loc: Mutex<location::LocationState>,
    history: Mutex<crate::history::History>,
    /// Ask the public-address monitor to look again (network changed).
    public_refresh: AtomicBool,
    /// Ask the Wi-Fi monitor to look again now (Location permission changed).
    wifi_refresh: AtomicBool,
    /// Set on a quiet login start: the first time capture turns out to need
    /// permission, a notification says so (once).
    quiet_start: AtomicBool,
}

#[derive(Serialize, Clone)]
pub struct FeedInfo {
    pub blocklist: BlocklistInfo,
    pub vendors: usize,
    pub updating: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub net: Option<NetInfo>,
    pub devices: Vec<Device>,
    pub alerts: Vec<Alert>,
    pub capture: CaptureStatus,
    pub feeds: FeedInfo,
    pub traffic: TrafficSnapshot,
    pub dns: Vec<DnsEntry>,
    pub scanning: bool,
    pub data_dir: String,
    pub settings: Settings,
    #[serde(flatten)]
    pub monitor: MonitorSnapshot,
    pub bt: BtSnapshot,
    pub audit: AuditSnapshot,
    pub location: LocationInfo,
}

#[derive(Serialize, Clone)]
struct AlertEvent {
    alert: Alert,
    is_new: bool,
}

#[derive(Serialize, Clone)]
struct ScanEvent {
    running: bool,
    phase: String,
}

impl Core {
    pub fn new(app: AppHandle, dir: PathBuf) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&dir);
        let mut store = DeviceStore::load(dir.join("devices.json"));
        let baseline = !store.devices.is_empty();
        // Online flags on disk are from the last run; recompute them quietly.
        store.update_online(now_ms());
        let settings = Settings::load(&dir.join("settings.json"));
        let export = Exporter::start(dir.clone(), ExportConfig::from_settings(&settings));
        Arc::new(Core {
            app,
            net: RwLock::new(None),
            store: Mutex::new(store),
            alerts: Mutex::new(AlertLog::load(dir.join("alerts.json"))),
            export,
            blocklist: Arc::new(RwLock::new(Blocklist::load(&dir))),
            oui: RwLock::new(Oui::load(&dir.join("manuf.txt"))),
            dns_names: Arc::default(),
            dns_log: Mutex::new(VecDeque::new()),
            dns_pending: Mutex::new(Vec::new()),
            traffic: Mutex::new(TrafficSnapshot::default()),
            capture: Mutex::new((CaptureStatus::Stopped, None)),
            pending_mdns: Mutex::new(HashMap::new()),
            mdns_sock: Mutex::new(None),
            mdns_generation: AtomicU64::new(0),
            sys: Mutex::new(sysinfo::System::new()),
            scanning: AtomicBool::new(false),
            feeds_updating: AtomicBool::new(false),
            feeds_error: Mutex::new(None),
            baseline: AtomicBool::new(baseline),
            presence_armed: AtomicBool::new(false),
            devices_dirty: AtomicBool::new(false),
            arp_memory: Mutex::default(),
            settings: RwLock::new(settings),
            mon: Mutex::new(MonitorState::load(&dir)),
            audit: Mutex::new(monitor::load_json(&dir.join("audit.json"))),
            usage: Mutex::new(UsageLog::load(dir.join("usage.json"))),
            apps: Mutex::new(AppTracker::default()),
            bt: Mutex::new(bluetooth::BtState::load(&dir)),
            loc: Mutex::default(),
            history: Mutex::new(crate::history::History::load(dir.join("history.json"))),
            public_refresh: AtomicBool::new(false),
            wifi_refresh: AtomicBool::new(false),
            quiet_start: AtomicBool::new(false),
            dir,
        })
    }

    /// Kicks off every background worker. Called once at startup. `quiet` is
    /// a login start, where blocked packet capture is worth a notification.
    pub fn start(self: &Arc<Self>, quiet: bool) {
        self.quiet_start.store(quiet, Ordering::SeqCst);
        self.refresh_net();
        self.start_mdns();
        self.update_feeds(false);
        self.start_capture();
        if self.net.read().unwrap().is_none() {
            self.start_when_online();
        }

        let core = self.clone();
        thread::spawn(move || loop {
            core.scan();
            thread::sleep(SCAN_INTERVAL);
        });

        let core = self.clone();
        thread::spawn(move || {
            let mut unsaved = false;
            let mut last_save = now_ms();
            let mut last_tray = String::new();
            let mut last_title: Option<String> = None;
            loop {
                thread::sleep(Duration::from_secs(2));
                let line = core.tray_status();
                if line != last_tray {
                    if let Some(t) = core.app.try_state::<crate::tray::TrayStatus<tauri::Wry>>() {
                        let _ = t.0.set_text(&line);
                    }
                    last_tray = line;
                }
                let title = core.tray_title();
                if title != last_title {
                    crate::tray::set_title(&core.app, title.as_deref());
                    last_title = title;
                }
                if core.devices_dirty.swap(false, Ordering::SeqCst) {
                    unsaved = true;
                    core.emit_devices();
                }
                // Sightings arrive constantly; write them out at a calmer pace.
                if unsaved && now_ms() - last_save >= DEVICE_SAVE_INTERVAL_MS {
                    core.store.lock().unwrap().save();
                    unsaved = false;
                    last_save = now_ms();
                }
            }
        });

        self.start_presence();
        self.start_monitors();
        self.start_bluetooth();
        self.start_location();
        self.start_audits();

        // Feeds only refresh when a list is due, so an hourly look keeps the
        // daily and 3-day schedules true for an app that runs for weeks.
        let core = self.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(3600));
            core.update_feeds(false);
        });

        let core = self.clone();
        thread::spawn(move || loop {
            thread::sleep(CONN_WATCH_INTERVAL);
            let _ = core.connections();
        });
    }

    /// A login start can beat Wi-Fi. Until a network shows up, look for one
    /// every few seconds, then start what needs it: mDNS, capture, a first scan.
    fn start_when_online(self: &Arc<Self>) {
        let core = self.clone();
        thread::spawn(move || {
            while net::default_net().is_err() {
                thread::sleep(NET_POLL);
            }
            core.refresh_net();
            core.start_mdns();
            core.start_capture();
            core.refresh_public();
            core.scan();
        });
    }

    fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) {
        let _ = self.app.emit(event, payload);
    }

    fn emit_devices(&self) {
        let devices = self.store.lock().unwrap().list();
        self.emit("devices", devices);
    }

    fn emit_scan(&self, running: bool, phase: impl Into<String>) {
        self.emit(
            "scan",
            ScanEvent {
                running,
                phase: phase.into(),
            },
        );
    }

    pub fn snapshot(&self) -> Snapshot {
        // Built first: it reads the settings itself, and the guards taken in the
        // literal below live until the end of the function.
        let monitor = self.monitor_snapshot();
        let location = self.location_info();
        Snapshot {
            net: self.net.read().unwrap().clone(),
            devices: self.store.lock().unwrap().list(),
            alerts: self.alerts.lock().unwrap().alerts.clone(),
            capture: self.capture.lock().unwrap().0.clone(),
            feeds: self.feed_info(),
            traffic: self.traffic.lock().unwrap().clone(),
            dns: self.dns_log.lock().unwrap().iter().cloned().collect(),
            scanning: self.scanning.load(Ordering::SeqCst),
            data_dir: self.dir.display().to_string(),
            settings: self.settings.read().unwrap().clone(),
            monitor,
            bt: self.bt_snapshot(),
            audit: self.audit_snapshot(),
            location,
        }
    }

    fn refresh_net(&self) -> Option<NetInfo> {
        match net::default_net() {
            Ok(n) => {
                *self.net.write().unwrap() = Some(n.clone());
                self.emit("net", n.clone());
                Some(n)
            }
            Err(e) => {
                eprintln!("network info: {e}");
                self.net.read().unwrap().clone()
            }
        }
    }

    fn in_subnet(&self, ip: Ipv4Addr) -> bool {
        self.net.read().unwrap().as_ref().is_some_and(|n| {
            let mask = u32::MAX.checked_shl(32 - n.prefix as u32).unwrap_or(0);
            u32::from(ip) & mask == u32::from(n.ip) & mask && ip != n.ip
        })
    }

    // ------------------------------------------------------------ alerts

    pub fn alert(&self, draft: AlertDraft) {
        let (alert, is_new) = {
            let mut log = self.alerts.lock().unwrap();
            let r = log.push(draft, now_ms());
            log.save();
            r
        };
        if is_new {
            self.export.alert(&alert);
            self.notify(&alert);
        }
        self.emit("alert", AlertEvent { alert, is_new });
    }

    /// Shows a system notification for a new alert, if settings allow and the
    /// window isn't already in front (it shows its own toast then).
    fn notify(&self, a: &Alert) {
        let min = match self.settings.read().unwrap().notify.as_str() {
            "off" => return,
            "high" => Severity::High,
            "low" => Severity::Low,
            _ => Severity::Medium,
        };
        // Join/leave alerts are only raised for devices the user chose to
        // watch, and the morning summary is something they asked for.
        if a.severity < min && a.kind != "presence" && a.kind != "daily_summary" {
            return;
        }
        if let Some(w) = self.app.get_webview_window("main") {
            if w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false) {
                return;
            }
        }
        self.show_notification(&a.title, &a.detail);
    }

    fn show_notification(&self, title: &str, body: &str) {
        use tauri_plugin_notification::NotificationExt;
        let _ = self.app.notification().builder().title(title).body(body).show();
    }

    /// After a login start macOS has reset packet-capture access. Says so
    /// once, unless the user switched system notifications off.
    fn notify_capture_blocked(self: &Arc<Self>) {
        if self.settings.read().unwrap().notify == "off" {
            return;
        }
        let core = self.clone();
        thread::spawn(move || {
            // Let the desktop finish logging in first.
            thread::sleep(Duration::from_secs(3));
            core.show_notification(
                "Traffic monitoring needs access",
                "NetWatch needs access to monitor traffic — click its menu-bar icon to grant it.",
            );
        });
    }

    /// One line for the tray menu: who's online and what needs attention.
    fn tray_status(&self) -> String {
        let online = self.store.lock().unwrap().devices.values().filter(|d| d.online).count();
        let open = self
            .alerts
            .lock()
            .unwrap()
            .alerts
            .iter()
            .filter(|a| !a.acknowledged && a.severity > Severity::Info)
            .count();
        let down = self.monitor_snapshot_outage();
        let mut s = format!("{online} device{} online", if online == 1 { "" } else { "s" });
        if open > 0 {
            s += &format!(" · {open} alert{}", if open == 1 { "" } else { "s" });
        }
        if let Some(kind) = down {
            s += if kind == "router" { " · router unreachable" } else { " · internet down" };
        }
        s
    }

    pub fn acknowledge(&self, id: Option<u64>) {
        let mut log = self.alerts.lock().unwrap();
        log.acknowledge(id);
        log.save();
        self.emit("alerts", log.alerts.clone());
    }

    pub fn clear_alerts(&self) {
        let mut log = self.alerts.lock().unwrap();
        log.alerts.clear();
        log.save();
        self.emit("alerts", log.alerts.clone());
    }

    // ------------------------------------------------------------ devices

    fn vendor_for(&self, mac: &str) -> Option<String> {
        if is_randomized_mac(mac) {
            return None;
        }
        self.oui.read().unwrap().lookup(mac)
    }

    /// Records a sighting of `mac` at `ip`, alerting if it's a newcomer.
    fn observe(&self, mac: &str, ip: Ipv4Addr, source: &str, hostname: Option<String>) {
        self.observe_with(mac, ip, source, hostname, |_| false)
    }

    /// Like `observe`, then lets `extra` fill in more details. `extra`
    /// returns whether it changed anything worth showing right away.
    fn observe_with(
        &self,
        mac: &str,
        ip: Ipv4Addr,
        source: &str,
        hostname: Option<String>,
        extra: impl FnOnce(&mut Device) -> bool,
    ) {
        let mut store = self.store.lock().unwrap();
        let seen = store.observe(mac, ip, source, now_ms());
        let dev = store.devices.get_mut(mac).expect("just observed");
        let mut changed = seen.changed | extra(dev);
        if dev.vendor.is_none() {
            dev.vendor = self.vendor_for(mac);
            changed |= dev.vendor.is_some();
        }
        if let Some(h) = hostname.filter(|_| dev.hostname.is_none()) {
            dev.hostname = Some(h);
            changed = true;
        }
        if let Some(info) = self.pending_mdns.lock().unwrap().remove(&ip) {
            changed |= apply_mdns(dev, &info);
        }
        let new_alert = (seen.is_new && self.baseline.load(Ordering::SeqCst) && !dev.trusted)
            .then(|| new_device_alert(dev));
        drop(store);
        self.devices_dirty.store(true, Ordering::SeqCst);
        if changed {
            self.emit_devices();
        }
        if let Some(a) = new_alert {
            self.alert(a);
        }
    }

    fn on_mdns(&self, info: MdnsInfo) {
        let Some(ip) = info.ip else { return };
        if !self.in_subnet(ip) {
            return;
        }
        let mut store = self.store.lock().unwrap();
        match store.by_ip_mut(ip) {
            Some(dev) => {
                if apply_mdns(dev, &info) {
                    drop(store);
                    self.devices_dirty.store(true, Ordering::SeqCst);
                    self.emit_devices();
                }
            }
            None => {
                let mut pending = self.pending_mdns.lock().unwrap();
                let slot = pending.entry(ip).or_default();
                merge_mdns(slot, info);
            }
        }
    }

    pub fn update_device(&self, mac: &str, f: impl FnOnce(&mut Device)) -> Result<(), String> {
        let mut store = self.store.lock().unwrap();
        let dev = store.devices.get_mut(mac).ok_or("unknown device")?;
        f(dev);
        store.save();
        drop(store);
        self.emit_devices();
        Ok(())
    }

    pub fn trust_all(&self) {
        let mut store = self.store.lock().unwrap();
        store.devices.values_mut().for_each(|d| d.trusted = true);
        store.save();
        drop(store);
        self.emit_devices();
    }

    pub fn forget_device(&self, mac: &str) {
        let mut store = self.store.lock().unwrap();
        store.devices.remove(mac);
        store.save();
        drop(store);
        self.emit_devices();
    }

    pub fn check_ports(self: &Arc<Self>, mac: String) -> Result<(), String> {
        let ip: Ipv4Addr = {
            let store = self.store.lock().unwrap();
            let dev = store.devices.get(&mac).ok_or("unknown device")?;
            dev.ip.parse().map_err(|_| "device has no IPv4 address")?
        };
        if !self.in_subnet(ip) && self.net.read().unwrap().as_ref().map(|n| n.ip) != Some(ip) {
            return Err("only devices on your own network can be checked".into());
        }
        let core = self.clone();
        thread::spawn(move || {
            let open = discovery::check_ports(ip);
            let risky: Vec<String> = RISKY_PORTS
                .iter()
                .filter(|(p, _)| open.contains(p))
                .map(|(p, name)| format!("{name} ({p})"))
                .collect();
            let mut described = None;
            let _ = core.update_device(&mac, |d| {
                d.open_ports = Some(open);
                d.ports_checked_at = Some(now_ms());
                described = Some(describe(d));
            });
            if let (false, Some(name)) = (risky.is_empty(), described) {
                core.alert(AlertDraft {
                    severity: Severity::Low,
                    kind: "exposed_service",
                    key: mac.clone(),
                    title: format!("Remote-access service open on {name}"),
                    detail: format!(
                        "{name} at {ip} accepts connections on {}. These services are often unencrypted or weakly protected — turn them off if you don't use them.",
                        risky.join(", ")
                    ),
                });
            }
        });
        Ok(())
    }

    // ------------------------------------------------------------ scanning

    pub fn scan(self: &Arc<Self>) -> bool {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return false;
        }
        let core = self.clone();
        thread::spawn(move || {
            let result = core.run_scan();
            core.scanning.store(false, Ordering::SeqCst);
            core.emit_scan(false, result.unwrap_or_else(|e| e));
        });
        true
    }

    fn run_scan(self: &Arc<Self>) -> Result<String, String> {
        let started = now_ms();
        self.emit_scan(true, "Reading network settings");
        let previous = self.net.read().unwrap().clone();
        let net = self.refresh_net().ok_or("Not connected to a network")?;
        if previous.is_some_and(|p| p.ip != net.ip || p.interface != net.interface) {
            self.restart_on_network_change();
        }

        if let Some(mac) = &net.mac {
            let host = sysinfo::System::host_name()
                .map(|h| h.trim_end_matches(".local").to_string());
            self.observe(mac, net.ip, "self", host);
            let _ = self.update_device(mac, |d| {
                d.is_self = true;
                d.trusted = true;
            });
        }
        if let (Some(ip), Some(mac)) = (net.gateway_ip, &net.gateway_mac) {
            self.observe(mac, ip, "gateway", None);
            let _ = self.update_device(mac, |d| d.is_gateway = true);
        }

        let hosts = net::subnet_hosts(net.ip, net.prefix);
        self.emit_scan(true, format!("Probing {} addresses", hosts.len()));
        let local_ip = net.ip;
        let ssdp = thread::spawn(move || discovery::ssdp_search(local_ip, Duration::from_secs(4)));
        if let Some(sock) = self.mdns_sock.lock().unwrap().as_ref() {
            discovery::send_mdns_queries(sock);
        }
        // The ARP table keeps entries for many minutes after a device leaves,
        // so an entry alone doesn't prove a device is here. Only fresh
        // evidence counts: a reply, or an ARP answer (see `ArpMemory`).
        let before = discovery::read_arp_table(&net.interface, net.ip);
        let mut fresh = self.arp_memory.lock().unwrap().fresh(&before, now_ms());
        // Pinging every address also makes the OS resolve each one via ARP.
        let mut replies = match ping::ping_many(&hosts, Duration::from_millis(2500)) {
            Ok(r) => r,
            Err(_) => {
                discovery::poke_hosts(&hosts);
                thread::sleep(Duration::from_millis(1500));
                // A second pass catches devices that were slow to wake their radios.
                discovery::poke_hosts(&hosts);
                thread::sleep(Duration::from_millis(1500));
                HashMap::new()
            }
        };

        self.emit_scan(true, "Reading ARP table");
        let table: Vec<_> = discovery::read_arp_table(&net.interface, net.ip)
            .into_iter()
            .filter(|e| self.in_subnet(e.ip))
            .collect();
        fresh.extend(self.arp_memory.lock().unwrap().fresh(&table, now_ms()));
        let unconfirmed: Vec<Ipv4Addr> = table
            .iter()
            .filter(|e| !replies.contains_key(&e.ip) && !fresh.contains(&e.ip))
            .map(|e| e.ip)
            .collect();
        if !unconfirmed.is_empty() {
            self.emit_scan(true, "Checking devices that ignore ping");
            replies.extend(ping::tcp_probe_many(&unconfirmed, Duration::from_millis(900)));
        }
        for e in &table {
            let reply = replies.get(&e.ip).copied();
            if fresh.contains(&e.ip) || reply.is_some() {
                self.observe_with(&e.mac, e.ip, "arp", None, |d| apply_reply(d, reply));
            }
        }

        self.emit_scan(true, "Asking devices to identify themselves");
        for info in ssdp.join().unwrap_or_default() {
            if Some(info.ip) == net.gateway_ip {
                if let Some(url) = &info.location {
                    self.set_router_hint(url.clone());
                }
            }
            self.apply_ssdp(info);
        }

        self.emit_scan(true, "Resolving names");
        let unnamed: Vec<Ipv4Addr> = {
            let store = self.store.lock().unwrap();
            store
                .devices
                .values()
                .filter(|d| d.last_seen >= started && d.hostname.is_none())
                .filter_map(|d| d.ip.parse().ok())
                .collect()
        };
        if let Some(sock) = self.mdns_sock.lock().unwrap().as_ref() {
            discovery::send_reverse_queries(sock, &unnamed);
        }
        let names = discovery::reverse_lookup(unnamed, Duration::from_secs(5));
        {
            let mut store = self.store.lock().unwrap();
            for (ip, name) in names {
                if let Some(d) = store.by_ip_mut(ip) {
                    d.hostname.get_or_insert(name);
                }
            }
            store.save();
        }
        self.baseline.store(true, Ordering::SeqCst);
        self.update_presence();
        self.emit_devices();

        let online = self
            .store
            .lock()
            .unwrap()
            .devices
            .values()
            .filter(|d| d.last_seen >= started)
            .count();
        Ok(format!("Found {online} devices online"))
    }

    fn apply_ssdp(&self, info: SsdpInfo) {
        let mut store = self.store.lock().unwrap();
        let Some(d) = store.by_ip_mut(info.ip) else { return };
        d.services.insert("upnp".into());
        if d.friendly_name.is_none() {
            d.friendly_name = info.friendly_name;
        }
        if d.model.is_none() {
            d.model = info.model.or(info.server);
        }
        if d.vendor.is_none() {
            d.vendor = info.manufacturer;
        }
    }

    fn restart_on_network_change(self: &Arc<Self>) {
        self.reset_router();
        self.start_mdns();
        let running = matches!(self.capture.lock().unwrap().0, CaptureStatus::Running { .. });
        if running {
            self.stop_capture();
            self.start_capture();
        }
    }

    fn start_mdns(self: &Arc<Self>) {
        let Some(net) = self.net.read().unwrap().clone() else { return };
        let sock = match discovery::mdns_socket(net.ip) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mDNS listener unavailable: {e}");
                return;
            }
        };
        let Ok(recv) = sock.try_clone() else { return };
        let _ = recv.set_read_timeout(Some(Duration::from_secs(2)));
        *self.mdns_sock.lock().unwrap() = Some(sock);
        let generation = self.mdns_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let core = self.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 9000];
            // A network change starts a new listener; this one then retires.
            while core.mdns_generation.load(Ordering::SeqCst) == generation {
                match recv.recv_from(&mut buf) {
                    Ok((n, SocketAddr::V4(from))) => {
                        if let Some(info) = discovery::parse_mdns(*from.ip(), &buf[..n]) {
                            core.on_mdns(info);
                        }
                    }
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(_) => break,
                }
            }
        });
    }

    // ------------------------------------------------------------ capture

    pub fn start_capture(self: &Arc<Self>) -> CaptureStatus {
        let mut cap = self.capture.lock().unwrap();
        if matches!(cap.0, CaptureStatus::Running { .. }) {
            return cap.0.clone();
        }
        let status = match self.net.read().unwrap().clone() {
            None => CaptureStatus::Error {
                message: "Not connected to a network".into(),
            },
            Some(net) => {
                let analyzer = Analyzer::new(
                    detect::Config {
                        local_mac: net.mac.clone(),
                        local_ips: net.local_ips.iter().copied().collect(),
                        gateway_ip: net.gateway_ip,
                        gateway_mac: net.gateway_mac.clone(),
                    },
                    self.blocklist.clone(),
                    self.dns_names.clone(),
                    now_ms(),
                );
                let stop = Arc::new(AtomicBool::new(false));
                let (on_events, on_tick, on_exit) = (self.clone(), self.clone(), self.clone());
                let exit_stop = stop.clone();
                match capture::start(
                    net.ip,
                    analyzer,
                    stop.clone(),
                    move |events| on_events.on_capture_events(events),
                    move |snap| on_tick.on_traffic(snap),
                    move |err| on_exit.on_capture_exit(&exit_stop, err),
                ) {
                    Ok(interface) => {
                        cap.1 = Some(stop);
                        CaptureStatus::Running { interface }
                    }
                    Err(s) => s,
                }
            }
        };
        cap.0 = status.clone();
        drop(cap);
        self.emit("capture", status.clone());
        match &status {
            CaptureStatus::NeedsPermission { .. } if self.quiet_start.swap(false, Ordering::SeqCst) => {
                self.notify_capture_blocked()
            }
            CaptureStatus::Running { .. } => self.quiet_start.store(false, Ordering::SeqCst),
            _ => {}
        }
        status
    }

    pub fn stop_capture(&self) -> CaptureStatus {
        let mut cap = self.capture.lock().unwrap();
        if let Some(stop) = cap.1.take() {
            stop.store(true, Ordering::SeqCst);
        }
        cap.0 = CaptureStatus::Stopped;
        drop(cap);
        self.emit("capture", CaptureStatus::Stopped);
        CaptureStatus::Stopped
    }

    pub fn grant_capture_access(self: &Arc<Self>) -> Result<CaptureStatus, String> {
        if capture::grant_access()? {
            Ok(self.start_capture())
        } else {
            Err("Access wasn't granted.".into())
        }
    }

    fn on_capture_exit(&self, stop: &Arc<AtomicBool>, error: Option<String>) {
        let Some(message) = error else { return };
        let mut cap = self.capture.lock().unwrap();
        // Only report if this is still the active capture session.
        if cap.1.as_ref().is_some_and(|s| Arc::ptr_eq(s, stop)) {
            cap.1 = None;
            cap.0 = CaptureStatus::Error { message };
            let status = cap.0.clone();
            drop(cap);
            self.emit("capture", status);
        }
    }

    fn on_capture_events(&self, events: Vec<Event>) {
        for e in events {
            match e {
                Event::Alert(d) => self.alert(d),
                Event::Device {
                    mac,
                    ip,
                    hostname,
                    source,
                    fingerprint,
                } => {
                    if self.in_subnet(ip) {
                        self.observe_with(&mac, ip, source, hostname, |d| match fingerprint {
                            Some((vendor, params)) => {
                                let before = (d.dhcp_vendor.clone(), d.dhcp_params.clone());
                                d.dhcp_vendor = vendor.or(d.dhcp_vendor.take());
                                d.dhcp_params = params.or(d.dhcp_params.take());
                                before != (d.dhcp_vendor.clone(), d.dhcp_params.clone())
                            }
                            None => false,
                        });
                    }
                }
                Event::Dns(entry) => {
                    let mut log = self.dns_log.lock().unwrap();
                    log.push_back(entry.clone());
                    if log.len() > DNS_LOG_LEN {
                        log.pop_front();
                    }
                    self.dns_pending.lock().unwrap().push(entry);
                }
            }
        }
    }

    fn on_traffic(&self, snap: TrafficSnapshot) {
        *self.traffic.lock().unwrap() = snap.clone();
        self.emit("traffic", snap);
        let dns: Vec<DnsEntry> = std::mem::take(&mut *self.dns_pending.lock().unwrap());
        if !dns.is_empty() {
            self.emit("dns", dns);
        }
    }

    // ------------------------------------------------------------ connections

    /// Lists sockets and alerts on any connection to a known botnet server.
    /// Works without packet capture.
    pub fn connections(&self) -> Result<Vec<Conn>, String> {
        let list = {
            let names = self.dns_names.read().unwrap();
            let bl = self.blocklist.read().unwrap();
            conns::list(&mut self.sys.lock().unwrap(), &names, &bl)?
        };
        for c in list.iter().filter(|c| c.flagged) {
            let who = c.process.clone().unwrap_or_else(|| "A process".into());
            let remote = c.remote_ip.clone().unwrap_or_default();
            self.alert(AlertDraft {
                severity: Severity::High,
                kind: "c2_connection",
                key: format!("{who}->{remote}"),
                title: format!("{who} is connected to a blocklisted server"),
                detail: format!(
                    "{who} (pid {}) has a {} connection to {remote}:{}, which is on a botnet or malware blocklist (see Settings). Consider quitting it and running a malware scan.",
                    c.pid.map_or("?".into(), |p| p.to_string()),
                    c.proto,
                    c.remote_port.unwrap_or(0)
                ),
            });
        }
        Ok(list)
    }

    // ------------------------------------------------------------ feeds

    pub fn feed_info(&self) -> FeedInfo {
        FeedInfo {
            blocklist: self.blocklist.read().unwrap().info(),
            vendors: self.oui.read().unwrap().entries,
            updating: self.feeds_updating.load(Ordering::SeqCst),
            error: self.feeds_error.lock().unwrap().clone(),
        }
    }

    /// Refreshes threat feeds and the vendor database when stale (or always, if forced).
    pub fn update_feeds(self: &Arc<Self>, force: bool) {
        let blocklist_stale = blocklist::any_due(&self.dir);
        let manuf = self.dir.join("manuf.txt");
        let vendors_stale = std::fs::metadata(&manuf)
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().map_or(true, |age| age.as_millis() as u64 > VENDOR_DB_MAX_AGE_MS))
            .unwrap_or(true);
        if !(force || blocklist_stale || vendors_stale) {
            return;
        }
        if self.feeds_updating.swap(true, Ordering::SeqCst) {
            return;
        }
        self.emit("feeds", self.feed_info());
        let core = self.clone();
        thread::spawn(move || {
            let mut errors = Vec::new();
            if force || blocklist_stale {
                if let Err(e) = blocklist::download(&core.dir, force) {
                    errors.push(e);
                }
                *core.blocklist.write().unwrap() = Blocklist::load(&core.dir);
            }
            if force || vendors_stale {
                match oui::download(&manuf) {
                    Ok(_) => {
                        *core.oui.write().unwrap() = Oui::load(&manuf);
                        core.fill_vendors();
                    }
                    Err(e) => errors.push(e),
                }
            }
            *core.feeds_error.lock().unwrap() = (!errors.is_empty()).then(|| errors.join("; "));
            core.feeds_updating.store(false, Ordering::SeqCst);
            core.emit("feeds", core.feed_info());
        });
    }

    fn fill_vendors(&self) {
        let mut store = self.store.lock().unwrap();
        for d in store.devices.values_mut().filter(|d| d.vendor.is_none()) {
            d.vendor = self.vendor_for(&d.mac);
        }
        store.save();
        drop(store);
        self.emit_devices();
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }

    pub fn set_settings(&self, s: Settings) -> Result<Settings, String> {
        let s = s.sanitized();
        s.save(&self.dir.join("settings.json"))?;
        let (lookup_turned_on, login_changed, schedule_changed, location_changed) = {
            let mut cur = self.settings.write().unwrap();
            let on = s.public_ip_lookup && !cur.public_ip_lookup;
            let login = s.launch_at_login != cur.launch_at_login;
            let schedule = s.speedtest_schedule != cur.speedtest_schedule;
            let location = s.location != cur.location;
            *cur = s.clone();
            (on, login, schedule, location)
        };
        if lookup_turned_on {
            self.public_refresh.store(true, Ordering::SeqCst);
        }
        if login_changed {
            crate::login::apply(&self.app, s.launch_at_login);
        }
        self.export.configure(ExportConfig::from_settings(&s));
        if schedule_changed {
            self.speedtest_schedule_changed(&s.speedtest_schedule);
        }
        self.check_data_cap();
        self.check_forecast();
        if location_changed {
            // The location worker notices by itself (it asks macOS for
            // permission on turning on); this just updates the window and
            // the Wi-Fi names now.
            self.wifi_refresh.store(true, Ordering::SeqCst);
            self.emit("location", self.location_info());
        }
        self.emit("settings", s.clone());
        Ok(s)
    }

    /// Sends one test event to the SIEM target in the saved settings. Looks the
    /// name up, so call it off the main thread. Returns the target.
    pub fn send_test_event(&self) -> Result<String, String> {
        export::send_test(&ExportConfig::from_settings(&self.settings()), now_ms())
    }

    pub fn refresh_public(&self) {
        self.public_refresh.store(true, Ordering::SeqCst);
    }

    /// Sends a Wake-on-LAN packet to a known device.
    pub fn wake_device(&self, mac: &str) -> Result<(), String> {
        if !self.store.lock().unwrap().devices.contains_key(mac) {
            return Err("unknown device".into());
        }
        let net = self.net.read().unwrap().clone().ok_or("Not connected to a network")?;
        crate::tools::wake(mac, net.ip, net.prefix)
    }

    /// Checks this computer's DNS servers against well-known public ones.
    pub fn dns_check(&self) -> Vec<crate::tools::DnsResult> {
        use crate::tools;
        let net = self.net.read().unwrap().clone();
        let mut servers: Vec<(IpAddr, String)> = Vec::new();
        for ip in net.as_ref().map(|n| n.dns_servers.clone()).unwrap_or_default() {
            let label = if net.as_ref().and_then(|n| n.gateway_ip).map(IpAddr::V4) == Some(ip) {
                "Your DNS (router)".to_string()
            } else {
                tools::resolver_name(&ip).map_or("Your DNS".to_string(), |n| format!("Your DNS ({n})"))
            };
            servers.push((ip, label));
        }
        for (ip, name) in [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")] {
            let ip: IpAddr = ip.parse().expect("valid");
            if !servers.iter().any(|(s, _)| *s == ip) {
                servers.push((ip, name.to_string()));
            }
        }
        let results = tools::dns_check(&servers, now_ms());
        for r in results.iter().filter(|r| r.label.starts_with("Your DNS") && r.nxdomain_hijack) {
            if !self.alerts.lock().unwrap().has("dns_hijack", &r.server) {
                self.alert(AlertDraft {
                    severity: Severity::Low,
                    kind: "dns_hijack",
                    key: r.server.clone(),
                    title: "Your DNS server redirects addresses that don't exist".into(),
                    detail: format!(
                        "{} returned an address for a made-up domain instead of saying it doesn't exist. Providers do this to show ads or search pages for typos, and it can break some apps. Switching your router's DNS to a public resolver such as Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) avoids it.",
                        r.server
                    ),
                });
            }
        }
        results
    }

    /// Writes an export (built by the UI) to the Downloads folder.
    pub fn save_export(&self, name: &str, content: &str) -> Result<String, String> {
        let ok = (name.ends_with(".csv") || name.ends_with(".html"))
            && name.starts_with("NetWatch-")
            && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if !ok {
            return Err("invalid file name".into());
        }
        let dir = self.app.path().download_dir().map_err(|e| e.to_string())?;
        let path = dir.join(name);
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(path.display().to_string())
    }

    /// Opens an export NetWatch wrote to Downloads in its default app.
    pub fn open_export(&self, path: &str) -> Result<(), String> {
        let dir = self.app.path().download_dir().map_err(|e| e.to_string())?;
        let p = std::path::Path::new(path);
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.parent() != Some(dir.as_path()) || !name.starts_with("NetWatch-") || !(name.ends_with(".html") || name.ends_with(".csv")) {
            return Err("not a NetWatch export".into());
        }
        #[cfg(target_os = "macos")]
        let r = std::process::Command::new("open").arg(p).spawn();
        #[cfg(windows)]
        let r = crate::util::quiet_command("explorer").arg(p).spawn();
        #[cfg(target_os = "linux")]
        let r = std::process::Command::new("xdg-open").arg(p).spawn();
        r.map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn custom_blocklist(&self) -> String {
        std::fs::read_to_string(self.dir.join(blocklist::CUSTOM_FILE)).unwrap_or_default()
    }

    pub fn set_custom_blocklist(&self, text: &str) -> Result<(), String> {
        std::fs::write(self.dir.join(blocklist::CUSTOM_FILE), text).map_err(|e| e.to_string())?;
        *self.blocklist.write().unwrap() = Blocklist::load(&self.dir);
        self.emit("feeds", self.feed_info());
        Ok(())
    }
}

fn merge_mdns(into: &mut MdnsInfo, from: MdnsInfo) {
    into.ip = into.ip.or(from.ip);
    into.hostname = into.hostname.take().or(from.hostname);
    into.friendly_name = into.friendly_name.take().or(from.friendly_name);
    into.model = into.model.take().or(from.model);
    into.services.extend(from.services);
}

/// Folds mDNS details into a device. Returns whether anything changed.
fn apply_mdns(d: &mut Device, info: &MdnsInfo) -> bool {
    let before = (
        d.hostname.clone(),
        d.friendly_name.clone(),
        d.model.clone(),
        d.services.len(),
    );
    if d.hostname.is_none() {
        d.hostname = info.hostname.clone();
    }
    if d.friendly_name.is_none() {
        d.friendly_name = info.friendly_name.clone();
    }
    if d.model.is_none() {
        d.model = info.model.clone();
    }
    d.services.extend(info.services.iter().cloned());
    if !info.services.is_empty() {
        d.sources.insert("mdns".into());
    }
    before
        != (
            d.hostname.clone(),
            d.friendly_name.clone(),
            d.model.clone(),
            d.services.len(),
        )
}

/// Stores what a ping or TCP probe learned. Never "changes" the device in a
/// way that needs an immediate UI push; the periodic refresh shows it.
fn apply_reply(d: &mut Device, reply: Option<ping::Reply>) -> bool {
    if let Some(r) = reply {
        d.last_reply = now_ms();
        d.rtt_ms = Some((r.rtt_ms * 10.0).round() / 10.0);
        if r.ttl.is_some() {
            d.ttl = r.ttl;
        }
    }
    false
}

fn describe(d: &Device) -> String {
    d.label
        .clone()
        .or_else(|| d.friendly_name.clone())
        .or_else(|| d.hostname.clone())
        .or_else(|| d.vendor.as_ref().map(|v| format!("{v} device")))
        .unwrap_or_else(|| {
            if is_randomized_mac(&d.mac) {
                "A device with a private MAC address".into()
            } else {
                "An unknown device".into()
            }
        })
}

fn new_device_alert(d: &Device) -> AlertDraft {
    let name = describe(d);
    let privacy = if is_randomized_mac(&d.mac) {
        " It uses a randomized MAC address, which phones and laptops do for Wi-Fi privacy."
    } else {
        ""
    };
    AlertDraft {
        severity: Severity::Medium,
        kind: "new_device",
        key: d.mac.clone(),
        title: format!("New device joined: {name}"),
        detail: format!(
            "{name} ({}, MAC {}) appeared on your network for the first time.{privacy} If you don't recognize it, mark it trusted once identified or change your Wi-Fi password.",
            d.ip, d.mac
        ),
    }
}

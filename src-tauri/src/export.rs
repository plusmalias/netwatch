//! Log export: every new alert can be appended to a JSON-lines file in the
//! data folder and/or sent to a SIEM or log collector as a syslog message over
//! UDP. Messages are RFC 5424 syslog whose payload is ArcSight CEF or the
//! alert as JSON.
//!
//! Exports run on their own thread, fed through a bounded queue, so raising an
//! alert never waits on the disk or a slow DNS lookup. If the queue is ever
//! full the alert is dropped from the export (it is still in the alert list).
//! Messages go only to the configured `siem_target`.

use crate::alerts::{Alert, Severity};
use crate::settings::{valid_siem_target, Settings};
use chrono::SecondsFormat;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock, RwLock};
use std::thread;

pub const LOG_NAME: &str = "alerts.jsonl";
pub const LOG_ROTATED: &str = "alerts.1.jsonl";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const QUEUE_LEN: usize = 256;
/// Syslog facility local0: the usual home for an application's own events.
const FACILITY: u8 = 16;
/// Limits that keep a syslog datagram far below the UDP maximum.
const MAX_TITLE: usize = 200;
const MAX_KEY: usize = 200;
const MAX_DETAIL: usize = 1000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Cef,
    Json,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportConfig {
    pub log_file: bool,
    /// "host:port", validated; `None` means forwarding is off.
    pub siem_target: Option<String>,
    pub format: Format,
}

impl ExportConfig {
    pub fn from_settings(s: &Settings) -> Self {
        ExportConfig {
            log_file: s.log_file,
            siem_target: Some(s.siem_target.trim().to_string()).filter(|t| valid_siem_target(t)),
            format: if s.siem_format == "json" { Format::Json } else { Format::Cef },
        }
    }

    fn is_off(&self) -> bool {
        !self.log_file && self.siem_target.is_none()
    }
}

// ------------------------------------------------------------ message formats

/// CEF severity, 0-10 (0-3 low, 4-6 medium, 7-8 high, 9-10 very high).
pub fn cef_severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
    }
}

/// Syslog severity (RFC 5424 table 2): 3 error, 4 warning, 5 notice, 6 informational.
pub fn syslog_severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 6,
        Severity::Low => 5,
        Severity::Medium => 4,
        Severity::High => 3,
    }
}

/// Escapes a CEF header field: `\` and `|` get a backslash. A header must stay
/// on one line, so line breaks (and other control characters) become spaces.
pub fn cef_header_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Escapes a CEF extension value: `\` and `=` get a backslash and line breaks
/// are written as `\n` and `\r`. `|` is left alone, as the format says.
pub fn cef_ext_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push('\t'),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max - 1).chain(['…']).collect()
    }
}

/// `CEF:0|NetWatch|NetWatch|<version>|<kind>|<title>|<severity>|<extensions>`.
pub fn cef_message(a: &Alert) -> String {
    format!(
        "CEF:0|NetWatch|NetWatch|{}|{}|{}|{}|rt={} externalId={} cs1Label=alertKey cs1={} msg={}",
        cef_header_escape(env!("CARGO_PKG_VERSION")),
        cef_header_escape(&a.kind),
        cef_header_escape(&a.title),
        cef_severity(a.severity),
        a.ts,
        a.id,
        cef_ext_escape(&a.key),
        cef_ext_escape(&a.detail),
    )
}

/// The alert as one line of JSON (no raw line breaks, so it is JSONL-safe).
pub fn json_line(a: &Alert) -> String {
    serde_json::to_string(a).unwrap_or_default()
}

/// A syslog header field: printable ASCII without spaces, at most `max` long,
/// or the nil value "-".
fn header_token(s: &str, max: usize) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '-' })
        .take(max)
        .collect();
    if t.is_empty() { "-".into() } else { t }
}

/// Wraps `payload` in an RFC 5424 syslog message:
/// `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`.
pub fn syslog_frame(a: &Alert, payload: &str, host: &str, pid: u32) -> String {
    let ts = i64::try_from(a.ts)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or("-".to_string(), |t| t.to_rfc3339_opts(SecondsFormat::Millis, true));
    format!(
        "<{}>1 {ts} {} NetWatch {pid} {} - {payload}",
        FACILITY * 8 + syslog_severity(a.severity),
        header_token(host, 255),
        header_token(&a.kind, 32),
    )
}

/// The complete datagram for an alert.
pub fn syslog_message(a: &Alert, format: Format, host: &str, pid: u32) -> String {
    let a = Alert {
        title: clip(&a.title, MAX_TITLE),
        key: clip(&a.key, MAX_KEY),
        detail: clip(&a.detail, MAX_DETAIL),
        ..a.clone()
    };
    let payload = match format {
        Format::Cef => cef_message(&a),
        Format::Json => json_line(&a),
    };
    syslog_frame(&a, &payload, host, pid)
}

fn hostname() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| sysinfo::System::host_name().unwrap_or_default())
}

pub fn test_alert(now: u64) -> Alert {
    Alert {
        id: 0,
        ts: now,
        last_ts: now,
        count: 1,
        severity: Severity::Info,
        kind: "test".into(),
        key: "test".into(),
        title: "NetWatch test event".into(),
        detail: "This is a test event from NetWatch. If you can read it, forwarding works.".into(),
        acknowledged: false,
    }
}

// ------------------------------------------------------------ outputs

/// Appends one line to `alerts.jsonl` in `dir`. When the line would push the
/// file past `max_bytes`, the file first becomes `alerts.1.jsonl` (replacing
/// the previous one).
pub fn append_line(dir: &Path, line: &str, max_bytes: u64) -> std::io::Result<()> {
    let path = dir.join(LOG_NAME);
    let size = std::fs::metadata(&path).map_or(0, |m| m.len());
    if size > 0 && size + line.len() as u64 + 1 > max_bytes {
        let old = dir.join(LOG_ROTATED);
        // Renaming onto an existing file fails on Windows.
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&path, &old)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(format!("{line}\n").as_bytes())
}

/// Sends one UDP datagram to `target` ("host:port"). A name that resolves to
/// several addresses gets the first IPv4 one (else the first).
pub fn send_udp(target: &str, msg: &[u8]) -> Result<SocketAddr, String> {
    if !valid_siem_target(target) {
        return Err(format!("\"{target}\" isn't a host:port"));
    }
    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|e| format!("Can't look up {target}: {e}"))?
        .collect();
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| format!("Can't look up {target}"))?;
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.send_to(msg, addr).map_err(|e| format!("Couldn't send to {target}: {e}"))?;
    Ok(addr)
}

/// "Send test event": one info-level event to the configured target.
/// Returns the target it went to.
pub fn send_test(cfg: &ExportConfig, now: u64) -> Result<String, String> {
    let target = cfg
        .siem_target
        .as_deref()
        .ok_or("Enter a target (host:port) first")?;
    let msg = syslog_message(&test_alert(now), cfg.format, hostname(), std::process::id());
    send_udp(target, msg.as_bytes())?;
    Ok(target.to_string())
}

fn deliver(dir: &Path, cfg: &ExportConfig, a: &Alert) {
    if cfg.log_file {
        if let Err(e) = append_line(dir, &json_line(a), MAX_LOG_BYTES) {
            eprintln!("alert log file: {e}");
        }
    }
    if let Some(target) = &cfg.siem_target {
        let msg = syslog_message(a, cfg.format, hostname(), std::process::id());
        if let Err(e) = send_udp(target, msg.as_bytes()) {
            eprintln!("alert forwarding: {e}");
        }
    }
}

pub struct Exporter {
    dir: PathBuf,
    cfg: Arc<RwLock<ExportConfig>>,
    tx: SyncSender<Alert>,
}

impl Exporter {
    pub fn start(dir: PathBuf, cfg: ExportConfig) -> Self {
        let cfg = Arc::new(RwLock::new(cfg));
        let (tx, rx) = sync_channel::<Alert>(QUEUE_LEN);
        {
            let (dir, cfg) = (dir.clone(), cfg.clone());
            thread::spawn(move || {
                for a in rx {
                    let c = cfg.read().unwrap().clone();
                    deliver(&dir, &c, &a);
                }
            });
        }
        let e = Exporter { dir, cfg, tx };
        e.touch_log();
        e
    }

    /// Hands a new alert to the export thread. Never blocks.
    pub fn alert(&self, a: &Alert) {
        if self.cfg.read().unwrap().is_off() {
            return;
        }
        match self.tx.try_send(a.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => eprintln!("alert export queue full; alert not exported"),
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    pub fn configure(&self, cfg: ExportConfig) {
        *self.cfg.write().unwrap() = cfg;
        self.touch_log();
    }

    /// With the log on, the file exists right away so "Show log file" has
    /// something to reveal.
    fn touch_log(&self) {
        if self.cfg.read().unwrap().log_file {
            let r = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join(LOG_NAME));
            if let Err(e) = r {
                eprintln!("alert log file: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const TS: u64 = 1_700_000_000_123; // 2023-11-14T22:13:20.123Z

    fn alert(id: u64, sev: Severity, title: &str, detail: &str) -> Alert {
        Alert {
            id,
            ts: TS,
            last_ts: TS,
            count: 1,
            severity: sev,
            kind: "arp_spoof".into(),
            key: "192.168.1.1".into(),
            title: title.into(),
            detail: detail.into(),
            acknowledged: false,
        }
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("netwatch-export-test-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Splits a CEF line at its unescaped pipes.
    fn cef_fields(s: &str) -> Vec<String> {
        let (mut out, mut cur, mut esc) = (Vec::new(), String::new(), false);
        for c in s.chars() {
            if esc {
                cur.push('\\');
                cur.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '|' && out.len() < 7 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        out.push(cur);
        out
    }

    #[test]
    fn cef_header_escapes_pipe_and_backslash_only() {
        assert_eq!(cef_header_escape("a|b"), "a\\|b");
        assert_eq!(cef_header_escape("a\\b"), "a\\\\b");
        assert_eq!(cef_header_escape("a\\|b"), "a\\\\\\|b");
        // `=` is only special in the extension; a header must be one line.
        assert_eq!(cef_header_escape("a=b"), "a=b");
        assert_eq!(cef_header_escape("a\nb\rc"), "a b c");
        assert_eq!(cef_header_escape("Résumé ✓"), "Résumé ✓");
    }

    #[test]
    fn cef_extension_escapes_backslash_equals_and_newlines_only() {
        assert_eq!(cef_ext_escape("a=b"), "a\\=b");
        assert_eq!(cef_ext_escape("a\\b"), "a\\\\b");
        assert_eq!(cef_ext_escape("a\nb"), "a\\nb");
        assert_eq!(cef_ext_escape("a\r\nb"), "a\\r\\nb");
        // Pipes are fine in an extension.
        assert_eq!(cef_ext_escape("a|b"), "a|b");
        assert_eq!(cef_ext_escape("x=1\\n"), "x\\=1\\\\n");
    }

    #[test]
    fn severity_mapping() {
        use Severity::*;
        assert_eq!([Info, Low, Medium, High].map(cef_severity), [1, 3, 5, 8]);
        assert!([Info, Low, Medium, High].iter().all(|s| cef_severity(*s) <= 10));
        assert_eq!([Info, Low, Medium, High].map(syslog_severity), [6, 5, 4, 3]);
        // Higher severity is never a larger syslog number.
        assert!(syslog_severity(High) < syslog_severity(Info));
    }

    #[test]
    fn cef_message_has_eight_fields_and_escaped_values() {
        let a = alert(7, Severity::High, "Router | MAC \\ changed = bad", "line one\nline two with a=b and c|d");
        let m = cef_message(&a);
        let f = cef_fields(&m);
        assert_eq!(f.len(), 8, "{m}");
        assert_eq!(f[0], "CEF:0");
        assert_eq!(f[1], "NetWatch");
        assert_eq!(f[2], "NetWatch");
        assert_eq!(f[3], env!("CARGO_PKG_VERSION"));
        assert_eq!(f[4], "arp_spoof");
        assert_eq!(f[5], "Router \\| MAC \\\\ changed = bad");
        assert_eq!(f[6], "8");
        assert_eq!(
            f[7],
            "rt=1700000000123 externalId=7 cs1Label=alertKey cs1=192.168.1.1 msg=line one\\nline two with a\\=b and c|d"
        );
        assert!(!m.contains('\n'));
    }

    #[test]
    fn syslog_framing_follows_rfc_5424() {
        let a = alert(1, Severity::Medium, "t", "d");
        let m = syslog_message(&a, Format::Cef, "mac.local", 4242);
        let mut p = m.splitn(8, ' ');
        // <PRI> = facility 16 * 8 + severity 4 (warning), then VERSION 1.
        assert_eq!(p.next(), Some("<132>1"));
        assert_eq!(p.next(), Some("2023-11-14T22:13:20.123Z"));
        assert_eq!(p.next(), Some("mac.local"));
        assert_eq!(p.next(), Some("NetWatch"));
        assert_eq!(p.next(), Some("4242"));
        assert_eq!(p.next(), Some("arp_spoof"));
        assert_eq!(p.next(), Some("-")); // no structured data
        assert!(p.next().unwrap().starts_with("CEF:0|NetWatch|NetWatch|"));
        for (sev, pri) in [(Severity::High, 131), (Severity::Low, 133), (Severity::Info, 134)] {
            let m = syslog_message(&alert(1, sev, "t", "d"), Format::Cef, "h", 1);
            assert!(m.starts_with(&format!("<{pri}>1 ")), "{m}");
        }
    }

    #[test]
    fn syslog_header_fields_are_printable_ascii_without_spaces() {
        let a = alert(1, Severity::Low, "t", "d");
        let m = syslog_message(&a, Format::Json, "Maka’s Mac mini", 1);
        assert_eq!(m.split(' ').nth(2), Some("Maka-s-Mac-mini"));
        // An empty host name and an odd kind become the nil value / hyphens.
        let mut b = a.clone();
        b.kind = "wéird kind".into();
        let m = syslog_message(&b, Format::Json, "", 1);
        let parts: Vec<&str> = m.splitn(8, ' ').collect();
        assert_eq!(parts[2], "-");
        assert_eq!(parts[5], "w-ird-kind");
        assert_eq!(header_token(&"x".repeat(100), 32).len(), 32);
        // A timestamp that can't be represented is the nil value.
        let mut c = a;
        c.ts = i64::MAX as u64;
        assert_eq!(syslog_message(&c, Format::Json, "h", 1).split(' ').nth(1), Some("-"));
    }

    #[test]
    fn json_payload_is_the_alert() {
        let a = alert(9, Severity::High, "Title \"quoted\"", "two\nlines");
        let m = syslog_message(&a, Format::Json, "h", 1);
        let body = m.splitn(8, ' ').nth(7).unwrap();
        let back: Alert = serde_json::from_str(body).unwrap();
        assert_eq!((back.id, back.kind.as_str(), back.title.as_str(), back.detail.as_str()), (9, "arp_spoof", "Title \"quoted\"", "two\nlines"));
        assert_eq!(back.severity, Severity::High);
        assert!(!body.contains('\n'));
    }

    #[test]
    fn oversized_alerts_are_clipped() {
        let big = "x".repeat(50_000);
        let m = syslog_message(&alert(1, Severity::Low, &big, &big), Format::Cef, "h", 1);
        assert!(m.len() < 2_000, "{}", m.len());
        assert!(m.contains('…'));
        let m = syslog_message(&alert(1, Severity::Low, &big, &big), Format::Json, "h", 1);
        assert!(m.len() < 2_000, "{}", m.len());
    }

    #[test]
    fn jsonl_appends_one_line_per_alert_and_rotates() {
        let dir = tmp_dir("jsonl");
        let lines: Vec<String> = (1..=9).map(|i| json_line(&alert(i, Severity::Low, "title", "detail"))).collect();
        let one = lines[0].len() as u64 + 1;
        // Room for exactly four lines per file.
        let max = one * 4 + 2;
        for l in &lines[..4] {
            append_line(&dir, l, max).unwrap();
        }
        let current = dir.join(LOG_NAME);
        let rotated = dir.join(LOG_ROTATED);
        assert!(!rotated.exists());
        assert_eq!(std::fs::read_to_string(&current).unwrap().lines().count(), 4);

        // The fifth line starts a new file and keeps the first four as .1.
        append_line(&dir, &lines[4], max).unwrap();
        assert_eq!(std::fs::read_to_string(&rotated).unwrap().lines().count(), 4);
        assert_eq!(std::fs::read_to_string(&current).unwrap().lines().count(), 1);

        // Rotating again replaces .1; nothing older is kept.
        for l in &lines[5..] {
            append_line(&dir, l, max).unwrap();
        }
        let old = std::fs::read_to_string(&rotated).unwrap();
        let new = std::fs::read_to_string(&current).unwrap();
        let ids: Vec<u64> = old.lines().chain(new.lines()).map(|l| serde_json::from_str::<Alert>(l).unwrap().id).collect();
        assert_eq!(ids, (5..=9).collect::<Vec<u64>>(), "each file is complete JSONL and only the last two files remain");
        assert!(std::fs::metadata(&current).unwrap().len() <= max);
        assert!(!dir.join("alerts.2.jsonl").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_comes_from_validated_settings() {
        let s = Settings { siem_target: "127.0.0.1:514".into(), siem_format: "json".into(), log_file: true, ..Default::default() };
        let c = ExportConfig::from_settings(&s);
        assert_eq!(c, ExportConfig { log_file: true, siem_target: Some("127.0.0.1:514".into()), format: Format::Json });
        assert!(ExportConfig::from_settings(&Settings::default()).is_off());
        // A hand-edited settings file with a bad target still means "off".
        let s = Settings { siem_target: "not a target".into(), ..Default::default() };
        assert_eq!(ExportConfig::from_settings(&s).siem_target, None);
        assert!(send_udp("nonsense", b"x").is_err());
        assert!(send_udp("host:0", b"x").is_err());
        assert!(send_test(&ExportConfig::default(), TS).is_err());
    }

    /// Reads one datagram, waiting up to `wait`.
    fn recv(sock: &UdpSocket, wait: Duration) -> Option<String> {
        sock.set_read_timeout(Some(wait)).unwrap();
        let mut buf = [0u8; 8192];
        sock.recv_from(&mut buf).ok().map(|(n, _)| String::from_utf8(buf[..n].to_vec()).unwrap())
    }

    fn wait_for(mut done: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn loopback_udp_receives_exactly_one_message_per_alert() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = format!("127.0.0.1:{}", sock.local_addr().unwrap().port());
        let dir = tmp_dir("udp");
        let ex = Exporter::start(dir.clone(), ExportConfig { log_file: false, siem_target: Some(target.clone()), format: Format::Cef });

        ex.alert(&alert(3, Severity::High, "Router's MAC changed", "details"));
        let m = recv(&sock, Duration::from_secs(5)).expect("a datagram");
        assert!(m.starts_with("<131>1 2023-11-14T22:13:20.123Z "), "{m}");
        assert!(m.contains(" NetWatch ") && m.contains(" arp_spoof - CEF:0|NetWatch|NetWatch|"), "{m}");
        assert!(m.contains("|Router's MAC changed|8|rt=1700000000123 externalId=3 "), "{m}");
        assert!(recv(&sock, Duration::from_millis(300)).is_none(), "one alert, one message");
        // The log file stays off, and the folder untouched.
        assert!(!dir.join(LOG_NAME).exists());

        // Switching format takes effect for the next alert.
        ex.configure(ExportConfig { log_file: false, siem_target: Some(target), format: Format::Json });
        ex.alert(&alert(4, Severity::Low, "second", "d"));
        let m = recv(&sock, Duration::from_secs(5)).expect("a second datagram");
        assert!(m.starts_with("<133>1 "), "{m}");
        let back: Alert = serde_json::from_str(m.splitn(8, ' ').nth(7).unwrap()).unwrap();
        assert_eq!((back.id, back.title.as_str()), (4, "second"));

        // Turning forwarding off stops the messages.
        ex.configure(ExportConfig::default());
        ex.alert(&alert(5, Severity::High, "third", "d"));
        assert!(recv(&sock, Duration::from_millis(400)).is_none());
        assert!(!dir.join(LOG_NAME).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_event_goes_only_to_the_configured_target() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = format!("127.0.0.1:{}", sock.local_addr().unwrap().port());
        let cfg = ExportConfig { log_file: false, siem_target: Some(target.clone()), format: Format::Cef };
        assert_eq!(send_test(&cfg, TS), Ok(target));
        let m = recv(&sock, Duration::from_secs(5)).expect("the test event");
        assert!(m.starts_with("<134>1 2023-11-14T22:13:20.123Z "), "{m}");
        assert!(m.contains(" test - CEF:0|NetWatch|NetWatch|") && m.contains("|NetWatch test event|1|"), "{m}");
        assert!(recv(&other, Duration::from_millis(300)).is_none());
    }

    #[test]
    fn log_file_gets_each_new_alert_as_a_json_line() {
        let dir = tmp_dir("log");
        let ex = Exporter::start(dir.clone(), ExportConfig::default());
        assert!(!dir.join(LOG_NAME).exists());
        // Switching the log on creates the (empty) file for "Show log file".
        ex.configure(ExportConfig { log_file: true, ..Default::default() });
        assert!(dir.join(LOG_NAME).exists());
        ex.alert(&alert(1, Severity::Low, "first", "a\nb"));
        ex.alert(&alert(2, Severity::High, "second", "d"));
        let path = dir.join(LOG_NAME);
        assert!(wait_for(|| std::fs::read_to_string(&path).unwrap_or_default().lines().count() == 2));
        let text = std::fs::read_to_string(&path).unwrap();
        let ids: Vec<u64> = text.lines().map(|l| serde_json::from_str::<Alert>(l).unwrap().id).collect();
        assert_eq!(ids, [1, 2]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

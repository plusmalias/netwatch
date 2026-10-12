//! Threat-intel lists: malware domains (abuse.ch URLhaus and ThreatFox), botnet
//! C2 IPs (abuse.ch Feodo Tracker and ThreatFox) and the user's own entries.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Format {
    /// Hosts-file lines, bare domains or bare IPs.
    Hosts,
    /// abuse.ch ThreatFox CSV export, with IOCs as `ip:port`.
    ThreatFoxCsv,
}

struct Feed {
    file: &'static str,
    url: &'static str,
    /// How alerts name the list ("… is on {source}").
    source: &'static str,
    format: Format,
    /// Don't download again before the saved copy is this old, to spare
    /// metered connections (the ThreatFox host file is ~1.4 MB).
    max_age_hours: u64,
    /// A ceiling even for "Update now": the daily lists are refreshed on
    /// request, but this one still waits out its interval.
    spare_data: bool,
}

const FEEDS: &[Feed] = &[
    Feed {
        file: "urlhaus.txt",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        source: "the abuse.ch URLhaus malware list",
        format: Format::Hosts,
        max_age_hours: 24,
        spare_data: false,
    },
    Feed {
        file: "feodo.txt",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        source: "the abuse.ch Feodo Tracker botnet list",
        format: Format::Hosts,
        max_age_hours: 24,
        spare_data: false,
    },
    Feed {
        file: "threatfox-domains.txt",
        url: "https://threatfox.abuse.ch/downloads/hostfile/",
        source: "the abuse.ch ThreatFox malware domain list",
        format: Format::Hosts,
        max_age_hours: 72,
        spare_data: true,
    },
    Feed {
        file: "threatfox-ips.csv",
        url: "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        source: "the abuse.ch ThreatFox botnet command-and-control list",
        format: Format::ThreatFoxCsv,
        max_age_hours: 24,
        spare_data: false,
    },
];
pub const CUSTOM_SOURCE: &str = "your blocklist";
pub const CUSTOM_FILE: &str = "custom.txt";

#[derive(Default)]
pub struct Blocklist {
    /// Entry → which list it came from, for alert text.
    domains: HashMap<String, &'static str>,
    ips: HashMap<IpAddr, &'static str>,
    pub updated: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct BlocklistInfo {
    pub domains: usize,
    pub ips: usize,
    pub updated: Option<u64>,
}

impl Blocklist {
    pub fn load(dir: &Path) -> Self {
        let mut bl = Blocklist::default();
        for feed in FEEDS {
            let path = dir.join(feed.file);
            if let Ok(text) = std::fs::read_to_string(&path) {
                match feed.format {
                    Format::Hosts => bl.add_list(&text, feed.source),
                    Format::ThreatFoxCsv => bl.add_threatfox_csv(&text, feed.source),
                }
                let mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64);
                bl.updated = bl.updated.max(mtime);
            }
        }
        if let Ok(text) = std::fs::read_to_string(dir.join(CUSTOM_FILE)) {
            bl.add_list(&text, CUSTOM_SOURCE);
        }
        bl
    }

    /// Accepts hosts-file lines (`127.0.0.1 evil.com`), bare domains and bare IPs.
    pub fn add_list(&mut self, text: &str, source: &'static str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut tokens = line.split_whitespace();
            let (Some(first), second) = (tokens.next(), tokens.next()) else {
                continue;
            };
            let entry = match second {
                Some(domain) if first.parse::<IpAddr>().is_ok() => domain,
                _ => first,
            };
            match entry.parse::<IpAddr>() {
                Ok(ip) => {
                    self.ips.insert(ip, source);
                }
                Err(_) => {
                    let d = entry.trim_end_matches('.').to_ascii_lowercase();
                    if d.contains('.') && d != "localhost" {
                        self.domains.insert(d, source);
                    }
                }
            }
        }
    }

    /// Reads the ThreatFox `ip:port` CSV export: comment lines start with `#`,
    /// and each row has the indicator as `ip:port` in the `ioc_value` column.
    /// The port is dropped (lists match addresses). Rather than trusting a
    /// column number, this takes the first field of a row that is an
    /// `ip:port`, so a reordered export still parses.
    pub fn add_threatfox_csv(&mut self, text: &str, source: &'static str) {
        for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
            if let Some(ip) = csv_fields(line).iter().find_map(|f| ip_from_ip_port(f)) {
                self.ips.insert(ip, source);
            }
        }
    }

    /// The listed entry matching `name` or one of its parent domains, and its list.
    pub fn match_domain(&self, name: &str) -> Option<(String, &'static str)> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut candidate = name.as_str();
        loop {
            if let Some(source) = self.domains.get(candidate) {
                return Some((candidate.to_string(), source));
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return None,
            }
        }
    }

    /// Which list `ip` is on, if any.
    pub fn match_ip(&self, ip: &IpAddr) -> Option<&'static str> {
        self.ips.get(ip).copied()
    }

    pub fn info(&self) -> BlocklistInfo {
        BlocklistInfo {
            domains: self.domains.len(),
            ips: self.ips.len(),
            updated: self.updated,
        }
    }
}

/// Whether a feed saved `age_secs` ago (`None` if never) is due again.
fn feed_due(age_secs: Option<u64>, max_age_hours: u64) -> bool {
    age_secs.is_none_or(|a| a >= max_age_hours * 3600)
}

/// Whether to download a feed now. `force` ("Update now") overrides the
/// interval, except for feeds that spare metered data.
fn should_download(force: bool, spare_data: bool, age_secs: Option<u64>, max_age_hours: u64) -> bool {
    feed_due(age_secs, max_age_hours) || (force && !spare_data)
}

/// Splits a CSV line into fields. Handles quotes, commas inside quotes, and
/// ThreatFox's `", "` separators.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    fields.push(cur.trim().to_string());
    fields
}

/// `1.2.3.4:443` or `[2001:db8::1]:443` → the address.
fn ip_from_ip_port(field: &str) -> Option<IpAddr> {
    let (host, port) = field.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn file_age_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
}

/// Whether any feed's saved copy is missing or older than its refresh interval.
pub fn any_due(dir: &Path) -> bool {
    FEEDS.iter().any(|f| feed_due(file_age_secs(&dir.join(f.file)), f.max_age_hours))
}

/// Downloads the feeds into `dir`. Each feed is skipped while its saved copy
/// is younger than its refresh interval, unless `force` (the user pressed
/// "Update now") and the feed isn't one that spares metered data. A feed that
/// fails keeps its previous copy.
pub fn download(dir: &Path, force: bool) -> Result<(), String> {
    let mut errors = Vec::new();
    for feed in FEEDS {
        let path = dir.join(feed.file);
        if !should_download(force, feed.spare_data, file_age_secs(&path), feed.max_age_hours) {
            continue;
        }
        let result = ureq::get(feed.url)
            .timeout(Duration::from_secs(60))
            .call()
            .map_err(|e| e.to_string())
            .and_then(|r| r.into_string().map_err(|e| e.to_string()))
            .and_then(|body| std::fs::write(&path, body).map_err(|e| e.to_string()));
        if let Err(e) = result {
            errors.push(format!("{}: {e}", feed.file));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_lists_and_matches_parents() {
        let mut bl = Blocklist::default();
        bl.add_list("# hosts\n127.0.0.1\tbad.example.com\n0.0.0.0 evil.test # trailing\n", "feed");
        bl.add_list("50.16.16.211\n\nmalware.org.\nlocalhost\n", CUSTOM_SOURCE);
        assert_eq!(bl.info().domains, 3);
        assert_eq!(bl.info().ips, 1);
        assert_eq!(bl.match_domain("cdn.bad.example.com"), Some(("bad.example.com".into(), "feed")));
        assert_eq!(bl.match_domain("EVIL.test."), Some(("evil.test".into(), "feed")));
        assert_eq!(bl.match_domain("x.malware.org"), Some(("malware.org".into(), CUSTOM_SOURCE)));
        assert_eq!(bl.match_domain("example.com"), None);
        assert_eq!(bl.match_domain("com"), None);
        assert_eq!(bl.match_ip(&"50.16.16.211".parse().unwrap()), Some(CUSTOM_SOURCE));
        assert_eq!(bl.match_ip(&"127.0.0.1".parse().unwrap()), None);
    }

    // Real rows from https://threatfox.abuse.ch/export/csv/ip-port/recent/
    const THREATFOX_CSV: &str = r#"################################################################
# ThreatFox IOCs: recent ip-port - CSV format                  #
# Last updated: 2026-10-03 12:05:06 UTC                        #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-10-03 12:05:06", "1948616", "156.254.20.47:5998", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "True", "None", "cobaltstrike", "1", "anonymous"
"2026-10-03 10:13:38", "1948398", "94.154.43.138:48101", "ip:port", "botnet_cc", "elf.mirai", "Katana", "Mirai", "", "100", "False", "", "mirai", "0", "redrabytes"

"2026-10-03 09:00:00", "1948000", "[2001:db8::1]:443", "ip:port", "botnet_cc", "win.x", "None", "X", "", "75", "False", "http://203.0.113.9:8080/x", "", "0", "someone"
"2026-10-03 08:00:00", "1947000", "evil.example.com:443", "domain", "botnet_cc", "win.y", "None", "Y", "", "75", "False", "", "", "0", "someone"
"bad line without an address"
"#;

    #[test]
    fn parses_threatfox_ip_port_csv() {
        let mut bl = Blocklist::default();
        bl.add_threatfox_csv(THREATFOX_CSV, "tf");
        assert_eq!(bl.info().ips, 3);
        assert_eq!(bl.info().domains, 0);
        assert_eq!(bl.match_ip(&"156.254.20.47".parse().unwrap()), Some("tf"));
        assert_eq!(bl.match_ip(&"94.154.43.138".parse().unwrap()), Some("tf"));
        assert_eq!(bl.match_ip(&"2001:db8::1".parse().unwrap()), Some("tf"));
        // Not an indicator: a URL in the reference column, a hostname, the timestamp.
        assert_eq!(bl.match_ip(&"203.0.113.9".parse().unwrap()), None);
        // A feed the user's own list overlaps with keeps working side by side.
        bl.add_list("156.254.20.47\n", CUSTOM_SOURCE);
        assert_eq!(bl.match_ip(&"156.254.20.47".parse().unwrap()), Some(CUSTOM_SOURCE));
    }

    #[test]
    fn csv_fields_handle_quotes_and_commas() {
        assert_eq!(csv_fields(r#""a", "b,c", "d ""q"" e", f"#), vec!["a", "b,c", "d \"q\" e", "f"]);
        assert_eq!(csv_fields("x,,y"), vec!["x", "", "y"]);
        assert_eq!(ip_from_ip_port("1.2.3.4:80"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(ip_from_ip_port("1.2.3.4"), None);
        assert_eq!(ip_from_ip_port("1.2.3.4:http"), None);
        assert_eq!(ip_from_ip_port("2026-10-03 12:05:06"), None);
    }

    #[test]
    fn parses_the_threatfox_host_file() {
        let mut bl = Blocklist::default();
        bl.add_list("# ThreatFox IOCs: host file\n#\n127.0.0.1\tj6vfh2b2.thelogicofmoney.com\n127.0.0.1\tgrillrecipespro.com\n", "tf");
        assert_eq!(bl.info().domains, 2);
        assert_eq!(bl.match_domain("cdn.grillrecipespro.com"), Some(("grillrecipespro.com".into(), "tf")));
    }

    #[test]
    fn feeds_refresh_on_their_own_schedule() {
        let hours = |h: u64| Some(h * 3600);
        assert!(feed_due(None, 72));
        assert!(!feed_due(hours(71), 72));
        assert!(feed_due(hours(72), 72));
        assert!(!feed_due(hours(23), 24));
        assert!(feed_due(hours(25), 24));
        // The big host file waits three days; the C2 list is daily.
        let by_file = |f: &str| FEEDS.iter().find(|x| x.file == f).unwrap().max_age_hours;
        assert_eq!(by_file("threatfox-domains.txt"), 72);
        assert_eq!(by_file("threatfox-ips.csv"), 24);
        assert!(FEEDS.iter().all(|f| f.url.starts_with("https://")));
    }

    #[test]
    fn update_now_skips_the_feed_that_spares_data() {
        let hours = |h: u64| Some(h * 3600);
        // "Update now" re-downloads the daily lists…
        assert!(should_download(true, false, hours(1), 24));
        // …but the 1.4 MB host file keeps its 3-day ceiling, forced or not.
        assert!(!should_download(true, true, hours(1), 72));
        assert!(!should_download(true, true, hours(71), 72));
        assert!(should_download(true, true, hours(73), 72));
        assert!(should_download(true, true, None, 72));
        assert!(!should_download(false, false, hours(1), 24));
        let spare: Vec<_> = FEEDS.iter().filter(|f| f.spare_data).map(|f| f.file).collect();
        assert_eq!(spare, vec!["threatfox-domains.txt"]);
    }

    #[test]
    fn any_due_follows_each_feeds_own_age() {
        use std::time::{Duration, SystemTime};
        let dir = std::env::temp_dir().join(format!("netwatch-feeds-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(any_due(&dir), "missing files are due");
        let age = |file: &str, hours: u64| {
            let p = dir.join(file);
            if !p.exists() {
                std::fs::write(&p, "x").unwrap();
            }
            let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(hours * 3600)).unwrap();
        };
        for f in FEEDS {
            age(f.file, 1);
        }
        assert!(!any_due(&dir));
        // The ThreatFox host file isn't due after 2 days, but is after 4.
        age("threatfox-domains.txt", 48);
        assert!(!any_due(&dir));
        age("threatfox-domains.txt", 96);
        assert!(any_due(&dir));
        age("threatfox-domains.txt", 1);
        age("threatfox-ips.csv", 25);
        assert!(any_due(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

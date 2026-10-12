//! Network usage per app on this computer. On macOS, `nettop` reports each
//! process's byte counters without needing any privileges.

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct AppUsage {
    pub name: String,
    /// Bytes since NetWatch started.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Bytes per second over the last sample.
    pub rate_in: u64,
    pub rate_out: u64,
    pub processes: usize,
    pub last_active: u64,
}

/// One `nettop` row: process name (possibly truncated), pid, bytes in, bytes out.
pub type Row = (String, u32, u64, u64);

#[cfg(target_os = "macos")]
pub fn sample() -> Option<Vec<Row>> {
    let out = crate::util::quiet_command("nettop")
        .args(["-P", "-L", "1", "-x", "-n", "-t", "external", "-J", "bytes_in,bytes_out"])
        .output()
        .ok()?;
    out.status.success().then(|| parse_nettop(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(not(target_os = "macos"))]
pub fn sample() -> Option<Vec<Row>> {
    None
}

/// `com.apple.WebKi.2152,2572164,500226,` → ("com.apple.WebKi", 2152, …)
pub fn parse_nettop(text: &str) -> Vec<Row> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split(',');
            let (name, pid) = cols.next()?.rsplit_once('.')?;
            Some((
                name.to_string(),
                pid.parse().ok()?,
                cols.next()?.parse().ok()?,
                cols.next()?.parse().ok()?,
            ))
        })
        .collect()
}

/// The app a process belongs to: the outermost `.app` bundle in its path, so
/// helper processes count toward their app ("Google Chrome", not
/// "Google Chrome Helper (Renderer)").
pub fn app_name(exe: &Path) -> Option<String> {
    exe.components()
        .filter_map(|c| c.as_os_str().to_str())
        .find_map(|c| c.strip_suffix(".app"))
        .map(String::from)
}

#[derive(Default)]
pub struct AppTracker {
    /// pid → (app name, last bytes in, last bytes out)
    procs: HashMap<u32, (String, u64, u64)>,
    totals: HashMap<String, AppUsage>,
    last_ts: u64,
}

impl AppTracker {
    /// Folds in a sample. `name_of` names new pids; it gets nettop's
    /// (truncated) name as a fallback.
    pub fn update(&mut self, rows: Vec<Row>, ts: u64, mut name_of: impl FnMut(u32, &str) -> String) {
        let first = self.last_ts == 0;
        let dt = ts.saturating_sub(self.last_ts).max(1);
        self.last_ts = ts;
        for t in self.totals.values_mut() {
            t.rate_in = 0;
            t.rate_out = 0;
            t.processes = 0;
        }
        let mut seen = HashMap::with_capacity(rows.len());
        for (short, pid, bin, bout) in rows {
            let (name, din, dout) = match self.procs.get(&pid) {
                // Counters went down: the pid was reused by a new process.
                Some((name, pin, pout)) if bin >= *pin && bout >= *pout => (name.clone(), bin - pin, bout - pout),
                // On the very first sample, earlier traffic isn't "since NetWatch started".
                None if first => (name_of(pid, &short), 0, 0),
                _ => (name_of(pid, &short), bin, bout),
            };
            seen.insert(pid, (name.clone(), bin, bout));
            let t = self.totals.entry(name.clone()).or_insert_with(|| AppUsage {
                name,
                ..Default::default()
            });
            t.bytes_in += din;
            t.bytes_out += dout;
            t.rate_in += din * 1000 / dt;
            t.rate_out += dout * 1000 / dt;
            t.processes += 1;
            if din + dout > 0 {
                t.last_active = ts;
            }
        }
        self.procs = seen;
    }

    /// Apps that have used the network, busiest first.
    pub fn list(&self) -> Vec<AppUsage> {
        let mut v: Vec<AppUsage> = self
            .totals
            .values()
            .filter(|t| t.bytes_in + t.bytes_out > 0)
            .cloned()
            .collect();
        v.sort_by_key(|t| std::cmp::Reverse((t.rate_in + t.rate_out, t.bytes_in + t.bytes_out)));
        v.truncate(100);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nettop_csv() {
        let text = ",bytes_in,bytes_out,\nlaunchd.1,0,0,\ncom.apple.WebKi.2152,2572164,500226,\n2.1.288.1987,10,20,\n";
        let rows = parse_nettop(text);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1], ("com.apple.WebKi".into(), 2152, 2572164, 500226));
        assert_eq!(rows[2], ("2.1.288".into(), 1987, 10, 20));
    }

    /// `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_nettop() {
        let rows = sample().expect("nettop failed");
        println!("{} rows, first: {:?}", rows.len(), rows.iter().take(3).collect::<Vec<_>>());
        assert!(!rows.is_empty());
    }

    #[test]
    fn finds_the_owning_app() {
        let p = Path::new("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper");
        assert_eq!(app_name(p).as_deref(), Some("Google Chrome"));
        assert_eq!(app_name(Path::new("/usr/sbin/mDNSResponder")), None);
    }

    #[test]
    fn tracks_deltas_rates_and_pid_reuse() {
        let mut t = AppTracker::default();
        let name = |_: u32, s: &str| s.to_string();
        t.update(vec![("Safari".into(), 10, 5_000, 100)], 1_000, name);
        assert!(t.list().is_empty(), "first sample is only a baseline");
        t.update(vec![("Safari".into(), 10, 7_000, 300), ("curl".into(), 20, 400, 50)], 3_000, name);
        let l = t.list();
        assert_eq!(l[0].name, "Safari");
        assert_eq!((l[0].bytes_in, l[0].bytes_out, l[0].rate_in), (2_000, 200, 1_000));
        // A process that started after the first sample counts in full.
        assert_eq!(l[1].bytes_in, 400);
        // pid 10 was reused by a new process with smaller counters.
        t.update(vec![("Mail".into(), 10, 100, 0)], 5_000, name);
        let l = t.list();
        let get = |n: &str| l.iter().find(|a| a.name == n).unwrap().clone();
        assert_eq!(get("Mail").bytes_in, 100);
        assert_eq!(get("Safari").bytes_in, 2_000);
        assert_eq!(get("Safari").rate_in, 0);
    }
}

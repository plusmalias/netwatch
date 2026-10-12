//! MAC vendor lookup backed by Wireshark's `manuf` database (downloaded on demand).

use std::collections::HashMap;
use std::path::Path;

pub const MANUF_URL: &str = "https://www.wireshark.org/download/automated/data/manuf";

#[derive(Default)]
pub struct Oui {
    /// Keyed by the prefix bits, for 24-, 28- and 36-bit assignments.
    by_len: [HashMap<u64, String>; 3],
    pub entries: usize,
}

const LENS: [u32; 3] = [36, 28, 24];

impl Oui {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|t| Self::parse(&t))
            .unwrap_or_default()
    }

    pub fn parse(text: &str) -> Self {
        let mut oui = Oui::default();
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').map(str::trim).collect();
            if cols.len() < 2 {
                continue;
            }
            let (prefix, bits) = match cols[0].split_once('/') {
                Some((p, b)) => (p, b.parse::<u32>().unwrap_or(24)),
                None => (cols[0], 24),
            };
            let Some(slot) = LENS.iter().position(|l| *l == bits) else {
                continue;
            };
            let Some(value) = prefix_value(prefix) else {
                continue;
            };
            let name = cols.get(2).filter(|s| !s.is_empty()).unwrap_or(&cols[1]);
            oui.by_len[slot].insert(value >> (48 - bits), name.to_string());
            oui.entries += 1;
        }
        oui
    }

    pub fn lookup(&self, mac: &str) -> Option<String> {
        let value = prefix_value(mac)?;
        LENS.iter()
            .zip(&self.by_len)
            .find_map(|(bits, map)| map.get(&(value >> (48 - bits))).cloned())
    }
}

/// Packs up to six hex octets into the top of a 48-bit value.
fn prefix_value(s: &str) -> Option<u64> {
    let octets: Vec<&str> = s.split([':', '-', '.']).collect();
    if octets.is_empty() || octets.len() > 6 {
        return None;
    }
    let mut v: u64 = 0;
    for (i, o) in octets.iter().enumerate() {
        v |= (u8::from_str_radix(o, 16).ok()? as u64) << (40 - 8 * i);
    }
    Some(v)
}

pub fn download(path: &Path) -> Result<usize, String> {
    let body = ureq::get(MANUF_URL)
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .map_err(|e| format!("vendor database download failed: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let parsed = Oui::parse(&body);
    if parsed.entries < 1000 {
        return Err("vendor database looked truncated; kept the old one".into());
    }
    std::fs::write(path, body).map_err(|e| e.to_string())?;
    Ok(parsed.entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# comment\n\
00:00:0C\tCisco\tCisco Systems, Inc\n\
00:55:DA:00/28\tShinkoTechno\tShinko Technos co.,ltd.\n\
00:1B:C5:00:00/36\tConvergi\tConverging Systems Inc.\n\
B8:27:EB\tRaspberryPi\tRaspberry Pi Foundation\n";

    #[test]
    fn longest_prefix_wins() {
        let oui = Oui::parse(SAMPLE);
        assert_eq!(oui.entries, 4);
        assert_eq!(oui.lookup("00:00:0c:12:34:56").as_deref(), Some("Cisco Systems, Inc"));
        assert_eq!(oui.lookup("b8:27:eb:aa:bb:cc").as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(oui.lookup("00:55:da:0f:00:01").as_deref(), Some("Shinko Technos co.,ltd."));
        assert_eq!(oui.lookup("00:55:da:1f:00:01"), None);
        assert_eq!(oui.lookup("00:1b:c5:00:00:0a").as_deref(), Some("Converging Systems Inc."));
    }
}

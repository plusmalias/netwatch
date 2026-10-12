//! Wi-Fi network names and BSSIDs from CoreWLAN, in this process. macOS hides
//! both from apps that Location Services hasn't authorised (`system_profiler`
//! says `<redacted>`), so `core/monitor.rs` only asks once it is. Thin by
//! design: the mapping into `Network` lives in `wifi.rs`, where it is tested.

use crate::wifi::CwScan;

#[cfg(not(target_os = "macos"))]
pub fn scan(_interface: &str) -> Option<CwScan> {
    None
}

/// What CoreWLAN reports for `interface` (such as "en0"): the network we're
/// on and the networks in the OS's last scan. When that cache is empty, scans
/// once, but never more often than every five minutes: a scan takes the radio
/// off its channel for a moment, which would show up as latency spikes.
#[cfg(target_os = "macos")]
pub fn scan(interface: &str) -> Option<CwScan> {
    // CoreWLAN hands back autoreleased objects; this runs once a minute forever.
    objc2::rc::autoreleasepool(|_| read(interface))
}

#[cfg(target_os = "macos")]
const SCAN_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[cfg(target_os = "macos")]
static LAST_SCAN: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// A reading CoreWLAN gives as 0 when it has none.
#[cfg(target_os = "macos")]
fn nonzero(v: isize) -> Option<i32> {
    (v != 0).then_some(v as i32)
}

#[cfg(target_os = "macos")]
fn read(interface: &str) -> Option<CwScan> {
    use crate::wifi::{self, Network};
    use objc2_core_wlan::{CWChannel, CWNetwork, CWPHYMode, CWSecurity, CWWiFiClient};
    use objc2_foundation::NSString;

    // Channel, band and width, as the labels the rest of NetWatch uses.
    fn channel_of(c: Option<&CWChannel>) -> (Option<u32>, Option<String>, Option<String>) {
        let Some(c) = c else { return (None, None, None) };
        // SAFETY: plain property reads on a live CWChannel.
        let (number, band, width) = unsafe { (c.channelNumber(), c.channelBand().0, c.channelWidth().0) };
        (u32::try_from(number).ok().filter(|n| *n > 0), wifi::band_label(band as i64), wifi::width_label(width as i64))
    }

    fn network(n: &CWNetwork) -> Network {
        // SAFETY: plain property reads and capability queries on a live CWNetwork.
        unsafe {
            let (channel, band, width) = channel_of(n.wlanChannel().as_deref());
            let security: Vec<i64> = wifi::cw::PROBE.iter().copied().filter(|v| n.supportsSecurity(CWSecurity(*v as isize))).collect();
            let phy: Vec<i64> = (1..=6).filter(|v| n.supportsPHYMode(CWPHYMode(*v as isize))).collect();
            Network {
                ssid: n.ssid().map(|s| s.to_string()).filter(|s| !s.is_empty()),
                bssid: n.bssid().and_then(|b| wifi::normalize_bssid(&b.to_string())),
                channel,
                band,
                width,
                phy: wifi::phy_label(&phy),
                security: wifi::cw_security_label(&security),
                rssi: nonzero(n.rssiValue()),
                noise: nonzero(n.noiseMeasurement()),
            }
        }
    }

    // SAFETY: CoreWLAN calls on objects it just returned, from a background thread (it allows that).
    unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let iface = client
            .interfaceWithName(Some(&NSString::from_str(interface)))
            .or_else(|| client.interface())?;
        if !iface.powerOn() {
            return None;
        }
        let (channel, band, width) = channel_of(iface.wlanChannel().as_deref());
        let security = iface.security().0;
        let current = Network {
            ssid: iface.ssid().map(|s| s.to_string()).filter(|s| !s.is_empty()),
            bssid: iface.bssid().and_then(|b| wifi::normalize_bssid(&b.to_string())),
            channel,
            band,
            width,
            security: wifi::cw_security_label(&[security as i64]),
            rssi: nonzero(iface.rssiValue()),
            noise: nonzero(iface.noiseMeasurement()),
            ..Default::default()
        };
        let mut results = iface.cachedScanResults();
        if results.as_ref().is_none_or(|r| r.is_empty()) {
            let due = LAST_SCAN.lock().ok().is_some_and(|mut last| {
                let due = last.is_none_or(|t| t.elapsed() >= SCAN_EVERY);
                if due {
                    *last = Some(std::time::Instant::now());
                }
                due
            });
            if due {
                results = iface.scanForNetworksWithName_error(None).ok();
            }
        }
        let nearby = results.map(|r| r.to_vec().iter().map(|n| network(n)).collect()).unwrap_or_default();
        Some(CwScan { current: Some(current), nearby })
    }
}

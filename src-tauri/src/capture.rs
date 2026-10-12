//! Live packet capture on the default interface, feeding the analyzer.
//! Capture is never promiscuous: we read this computer's own traffic plus
//! broadcast/multicast, which is all an ordinary LAN client receives anyway.

use crate::detect::{Analyzer, Event, TrafficSnapshot};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CaptureStatus {
    Stopped,
    Running { interface: String },
    NeedsPermission { message: String },
    Unavailable { message: String },
    Error { message: String },
}

#[cfg(feature = "capture")]
pub fn start<E, T, D>(
    local_ip: Ipv4Addr,
    mut analyzer: Analyzer,
    stop: Arc<AtomicBool>,
    mut on_events: E,
    mut on_tick: T,
    on_exit: D,
) -> Result<String, CaptureStatus>
where
    E: FnMut(Vec<Event>) + Send + 'static,
    T: FnMut(TrafficSnapshot) + Send + 'static,
    D: FnOnce(Option<String>) + Send + 'static,
{
    use crate::util::now_ms;
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;

    #[cfg(windows)]
    if !npcap::available() {
        return Err(CaptureStatus::Unavailable {
            message: "Npcap isn't installed. Install it from npcap.com, then press Start capture."
                .into(),
        });
    }

    let device = pcap::Device::list()
        .map_err(classify)?
        .into_iter()
        .find(|d| d.addresses.iter().any(|a| a.addr == IpAddr::V4(local_ip)))
        .ok_or_else(|| CaptureStatus::Error {
            message: format!("No capture device has address {local_ip}"),
        })?;
    let name = device.name.clone();
    let mut cap = pcap::Capture::from_device(device)
        .map_err(classify)?
        .promisc(false)
        .snaplen(65_535)
        .immediate_mode(true)
        .timeout(250)
        .open()
        .map_err(classify)?;
    if cap.get_datalink() != pcap::Linktype::ETHERNET {
        return Err(CaptureStatus::Unavailable {
            message: format!("{name} isn't an Ethernet/Wi-Fi interface"),
        });
    }

    std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let mut last_tick = now_ms();
            let mut error = None;
            while !stop.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(p) => {
                        let events = analyzer.process(now_ms(), p.data, p.header.len);
                        if !events.is_empty() {
                            on_events(events);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        error = Some(e.to_string());
                        break;
                    }
                }
                let now = now_ms();
                if now.saturating_sub(last_tick) >= 1000 {
                    last_tick = now;
                    on_tick(analyzer.snapshot(now));
                }
            }
            on_exit(error);
        })
        .map_err(|e| CaptureStatus::Error {
            message: e.to_string(),
        })?;
    Ok(name)
}

#[cfg(not(feature = "capture"))]
pub fn start<E, T, D>(
    _local_ip: Ipv4Addr,
    _analyzer: Analyzer,
    _stop: Arc<AtomicBool>,
    _on_events: E,
    _on_tick: T,
    _on_exit: D,
) -> Result<String, CaptureStatus> {
    Err(CaptureStatus::Unavailable {
        message: "This build of NetWatch was compiled without packet capture.".into(),
    })
}

#[cfg(feature = "capture")]
fn classify(e: pcap::Error) -> CaptureStatus {
    let message = e.to_string();
    let lower = message.to_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        CaptureStatus::NeedsPermission {
            message: permission_hint(),
        }
    } else {
        CaptureStatus::Error { message }
    }
}

pub fn permission_hint() -> String {
    if cfg!(target_os = "macos") {
        "macOS only lets administrators read network packets. Grant access once per restart (the same thing Wireshark's ChmodBPF does).".into()
    } else if cfg!(target_os = "linux") {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<path to netwatch>".into());
        format!("Give NetWatch capture rights, then restart it:\nsudo setcap cap_net_raw,cap_net_admin=eip {exe}")
    } else {
        "Npcap is restricted to administrators. Reinstall Npcap without \"Restrict Npcap driver's access to Administrators only\", or run NetWatch as administrator.".into()
    }
}

/// Asks the OS for capture rights. `Ok(true)` means capture can be retried now.
pub fn grant_access() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        // Gives the admin group read/write on the BPF devices until the next reboot.
        let script = "do shell script \"chgrp admin /dev/bpf* && chmod g+rw /dev/bpf*\" with administrator privileges with prompt \"NetWatch needs access to the packet capture devices to monitor traffic.\"";
        let status = std::process::Command::new("osascript")
            .args(["-e", script])
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(true)
        } else {
            Err("Access wasn't granted.".into())
        }
    }
    #[cfg(target_os = "linux")]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let status = std::process::Command::new("pkexec")
            .args(["setcap", "cap_net_raw,cap_net_admin=eip"])
            .arg(&exe)
            .status()
            .map_err(|_| permission_hint())?;
        if status.success() {
            Err("Capture rights granted. Restart NetWatch to use them.".into())
        } else {
            Err(permission_hint())
        }
    }
    #[cfg(windows)]
    {
        Err("Install Npcap from https://npcap.com (default options), then press Start capture.".into())
    }
}

#[cfg(all(windows, feature = "capture"))]
mod npcap {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    /// Npcap installs wpcap.dll under System32\Npcap, which isn't on the DLL
    /// search path. wpcap.dll is delay-loaded (see build.rs), so the app still
    /// starts when Npcap is missing and capture reports it instead.
    pub fn available() -> bool {
        let mut buf = [0u16; 260];
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if len == 0 || len >= buf.len() {
            return false;
        }
        let mut dir: Vec<u16> = buf[..len].to_vec();
        dir.extend("\\Npcap\0".encode_utf16());
        let dll: Vec<u16> = "wpcap.dll\0".encode_utf16().collect();
        unsafe {
            SetDllDirectoryW(dir.as_ptr());
            !LoadLibraryW(dll.as_ptr()).is_null()
        }
    }
}

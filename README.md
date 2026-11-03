<div align="center">

<img src="src-tauri/icons/128x128@2x.png" width="110" alt="NetWatch icon" />

# NetWatch

### Know exactly what's on your home network, and when something's wrong.

**A local-first desktop monitor for your own network.** It finds every device on your LAN,
watches your router, connection, Wi-Fi and Bluetooth, and explains alerts in plain language.
**It only detects:** it never spoofs, intercepts other devices' traffic, or attacks anything.

![Tauri 2](https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white)
![Rust](https://img.shields.io/badge/backend-Rust-000000?logo=rust&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-tested-success?logo=apple&logoColor=white)
![Windows / Linux](https://img.shields.io/badge/Windows%20%2F%20Linux-experimental-lightgrey)
![No cloud](https://img.shields.io/badge/data-stays%20on%20your%20machine-informational)
![Detect only](https://img.shields.io/badge/mode-detect%20only-blueviolet)

[Highlights](#-at-a-glance) · [Features](#-features) · [Detectors](#-detectors) · [Permissions](#-permissions) · [Build](#-building) · [Data](#-data)

</div>

---

## 🔭 At a glance

| | |
|---|---|
| 🖥️ **Every device on your LAN** | Discovery, live presence, vendor + OS guesses, a network map, and "new device" alerts |
| 🛡️ **30+ detectors** | ARP spoofing, rogue DHCP, malware domains, botnet traffic, port scans, look-alike Wi-Fi, HTTPS interception… |
| 📶 **Your connection, measured** | Latency, packet loss, outage log, speed tests, whole-network data usage with allowance forecasts |
| 🔵 **Bluetooth awareness** | AirTag / Tile / SmartTag tracker alerts, a "tracker travelling with you" warning, BLE pop-up spam detection, locate mode |
| 🔍 **Security checkup + audits** | Weekly port audits, new listening apps, startup items, DNS/router changes, certificate checks |
| 🧰 **Tools** | Watched hosts, traceroute, DNS check, Wake-on-LAN, weekly HTML report, morning summary |
| 🧑‍💻 **Expert mode** | MITRE ATT&CK mapping per alert, JSONL log file, SIEM forwarding (syslog + CEF/JSON) |

> Built with **Tauri 2**: a Rust backend and a plain HTML/JS UI with **no build step**. Runs on macOS, Windows and Linux.

---

## ✨ Features

The interface is a light, dashboard-style app with top navigation (Overview, Activity, Devices, Network, Bluetooth, Traffic, Security, plus Settings). Sections with several pages have sub-tabs. Press **⌘K** to search pages, devices and actions, **⌘1–⌘7** to jump between sections, and **⌘,** for Settings. Dark mode is available in Settings → Appearance.

### 🖥️ Devices
- Finds devices by pinging every address in your subnet, which also makes the OS resolve each one through ARP, then reading the ARP table.
- **Presence**: every minute it pings known devices, falling back to a TCP connection check for devices that ignore ping (most phones). A device counts as online only if it answered or was seen on the network in the last 3 minutes. Stale ARP-cache entries don't count. It keeps 30 days of online history per device, shown as a 7-day strip, and you can **watch** a device to be alerted when it joins or leaves.
- Per-device latency, plus an operating-system guess from DHCP fingerprints (option 55/60, seen in broadcast DHCP requests), advertised services, model names and ping TTL.
- Listens for **mDNS/Bonjour** and **SSDP/UPnP** announcements, and learns hostnames from DHCP and from mDNS reverse lookups (which name most Apple devices and Linux boxes).
- Names each device's vendor from the Wireshark manufacturer database. It recognizes randomized "private" MACs, and guesses device type (TV, speaker, printer, phone…) from advertised services.
- Remembers devices with first-seen and last-seen times. You can trust devices, rename them, or forget them.
- Raises a **new device** alert when an untrusted device joins. The first scan sets the baseline, so existing devices don't alert.
- **Open-port check**: an on-demand TCP connect to 26 well-known ports on one device. It flags remote-access services such as Telnet, FTP, RDP and VNC.
- **Export** the device list as CSV to your Downloads folder.
- **Network map**: your router in the middle with the internet above it, and every device around it grouped by type and coloured by status (online, asleep, offline). Click a device for its details.

### 🌐 Network
*No special permission.*

- **Router** over read-only UPnP IGD: model, internet (WAN) address with carrier-grade NAT detection, connection uptime, and the **port forwards** devices have opened. A new port forward raises an alert. NetWatch never adds, changes or deletes mappings. When SSDP discovery is blocked (for example by macOS's "block all incoming connections"), it probes the gateway's usual description URLs directly.
- **Whole-network data usage** from the router's WAN byte counters, kept per local hour for 120 days, so it covers every device on the network, not just this one. Optional monthly allowance alerts at 80% and 100%, for capped 4G/5G plans, plus a forecast of where the billing cycle is heading (used so far plus the median of the last week's complete days for each day left), with a warning once per cycle if you're on course to go over. Handles 32-bit counter wraps, router reboots, routers that briefly re-report a slightly lower count, and switching networks.
- **Connection quality**: ping time to the router and to the internet (1.1.1.1 and 8.8.8.8) every 10 seconds, packet loss, and an **outage log**. Three missed checks in a row count as an outage, and sleep isn't mistaken for one.
- Public IP address and provider from one hourly request to ipinfo.io. You can turn it off.
- **Speed test** against Cloudflare, on demand or on a schedule (off by default). It sizes its transfers to the link and shows how much data it used (at most about 38 MB). A daily or weekly schedule runs around 3 am (Mondays for weekly), or at the next chance if the computer was asleep, never during an outage, and by default as a light test of about 10 MB at most. Results are charted in History.
- **History**: latency, packet loss and whole-network throughput in five-minute buckets, kept for 30 days and shown over 24 hours, 7 days or 30 days, with uptime, average latency, outages and data used.
- **Wi-Fi channel analyzer** (macOS): nearby networks drawn by channel and signal for 2.4 and 5 GHz, with your network highlighted and the least crowded of channels 1, 6 and 11 recommended.
- **VPN and DNS leak check**: shows whether traffic is going through a VPN, and runs a DNS leak test (via bash.ws) that lists which resolvers answer your lookups and flags a leak when you're on a VPN but your own provider answers them.
- **Wi-Fi** (macOS): channel, band, width, standard, link rate, signal and noise, security mode (with an alert for open, WEP or WPA/TKIP-mixed networks), and nearby networks on overlapping channels. This computer's firewall state.

### 📈 Traffic
*Needs capture permission.*

- Live download and upload throughput, and the top remote hosts, named from the DNS answers capture has seen.
- A DNS lookup log.

### 🔵 Bluetooth and nearby
*macOS.*

- Your paired Bluetooth devices, with connection state and battery levels (AirPods left, right and case; keyboards; mice; Magic Mouse, Keyboard and Trackpad via the system registry). A connected accessory at 15% or below raises a Low "battery low" alert, at most once a day per device.
- Opt-in **nearby scan** that only listens to the advertisements devices broadcast. It never connects, pairs or sends anything. It names makers from Bluetooth company IDs and recognizes Apple Continuity types (AirPods, Apple Watch, iPhone/iPad/Mac).
- **Unknown tracker alerts**: Apple Find My tags that report being away from their owner, Tile, Samsung SmartTag and Google Find My Device tags. If one you haven't marked as yours stays in range for 15 minutes, NetWatch raises an alert.
- Each device gets a type (phone, tracker, headphones, car, smart lock, garage/gate opener, solar inverter, e-scooter and more) and a brand, from its name, the Bluetooth SIG company list (about 4,000 makers) and its advertised services.
- **Locate mode**: a live, smoothed signal meter for one device with a warmer/colder trend, a 60-second trail and optional beeps, to walk towards a lost or unknown device.
- **Pop-up spam detection**: alerts when a burst of fake Apple, Fast Pair or Swift Pair devices appears (the kind Flipper Zero or ESP32 "BLE spam" firmware sends).
- A **proximity map** of nearby Bluetooth devices and Wi-Fi networks: bands from Touching (under 1 m) to Far (10 m and up) above "This Mac", with distance estimated from signal strength, smoothed, and a margin before a device changes band. One receiver can't tell direction, so devices are grouped by type within a band (yours first, then trackers), not placed by angle. Filter by All, Mine, Trackers or Wi-Fi; click a Bluetooth device for its **details panel** (services, TX power, a 10-minute signal graph, Locate, and a "This is mine" switch).
- **Your devices nearby today**: for paired devices (while connected) and devices you mark as yours (while heard), NetWatch keeps sessions for 30 days, shows a 24-hour bar and the time nearby today. Nothing else is recorded over time. Phones and tags rotate their Bluetooth address, so an unpaired device may split into several entries; unmarking a device deletes its history.
- The Security checkup flags a Mac that is discoverable over Bluetooth, and paired devices unused for 30+ days.

### 🗓️ Timeline
- A **weekly report**: one click saves a self-contained HTML report (uptime, latency, data by day, checkup results, alerts, devices, outages, speed tests) to Downloads and opens it; print it to PDF from your browser.
- Seven days of what happened on one page: devices appearing, joining and leaving, outages, 4G link changes, speed tests, alerts and morning summaries, filterable by kind.

### ✅ Security checkup
- One list of what NetWatch knows: apps on this computer accepting network connections, UPnP and port forwards, CGNAT exposure, Wi-Fi security, the firewall, untrusted devices, risky open ports, open alerts, whether capture and the threat lists are current, DNS honesty, unknown trackers and data allowance. Each item is marked good, worth a look, or a problem, with a button to act on it.

### 🔍 Security audits
*Security → Audit; each can be switched off in Settings; every one takes a baseline first and alerts on changes after that.*

- **Weekly port audit**: every 7 days (or "Run audit now") the common ports on every online device, this computer included, two devices at a time. New open ports alert; closed ones are recorded. The last 12 runs are kept.
- **New listening apps**: every minute, the (app, port) pairs accepting TCP connections on non-loopback addresses.
- **Startup items** (macOS): every 5 minutes, the launch agents and daemons in `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons`, read with `plutil`. NetWatch's own login item is ignored.
- **DNS and router changes**: one baseline per network (keyed by the router's MAC) for the DNS servers and the DHCP server.
- **Look-alike Wi-Fi**: other access points using your network's name, told apart by BSSID. Needs Wi-Fi names to be visible, which macOS only allows with Location permission (Settings → Location; until it's allowed the page says so and offers an **Allow location** button).
- **Certificates and HTTPS interception**: a TLS handshake with each watched *hostname* every 6 hours (rustls with the bundled Mozilla roots, not the keychain), and once a day a check of apple.com, cloudflare.com and google.com for a proxy re-signing HTTPS.

### 🧰 Tools
- **Watched hosts**: up to 10 websites or servers checked every 15 seconds (ping, or a TCP connect for `host:port`), with uptime, latency sparklines and alerts when one stops or starts answering.
- **Morning summary**: an 8 am notification with yesterday's data use, outages, 4G drops, new devices and alerts.
- **Mobile connection** (TP-Link 4G hotspots such as the M7350): network type (4G/3G/2G), SIM state, devices on the hotspot and a log of every network-type change, read from the hotspot's status page without logging in. Alerts when the link drops from 4G.
- **Traceroute** to any host, with reverse DNS and the biggest latency jump highlighted.
- **DNS check**: your DNS servers against Cloudflare, Google and Quad9 (cached and full-lookup times), plus an NXDOMAIN-hijacking test, which alerts if your provider answers for domains that don't exist.
- **Wake-on-LAN** from a device's details.
- **Notes and tags** on devices (searchable, included in the CSV export).

### 🧑‍💻 Expert mode and log export
*Off by default, in Settings.*

- **Expert mode**: each alert card gets an "Expert details" section with the MITRE ATT&CK technique (linked to attack.mitre.org) and tactic where one clearly applies, why the alert matters, what to do, and the raw alert as JSON with a Copy button. The table is in `expert.rs`; a test fails if a new alert kind is added without an entry.
- **Log file**: every new alert is appended as one JSON line to `alerts.jsonl` in the data folder, which becomes `alerts.1.jsonl` at 10 MB. Repeats merged into an existing alert aren't written again.
- **SIEM forwarding**: set a `host:port` and each new alert is sent there over UDP as an RFC 5424 syslog message, with either a CEF payload (`CEF:0|NetWatch|NetWatch|<version>|<kind>|<title>|<0-10 severity>|…`) or the alert as JSON. "Send test event" sends one info-level event. Only the address you enter is ever contacted.

### 📊 Apps
*macOS, no special permission.*

- Download and upload per app on this computer, from `nettop`. Helper processes count toward their app.

### 🔌 Connections
*No special permission.*

- Every open socket, with its process. Connections are flagged if the remote end is on a blocklist.

### 🔔 Notifications and background
- System notifications for new alerts at the severity you choose, shown when the window isn't in front.
- A menu-bar (tray) icon with a status line, Scan now and Quit. Closing the window keeps NetWatch monitoring; you can turn that off in Settings.

## 🚨 Detectors

| Alert | How it's detected | Severity |
|---|---|---|
| ARP spoofing | The router's IP is suddenly claimed by a different MAC | High |
| Rogue DHCP server | A second server hands out addresses | High |
| Malware domain lookup | A DNS name, or its parent domain, is on abuse.ch URLhaus or ThreatFox, or your list | High |
| Botnet server traffic | Traffic or a socket to an abuse.ch Feodo Tracker or ThreatFox IP, or your list | High |
| Port scan | One source hits ≥20 different ports on this machine within 15 s | Medium |
| IP conflict | Two MACs answer for one IP within 10 minutes | Medium |
| Suspicious port | Outbound to the internet on 23, 1337, 4444, 6667–6669 or 31337 | Medium |
| New device | An untrusted MAC appears after the baseline | Medium |
| Beaconing | 10 connections to one host:port at a steady interval (≥20 s, <8% jitter) | Low |
| Exposed service | A port check finds Telnet, FTP, RDP or VNC open | Low |
| New port forward | A device opens a UPnP port mapping on the router | Medium |
| Data allowance | Whole-network usage passes 80% / 100% of your monthly allowance | Low / Medium |
| Data forecast | At the pace of the last week the cycle's usage will pass your allowance, with 3+ days left (once per cycle) | Low |
| Weak Wi-Fi security | Open, WEP, or WPA/WPA2 mixed (TKIP) mode | Medium / Low |
| Outage | Internet or router unreachable for 30 s or more | Low |
| Device joined / left | A device you watch comes online or goes offline | Info |
| Unknown tracker | A tracker not marked as yours stays in Bluetooth range for 15 min | Medium |
| Tracker travelling with you | An unknown tracker is near this Mac before and after it moved 1 km or more, 15+ min apart (needs Location and the nearby Bluetooth scan) | High |
| DNS redirects typos | Your DNS server answers for a domain that doesn't exist | Low |
| Low accessory battery | A connected Bluetooth accessory reports 15% or less (once a day per device) | Low |
| Bluetooth pop-up spam | 12+ new fake pop-up devices within 10 s | Medium |
| Watched host down / up | No answer for 3 checks in a row, then answering again | Low |
| Mobile link drop | The hotspot falls from 4G to 3G, 2G or no service | Low |
| New open port | The weekly port audit finds a port that wasn't open last time (Telnet, FTP, RDP, VNC: Medium) | Low / Medium |
| Port audit summary | One line per audit run, e.g. "7 devices checked, 1 change" | Info |
| New listening app | An app starts accepting connections on a (app, port) not seen before | Low |
| New startup item | A launch agent or daemon appears (High if it runs from /tmp, /var/tmp, /Users/Shared or a hidden folder, or fails `codesign -v`) | Medium / High |
| DNS servers changed | A DNS server this network never used before ("possible DNS hijack") | Medium |
| DHCP server changed | A different DHCP server than last time on this network | Low |
| Look-alike Wi-Fi | Your network's name from another BSSID with weaker or no security (High), or with the same security from a BSSID not seen before (Low) | High / Low |
| Certificate | A watched site's certificate expires within 14 days (Medium) or 3 days / is expired / doesn't verify (High), or changes to another issuer (Medium) | Medium / High |
| HTTPS interception | Every reachable test site fails with an unknown-issuer error | High |

Repeats of the same alert are merged until you acknowledge it. The threat feeds refresh daily, and the vendor database refreshes monthly.

## 👁️ What it can see

Capture is **not promiscuous**. It sees this computer's own traffic plus broadcast and multicast traffic, which every LAN device receives (ARP, DHCP, mDNS). That covers the spoofing, rogue DHCP and new-device detectors network-wide, but on Wi-Fi or a switched network a laptop can't see *other* devices' private traffic. To watch everything, run NetWatch on a machine connected to a **mirrored (SPAN) switch port** or on the router itself.

DNS lookups made over DNS-over-HTTPS or DNS-over-TLS (some browsers, iCloud Private Relay) are encrypted and won't appear in the DNS log.

## 🔐 Permissions

| OS | What capture needs |
|---|---|
| macOS | Read access to `/dev/bpf*`. The in-app **Grant access** button gives the `admin` group read/write on them, behind a password prompt, the same way Wireshark's ChmodBPF does. It resets at reboot. |
| Linux | `sudo setcap cap_net_raw,cap_net_admin=eip /path/to/netwatch`, then restart the app. The in-app button tries this through `pkexec`. |
| Windows | Install [Npcap](https://npcap.com). The app starts without it, and only capture is disabled. |

**Location Services** (macOS, off by default, Settings → Location): turning it on makes macOS ask once. NetWatch uses the permission for two things only: real Wi-Fi network names and BSSIDs from CoreWLAN (shown in the Wi-Fi analyzer, the Connection page, the proximity map and the look-alike check), and the tracker-travel warning. This Mac's position is only read while an unknown tracker is near, held in memory, and never saved, logged, put in an alert or recorded next to anyone else's Wi-Fi networks or Bluetooth devices; the only thing remembered is where this Mac was when each unknown tracker was first heard, until that tracker is gone.

Device discovery, presence, mDNS/SSDP, the port check, the Network page, per-app usage and the Connections view all work without these permissions. Ping uses an unprivileged ICMP socket. macOS allows that, and on Linux it works when `net.ipv4.ping_group_range` includes your group (the default on most distributions). Without it, presence falls back to TCP checks and the connection-quality chart is unavailable.

## 🛠️ Building

Prerequisites: Rust (`rustup`) and the Tauri CLI (`cargo install tauri-cli --version "^2" --locked`). No Node is needed.

```sh
cd src-tauri
cargo run                          # dev build
cargo test                         # detector, parser and store tests
cargo tauri build                  # release bundles for the current OS
cargo build --no-default-features  # build without packet capture (no libpcap needed)
```

- **macOS** needs only Xcode's command-line tools; libpcap ships with the OS. Output: `src-tauri/target/release/bundle/macos/NetWatch.app`.
- **Linux** (Debian/Ubuntu): `sudo apt install libpcap-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev build-essential`.
- **Windows** needs MSVC Build Tools, WebView2 (preinstalled on Windows 11) and the [Npcap SDK](https://npcap.com/#download). Set `LIB` to its `Lib\x64` folder before building, for example `set LIB=%LIB%;C:\npcap-sdk\Lib\x64`. `wpcap.dll` is delay-loaded, so the app still starts without Npcap.

> Status: built and tested on macOS (Intel, macOS 26) only. The Windows and Linux code paths are written behind `#[cfg]` gates, and their parsers (ARP table output for each OS) are unit-tested, but they have **never been compiled or run** on those systems. Wi-Fi details, the firewall state, DHCP lease details, per-app usage and paired Bluetooth devices are macOS-only for now. The nearby Bluetooth scan uses btleplug, which supports all three systems.

## 💾 Data

<details>
<summary>Where NetWatch keeps its files</summary>

Data is stored in the OS app-data folder, `dev.netwatch.desktop`. On macOS that's `~/Library/Application Support/dev.netwatch.desktop/`.
- `devices.json`: the device inventory, including each device's online history.
- `usage.json`: hourly whole-network data usage. `outages.json`, `speedtests.json`, `speedtest-schedule.json` (when the scheduled speed test was switched on and last ran), `router.json` (port forwards already seen), `bluetooth.json` (devices you marked as yours, plus their presence history and when each paired device last connected), `mobile-link.json` (4G/3G changes), `settings.json` (including watched hosts).
- `alerts.json`: alert history, capped at 1000.
- `alerts.jsonl`, `alerts.1.jsonl`: the optional log file (Settings → Expert mode & log export).
- `audit.json`: what the security audits remember (baselines, the last 12 port audits, certificates).
- `urlhaus.txt`, `feodo.txt`, `threatfox-domains.txt` (at most every 3 days, even on "Update now"), `threatfox-ips.csv`, `manuf.txt`: cached feeds.
- `custom.txt`: your own blocklist, editable in Settings.

</details>

## 🗂️ Layout

<details>
<summary>Source tree</summary>

```
ui/                    index.html, style.css, app.js, network.js, bluetooth.js, security.js, audit.js, timeline.js, insights.js, tools.js (no build step)
src-tauri/src/
  main.rs              Tauri commands, window and tray wiring
  core/mod.rs          shared state and background workers (scans, mDNS, capture, feeds, notifications)
  core/presence.rs     minute-by-minute presence checks and join/leave alerts
  core/monitor.rs      router, data usage, connection health, Wi-Fi, public IP, apps, speed test
  core/audit.rs        schedules for the security audits, their saved state and alerts
  audit.rs             the audit rules (port, listener, startup-item, DNS/DHCP and Wi-Fi look-alike diffs), with tests
  certs.rs             TLS handshakes (rustls + webpki-roots), x509 parsing, certificate and interception rules
  ping.rs              unprivileged ICMP echo and TCP liveness checks
  upnp.rs              read-only UPnP IGD queries
  usage.rs             counter deltas (wraps, reboots) and hourly usage buckets
  health.rs            latency samples and the outage tracker
  internet.rs          public IP lookup and the speed test
  wifi.rs              macOS Wi-Fi and firewall readers
  apps.rs              per-app usage from nettop
  bluetooth.rs         paired devices and batteries, advertisement classification, tracker recognition
  bt_bands.rs          proximity bands: distance smoothing and band hysteresis
  bt_presence.rs       presence sessions for your own devices, stale pairings
  core/bluetooth.rs    the passive BLE scan (btleplug), tracker and battery alerts
  tools.rs             Wake-on-LAN, traceroute, DNS check
  bt_types.rs          device type and brand rules for Bluetooth names
  mifi.rs              TP-Link 4G hotspot status
  data/bt_*.txt        Bluetooth SIG company, service and member-UUID lists
  history.rs           five-minute latency/loss/traffic buckets for 30 days
  expert.rs            expert mode's table: ATT&CK technique, tactic, why it matters and what to do for every alert kind
  export.rs            the log file and SIEM forwarding (RFC 5424 syslog with CEF or JSON), on its own thread
  tray.rs, settings.rs
  detect.rs            packet analyzer and all traffic detectors, with tests
  discovery.rs         ARP sweep and tables, mDNS, SSDP, port check
  capture.rs           libpcap thread and per-OS permission handling
  conns.rs             sockets → processes
  blocklist.rs, oui.rs, store.rs, alerts.rs, net.rs, util.rs
```

For dev builds only, `NETWATCH_EVAL='setView("devices")' cargo run` runs that JS in the window after it loads. It's handy for scripted screenshots.

</details>

---

<div align="center">

Built by <b>Jorden Armstrong</b>. Feedback and bug reports welcome: open an <a href="../../issues">issue</a>.

</div>

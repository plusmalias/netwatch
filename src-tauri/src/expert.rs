//! Expert mode's knowledge table: for every alert kind, the MITRE ATT&CK
//! technique(s) it relates to, the tactic, why it matters and what to do.
//!
//! A technique is only listed where the mapping is solid. Alerts with
//! ordinary innocent causes (a new phone, a router swap) or that aren't about
//! an attacker at all (battery, data allowance) have none, and then no tactic
//! either: a tactic without a technique would be a guess. Technique ids and
//! names are as published at https://attack.mitre.org.
//!
//! Adding an alert kind elsewhere without an entry here fails
//! `every_alert_kind_in_the_code_has_an_entry`.

use serde::Serialize;

/// An ATT&CK technique or sub-technique: id ("T1557.002") and its full name.
pub type Technique = (&'static str, &'static str);

pub struct KindInfo {
    pub kind: &'static str,
    pub techniques: &'static [Technique],
    /// ATT&CK tactic(s), comma separated. Empty exactly when there are no techniques.
    pub tactic: &'static str,
    pub why: &'static str,
    pub steps: &'static [&'static str],
}

const AITM: &str = "Credential Access, Collection";
const PERSIST: &str = "Persistence, Privilege Escalation";
const C2: &str = "Command and Control";

const T_APP_LAYER: Technique = ("T1071", "Application Layer Protocol");
const T_ARP: Technique = ("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning");
const T_DHCP: Technique = ("T1557.003", "Adversary-in-the-Middle: DHCP Spoofing");
const T_TWIN: Technique = ("T1557.004", "Adversary-in-the-Middle: Evil Twin");
const T_MASQ: Technique = ("T1036", "Masquerading");

pub const KINDS: &[KindInfo] = &[
    // ---- network attacks (packet capture)
    KindInfo {
        kind: "arp_spoof",
        techniques: &[T_ARP],
        tactic: AITM,
        why: "Another device is claiming your router's address, which is how someone on your network can sit between you and the internet to read or alter your traffic.",
        steps: &[
            "If you just replaced, reset or reconfigured the router, a new MAC address is expected; acknowledge the alert.",
            "Otherwise find the MAC address from the alert in Devices and identify it; remove it from the network (block it in the router, or change the Wi-Fi password).",
            "Avoid signing in to anything sensitive until it is resolved; a VPN or a wired connection helps.",
        ],
    },
    KindInfo {
        kind: "ip_conflict",
        techniques: &[],
        tactic: "",
        why: "Two devices answered for the same address. Usually that is a DHCP or fixed-address mix-up, but ARP spoofing looks identical from here.",
        steps: &[
            "Find both MAC addresses from the alert in Devices and see whether they are devices you know.",
            "If one has a manually set address inside the router's DHCP range, move it outside the range or switch it back to automatic.",
            "If it keeps happening with an unfamiliar device, treat it like an ARP spoofing alert.",
        ],
    },
    KindInfo {
        kind: "rogue_dhcp",
        techniques: &[T_DHCP],
        tactic: AITM,
        why: "A second device is handing out network settings. A rogue DHCP server can point other devices at its own gateway or DNS server and intercept their traffic.",
        steps: &[
            "If you added a second router, access point or Pi-hole on purpose, acknowledge the alert.",
            "Otherwise find the device at the address in the alert in Devices and unplug or block it.",
            "Check your router's DHCP settings and DNS servers, then renew the lease on affected devices.",
        ],
    },
    KindInfo {
        kind: "port_scan",
        techniques: &[("T1046", "Network Service Discovery")],
        tactic: "Discovery",
        why: "Something probed many ports on this computer in a short time, which is how attackers (and some security tools) look for services to attack.",
        steps: &[
            "If the source is a device on your network, check whether it is yours; a vulnerability scanner or network tool can cause this.",
            "If it came from the internet, make sure your router isn't forwarding ports you don't need (see UPnP port forwards) and that the macOS firewall is on.",
            "Keep this computer's software up to date.",
        ],
    },
    KindInfo {
        kind: "suspicious_port",
        techniques: &[("T1571", "Non-Standard Port")],
        tactic: C2,
        why: "This computer connected out on a port that backdoors, trojans and IRC botnets favour and ordinary software rarely uses.",
        steps: &[
            "Open Connections and find which app owns the connection.",
            "If you don't recognise the app, quit it and run a malware scan.",
            "Telnet and IRC clients are legitimate if you use them yourself; acknowledge the alert then.",
        ],
    },
    KindInfo {
        kind: "c2_traffic",
        techniques: &[T_APP_LAYER],
        tactic: C2,
        why: "This computer exchanged traffic with a server on a botnet command-and-control blocklist, a strong sign that malware is talking to its operator.",
        steps: &[
            "Open Connections to see which app is talking to the server.",
            "Quit that app, then run a malware scan and review the startup items on the Audit page.",
            "If you can't explain it, disconnect the computer and change important passwords from a clean device.",
        ],
    },
    KindInfo {
        kind: "c2_connection",
        techniques: &[T_APP_LAYER],
        tactic: C2,
        why: "A running process has an open connection to a server on a botnet or malware blocklist, a strong sign that malware is talking to its operator.",
        steps: &[
            "Note the process name and pid from the alert and quit it.",
            "Find where it lives (Activity Monitor, or Connections) and remove it; run a malware scan.",
            "Review the startup items on the Audit page in case it comes back.",
        ],
    },
    KindInfo {
        kind: "beacon",
        techniques: &[T_APP_LAYER],
        tactic: C2,
        why: "This computer opened connections to the same server at a steady interval, the check-in pattern malware uses to wait for orders. Updaters and sync clients look the same.",
        steps: &[
            "Open Connections and see which app owns the connection and whether the server name is one you know.",
            "If it's a sync client, updater or chat app, acknowledge the alert.",
            "If you don't recognise the app or the server, quit it and run a malware scan.",
        ],
    },
    KindInfo {
        kind: "malicious_domain",
        // URLhaus lists malware distribution sites and ThreatFox adds C2 domains;
        // a lookup alone doesn't say which, so no single technique fits.
        techniques: &[],
        tactic: "",
        why: "A device looked up a domain that is on a malware blocklist. It may have clicked a bad link, or software on it may be reaching for a malware server.",
        steps: &[
            "Find the app or page that made the request: Connections shows the app on this computer, and the DNS log shows which device asked.",
            "Scan that device for malware and check its browser extensions.",
            "If you added the entry to your own blocklist as a test, acknowledge the alert.",
        ],
    },
    KindInfo {
        kind: "tls_intercept",
        techniques: &[("T1557", "Adversary-in-the-Middle")],
        tactic: AITM,
        why: "Real sites' HTTPS certificates always chain to a public authority. When they don't, something is re-signing your HTTPS traffic and can read it.",
        steps: &[
            "Antivirus, parental controls, a company or school proxy and Wi-Fi sign-in pages all do this legitimately; check whether any applies.",
            "If none does, treat the network as untrusted: don't sign in to anything sensitive and switch to another network or a VPN.",
            "Check this computer's keychain for certificates you don't recognise.",
        ],
    },
    KindInfo {
        kind: "cert",
        techniques: &[],
        tactic: "",
        why: "A watched site's HTTPS certificate is about to expire, has expired, changed to one from a different issuer, or doesn't verify. Most causes are an owner's forgotten renewal, but a changed issuer can also mean interception.",
        steps: &[
            "If it is your own site or server, renew or fix the certificate.",
            "If it is someone else's site, check whether it also looks wrong from another network or device.",
            "A changed issuer on a site you didn't expect to change is worth treating like an HTTPS interception alert.",
        ],
    },
    // ---- security audits
    KindInfo {
        kind: "launch_item",
        techniques: &[
            ("T1543.001", "Create or Modify System Process: Launch Agent"),
            ("T1543.004", "Create or Modify System Process: Launch Daemon"),
        ],
        tactic: PERSIST,
        why: "A new launch agent or daemon makes a program start by itself at login or boot. Installers use this legitimately; malware uses it to survive a restart.",
        steps: &[
            "Check whether you just installed something that would add it.",
            "Open the plist from the alert and look at the program it runs; be wary of temporary or hidden folders and unsigned programs.",
            "If you don't recognise it, unload and delete the plist, delete the program, and run a malware scan.",
        ],
    },
    KindInfo {
        kind: "new_listener",
        techniques: &[],
        tactic: "",
        why: "An app on this computer started accepting connections from other devices. That is normal for sharing and developer tools, and an unexpected one widens what an attacker on your network can reach.",
        steps: &[
            "Check that you know the app and expected it to listen.",
            "If you don't need it, quit the app or turn off its sharing option.",
            "Turn on the macOS firewall in System Settings → Network.",
        ],
    },
    KindInfo {
        kind: "port_audit",
        techniques: &[],
        tactic: "",
        why: "A device on your network started accepting connections on a port that was closed at the previous audit, so it is exposing something new, perhaps after an update or a setting change.",
        steps: &[
            "Check whether you or someone at home just set up or updated that device.",
            "If not, look at what the device runs and turn off the service on that port.",
            "Remote-access ports (Telnet, FTP, VNC, Remote Desktop) deserve the quickest look.",
        ],
    },
    KindInfo {
        kind: "port_audit_summary",
        techniques: &[],
        tactic: "",
        why: "The weekly port audit finished. It's a record of what changed, not a warning.",
        steps: &[
            "Review the Audit page if any ports newly opened.",
            "Nothing to do when the ports are the same as last time.",
        ],
    },
    KindInfo {
        kind: "exposed_service",
        techniques: &[],
        tactic: "",
        why: "A device accepts connections on a remote-access service (FTP, Telnet, Remote Desktop or VNC). These are often unencrypted or weakly protected and are favourite targets once someone is on your network.",
        steps: &[
            "Turn the service off on the device if you don't use it.",
            "If you do use it, use a strong password and prefer an encrypted alternative such as SSH.",
            "Never forward its port from your router to the internet.",
        ],
    },
    KindInfo {
        kind: "dns_change",
        techniques: &[],
        tactic: "",
        why: "This computer now uses DNS servers it has never used on this network. DNS decides where every name leads, so a changed server can silently send you to fake sites. Providers and router updates also change it.",
        steps: &[
            "Compare the new servers with your router's DNS settings and your provider's.",
            "If you didn't change anything and the servers are unfamiliar, set the router's DNS to a public resolver (Cloudflare 1.1.1.1 or Quad9 9.9.9.9) and check the router's admin password.",
            "Run the DNS check on the Connection page to see how the servers answer.",
        ],
    },
    KindInfo {
        kind: "dhcp_change",
        techniques: &[],
        tactic: "",
        why: "A different device is handing out network settings than before. That's normal after swapping a router, but a rogue DHCP server can redirect your traffic.",
        steps: &[
            "If you changed or reconfigured the router or added an access point, acknowledge the alert.",
            "Otherwise identify the new server's address in Devices.",
            "If it is unfamiliar, unplug it and check your router's DHCP and DNS settings.",
        ],
    },
    KindInfo {
        kind: "evil_twin",
        techniques: &[T_TWIN],
        tactic: AITM,
        why: "Another access point is broadcasting your Wi-Fi network's name. If it has weaker security it is a classic evil twin: devices that join it hand over their traffic. With the same security it is often just a mesh node or extender.",
        steps: &[
            "Don't connect to the other network.",
            "If it's your own router, extender or guest network, fix its security or give it a different name.",
            "If you can't account for it, check for an unfamiliar device nearby and let the router's admin know.",
        ],
    },
    // ---- network health and housekeeping
    KindInfo {
        kind: "new_device",
        techniques: &[],
        tactic: "",
        why: "A device joined your network for the first time. Visitors' phones and new gadgets cause most of these, but it is also how an uninvited device shows up.",
        steps: &[
            "Open Devices and identify it (vendor, name, services).",
            "Mark it trusted if it is yours.",
            "If you don't recognise it, change the Wi-Fi password and see if it comes back.",
        ],
    },
    KindInfo {
        kind: "identity_change",
        techniques: &[T_MASQ],
        tactic: "Defense Evasion",
        why: "A device you trusted now describes itself differently when it asks for an address. Updates and resets do this, but so does another device that copied its MAC address to slip past MAC filtering and inherit its trust.",
        steps: &[
            "Check whether the named device was updated, reset or replaced recently; if so, acknowledge the alert.",
            "If not, see whether the original device is switched off or away while this one is online; a clone usually appears when the original isn't there.",
            "Don't rely on MAC filtering. Change the Wi-Fi password if you can't account for the change.",
        ],
    },
    KindInfo {
        kind: "presence",
        techniques: &[],
        tactic: "",
        why: "A device you chose to watch joined or left the network.",
        steps: &["Nothing to do unless the timing is unexpected; turn off watching in the device's details if it's noisy."],
    },
    KindInfo {
        kind: "port_forward",
        techniques: &[],
        tactic: "",
        why: "A device asked your router (over UPnP) to open a port to the internet. Games, consoles and media servers do this on purpose, but every forwarded port is reachable from outside.",
        steps: &[
            "Check that you know the device and expected it.",
            "If you don't need it, remove the mapping in the router and turn off UPnP.",
            "Make sure whatever listens on that port is up to date and password protected.",
        ],
    },
    KindInfo {
        kind: "dns_hijack",
        techniques: &[],
        tactic: "",
        why: "Your DNS server returns addresses for domains that don't exist. Providers do this to show ads or search pages for typos, and it can break apps; it isn't an attack in itself.",
        steps: &[
            "Switch the router's DNS to a public resolver such as Cloudflare (1.1.1.1) or Quad9 (9.9.9.9).",
            "Run the DNS check on the Connection page to confirm it stops.",
        ],
    },
    KindInfo {
        kind: "wifi_security",
        techniques: &[],
        tactic: "",
        why: "Your Wi-Fi uses an outdated or missing security mode, which makes it easier for someone nearby to join or listen in.",
        steps: &[
            "Open the router's Wi-Fi settings and choose WPA2 (AES) or WPA2/WPA3.",
            "Turn off old WPA/TKIP and WEP modes; replace devices that can't cope.",
            "Change the Wi-Fi password afterwards if the network was open or used WEP.",
        ],
    },
    KindInfo {
        kind: "outage",
        techniques: &[],
        tactic: "",
        why: "Your internet or router stopped answering for a while. It's a record for your own reference or for your provider.",
        steps: &[
            "If it repeats, note the times and report them to your provider.",
            "Restart the router and check its cables if it keeps happening.",
        ],
    },
    KindInfo {
        kind: "data_cap",
        techniques: &[],
        tactic: "",
        why: "You are close to or over your monthly data allowance, which can mean extra charges or a slowed connection.",
        steps: &[
            "Check the Network page for when the data was used and Traffic for which apps used it.",
            "Pause large downloads, backups and video streaming until the allowance renews.",
        ],
    },
    KindInfo {
        kind: "data_forecast",
        techniques: &[],
        tactic: "",
        why: "At the pace of the last week, your network is on course to use more than your monthly data allowance before it renews, which can mean extra charges or a slowed connection.",
        steps: &[
            "Check the Network page for which days used the most, and Traffic for which apps on this computer used it.",
            "Pause large downloads, backups, cloud sync and video streaming, or lower video quality, to bring the pace down.",
            "If you often go over, consider a bigger plan or a top-up before the allowance runs out.",
        ],
    },
    KindInfo {
        kind: "link_downgrade",
        techniques: &[],
        tactic: "",
        why: "Your 4G hotspot dropped to a slower mobile connection type or lost service.",
        steps: &[
            "Move the hotspot nearer a window or to higher ground and check again.",
            "If it often happens where coverage is normally good, share the times in the Network page's log with your provider.",
        ],
    },
    KindInfo {
        kind: "daily_summary",
        techniques: &[],
        tactic: "",
        why: "The morning summary of yesterday on your network.",
        steps: &["Nothing to do; switch it off in Settings if you don't want it."],
    },
    // ---- Bluetooth
    KindInfo {
        kind: "bt_battery",
        techniques: &[],
        tactic: "",
        why: "A Bluetooth device you use reports a low battery.",
        steps: &["Charge it or change its batteries."],
    },
    KindInfo {
        kind: "ble_spam",
        techniques: &[],
        tactic: "",
        why: "Many fake Bluetooth devices appeared at once: a spam tool (a Flipper Zero or ESP32 with spam firmware, for example) flooding nearby phones with pairing pop-ups. It can't pair with your devices, but it is a nuisance and can drain batteries.",
        steps: &[
            "Don't accept unexpected pairing requests.",
            "It stops when the sender moves out of range; turn Bluetooth off briefly if it doesn't.",
        ],
    },
    KindInfo {
        kind: "ble_tracker",
        techniques: &[],
        tactic: "",
        why: "A tracker tag that isn't yours has stayed near you for a long time, which is how someone can follow your movements.",
        steps: &[
            "Check your bags, jacket pockets and car; watch the signal on the Bluetooth page grow as you get closer.",
            "If you find one you don't own, take a photo and contact local police; don't just throw it away.",
            "If it belongs to you or someone you live with, mark it as yours.",
        ],
    },
    KindInfo {
        kind: "tracker_following",
        techniques: &[],
        tactic: "",
        why: "A tracker tag that isn't yours was near this Mac, and still was after the Mac had moved at least 1 km over at least 15 minutes. A tag that rides along with you rather than staying put is how someone can follow your movements.",
        steps: &[
            "Check your bags, jacket pockets and car; watch the signal on the Bluetooth page grow as you get closer.",
            "On an iPhone, open Find My and look under Items for \"Items Detected Near You\"; Android has Unknown tracker alerts in its safety settings.",
            "If you find one you don't own, take a photo and keep it; if you feel threatened, contact local police and don't just throw it away.",
            "If it belongs to you or someone you live with, mark it as yours on the Bluetooth page.",
        ],
    },
];

/// The attack.mitre.org page for a technique: "T1557.002" → ".../techniques/T1557/002/".
pub fn attack_url(id: &str) -> String {
    format!("https://attack.mitre.org/techniques/{}/", id.replace('.', "/"))
}

#[derive(Serialize)]
pub struct TechniqueView {
    pub id: &'static str,
    pub name: &'static str,
    pub url: String,
}

/// One table entry as the window receives it.
#[derive(Serialize)]
pub struct KindView {
    pub kind: &'static str,
    pub techniques: Vec<TechniqueView>,
    pub tactic: &'static str,
    pub why: &'static str,
    pub steps: &'static [&'static str],
}

pub fn all() -> Vec<KindView> {
    KINDS
        .iter()
        .map(|k| KindView {
            kind: k.kind,
            techniques: k
                .techniques
                .iter()
                .map(|(id, name)| TechniqueView { id, name, url: attack_url(id) })
                .collect(),
            tactic: k.tactic,
            why: k.why,
            steps: k.steps,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn lookup(kind: &str) -> Option<&'static KindInfo> {
        KINDS.iter().find(|k| k.kind == kind)
    }

    /// Every alert kind NetWatch can raise, as of this writing. The scan below
    /// finds new ones; this list catches an entry being dropped by accident.
    const KNOWN_KINDS: &[&str] = &[
        "arp_spoof", "beacon", "ble_spam", "ble_tracker", "bt_battery", "c2_connection", "c2_traffic", "cert",
        "daily_summary", "data_cap", "data_forecast", "dhcp_change", "dns_change", "dns_hijack", "evil_twin", "exposed_service",
        "identity_change", "ip_conflict", "launch_item", "link_downgrade", "malicious_domain", "new_device", "new_listener", "outage",
        "port_audit", "port_audit_summary", "port_forward", "port_scan", "presence", "rogue_dhcp", "suspicious_port",
        "tls_intercept", "tracker_following", "wifi_security",
    ];

    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("source folder") {
            let p = e.unwrap().path();
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Every `kind: "name",` in the source: how an `AlertDraft` names its kind
    /// (other structs write `kind: "x".into()` and don't match).
    fn kinds_in_source() -> BTreeSet<String> {
        let mut files = Vec::new();
        rust_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        let mut kinds = BTreeSet::new();
        for f in files.iter().filter(|f| f.file_name().is_some_and(|n| n != "expert.rs")) {
            let text = std::fs::read_to_string(f).unwrap();
            // Comments quote kinds of other things ("phone", "tracker").
            for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
                for part in line.split("kind: \"").skip(1) {
                    if let Some((name, rest)) = part.split_once('"') {
                        let ident = !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                        if ident && rest.starts_with(',') {
                            kinds.insert(name.to_string());
                        }
                    }
                }
            }
        }
        kinds
    }

    #[test]
    fn every_alert_kind_in_the_code_has_an_entry() {
        let found = kinds_in_source();
        // A wrong path or a changed pattern must not pass by finding nothing.
        assert!(found.len() >= KNOWN_KINDS.len(), "source scan found only {found:?}");
        for k in KNOWN_KINDS {
            assert!(found.contains(*k), "{k} is listed here but no longer raised; remove it from KNOWN_KINDS and the table");
        }
        for k in found.iter().map(String::as_str).chain(KNOWN_KINDS.iter().copied()) {
            assert!(lookup(k).is_some(), "alert kind {k:?} has no entry in expert.rs");
        }
        // And the table holds nothing that isn't a real kind.
        for k in KINDS {
            assert!(found.contains(k.kind), "{} is in the table but never raised", k.kind);
        }
    }

    #[test]
    fn table_entries_are_complete_and_well_formed() {
        let mut seen = BTreeSet::new();
        for k in KINDS {
            assert!(seen.insert(k.kind), "duplicate entry for {}", k.kind);
            assert!(k.why.len() > 20 && !k.steps.is_empty(), "{} needs a reason and steps", k.kind);
            assert!(k.steps.iter().all(|s| !s.is_empty()));
            // A tactic goes with a technique and vice versa.
            assert_eq!(k.techniques.is_empty(), k.tactic.is_empty(), "{}: tactic/technique mismatch", k.kind);
            for (id, name) in k.techniques {
                let (main, sub) = id.split_once('.').map_or((*id, None), |(m, s)| (m, Some(s)));
                assert!(main.len() == 5 && main.starts_with('T') && main[1..].chars().all(|c| c.is_ascii_digit()), "bad id {id}");
                assert!(sub.is_none_or(|s| s.len() == 3 && s.chars().all(|c| c.is_ascii_digit())), "bad id {id}");
                assert!(!name.is_empty());
                // A sub-technique's name is "Parent: Name".
                assert_eq!(sub.is_some(), name.contains(": "), "{id} name {name:?}");
            }
        }
    }

    #[test]
    fn maps_the_documented_techniques() {
        let ids = |k: &str| lookup(k).unwrap().techniques.iter().map(|t| t.0).collect::<Vec<_>>();
        assert_eq!(ids("arp_spoof"), ["T1557.002"]);
        assert_eq!(ids("rogue_dhcp"), ["T1557.003"]);
        assert_eq!(ids("evil_twin"), ["T1557.004"]);
        assert_eq!(ids("tls_intercept"), ["T1557"]);
        assert_eq!(ids("port_scan"), ["T1046"]);
        assert_eq!(ids("launch_item"), ["T1543.001", "T1543.004"]);
        assert_eq!(ids("suspicious_port"), ["T1571"]);
        for k in ["c2_traffic", "c2_connection", "beacon"] {
            assert_eq!(ids(k), ["T1071"], "{k}");
        }
        // Mapped only where it's solid.
        for k in ["new_device", "ip_conflict", "malicious_domain", "bt_battery", "outage", "ble_tracker", "tracker_following"] {
            assert!(ids(k).is_empty(), "{k}");
        }
        assert!(lookup("nonsense").is_none());
    }

    #[test]
    fn attack_links_use_slashes_for_sub_techniques() {
        assert_eq!(attack_url("T1046"), "https://attack.mitre.org/techniques/T1046/");
        assert_eq!(attack_url("T1557.002"), "https://attack.mitre.org/techniques/T1557/002/");
        let view = all();
        assert_eq!(view.len(), KINDS.len());
        let arp = view.iter().find(|v| v.kind == "arp_spoof").unwrap();
        assert_eq!(arp.techniques[0].url, "https://attack.mitre.org/techniques/T1557/002/");
        // The window opens these through open_url, which only takes plain https links.
        assert!(view.iter().flat_map(|v| &v.techniques).all(|t| t.url.starts_with("https://") && !t.url.contains([' ', '"', '\''])));
    }
}

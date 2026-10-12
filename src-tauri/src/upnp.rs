//! Read-only UPnP IGD queries to the router: its model, WAN address, uptime,
//! traffic counters and the port forwards devices have opened on it.
//! NetWatch never adds, changes or deletes port mappings.

use crate::discovery::xml_tag;
use crate::util::is_private_ip;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

/// Where routers commonly serve their IGD description, tried when SSDP
/// discovery gets no answer (for example behind macOS's "block all incoming").
const DESC_PORTS: &[u16] = &[1900, 5000, 49152, 49000, 5431, 2869, 52869, 37215, 80];
const DESC_PATHS: &[&str] = &[
    "/gatedesc.xml",
    "/rootDesc.xml",
    "/igd.xml",
    "/description.xml",
    "/upnp/IGD.xml",
    "/igddesc.xml",
    "/DeviceDescription.xml",
    "/devicedesc.xml",
    "/gatedesc0b.xml",
];
const MAX_MAPPINGS: u32 = 128;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct PortMapping {
    pub protocol: String,
    pub external_port: u16,
    pub internal_client: String,
    pub internal_port: u16,
    pub description: String,
    pub enabled: bool,
    /// Empty means any remote host may connect.
    pub remote_host: String,
    pub lease_s: u64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct WanStatus {
    pub external_ip: Option<String>,
    /// The WAN address is itself private: the ISP uses carrier-grade NAT.
    pub cgnat: bool,
    pub connection: Option<String>,
    pub uptime_s: Option<u64>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Identity {
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub model_number: Option<String>,
    pub description: Option<String>,
    pub admin_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Service {
    kind: String,
    control_url: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Igd {
    pub location: String,
    pub identity: Identity,
    wan_conn: Option<Service>,
    wan_common: Option<Service>,
}

/// Finds the gateway's IGD description, starting with `hint` (a URL learned
/// from SSDP), then probing the usual ports and paths on the gateway.
pub fn discover(gateway: Ipv4Addr, hint: Option<String>) -> Option<Igd> {
    if let Some(igd) = hint.and_then(|url| fetch_description(&url)) {
        return Some(igd);
    }
    let open: Vec<u16> = DESC_PORTS
        .iter()
        .map(|&port| {
            thread::spawn(move || {
                TcpStream::connect_timeout(&SocketAddr::from((gateway, port)), Duration::from_millis(500))
                    .is_ok()
                    .then_some(port)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect();
    for port in open {
        for path in DESC_PATHS {
            if let Some(igd) = fetch_description(&format!("http://{gateway}:{port}{path}")) {
                return Some(igd);
            }
        }
    }
    None
}

fn fetch_description(url: &str) -> Option<Igd> {
    let xml = ureq::get(url)
        .timeout(Duration::from_millis(1500))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    parse_description(&xml, url)
}

fn origin(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    match url[after_scheme..].find('/') {
        Some(i) => &url[..after_scheme + i],
        None => url,
    }
}

fn resolve(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{}{path}", origin(base))
    } else {
        format!("{}/{path}", origin(base))
    }
}

fn parse_description(xml: &str, location: &str) -> Option<Igd> {
    if !xml.contains("InternetGatewayDevice") {
        return None;
    }
    let base = xml_tag(xml, "URLBase").unwrap_or_else(|| location.to_string());
    let mut wan_conn = None;
    let mut wan_common = None;
    for block in xml.split("<service>").skip(1) {
        let block = block.split("</service>").next().unwrap_or(block);
        let (Some(kind), Some(ctrl)) = (xml_tag(block, "serviceType"), xml_tag(block, "controlURL")) else {
            continue;
        };
        let svc = Service {
            control_url: resolve(&base, &ctrl),
            kind: kind.clone(),
        };
        if kind.contains(":WANIPConnection:") {
            wan_conn = Some(svc);
        } else if kind.contains(":WANPPPConnection:") {
            wan_conn.get_or_insert(svc);
        } else if kind.contains(":WANCommonInterfaceConfig:") {
            wan_common = Some(svc);
        }
    }
    Some(Igd {
        location: location.to_string(),
        identity: Identity {
            name: xml_tag(xml, "friendlyName"),
            manufacturer: xml_tag(xml, "manufacturer"),
            model: xml_tag(xml, "modelName"),
            model_number: xml_tag(xml, "modelNumber"),
            description: xml_tag(xml, "modelDescription"),
            admin_url: xml_tag(xml, "presentationURL").map(|u| resolve(location, &u)),
        },
        wan_conn,
        wan_common,
    })
}

/// One read-only SOAP action. Returns the response body, or the UPnP error.
fn soap(svc: &Service, action: &str, args: &str) -> Result<String, String> {
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{}\">{args}</u:{action}></s:Body></s:Envelope>",
        svc.kind
    );
    match ureq::post(&svc.control_url)
        .timeout(Duration::from_secs(2))
        .set("Content-Type", "text/xml; charset=\"utf-8\"")
        .set("SOAPAction", &format!("\"{}#{action}\"", svc.kind))
        .send_string(&body)
    {
        Ok(r) => r.into_string().map_err(|e| e.to_string()),
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(xml_tag(&text, "errorCode").map_or(format!("HTTP {code}"), |c| format!("UPnP error {c}")))
        }
        Err(e) => Err(e.to_string()),
    }
}

impl Igd {
    pub fn has_counters(&self) -> bool {
        self.wan_common.is_some()
    }

    pub fn status(&self) -> WanStatus {
        let Some(svc) = &self.wan_conn else {
            return WanStatus::default();
        };
        let external_ip = soap(svc, "GetExternalIPAddress", "")
            .ok()
            .and_then(|b| xml_tag(&b, "NewExternalIPAddress"))
            .filter(|ip| ip != "0.0.0.0");
        let info = soap(svc, "GetStatusInfo", "").ok();
        let cgnat = external_ip
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .is_some_and(|ip| is_private_ip(&ip));
        WanStatus {
            cgnat,
            external_ip,
            connection: info.as_deref().and_then(|b| xml_tag(b, "NewConnectionStatus")),
            uptime_s: info
                .as_deref()
                .and_then(|b| xml_tag(b, "NewUptime"))
                .and_then(|u| u.parse().ok()),
        }
    }

    /// Total bytes received and sent on the WAN link since the router booted.
    pub fn counters(&self) -> Option<(u64, u64)> {
        let svc = self.wan_common.as_ref()?;
        let rx = soap(svc, "GetTotalBytesReceived", "").ok()?;
        let tx = soap(svc, "GetTotalBytesSent", "").ok()?;
        Some((
            xml_tag(&rx, "NewTotalBytesReceived")?.parse().ok()?,
            xml_tag(&tx, "NewTotalBytesSent")?.parse().ok()?,
        ))
    }

    /// Lists port forwards. `None` if the router won't say.
    pub fn mappings(&self) -> Option<Vec<PortMapping>> {
        let svc = self.wan_conn.as_ref()?;
        let mut out = Vec::new();
        for i in 0..MAX_MAPPINGS {
            match soap(svc, "GetGenericPortMappingEntry", &format!("<NewPortMappingIndex>{i}</NewPortMappingIndex>")) {
                Ok(body) => out.extend(parse_mapping(&body)),
                // 713 (SpecifiedArrayIndexInvalid) marks the end of the list.
                Err(e) if i > 0 || e.contains("713") => break,
                Err(_) => return None,
            }
        }
        Some(out)
    }
}

fn parse_mapping(body: &str) -> Option<PortMapping> {
    let num = |tag: &str| xml_tag(body, tag).and_then(|v| v.parse::<u64>().ok());
    Some(PortMapping {
        protocol: xml_tag(body, "NewProtocol")?,
        external_port: num("NewExternalPort")? as u16,
        internal_client: xml_tag(body, "NewInternalClient").unwrap_or_default(),
        internal_port: num("NewInternalPort").unwrap_or(0) as u16,
        description: xml_tag(body, "NewPortMappingDescription").unwrap_or_default(),
        enabled: xml_tag(body, "NewEnabled").is_none_or(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        remote_host: xml_tag(body, "NewRemoteHost").unwrap_or_default(),
        lease_s: num("NewLeaseDuration").unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESC: &str = r#"<?xml version="1.0"?><root><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<presentationURL>http://192.168.0.1:80/</presentationURL>
<friendlyName>M7350</friendlyName><manufacturer>TP-Link</manufacturer>
<modelDescription>4G LTE Mobile Wi-Fi</modelDescription><modelName>M7350</modelName><modelNumber>v9.0</modelNumber>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/upnp/control/dummy</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>M7350</friendlyName>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/WANCommonIFC1</controlURL></service></serviceList>
<deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control/WANIPConn1</controlURL></service></serviceList></device></deviceList>
</device></deviceList></device></root>"#;

    #[test]
    fn parses_igd_description() {
        let igd = parse_description(DESC, "http://192.168.0.1:1900/gatedesc.xml").unwrap();
        assert_eq!(igd.identity.name.as_deref(), Some("M7350"));
        assert_eq!(igd.identity.description.as_deref(), Some("4G LTE Mobile Wi-Fi"));
        assert_eq!(igd.identity.admin_url.as_deref(), Some("http://192.168.0.1:80/"));
        let conn = igd.wan_conn.unwrap();
        assert_eq!(conn.control_url, "http://192.168.0.1:1900/upnp/control/WANIPConn1");
        assert_eq!(conn.kind, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(
            igd.wan_common.unwrap().control_url,
            "http://192.168.0.1:1900/upnp/control/WANCommonIFC1"
        );
        assert!(parse_description("<root>printer</root>", "http://x/").is_none());
    }

    #[test]
    fn parses_port_mapping_entry() {
        let body = "<u:GetGenericPortMappingEntryResponse><NewRemoteHost></NewRemoteHost><NewExternalPort>32400</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>32400</NewInternalPort><NewInternalClient>192.168.0.20</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Plex Media Server</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse>";
        let m = parse_mapping(body).unwrap();
        assert_eq!(m.external_port, 32400);
        assert_eq!(m.internal_client, "192.168.0.20");
        assert_eq!(m.description, "Plex Media Server");
        assert!(m.enabled);
    }

    #[test]
    fn resolves_relative_urls() {
        assert_eq!(resolve("http://10.0.0.1:5000/rootDesc.xml", "/ctl/IPConn"), "http://10.0.0.1:5000/ctl/IPConn");
        assert_eq!(resolve("http://10.0.0.1:5000/", "ctl/IPConn"), "http://10.0.0.1:5000/ctl/IPConn");
        assert_eq!(resolve("http://10.0.0.1:5000/x.xml", "http://10.0.0.1:80/y"), "http://10.0.0.1:80/y");
    }

    /// Needs the router: `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_router_queries() {
        let gw: Ipv4Addr = std::env::var("NW_GW").unwrap_or("192.168.0.1".into()).parse().unwrap();
        let igd = discover(gw, None).expect("no IGD found");
        println!("{:?}", igd.identity);
        println!("{:?}", igd.status());
        println!("counters {:?}", igd.counters());
        println!("mappings {:?}", igd.mappings());
    }
}

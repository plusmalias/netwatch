//! Open sockets on this computer and the processes that own them.

use crate::blocklist::Blocklist;
use crate::util::is_private_ip;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Serialize, Clone, Debug)]
pub struct Conn {
    pub proto: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub remote_name: Option<String>,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// "internet", "lan" or "local" for the remote end; "listen" for listeners.
    pub scope: &'static str,
    pub flagged: bool,
}

pub fn list(
    sys: &mut System,
    dns_names: &HashMap<IpAddr, String>,
    blocklist: &Blocklist,
) -> Result<Vec<Conn>, String> {
    let sockets = netstat2::get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(|e| e.to_string())?;
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let process_name = |pid: u32| {
        sys.process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().into_owned())
    };
    let mut out = Vec::with_capacity(sockets.len());
    for s in sockets {
        let pid = s.associated_pids.first().copied();
        let process = pid.and_then(process_name);
        let conn = match s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => {
                let listening = t.state == TcpState::Listen;
                let remote = (!listening && !t.remote_addr.is_unspecified()).then_some(t.remote_addr);
                Conn {
                    proto: "TCP",
                    local_ip: t.local_addr.to_string(),
                    local_port: t.local_port,
                    remote_ip: remote.map(|r| r.to_string()),
                    remote_port: remote.map(|_| t.remote_port),
                    remote_name: remote.and_then(|r| dns_names.get(&r).cloned()),
                    state: format!("{:?}", t.state),
                    pid,
                    process,
                    scope: scope(remote),
                    flagged: remote.is_some_and(|r| blocklist.match_ip(&r).is_some()),
                }
            }
            ProtocolSocketInfo::Udp(u) => Conn {
                proto: "UDP",
                local_ip: u.local_addr.to_string(),
                local_port: u.local_port,
                remote_ip: None,
                remote_port: None,
                remote_name: None,
                state: "Bound".into(),
                pid,
                process,
                scope: "listen",
                flagged: false,
            },
        };
        out.push(conn);
    }
    Ok(out)
}

fn scope(remote: Option<IpAddr>) -> &'static str {
    match remote {
        None => "listen",
        Some(r) if r.is_loopback() => "local",
        Some(r) if is_private_ip(&r) => "lan",
        Some(_) => "internet",
    }
}

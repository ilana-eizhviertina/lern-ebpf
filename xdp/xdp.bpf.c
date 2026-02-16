//go:build ignore
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define bpf_htons(x) __builtin_bswap16(x)

// XDP is for the ingress traffic. It runs before the kernel even processes the packet.
// This program will drop all ICMP (Ping) packets that it sees.
// The 'ctx' parameter gives us access to the packet data and metadata.
SEC("xdp")
int ping_drop(struct xdp_md *ctx) {
    // The eBPF Verifier will instantly reject your code if you try to read packet data 
    // without first proving that your read will not go past data_end.
    // data is the memory address where the packet begins.
    // data_end is the memory address where the packet ends.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // (eth + 1) calculates the address right after the Ethernet header. 
    // If this address is greater than data_end, the packet is deformed or too small. 
    // We say XDP_PASS to let the normal kernel handle the garbage.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // We check the Ethernet header to see if the payload is an IPv4 packet (ETH_P_IP). 
    // If it's IPv6 or something else, we ignore it and pass it along (XDP_PASS).
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Because we confirmed the Ethernet header is safe, we can jump right past it (eth + 1) to look at the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // If it's an ICMP packet (Ping = Protocol 1), Drop it!
    if (ip->protocol == IPPROTO_ICMP) {
        bpf_printk("XDP: BOOP! Ping packet dropped.");
        return XDP_DROP; 
    }

    return XDP_PASS;
}

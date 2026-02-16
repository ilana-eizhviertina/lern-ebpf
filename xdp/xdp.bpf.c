//go:build ignore
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define bpf_htons(x) __builtin_bswap16(x)

SEC("xdp")
int ping_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // THE RULE: If it's an ICMP packet (Ping = Protocol 1), Drop it!
    if (ip->protocol == IPPROTO_ICMP) {
        bpf_printk("XDP: BOOP! Ping packet dropped.");
        return XDP_DROP; 
    }

    return XDP_PASS;
}
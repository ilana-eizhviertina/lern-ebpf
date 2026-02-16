//go:build ignore
#include <linux/bpf.h>
#include <linux/pkt_cls.h> // Gives us TC_ACT_OK and TC_ACT_SHOT
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define bpf_htons(x) __builtin_bswap16(x)

// TC stands for "Traffic Control". It runs on both ingress and egress traffic, but in this example we'll focus on egress (outgoing) traffic.
// This program will drop all outgoing ICMP (Ping) packets that it sees.

// This is a "Section" macro. It tells the eBPF loader: "This function belongs in the Traffic Control category."
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    // data: The memory address where the packet begins.
    // data_end: The memory address where the packet ends. We use these two to ensure we don't try 
    // to read memory outside the packet (which would crash the kernel).
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // We treat the start of the packet as an Ethernet header.
    // The Guard: (eth + 1) points to the end of the header. If that address is past data_end, 
    // the packet is too small to be valid. We return TC_ACT_OK (pass it) because we can't process it.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK; // TC_ACT_OK means "Pass"

    // We check if the packet contains IPv4 traffic. If it's IPv6 or something else, we ignore it and let it pass.    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Because we confirmed the Ethernet header is safe, we can jump right past it (eth + 1) to look at the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // THE RULE: If it's an ICMP packet (Ping = Protocol 1), Drop it!
    if (ip->protocol == IPPROTO_ICMP) {
        bpf_printk("TC: BOOP! Blocked OUTGOING ping!");
        return TC_ACT_SHOT; // TC_ACT_SHOT means "Drop"
    }

    return TC_ACT_OK;
}

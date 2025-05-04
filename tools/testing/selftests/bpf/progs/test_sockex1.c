// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/**
 * This test demonstrates a simple socket filter BPF program that 
 * counts outgoing packets by IP protocol type (TCP/UDP/ICMP).
 * 
 * The program is attached to a raw socket and counts the size of
 * outgoing packets, storing totals in a BPF array map indexed by
 * protocol number.
 */

/* Create an array map with 256 entries (one for each protocol value) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long long);
    __uint(max_entries, 256);
} my_map SEC(".maps");

/* 
 * Socket filter program that counts outgoing packets by protocol
 * This section name (socket1) will be used to reference the program
 */
SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    int index;
    long long *value;
    unsigned char protocol;
    
    /* 
     * Extract IP protocol field from the packet
     * ETH_HLEN: skip Ethernet header to get to the IP header
     * offsetof(struct iphdr, protocol): protocol field offset within IP header
     */
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), 
                       &protocol, sizeof(protocol));
    index = protocol;

    /* 
     * Only process outgoing packets
     * PACKET_OUTGOING is defined in linux/if_packet.h 
     */
    if (skb->pkt_type != PACKET_OUTGOING)
        return 0;  // Skip non-outgoing packets

    /* Look up the protocol counter in our map */
    value = bpf_map_lookup_elem(&my_map, &index);
    if (value) {
        /* 
         * Add packet length to the counter using atomic operation
         * __ATOMIC_RELAXED: no ordering constraints imposed on memory operations
         */
        __atomic_add_fetch(value, skb->len, __ATOMIC_RELAXED);
    }

    /* 
     * Return 0 to allow the packet to continue through the network stack
     * Returning non-zero would drop the packet
     */
    return 0;
}

/* Required GPL license for loading into the kernel */
char _license[] SEC("license") = "GPL";
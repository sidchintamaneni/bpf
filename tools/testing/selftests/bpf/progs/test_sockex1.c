/**
 * Test BPF Socket Filter Programs
 *
 * This file contains two BPF socket filter programs that demonstrate:
 * 1. Basic protocol counting (sockex1)
 * 2. Advanced flow tracking (sockex2)
 *
 * The programs attach to raw sockets and track:
 * - Per-protocol packet statistics
 * - Per-flow (src/dst IP) statistics
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Protocol counter map for sockex1
 * - Array map indexed by protocol number (0-255)
 * - Values are packet byte counts
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long long);
    __uint(max_entries, 256);
} proto_map SEC(".maps");

/* Flow tracking key structure
 * Used to uniquely identify network flows based on:
 * - Source IP address
 * - Destination IP address
 * - Source/Destination ports
 * - Protocol
 */
struct flow_key_record {
    __be32 src;          /* Source IP address (network byte order) */
    __be32 dst;          /* Destination IP address (network byte order) */
    union {
        __be32 ports;    /* Combined src/dst ports */
        __be16 port16[2];/* Individual port access */
    };
    __u16 thoff;         /* Transport header offset */
    __u8 ip_proto;       /* IP protocol number */
};

/* Per-flow statistics structure */
struct pair {
    __u64 packets;       /* Packet counter */
    __u64 bytes;         /* Byte counter */
};

/* Flow statistics map for sockex2
 * - Hash map keyed by flow_key_record
 * - Values track packets/bytes per flow
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key_record);
    __type(value, struct pair);
    __uint(max_entries, 1024);
} flow_map SEC(".maps");

/**
 * Basic protocol counter (sockex1 functionality)
 * Counts bytes per protocol for outgoing packets
 */
SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    __u32 key;
    long long *value;
    unsigned char protocol;
    
    /* Read IP protocol field */
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), 
                          &protocol, sizeof(protocol)))
        return 0;

    /* Only process outgoing packets */
    if (skb->pkt_type != PACKET_OUTGOING)
        return 0;

    /* Use protocol as key */
    key = protocol;
    
    /* Update protocol statistics */
    value = bpf_map_lookup_elem(&proto_map, &key);
    if (value)
        __atomic_add_fetch(value, skb->len, __ATOMIC_RELAXED);

    return 0;
}

/**
 * Flow tracker (sockex2 functionality)
 * Tracks statistics per source/destination IP pair
 */
SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
    struct flow_key_record flow = {};
    struct pair *value, new_value = {};
    __u32 nhoff = ETH_HLEN;
    
    /* Read IP protocol */
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                          &flow.ip_proto, sizeof(flow.ip_proto)))
        return 0;

    /* Get source and destination IPs */
    if (bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr),
                          &flow.src, sizeof(flow.src)))
        return 0;
    
    if (bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr),
                          &flow.dst, sizeof(flow.dst)))
        return 0;

    /* Update flow statistics */
    value = bpf_map_lookup_elem(&flow_map, &flow);
    if (value) {
        __atomic_add_fetch(&value->packets, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&value->bytes, skb->len, __ATOMIC_RELAXED);
    } else {
        new_value.packets = 1;
        new_value.bytes = skb->len;
        bpf_map_update_elem(&flow_map, &flow, &new_value, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
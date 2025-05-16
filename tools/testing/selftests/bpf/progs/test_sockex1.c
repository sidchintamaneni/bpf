// SPDX-License-Identifier: GPL-2.0
/**
 * Combined BPF Socket Filter Test Programs
 *
 * This file contains three classic socket filter BPF programs that replace
 * the legacy sockex1, sockex2, and sockex3 samples:
 * 
 * 1. Basic protocol counting (sockex1) - Tracks packet counts by IP protocol
 * 2. Flow tracking (sockex2) - Collects statistics per source/destination IP pair
 * 3. Advanced protocol parsing (sockex3) - Handles VLAN/MPLS/IPv4/IPv6 parsing
 *
 * Each program demonstrates specific BPF socket filter capabilities and map types:
 * - Array maps (protocol counters)
 * - Hash maps (flow tracking)
 * - Per-CPU array maps (protocol parsing state)
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/mpls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* VLAN header structure */
struct vlan_hdr {
    __be16 h_vlan_TCI;                  /* Priority and VLAN ID */
    __be16 h_vlan_encapsulated_proto;   /* Encapsulated protocol */
};

/* MPLS header structure */
struct mpls_hdr {
    __be32 label_stack_entry;           /* Label stack entry */
};

/* Protocol counter map (sockex1) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long long);
    __uint(max_entries, 256);
} proto_map SEC(".maps");

/* Flow tracking key structure */
struct flow_key_record {
    __be32 src;          /* Source IP address */
    __be32 dst;          /* Destination IP address */
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

/* Flow statistics map (sockex2) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key_record);
    __type(value, struct pair);
    __uint(max_entries, 1024);
} flow_map SEC(".maps");

/* Per-CPU state for protocol parsing */
struct globals {
    struct flow_key_record flow;
};

/* Per-CPU array for sockex3 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct globals);
    __uint(max_entries, 32);
} percpu_map SEC(".maps");

/* Basic protocol counter (sockex1) */
SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
    __u32 key;
    long long *value;
    unsigned char proto;
    
    /* Read IP protocol field */
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), 
                          &proto, sizeof(proto)))
        return 0;

    /* Only process outgoing packets */
    if (skb->pkt_type != PACKET_OUTGOING)
        return 0;

    /* Update protocol counter */
    key = proto;
    value = bpf_map_lookup_elem(&proto_map, &key);
    if (value)
        __atomic_add_fetch(value, skb->len, __ATOMIC_RELAXED);

    return 0;
}

/* Flow tracker (sockex2) */
SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
    struct flow_key_record flow = {};
    struct pair *value, new_value = {};
    __u32 nhoff = ETH_HLEN;
    
    /* Read IP header fields */
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                          &flow.ip_proto, sizeof(flow.ip_proto)))
        return 0;

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

/* Advanced protocol parser (sockex3) */
SEC("socket3")
int bpf_prog3(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;
    __u32 cpu = bpf_get_smp_processor_id();
    struct globals *g;
    __u16 proto;
    
    /* Initialize per-CPU state */
    g = bpf_map_lookup_elem(&percpu_map, &cpu);
    if (!g)
        return 0;

    /* Read ethernet protocol */
    if (bpf_skb_load_bytes(skb, 12, &proto, 2))
        return 0;
    
    proto = bpf_ntohs(proto);
    
    /* Handle protocols inline */
    switch (proto) {
    case ETH_P_8021Q:
    case ETH_P_8021AD: {
        /* VLAN parsing */
        struct vlan_hdr vh;
        if (bpf_skb_load_bytes(skb, nhoff, &vh, sizeof(vh)))
            return 0;
        nhoff += sizeof(vh);
        proto = bpf_ntohs(vh.h_vlan_encapsulated_proto);
    }
        /* Fall through to handle encapsulated protocol */
        
    case ETH_P_IP: {
        /* IPv4 parsing */
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, nhoff, &iph, sizeof(iph)))
            return 0;
        g->flow.src = iph.saddr;
        g->flow.dst = iph.daddr;
        g->flow.ip_proto = iph.protocol;
        g->flow.thoff = nhoff + sizeof(iph);
        break;
    }
    
    case ETH_P_IPV6: {
        /* IPv6 parsing */
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes(skb, nhoff, &ip6h, sizeof(ip6h)))
            return 0;
        g->flow.ip_proto = ip6h.nexthdr;
        g->flow.thoff = nhoff + sizeof(ip6h);
        break;
    }
    
    case ETH_P_MPLS_UC:
    case ETH_P_MPLS_MC: {
        /* MPLS parsing */
        struct mpls_hdr hdr;
        if (bpf_skb_load_bytes(skb, nhoff, &hdr, sizeof(hdr)))
            return 0;
        nhoff += sizeof(hdr);
        /* If bottom of stack, assume IPv4 follows */
        if (hdr.label_stack_entry & MPLS_LS_S_MASK) {
            struct iphdr iph;
            if (bpf_skb_load_bytes(skb, nhoff, &iph, sizeof(iph)))
                return 0;
            g->flow.src = iph.saddr;
            g->flow.dst = iph.daddr;
            g->flow.ip_proto = iph.protocol;
            g->flow.thoff = nhoff + sizeof(iph);
        }
        break;
    }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
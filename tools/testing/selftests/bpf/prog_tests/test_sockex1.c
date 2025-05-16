// SPDX-License-Identifier: GPL-2.0
/**
 * BPF Socket Filter Selftest
 *
 * This test verifies the functionality of two BPF socket filter programs:
 * 1. Protocol counter (sockex1)
 * 2. Flow tracker (sockex2)
 *
 * Test methodology:
 * - Load and attach both BPF programs to raw sockets
 * - Generate ICMP traffic using ping
 * - Verify both protocol counts and flow statistics
 */

#include <test_progs.h>
#include <network_helpers.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

/* Flow key structure - must match BPF program definition */
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

/* Statistics pair structure - must match BPF program definition */
struct pair {
    __u64 packets;       /* Packet counter */
    __u64 bytes;         /* Byte counter */
};

/**
 * Creates a raw socket bound to specified network interface
 *
 * @param name  Interface name (e.g., "lo" for loopback)
 * @return      Socket file descriptor or -1 on error
 */
static int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0)
        return -1;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * Main test function - validates both sockex1 and sockex2 functionality
 *
 * Test sequence:
 * 1. Load BPF object file containing both programs
 * 2. Set up and attach both socket filters
 * 3. Generate test traffic using ping
 * 4. Verify protocol counting (sockex1)
 * 5. Verify flow statistics (sockex2)
 */
void test_sock_filter(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog1, *prog2;
    int map1_fd = -1, map2_fd = -1, prog1_fd = -1, prog2_fd = -1;
    int sock1 = -1, sock2 = -1;
    __u32 key = IPPROTO_ICMP;
    long long proto_count = 0;
    struct flow_key_record flow_key = {};
    struct pair flow_stats = {};
    int err;

    /* Load and verify BPF object file */
    obj = bpf_object__open_file("./test_sockex1.bpf.o", NULL);
    if (!ASSERT_OK_PTR(obj, "open_bpf_object"))
        return;

    /* Set up and load both BPF programs */
    prog1 = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (!ASSERT_OK_PTR(prog1, "find_prog1"))
        goto cleanup;
    bpf_program__set_type(prog1, BPF_PROG_TYPE_SOCKET_FILTER);

    prog2 = bpf_object__find_program_by_name(obj, "bpf_prog2");
    if (!ASSERT_OK_PTR(prog2, "find_prog2"))
        goto cleanup;
    bpf_program__set_type(prog2, BPF_PROG_TYPE_SOCKET_FILTER);

    err = bpf_object__load(obj);
    if (!ASSERT_OK(err, "load_object"))
        goto cleanup;

    prog1_fd = bpf_program__fd(prog1);
    prog2_fd = bpf_program__fd(prog2);
    map1_fd = bpf_object__find_map_fd_by_name(obj, "proto_map");
    map2_fd = bpf_object__find_map_fd_by_name(obj, "flow_map");

    /* Initialize maps and create test sockets */
    key = IPPROTO_ICMP;
    proto_count = 0;
    err = bpf_map_update_elem(map1_fd, &key, &proto_count, BPF_ANY);
    if (!ASSERT_OK(err, "init_proto_map"))
        goto cleanup;

    sock1 = open_raw_sock("lo");
    sock2 = open_raw_sock("lo");
    if (!ASSERT_GE(sock1, 0, "open_sock1") || !ASSERT_GE(sock2, 0, "open_sock2"))
        goto cleanup;

    err = setsockopt(sock1, SOL_SOCKET, SO_ATTACH_BPF, &prog1_fd, sizeof(prog1_fd));
    if (!ASSERT_OK(err, "attach_prog1"))
        goto cleanup;

    err = setsockopt(sock2, SOL_SOCKET, SO_ATTACH_BPF, &prog2_fd, sizeof(prog2_fd));
    if (!ASSERT_OK(err, "attach_prog2"))
        goto cleanup;

    /* Generate test traffic and verify results */
    ASSERT_OK(system("ping -4 -c3 -q localhost > /dev/null"), "ping");

    err = bpf_map_lookup_elem(map1_fd, &key, &proto_count);
    if (!ASSERT_OK(err, "get_proto_count"))
        goto cleanup;
    ASSERT_GT(proto_count, 0, "proto_count_captured");

    memset(&flow_key, 0, sizeof(flow_key));
    flow_key.ip_proto = IPPROTO_ICMP;
    flow_key.dst = htonl(0x7f000001);  /* 127.0.0.1 in network byte order */
    flow_key.src = htonl(0x7f000001);  /* 127.0.0.1 in network byte order */
    
    err = bpf_map_lookup_elem(map2_fd, &flow_key, &flow_stats);
    if (!ASSERT_OK(err, "get_flow_stats"))
        goto cleanup;
    ASSERT_GT(flow_stats.packets, 0, "flow_packets_captured");
    ASSERT_GT(flow_stats.bytes, 0, "flow_bytes_captured");

cleanup:
    /* Clean up all resources */
    if (sock1 >= 0)
        close(sock1);
    if (sock2 >= 0)
        close(sock2);
    if (obj)
        bpf_object__close(obj);
}
// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

/**
 * Test for BPF socket filter functionality
 *
 * This test verifies that a BPF socket filter can:
 * 1. Be properly loaded and attached to a socket
 * 2. Filter and count packets by protocol type
 * 3. Update map values that can be read from userspace
 */

/**
 * Creates a raw socket bound to a specific network interface
 *
 * @param name  The interface name (e.g., "lo" for loopback)
 * @return      Socket file descriptor on success, -1 on failure
 */
static int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;

    /* Create raw packet socket with non-blocking and close-on-exec flags */
    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0)
        return -1;

    /* Prepare sockaddr_ll structure for binding to the interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);  /* Convert interface name to index */
    sll.sll_protocol = htons(ETH_P_ALL);     /* Receive all protocol packets */

    /* Bind socket to the specified interface */
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * Main test function for the socket filter BPF program
 *
 * Tests the ability of a BPF program to filter and count packets on a socket
 */
void test_sockex1(void)
{
    struct bpf_object *obj = NULL;
    int map_fd = -1, prog_fd = -1, sock = -1;
    __u32 key = IPPROTO_ICMP;  /* Using ICMP protocol as our test case */
    long long value = 0;
    struct bpf_program *prog;
    int err;

    /* Step 1: Open the BPF object file containing the socket filter program */
    obj = bpf_object__open_file("./test_sockex1.bpf.o", NULL);
    if (!ASSERT_OK_PTR(obj, "open_bpf_object"))
        return;

    /* Step 2: Find the program by name in the object file */
    prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (!ASSERT_OK_PTR(prog, "find_prog"))
        goto cleanup;

    /* Step 3: Set the program type to socket filter */
    bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);

    /* Step 4: Load the BPF program into the kernel */
    err = bpf_object__load(obj);
    if (!ASSERT_OK(err, "load_object"))
        goto cleanup;

    /* Step 5: Get file descriptors for the program and map */
    prog_fd = bpf_program__fd(prog);
    map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");
    if (!ASSERT_GE(map_fd, 0, "get_map_fd"))
        goto cleanup;

    /* Step 6: Initialize the ICMP counter in the map to zero */
    key = IPPROTO_ICMP;
    value = 0;
    err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (!ASSERT_OK(err, "init_map_elem"))
        goto cleanup;

    /* Step 7: Create a raw socket on the loopback interface */
    sock = open_raw_sock("lo");
    if (!ASSERT_GE(sock, 0, "open_raw_sock"))
        goto cleanup;

    /* Step 8: Attach the BPF program to the socket */
    err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (!ASSERT_OK(err, "attach_filter"))
        goto cleanup;

    /* Step 9: Generate test traffic - ping sends ICMP packets */
    ASSERT_OK(system("ping -4 -c3 -q localhost > /dev/null"), "ping");

    /* Step 10: Verify the BPF program counted the ICMP packets */
    err = bpf_map_lookup_elem(map_fd, &key, &value);
    if (!ASSERT_OK(err, "get_icmp_count"))
        goto cleanup;

    /* Step 11: Confirm we received some ICMP traffic */
    ASSERT_GT(value, 0, "icmp_packet_captured");

cleanup:
    /* Step 12: Clean up resources */
    if (sock >= 0)
        close(sock);
    if (obj)
        bpf_object__close(obj);
}
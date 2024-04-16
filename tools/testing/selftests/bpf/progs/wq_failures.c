// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Benjamin Tissoires
 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct elem {
	struct bpf_wq w;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct elem);
} lru SEC(".maps");

/* callback for non sleepable workqueue */
static int wq_callback(void *map, int *key, struct bpf_wq *work)
{
	bpf_kfunc_common_test();
	return 0;
}

/* callback for sleepable workqueue */
static int wq_cb_sleepable(void *map, int *key, struct bpf_wq *work)
{
	bpf_kfunc_call_test_sleepable();
	return 0;
}

SEC("tc")
/* test that bpf_wq_init takes a map as a second argument
 */
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__failure
/* check that code path marks r1 as precise */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_wq_init#") /* anchor message */
__msg("workqueue pointer in R1 map_uid=0 doesn't match map pointer in R2 map_uid=0")
long test_wq_init_nomap(void *ctx)
{
	struct bpf_wq *wq;
	struct elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return -1;

	wq = &val->w;
	if (bpf_wq_init(wq, &key, 0) != 0)
		return -3;

	return 0;
}

SEC("tc")
/* test that the workqueue is part of the map in bpf_wq_init
 */
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__failure
/* check that code path marks r1 as precise */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_wq_init#") /* anchor message */
__msg("workqueue pointer in R1 map_uid=0 doesn't match map pointer in R2 map_uid=0")
long test_wq_init_wrong_map(void *ctx)
{
	struct bpf_wq *wq;
	struct elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return -1;

	wq = &val->w;
	if (bpf_wq_init(wq, &lru, 0) != 0)
		return -3;

	return 0;
}

SEC("?tc")
__log_level(2)
__failure
/* check that bpf_wq_set_callback() can not be called with a
 * sleepable callback without BPF_F_WQ_SLEEPABLE
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_kfunc_call_test_sleepable#") /* anchor message */
__msg("program must be sleepable to call sleepable kfunc bpf_kfunc_call_test_sleepable")
long test_call_sleepable_callback_missing_flag(void *ctx)
{
	int key = 0;
	struct bpf_wq *wq;

	wq = bpf_map_lookup_elem(&array, &key);
	if (wq) {
		bpf_wq_init(wq, &array, 0);
		bpf_wq_set_callback(wq, wq_cb_sleepable, 0);
	}

	return 0;
}

SEC("tc")
/* check that calling a non sleepable callback with
 * bpf_wq_set_callback() while providing BPF_F_WQ_SLEEPABLE
 * fails.
 */
__retval(3)
long test_call_non_sleepable_callback_wrong_flag(void *ctx)
{
	int key = 1;
	struct bpf_wq *wq;

	wq = bpf_map_lookup_elem(&array, &key);
	if (!wq)
		return 1;

	if (bpf_wq_init(wq, &array, 0))
		return 2;

	if (bpf_wq_set_callback(wq, wq_callback, BPF_F_WQ_SLEEPABLE))
		return 3;

	return -22;
}

SEC("?tc")
__log_level(2)
__failure
/* check that the first argument of bpf_wq_set_callback()
 * is a correct bpf_wq pointer.
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_wq_set_callback_impl#") /* anchor message */
__msg("arg#0 doesn't point to a map value")
long test_wrong_wq_pointer(void *ctx)
{
	int key = 0;
	struct bpf_wq *wq;

	wq = bpf_map_lookup_elem(&array, &key);
	if (!wq)
		return 1;

	if (bpf_wq_init(wq, &array, 0))
		return 2;

	if (bpf_wq_set_callback((void *)&wq, wq_callback, 0))
		return 3;

	return -22;
}

SEC("?tc")
__log_level(2)
__failure
/* check that the first argument of bpf_wq_set_callback()
 * is a correct bpf_wq pointer.
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_wq_set_callback_impl#") /* anchor message */
__msg("off 1 doesn't point to 'struct bpf_wq' that is at 0")
long test_wrong_wq_pointer_offset(void *ctx)
{
	int key = 0;
	struct bpf_wq *wq;

	wq = bpf_map_lookup_elem(&array, &key);
	if (!wq)
		return 1;

	if (bpf_wq_init(wq, &array, 0))
		return 2;

	if (bpf_wq_set_callback((void *)wq + 1, wq_cb_sleepable, 0))
		return 3;

	return -22;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_kfifo_test.c — KUnit coverage for the per-CPU mailbox.
 *
 * Covers the mailbox lifecycle (allocation guards, -EBUSY re-init,
 * teardown), FIFO order and header fidelity, the C-S6 full rejection
 * (-AIRY_EIPC_KFIFO), the C-S5 owner-CPU gate that degrades foreign
 * senders and receivers to -EAGAIN, occupancy bands and the
 * backpressure latch that is set at HI and released below LO, the
 * blocking receive with its timeout and signal paths, the per-CPU
 * fastpath counters and the CPU lookup helper.
 *
 * The mailbox entry points are non-static (airy_ipc_internal.h), so
 * the test links against airy_ipc_kfifo.o within the airy_ck_ipc
 * module.
 */

#include <kunit/test.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/kfifo.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

#define TEST_KFIFO_ENTRIES	8

static void fill_hdr(struct airy_ipc_msg_hdr *hdr, __u64 badge)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->capability_badge = badge;
}

static int ipc_kfifo_test_init(struct kunit *test)
{
	struct airy_ipc_kfifo *kf;

	kf = kunit_kzalloc(test, sizeof(*kf), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, kf);
	KUNIT_ASSERT_EQ(test, 0,
			airy_ipc_kfifo_init(kf, 0, TEST_KFIFO_ENTRIES));
	test->priv = kf;
	return 0;
}

static void ipc_kfifo_test_exit(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;

	if (kf)
		airy_ipc_kfifo_exit(kf);
}

static void kfifo_init_rejects_bad_arguments_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf;

	kf = kunit_kzalloc(test, sizeof(*kf), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, kf);

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_init(NULL, 0, TEST_KFIFO_ENTRIES));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_init(kf, -1, TEST_KFIFO_ENTRIES));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_init(kf, nr_cpu_ids,
					    TEST_KFIFO_ENTRIES));

	/* Capacity must be a power of two inside the configured ceiling. */
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_kfifo_init(kf, 0, 0));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_kfifo_init(kf, 0, 3));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_init(kf, 0,
					    AIRY_IPC_KFIFO_MAX_ENTRIES * 2));

	/* A rejected init must leave the mailbox uninitialised. */
	KUNIT_EXPECT_FALSE(test, kfifo_initialized(&kf->fifo));
}

static void kfifo_init_rejects_reinit_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;

	KUNIT_EXPECT_EQ(test, -EBUSY,
			airy_ipc_kfifo_init(kf, 0, TEST_KFIFO_ENTRIES));
}

static void kfifo_preserves_fifo_order_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr sent[3], out;
	u32 i;

	for (i = 0; i < 3; i++) {
		fill_hdr(&sent[i], (__u64)(0x100 + i));
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &sent[i]));
	}

	for (i = 0; i < 3; i++) {
		memset(&out, 0, sizeof(out));
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
		KUNIT_EXPECT_EQ(test, 0, memcmp(&sent[i], &out,
						sizeof(out)));
	}
}

static void kfifo_empty_recv_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr out;

	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, 0UL, READ_ONCE(kf->water_mark));
}

static void kfifo_full_rejects_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	u32 i;

	for (i = 0; i < TEST_KFIFO_ENTRIES; i++) {
		WRITE_ONCE(kf->backpressure, false);
		fill_hdr(&hdr, (__u64)i);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
	}
	KUNIT_EXPECT_EQ(test, TEST_KFIFO_ENTRIES, kfifo_len(&kf->fifo));
	KUNIT_EXPECT_EQ(test, (unsigned long)TEST_KFIFO_ENTRIES,
			READ_ONCE(kf->water_mark));

	/* C-S6: a full mailbox rejects instead of overwriting. */
	fill_hdr(&hdr, 0xFFULL);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_KFIFO,
			airy_ipc_kfifo_send(kf, &hdr));
	KUNIT_EXPECT_EQ(test, TEST_KFIFO_ENTRIES, kfifo_len(&kf->fifo));

	/* Draining one slot makes room for exactly one more header. */
	WRITE_ONCE(kf->backpressure, false);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
}

static void kfifo_level_bands_test(struct kunit *test)
{
	static const enum airy_ipc_wmark bands[TEST_KFIFO_ENTRIES + 1] = {
		AIRY_IPC_WMARK_NONE,	/* 0: empty */
		AIRY_IPC_WMARK_NONE,	/* 1 */
		AIRY_IPC_WMARK_LO,	/* 2: 25% */
		AIRY_IPC_WMARK_LO,	/* 3 */
		AIRY_IPC_WMARK_MID,	/* 4: 50% */
		AIRY_IPC_WMARK_MID,	/* 5 */
		AIRY_IPC_WMARK_HI,	/* 6: 75% */
		AIRY_IPC_WMARK_HI,	/* 7 */
		AIRY_IPC_WMARK_FULL,	/* 8: 100% */
	};
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr hdr;
	int i;

	KUNIT_ASSERT_EQ(test, AIRY_IPC_WMARK_NONE, airy_ipc_kfifo_level(kf));

	for (i = 1; i <= TEST_KFIFO_ENTRIES; i++) {
		WRITE_ONCE(kf->backpressure, false);
		fill_hdr(&hdr, (__u64)i);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
		KUNIT_ASSERT_EQ(test, i, kfifo_len(&kf->fifo));
		KUNIT_EXPECT_EQ(test, bands[i], airy_ipc_kfifo_level(kf));
	}

	KUNIT_EXPECT_EQ(test, AIRY_IPC_WMARK_NONE,
			airy_ipc_kfifo_level(NULL));
}

static void kfifo_backpressure_latch_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	struct airy_ipc_stats before, after;
	int i;

	fill_hdr(&hdr, 0x5ULL);
	for (i = 0; i < 6; i++)
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));

	/* Reaching HI latches backpressure, although slots remain free. */
	KUNIT_ASSERT_TRUE(test, READ_ONCE(kf->backpressure));
	KUNIT_EXPECT_EQ(test, AIRY_IPC_WMARK_HI, airy_ipc_kfifo_level(kf));

	airy_ipc_stats_read(&before);
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_kfifo_send(kf, &hdr));
	airy_ipc_stats_read(&after);
	KUNIT_EXPECT_EQ(test, before.backpressure_hit + 1,
			after.backpressure_hit);
	KUNIT_EXPECT_EQ(test, 6, kfifo_len(&kf->fifo));

	/* A single drain stays above LO, so the latch must survive. */
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, AIRY_IPC_WMARK_MID, airy_ipc_kfifo_level(kf));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(kf->backpressure));
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_kfifo_send(kf, &hdr));

	/* Draining below LO releases the latch for the next producer. */
	for (i = 0; i < 4; i++)
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, AIRY_IPC_WMARK_NONE, airy_ipc_kfifo_level(kf));
	KUNIT_EXPECT_FALSE(test, READ_ONCE(kf->backpressure));
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
}

static void kfifo_recv_wait_ready_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr sent, out;

	fill_hdr(&sent, 0x77ULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &sent));

	memset(&out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv_wait(kf, &out, 1));
	KUNIT_EXPECT_EQ(test, 0, memcmp(&sent, &out, sizeof(out)));

	/* A zero timeout polls and reports the empty mailbox as -EAGAIN. */
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_kfifo_recv_wait(kf, &out, 0));
}

static void kfifo_recv_wait_timeout_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr out;

	KUNIT_EXPECT_EQ(test, -ETIMEDOUT,
			airy_ipc_kfifo_recv_wait(kf, &out, 1));
	KUNIT_EXPECT_EQ(test, 0UL, READ_ONCE(kf->water_mark));
}

static void kfifo_recv_wait_bad_args_test(struct kunit *test)
{
	struct airy_ipc_kfifo bogus;
	struct airy_ipc_msg_hdr out;

	memset(&bogus, 0, sizeof(bogus));

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_recv_wait(NULL, &out, 1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_recv_wait(test->priv, NULL, 1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_recv_wait(test->priv, &out, -1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_kfifo_recv_wait(&bogus, &out, 0));
}

static void kfifo_foreign_cpu_degrades_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	int cpu = smp_processor_id();

	WRITE_ONCE(kf->home_cpu, cpu + 1);

	fill_hdr(&hdr, 0x1ULL);
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_kfifo_send(kf, &hdr));
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, 0UL, READ_ONCE(kf->water_mark));

	/* Re-pinning to the local CPU restores both directions. */
	WRITE_ONCE(kf->home_cpu, cpu);
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_kfifo_recv(kf, &out));
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
}

static void kfifo_stats_counters_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	struct airy_ipc_stats before, after;

	fill_hdr(&hdr, 0x2ULL);

	airy_ipc_stats_read(&before);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_send(kf, &hdr));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_kfifo_recv(kf, &out));
	airy_ipc_stats_read(&after);

	KUNIT_EXPECT_EQ(test, before.fast_send_hit + 1,
			after.fast_send_hit);
	KUNIT_EXPECT_EQ(test, before.fast_recv_hit + 1,
			after.fast_recv_hit);

	/* A NULL sink is ignored rather than dereferenced. */
	airy_ipc_stats_read(NULL);
}

static void kfifo_cpu_lookup_test(struct kunit *test)
{
	struct airy_ipc_kfifo *kf;

	KUNIT_EXPECT_NULL(test, airy_ipc_kfifo_cpu(-1));
	KUNIT_EXPECT_NULL(test, airy_ipc_kfifo_cpu(nr_cpu_ids));

	kf = airy_ipc_kfifo_cpu(0);
	KUNIT_ASSERT_NOT_NULL(test, kf);
	KUNIT_EXPECT_TRUE(test, kfifo_initialized(&kf->fifo));
	KUNIT_EXPECT_EQ(test, 0, READ_ONCE(kf->home_cpu));
	KUNIT_EXPECT_NOT_NULL(test, kf->stats);
}

static struct kunit_case airy_ipc_kfifo_cases[] = {
	KUNIT_CASE(kfifo_init_rejects_bad_arguments_test),
	KUNIT_CASE(kfifo_init_rejects_reinit_test),
	KUNIT_CASE(kfifo_preserves_fifo_order_test),
	KUNIT_CASE(kfifo_empty_recv_test),
	KUNIT_CASE(kfifo_full_rejects_test),
	KUNIT_CASE(kfifo_level_bands_test),
	KUNIT_CASE(kfifo_backpressure_latch_test),
	KUNIT_CASE(kfifo_recv_wait_ready_test),
	KUNIT_CASE(kfifo_recv_wait_timeout_test),
	KUNIT_CASE(kfifo_recv_wait_bad_args_test),
	KUNIT_CASE(kfifo_foreign_cpu_degrades_test),
	KUNIT_CASE(kfifo_stats_counters_test),
	KUNIT_CASE(kfifo_cpu_lookup_test),
	{}
};

static struct kunit_suite airy_ipc_kfifo_suite = {
	.name = "airy_ipc_kfifo",
	.init = ipc_kfifo_test_init,
	.exit = ipc_kfifo_test_exit,
	.test_cases = airy_ipc_kfifo_cases,
};

kunit_test_suites(&airy_ipc_kfifo_suite);

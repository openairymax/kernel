// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath_test.c — KUnit coverage for the fastpath send chain.
 *
 * Pins how the data-plane entries order C-S0, the shared header chain
 * (C-S1..C-S4, C-S8..C-S10) and C-S12, and proves that a rejected
 * message never takes ring or mailbox capacity. Both entries count a
 * send handed back to the slowpath in slow_send_hit, and the
 * corrupt-digest case drives the AIRY_FAULT_RING_CORRUPT report the
 * send path owes that check.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

#define TEST_RING_ENTRIES	4
#define TEST_KFIFO_ENTRIES	8

struct fp_fixture {
	struct airy_ipc_ring	ring;
	struct airy_ipc_kfifo	kf;
};

static void fill_hdr(struct airy_ipc_msg_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->opcode = AIRY_IPC_OP_SEND;
	hdr->trace_id = 0x1122334455667788ULL;
	hdr->crc32 = airy_crc32_calc(hdr, NULL);
}

static u64 slow_hits(void)
{
	struct airy_ipc_stats st;

	airy_ipc_stats_read(&st);
	return st.slow_send_hit;
}

static int fastpath_init(struct kunit *test)
{
	struct fp_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_ipc_ring_init(&f->ring, TEST_RING_ENTRIES));
	KUNIT_ASSERT_EQ(test, 0,
			airy_ipc_kfifo_init(&f->kf, 0, TEST_KFIFO_ENTRIES));
	test->priv = f;
	return 0;
}

static void fastpath_exit(struct kunit *test)
{
	struct fp_fixture *f = test->priv;

	if (!f)
		return;

	airy_ipc_kfifo_exit(&f->kf);
	airy_ipc_ring_destroy(&f->ring);
}

/* ─── Ring entry ──────── */

static void fastpath_accept_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_fastpath_send(&f->ring, &hdr));
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_ring_consume(&f->ring, &out));
	KUNIT_EXPECT_EQ(test, hdr.trace_id, out.trace_id);
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(&f->ring, &out));
}

static void fastpath_frozen_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	WRITE_ONCE(f->ring.frozen, 1);

	/* C-S0 wins over the header chain and the digest. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_fastpath_send(&f->ring, &hdr));

	/* Nothing was posted: the empty-ring test precedes the frozen one. */
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(&f->ring, &out));
}

static void fastpath_null_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fastpath_send(NULL, &hdr));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fastpath_send(&f->ring, NULL));
}

static void fastpath_bad_magic_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	hdr.magic = 0xdeadbeefu;

	/* C-S1 precedes C-S12, so the field failure is what surfaces. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC,
			airy_ipc_fastpath_send(&f->ring, &hdr));
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(&f->ring, &out));
}

static void fastpath_bad_crc_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	hdr.crc32 ^= 1u;

	/*
	 * C-S12 rejects the header and raises AIRY_FAULT_RING_CORRUPT; the
	 * slot must stay untouched so the consumer never sees it.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CRC32,
			airy_ipc_fastpath_send(&f->ring, &hdr));
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(&f->ring, &out));
}

static void fastpath_foreign_cpu_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	u64 before;

	fill_hdr(&hdr);
	WRITE_ONCE(f->ring.home_cpu, smp_processor_id() + 1);

	/* C-S5 degrades the foreign sender and the fastpath records it. */
	before = slow_hits();
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			airy_ipc_fastpath_send(&f->ring, &hdr));
	KUNIT_EXPECT_EQ(test, before + 1, slow_hits());
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(&f->ring, &out));
}

/* ─── Mailbox entry ──────── */

static void fast_send_kfifo_accept_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, 0, airy_ipc_fast_send_kfifo(&f->kf, &hdr));
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_kfifo_recv(&f->kf, &out));
	KUNIT_EXPECT_EQ(test, hdr.trace_id, out.trace_id);
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_kfifo_recv(&f->kf, &out));
}

static void fast_send_kfifo_null_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fast_send_kfifo(NULL, &hdr));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fast_send_kfifo(&f->kf, NULL));
}

static void fast_send_kfifo_bad_magic_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	hdr.magic = 0xdeadbeefu;

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC,
			airy_ipc_fast_send_kfifo(&f->kf, &hdr));
	KUNIT_EXPECT_EQ(test, 0UL, READ_ONCE(f->kf.water_mark));
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_kfifo_recv(&f->kf, &out));
}

static void fill_kfifo(struct kunit *test, struct airy_ipc_kfifo *kf, int n)
{
	struct airy_ipc_msg_hdr hdr;
	int i;

	fill_hdr(&hdr);
	for (i = 0; i < n; i++) {
		WRITE_ONCE(kf->backpressure, false);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_fast_send_kfifo(kf, &hdr));
	}
}

static void fast_send_kfifo_latch_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr;
	u64 before;

	fill_kfifo(test, &f->kf, 6);
	KUNIT_ASSERT_TRUE(test, READ_ONCE(f->kf.backpressure));

	fill_hdr(&hdr);
	before = slow_hits();
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_ipc_fast_send_kfifo(&f->kf, &hdr));
	KUNIT_EXPECT_EQ(test, before + 1, slow_hits());
	KUNIT_EXPECT_EQ(test, 6UL, READ_ONCE(f->kf.water_mark));
}

static void fast_send_kfifo_full_test(struct kunit *test)
{
	struct fp_fixture *f = test->priv;
	struct airy_ipc_msg_hdr hdr;
	u64 before;

	fill_kfifo(test, &f->kf, TEST_KFIFO_ENTRIES);

	fill_hdr(&hdr);
	before = slow_hits();
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_KFIFO,
			airy_ipc_fast_send_kfifo(&f->kf, &hdr));
	KUNIT_EXPECT_EQ(test, before + 1, slow_hits());
}

static struct kunit_case airy_ipc_fastpath_cases[] = {
	KUNIT_CASE(fastpath_accept_test),
	KUNIT_CASE(fastpath_frozen_test),
	KUNIT_CASE(fastpath_null_test),
	KUNIT_CASE(fastpath_bad_magic_test),
	KUNIT_CASE(fastpath_bad_crc_test),
	KUNIT_CASE(fastpath_foreign_cpu_test),
	KUNIT_CASE(fast_send_kfifo_accept_test),
	KUNIT_CASE(fast_send_kfifo_null_test),
	KUNIT_CASE(fast_send_kfifo_bad_magic_test),
	KUNIT_CASE(fast_send_kfifo_latch_test),
	KUNIT_CASE(fast_send_kfifo_full_test),
	{}
};

static struct kunit_suite airy_ipc_fastpath_suite = {
	.name = "airy_ipc_fastpath",
	.init = fastpath_init,
	.exit = fastpath_exit,
	.test_cases = airy_ipc_fastpath_cases,
};

kunit_test_suite(airy_ipc_fastpath_suite);

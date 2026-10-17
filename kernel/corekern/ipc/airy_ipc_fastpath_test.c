// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath_test.c — KUnit coverage for the fastpath send chain.
 *
 * Pins how the data-plane entry orders C-S0, the shared header chain
 * (C-S1..C-S4, C-S8..C-S10) and C-S12, and proves that a rejected
 * message never takes ring capacity. The corrupt-digest case also drives
 * the AIRY_FAULT_RING_CORRUPT report the send path owes that check.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

#define TEST_RING_ENTRIES	4

static void fill_hdr(struct airy_ipc_msg_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->opcode = AIRY_IPC_OP_SEND;
	hdr->trace_id = 0x1122334455667788ULL;
	hdr->crc32 = airy_crc32_calc(hdr, NULL);
}

static int fastpath_init(struct kunit *test)
{
	struct airy_ipc_ring *ring;

	ring = kunit_kzalloc(test, sizeof(*ring), GFP_KERNEL);
	if (!ring)
		return -ENOMEM;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_ipc_ring_init(ring, TEST_RING_ENTRIES));
	test->priv = ring;
	return 0;
}

static void fastpath_accept_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_fastpath_send(ring, &hdr));
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, hdr.trace_id, out.trace_id);
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void fastpath_frozen_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	WRITE_ONCE(ring->frozen, 1);

	/* C-S0 wins over the header chain and the digest. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_fastpath_send(ring, &hdr));

	/* Nothing was posted: the empty-ring test precedes the frozen one. */
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void fastpath_null_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr;

	fill_hdr(&hdr);

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fastpath_send(NULL, &hdr));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_fastpath_send(ring, NULL));
}

static void fastpath_bad_magic_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	hdr.magic = 0xdeadbeefu;

	/* C-S1 precedes C-S12, so the field failure is what surfaces. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC,
			airy_ipc_fastpath_send(ring, &hdr));
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void fastpath_bad_crc_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr);
	hdr.crc32 ^= 1u;

	/*
	 * C-S12 rejects the header and raises AIRY_FAULT_RING_CORRUPT; the
	 * slot must stay untouched so the consumer never sees it.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CRC32,
			airy_ipc_fastpath_send(ring, &hdr));
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static struct kunit_case airy_ipc_fastpath_cases[] = {
	KUNIT_CASE(fastpath_accept_test),
	KUNIT_CASE(fastpath_frozen_test),
	KUNIT_CASE(fastpath_null_test),
	KUNIT_CASE(fastpath_bad_magic_test),
	KUNIT_CASE(fastpath_bad_crc_test),
	{}
};

static struct kunit_suite airy_ipc_fastpath_suite = {
	.name = "airy_ipc_fastpath",
	.init = fastpath_init,
	.test_cases = airy_ipc_fastpath_cases,
};

kunit_test_suite(airy_ipc_fastpath_suite);

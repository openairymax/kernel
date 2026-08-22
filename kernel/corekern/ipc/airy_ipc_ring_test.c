// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_ring_test.c — KUnit regression for the P1-8 cancelBadgedSends fix.
 *
 * P1-8 implemented airy_ipc_cancel_badged_sends(): the agent-linux
 * analogue of seL4's cancelBadgedSends (endpoint.c:476-489).  It walks
 * the pending region of an SPSC ring and zeroes the magic field of every
 * slot whose capability_badge matches, so airy_ipc_ring_consume() skips
 * them.  These tests verify that cancelled (badged) sends are dropped
 * while unbadged (different-badge) sends are delivered untouched.
 *
 * The ring entry points are non-static (declared in airy_ipc_internal.h),
 * so the test links against airy_ipc_ring.o within the airy_ck_ipc module
 * without including the .c file.
 */

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_ipc_internal.h"

#define TEST_RING_ENTRIES	4

static void fill_hdr(struct airy_ipc_msg_hdr *hdr, __u64 badge)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->capability_badge = badge;
}

static int ipc_ring_test_init(struct kunit *test)
{
	struct airy_ipc_ring *ring;

	ring = kunit_kzalloc(test, sizeof(*ring), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ring);
	KUNIT_ASSERT_EQ(test, 0,
			airy_ipc_ring_init(ring, TEST_RING_ENTRIES));
	test->priv = ring;
	return 0;
}

static void ipc_ring_test_exit(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;

	if (ring)
		airy_ipc_ring_destroy(ring);
	/* ring itself is auto-freed by kunit_kzalloc. */
}

static void cancel_drops_matching_preserves_other_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr1, hdr2, out;
	const __u64 badged = 0xDEADBEEFCAFEBABEULL;
	const __u64 other = 0x1234567890ABCDEFULL;
	int ret;

	/* Post one badged and one unbadged message. */
	fill_hdr(&hdr1, badged);
	fill_hdr(&hdr2, other);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr1));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr2));

	/* Cancel the badged send: exactly one slot should be cancelled. */
	ret = airy_ipc_cancel_badged_sends(ring, badged);
	KUNIT_EXPECT_EQ(test, 1, ret);

	/* The consumer must skip the cancelled slot and return the
	 * unbadged message, proving the badged send was dropped. */
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, other, out.capability_badge);

	/* Ring is now empty. */
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void cancel_preserves_non_matching_badges_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr_a, hdr_b, hdr_c, out;
	const __u64 badge_a = 0xAAAA000000000000ULL;
	const __u64 badge_b = 0xBBBB000000000000ULL;
	const __u64 badge_c = 0xCCCC000000000000ULL;
	int ret;

	fill_hdr(&hdr_a, badge_a);
	fill_hdr(&hdr_b, badge_b);
	fill_hdr(&hdr_c, badge_c);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr_a));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr_b));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr_c));

	/* Cancel only badge_b; a and c must survive and be delivered in
	 * order, proving unbadged (non-matching) sends are unaffected. */
	ret = airy_ipc_cancel_badged_sends(ring, badge_b);
	KUNIT_EXPECT_EQ(test, 1, ret);

	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, badge_a, out.capability_badge);

	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, badge_c, out.capability_badge);

	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void cancel_no_match_leaves_ring_intact_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	const __u64 present = 0x1111000000000000ULL;
	const __u64 absent = 0x2222000000000000ULL;
	int ret;

	fill_hdr(&hdr, present);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));

	/* Cancelling a badge that was never sent must report zero and leave
	 * the pending message intact. */
	ret = airy_ipc_cancel_badged_sends(ring, absent);
	KUNIT_EXPECT_EQ(test, 0, ret);

	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, present, out.capability_badge);
}

static void cancel_null_ring_returns_einval_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_ipc_cancel_badged_sends(NULL, 0));
}

static void cancel_multiple_matching_sends_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr1, hdr2, hdr3, out;
	const __u64 badge = 0xBEEF000000000000ULL;
	int ret;

	/* Three posts with the SAME badge; a 4-entry ring holds up to 3
	 * (one slot is reserved for full-detection). */
	fill_hdr(&hdr1, badge);
	fill_hdr(&hdr2, badge);
	fill_hdr(&hdr3, badge);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr1));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr2));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr3));

	ret = airy_ipc_cancel_badged_sends(ring, badge);
	KUNIT_EXPECT_EQ(test, 3, ret);

	/* All three were cancelled, so the ring behaves as empty. */
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static struct kunit_case airy_ipc_ring_cases[] = {
	KUNIT_CASE(cancel_drops_matching_preserves_other_test),
	KUNIT_CASE(cancel_preserves_non_matching_badges_test),
	KUNIT_CASE(cancel_no_match_leaves_ring_intact_test),
	KUNIT_CASE(cancel_null_ring_returns_einval_test),
	KUNIT_CASE(cancel_multiple_matching_sends_test),
	{}
};

static struct kunit_suite airy_ipc_ring_suite = {
	.name = "airy_ipc_ring_p1_8",
	.init = ipc_ring_test_init,
	.exit = ipc_ring_test_exit,
	.test_cases = airy_ipc_ring_cases,
};

kunit_test_suites(&airy_ipc_ring_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_ring_test.c — KUnit coverage for the IPC ring core.
 *
 * Covers the SPSC ring's capacity and teardown contract
 * (airy_ipc_ring_init/destroy), cursor semantics (FIFO order,
 * exact-full/empty detection, wrap-around) guarded by the
 * release/acquire pairing in post()/consume(), the argument and
 * C-S0/C-S1/C-S6 rejection codes (-EINVAL, -ENOMSG,
 * -AIRY_EIPC_FROZEN, -AIRY_EIPC_MAGIC, -AIRY_EIPC_KFIFO), P1-8
 * cancelBadgedSends (the agent-linux analogue of seL4's
 * cancelBadgedSends, endpoint.c:476-489), and the occupancy
 * accounting airy_ipc_ring_depth_stats() samples.
 *
 * The ring entry points are non-static (airy_ipc_internal.h), so the
 * test links against airy_ipc_ring.o within the airy_ck_ipc module.
 */

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/airymax/error.h>

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

	/*
	 * The consumer must skip the cancelled slot and return the
	 * unbadged message, proving the badged send was dropped.
	 */
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

	/*
	 * Cancel only badge_b; a and c must survive and be delivered in
	 * order, proving unbadged (non-matching) sends are unaffected.
	 */
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

	/*
	 * Cancelling a badge that was never sent must report zero and leave
	 * the pending message intact.
	 */
	ret = airy_ipc_cancel_badged_sends(ring, absent);
	KUNIT_EXPECT_EQ(test, 0, ret);

	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, present, out.capability_badge);
}

static void cancel_multiple_matching_sends_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr1, hdr2, hdr3, out;
	const __u64 badge = 0xBEEF000000000000ULL;
	int ret;

	/*
	 * Three posts with the SAME badge; a 4-entry ring holds up to 3
	 * (one slot is reserved for full-detection).
	 */
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

static void cancel_walks_pending_region_across_wrap_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	const __u64 badge = 0xFEEDULL;
	u32 i;
	int ret;

	/*
	 * Cycle the cursors until both sit on the last slot, so the next
	 * two posts land on slot (entries - 1) then slot 0: the pending
	 * region [tail, head) now straddles the wrap point and the
	 * modular walk in cancelBadgedSends() must cross it.
	 */
	for (i = 0; i < (u32)TEST_RING_ENTRIES - 1; i++) {
		fill_hdr(&hdr, (__u64)i + 1);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	}

	fill_hdr(&hdr, 0x1ULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
	fill_hdr(&hdr, badge);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));

	ret = airy_ipc_cancel_badged_sends(ring, badge);
	KUNIT_EXPECT_EQ(test, 1, ret);

	/* The unbadged message survives; the badged one is dropped. */
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, 0x1ULL, out.capability_badge);
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void init_rejects_bad_capacity_test(struct kunit *test)
{
	struct airy_ipc_ring ring;

	memset(&ring, 0, sizeof(ring));

	/*
	 * Capacity must be a power of two of at least two entries; zero,
	 * one and three are all refused before any allocation happens.
	 */
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_init(&ring, 0));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_init(&ring, 1));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_init(&ring, 3));
	KUNIT_EXPECT_NULL(test, ring.slots);
}

static void destroy_clears_slots_and_tolerates_null_test(struct kunit *test)
{
	struct airy_ipc_ring ring;

	memset(&ring, 0, sizeof(ring));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_init(&ring, TEST_RING_ENTRIES));
	KUNIT_ASSERT_NOT_NULL(test, ring.slots);

	airy_ipc_ring_destroy(&ring);
	KUNIT_EXPECT_NULL(test, ring.slots);

	/* Tearing down twice, or a NULL ring, must both be harmless. */
	airy_ipc_ring_destroy(&ring);
	KUNIT_EXPECT_NULL(test, ring.slots);
	airy_ipc_ring_destroy(NULL);
}

static void entry_null_guards_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_ring uninit;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr, 0x1ULL);

	/* A NULL ring is refused by every entry point. */
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_post(NULL, &hdr));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_consume(NULL, &out));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_cancel_badged_sends(NULL, 0));

	/* A NULL buffer on a live ring is refused. */
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_post(ring, NULL));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_consume(ring, NULL));

	/*
	 * A zero-initialised ring has no slot array; the entry points must
	 * refuse it rather than dereferencing NULL.
	 */
	memset(&uninit, 0, sizeof(uninit));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_post(&uninit, &hdr));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_consume(&uninit, &out));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_cancel_badged_sends(&uninit, 0));
}

static void frozen_ring_blocks_post_and_consume_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	fill_hdr(&hdr, 0x5A5AULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));

	/*
	 * C-S0: a frozen ring refuses both directions yet preserves the
	 * queued message, so unfreezing restores normal service.
	 */
	WRITE_ONCE(ring->frozen, 1);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_ring_post(ring, &hdr));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_ring_consume(ring, &out));

	WRITE_ONCE(ring->frozen, 0);
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, 0x5A5AULL, out.capability_badge);
}

static void init_rejects_capacity_above_max_test(struct kunit *test)
{
	struct airy_ipc_ring ring;
	int ret;

	/*
	 * A zero-initialised ring makes a rejected init observable: if the
	 * ceiling check runs before the allocation, slots stays NULL.
	 */
	memset(&ring, 0, sizeof(ring));

	/*
	 * MAX_ENTRIES * 2 is still a power of two, so only the ceiling
	 * check can reject it.
	 */
	ret = airy_ipc_ring_init(&ring, AIRY_IPC_RING_MAX_ENTRIES * 2);
	KUNIT_EXPECT_EQ(test, -EINVAL, ret);
	KUNIT_EXPECT_NULL(test, ring.slots);
}

static void init_accepts_default_capacity_test(struct kunit *test)
{
	struct airy_ipc_ring ring;
	int ret;

	/*
	 * The shared default must be a usable capacity, not just a
	 * declarative constant.
	 */
	memset(&ring, 0, sizeof(ring));
	ret = airy_ipc_ring_init(&ring, AIRY_IPC_RING_DEF_ENTRIES);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_NOT_NULL(test, ring.slots);
	KUNIT_EXPECT_EQ(test, (u32)(AIRY_IPC_RING_DEF_ENTRIES - 1), ring.mask);
	airy_ipc_ring_destroy(&ring);
}

static void spsc_wrap_around_preserves_fifo_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	__u64 i;

	/*
	 * Fill the ring to capacity (entries - 1) with distinct badges.
	 * This also drives head/tail through the full/empty boundary that
	 * the release/acquire cursor pairing guards.
	 */
	for (i = 1; i < TEST_RING_ENTRIES; i++) {
		fill_hdr(&hdr, i);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
	}

	/* One more post must be rejected: the ring is exactly full. */
	fill_hdr(&hdr, 0xFFFFFFFFFFFFFFFFULL);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_KFIFO,
			airy_ipc_ring_post(ring, &hdr));

	/* Drain in FIFO order. */
	for (i = 1; i < TEST_RING_ENTRIES; i++) {
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
		KUNIT_EXPECT_EQ(test, i, out.capability_badge);
	}
	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));

	/*
	 * Posting after a full drain forces both cursors to wrap past the
	 * mask; the value must still round-trip in order.
	 */
	fill_hdr(&hdr, 0xABCDEFULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_EXPECT_EQ(test, 0xABCDEFULL, out.capability_badge);
}

static void post_rejects_bad_magic_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;

	/*
	 * C-S1: a header whose magic is not 'ARE1' must be refused with
	 * -AIRY_EIPC_MAGIC, and the slot must stay untouched so a later
	 * consume still reports the ring as empty.
	 */
	fill_hdr(&hdr, 0x1ULL);
	hdr.magic = 0xDEADBEEF;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC, airy_ipc_ring_post(ring, &hdr));

	KUNIT_EXPECT_EQ(test, -ENOMSG, airy_ipc_ring_consume(ring, &out));
}

static void depth_stats_init_snapshot_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_ring_depth d;

	/* A freshly initialised ring is empty and has rejected nothing. */
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_depth_stats(ring, &d));
	KUNIT_EXPECT_EQ(test, (u32)TEST_RING_ENTRIES, d.entries);
	KUNIT_EXPECT_EQ(test, (u32)0, d.depth);
	KUNIT_EXPECT_EQ(test, (u32)0, d.pct);
	KUNIT_EXPECT_EQ(test, (u32)0, d.peak_depth);
	KUNIT_EXPECT_EQ(test, (u64)0, d.full_count);
}

static void depth_stats_tracks_occupancy_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr, out;
	struct airy_ipc_ring_depth d;

	fill_hdr(&hdr, 0x1ULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
	fill_hdr(&hdr, 0x2ULL);
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));

	/* Two of four slots are pending: 50% of the declared capacity. */
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_depth_stats(ring, &d));
	KUNIT_EXPECT_EQ(test, (u32)2, d.depth);
	KUNIT_EXPECT_EQ(test, (u32)50, d.pct);
	KUNIT_EXPECT_EQ(test, (u32)2, d.peak_depth);

	/* Draining lowers depth but must not lower the high-water mark. */
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_consume(ring, &out));
	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_depth_stats(ring, &d));
	KUNIT_EXPECT_EQ(test, (u32)1, d.depth);
	KUNIT_EXPECT_EQ(test, (u32)25, d.pct);
	KUNIT_EXPECT_EQ(test, (u32)2, d.peak_depth);
}

static void depth_stats_counts_full_rejection_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_msg_hdr hdr;
	struct airy_ipc_ring_depth d;
	u32 i;

	/* Fill the ring to its exact-full boundary (entries - 1). */
	for (i = 1; i < (u32)TEST_RING_ENTRIES; i++) {
		fill_hdr(&hdr, (__u64)i);
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(ring, &hdr));
	}

	/* The rejected post is the event the nightly monitor fails on. */
	fill_hdr(&hdr, 0xFFFFULL);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_KFIFO, airy_ipc_ring_post(ring, &hdr));

	KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_depth_stats(ring, &d));
	KUNIT_EXPECT_EQ(test, (u32)3, d.depth);
	KUNIT_EXPECT_EQ(test, (u32)75, d.pct);
	KUNIT_EXPECT_EQ(test, (u32)3, d.peak_depth);
	KUNIT_EXPECT_EQ(test, (u64)1, d.full_count);
}

static void depth_stats_null_guards_test(struct kunit *test)
{
	struct airy_ipc_ring *ring = test->priv;
	struct airy_ipc_ring uninit;
	struct airy_ipc_ring_depth d;

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_depth_stats(NULL, &d));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_depth_stats(ring, NULL));

	/*
	 * A zero-initialised ring has no slot array: sampling it must be
	 * refused rather than dividing by a bogus capacity.
	 */
	memset(&uninit, 0, sizeof(uninit));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_ring_depth_stats(&uninit, &d));
}

static struct kunit_case airy_ipc_ring_cases[] = {
	KUNIT_CASE(cancel_drops_matching_preserves_other_test),
	KUNIT_CASE(cancel_preserves_non_matching_badges_test),
	KUNIT_CASE(cancel_no_match_leaves_ring_intact_test),
	KUNIT_CASE(cancel_multiple_matching_sends_test),
	KUNIT_CASE(cancel_walks_pending_region_across_wrap_test),
	KUNIT_CASE(init_rejects_capacity_above_max_test),
	KUNIT_CASE(init_rejects_bad_capacity_test),
	KUNIT_CASE(init_accepts_default_capacity_test),
	KUNIT_CASE(destroy_clears_slots_and_tolerates_null_test),
	KUNIT_CASE(entry_null_guards_test),
	KUNIT_CASE(frozen_ring_blocks_post_and_consume_test),
	KUNIT_CASE(spsc_wrap_around_preserves_fifo_test),
	KUNIT_CASE(post_rejects_bad_magic_test),
	KUNIT_CASE(depth_stats_init_snapshot_test),
	KUNIT_CASE(depth_stats_tracks_occupancy_test),
	KUNIT_CASE(depth_stats_counts_full_rejection_test),
	KUNIT_CASE(depth_stats_null_guards_test),
	{}
};

static struct kunit_suite airy_ipc_ring_suite = {
	.name = "airy_ipc_ring",
	.init = ipc_ring_test_init,
	.exit = ipc_ring_test_exit,
	.test_cases = airy_ipc_ring_cases,
};

kunit_test_suites(&airy_ipc_ring_suite);

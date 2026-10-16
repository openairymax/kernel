// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_eventfd_test.c — KUnit coverage for the fault event detail ring
 * (airy_fev_*, A-20).
 *
 * The eventfd counter carries only a packed (fault_code, agent_id) pair,
 * so the full detail a woken Macro-Supervisor drains lives in this
 * bounded ring. These cases pin its FIFO order and its best-effort loss
 * contract: post() never blocks and never overwrites a detail that has
 * not been fetched, and a full or contended ring drops the detail
 * instead of stalling the NMI-safe caller.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"

#define FEV_SEQ_BASE	0x1000u
#define FEV_PREWRAP_NR	40u

static void fev_ev(struct airy_fault_event *ev, __u32 seq)
{
	memset(ev, 0, sizeof(*ev));
	ev->ring_id = seq & 0x7u;
	ev->fault_code = FEV_SEQ_BASE + seq;
	ev->timestamp_ns = (__u64)seq * 1000u;
	ev->agent_id = seq;
}

static void fev_post_seq(struct kunit *test, __u32 seq)
{
	struct airy_fault_event ev;

	fev_ev(&ev, seq);
	KUNIT_ASSERT_EQ(test, 0, airy_fev_post(&ev));
}

static void fev_expect_seq(struct kunit *test, __u32 seq)
{
	struct airy_fault_event ev;

	KUNIT_ASSERT_EQ(test, 0, airy_fev_fetch(&ev));
	KUNIT_EXPECT_EQ(test, seq & 0x7u, ev.ring_id);
	KUNIT_EXPECT_EQ(test, FEV_SEQ_BASE + seq, ev.fault_code);
	KUNIT_EXPECT_EQ(test, (__u64)seq * 1000u, ev.timestamp_ns);
	KUNIT_EXPECT_EQ(test, seq, ev.agent_id);
}

static void airy_fev_post_null_test(struct kunit *test)
{
	airy_fev_reset();

	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_fev_post(NULL));
}

static void airy_fev_fetch_null_test(struct kunit *test)
{
	airy_fev_reset();

	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_fev_fetch(NULL));
}

static void airy_fev_fetch_empty_test(struct kunit *test)
{
	struct airy_fault_event ev;

	airy_fev_reset();

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static void airy_fev_roundtrip_test(struct kunit *test)
{
	struct airy_fault_event ev = {
		.ring_id = 7u,
		.fault_code = AIRY_FAULT_VM_FAULT,
		.timestamp_ns = 0xDEADBEEFu,
		.agent_id = 42u,
	};
	struct airy_fault_event out;

	airy_fev_reset();

	KUNIT_ASSERT_EQ(test, 0, airy_fev_post(&ev));
	KUNIT_ASSERT_EQ(test, 0, airy_fev_fetch(&out));
	KUNIT_EXPECT_EQ(test, 7u, out.ring_id);
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_VM_FAULT, out.fault_code);
	KUNIT_EXPECT_EQ(test, (__u64)0xDEADBEEFu, out.timestamp_ns);
	KUNIT_EXPECT_EQ(test, 42u, out.agent_id);
	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&out));
}

static void airy_fev_fifo_order_test(struct kunit *test)
{
	struct airy_fault_event ev;
	__u32 i;

	airy_fev_reset();

	for (i = 0; i < 3u; i++)
		fev_post_seq(test, i);

	for (i = 0; i < 3u; i++)
		fev_expect_seq(test, i);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static void airy_fev_wrap_order_test(struct kunit *test)
{
	struct airy_fault_event scratch;
	__u32 i;

	airy_fev_reset();

	for (i = 0; i < FEV_PREWRAP_NR; i++)
		fev_post_seq(test, i);
	for (i = 0; i < FEV_PREWRAP_NR; i++)
		fev_expect_seq(test, i);

	for (i = 0; i < AIRY_FEV_RING_NR; i++)
		fev_post_seq(test, 100u + i);
	for (i = 0; i < AIRY_FEV_RING_NR; i++)
		fev_expect_seq(test, 100u + i);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&scratch));
}

static void airy_fev_capacity_test(struct kunit *test)
{
	struct airy_fault_event ev = {
		.ring_id = 1u,
		.fault_code = AIRY_FAULT_RING_CORRUPT,
		.timestamp_ns = 1u,
		.agent_id = 1u,
	};
	__u32 i;

	airy_fev_reset();

	for (i = 0; i < AIRY_FEV_RING_NR; i++)
		fev_post_seq(test, i);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOMEM, airy_fev_post(&ev));
	KUNIT_EXPECT_EQ(test, 1u, airy_fev_lost());

	fev_expect_seq(test, 0u);
	fev_post_seq(test, 0u);
	KUNIT_EXPECT_EQ(test, 1u, airy_fev_lost());
	fev_expect_seq(test, 1u);
}

static void airy_fev_reset_lost_test(struct kunit *test)
{
	struct airy_fault_event ev = {
		.ring_id = 2u,
		.fault_code = AIRY_FAULT_RING_CORRUPT,
		.timestamp_ns = 2u,
		.agent_id = 2u,
	};
	struct airy_fault_event out;
	__u32 i;

	airy_fev_reset();

	for (i = 0; i < AIRY_FEV_RING_NR; i++)
		fev_post_seq(test, i);
	KUNIT_ASSERT_EQ(test, -AIRY_ENOMEM, airy_fev_post(&ev));
	KUNIT_ASSERT_EQ(test, 1u, airy_fev_lost());

	airy_fev_reset();

	KUNIT_EXPECT_EQ(test, 0u, airy_fev_lost());
	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&out));
}

static struct kunit_case airy_eventfd_cases[] = {
	KUNIT_CASE(airy_fev_post_null_test),
	KUNIT_CASE(airy_fev_fetch_null_test),
	KUNIT_CASE(airy_fev_fetch_empty_test),
	KUNIT_CASE(airy_fev_roundtrip_test),
	KUNIT_CASE(airy_fev_fifo_order_test),
	KUNIT_CASE(airy_fev_wrap_order_test),
	KUNIT_CASE(airy_fev_capacity_test),
	KUNIT_CASE(airy_fev_reset_lost_test),
	{}
};

static struct kunit_suite airy_eventfd_suite = {
	.name = "airy_eventfd_fault_ring",
	.test_cases = airy_eventfd_cases,
};

kunit_test_suites(&airy_eventfd_suite);

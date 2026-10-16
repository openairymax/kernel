// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_sched_test.c — KUnit coverage for the syscall 550 sched_tac
 * control entry defined in airy_sched.c.
 *
 * airy_sched_serve() is pure: it reads no kernel state, takes no lock and
 * depends on neither current nor a caller-owned object, so the suite
 * drives it directly and needs no init or exit hook. It checks the
 * boundary contract: every [SC] airy_sched_op is recognised and answered
 * with the explicit -AIRY_ENOTSUP degradation registered for milestone
 * M3, while every other op value is refused fail-closed with
 * -AIRY_EINVAL before the degradation answer is reached, so a malformed
 * request is never told its feature is merely missing.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/sched.h>

#include "airy_sched.h"

static void airy_sched_kind_accept_test(struct kunit *test)
{
	__u32 op;

	/*
	 * Every defined [SC] operation is recognised. Scanning the space
	 * keeps airy_sched_kind() and the enum in step as it grows, and
	 * pins the lower bound: AIRY_SCHED_SET_POLICY is a live op, not a
	 * reserved zero.
	 */
	for (op = AIRY_SCHED_SET_POLICY;
	     op < (__u32)AIRY_SCHED_OP_MAX; op++)
		KUNIT_ASSERT_EQ_MSG(test, AIRY_SCHED_CLASS_OP,
				    airy_sched_kind(op),
				    "op %u not classified OP", op);
}

static void airy_sched_kind_reject_test(struct kunit *test)
{
	/* Zero sits below the first op, so it is a contract violation. */
	KUNIT_EXPECT_EQ(test, AIRY_SCHED_CLASS_INVALID,
			airy_sched_kind(0));
	/* The enum's exclusive ceiling is not itself an operation. */
	KUNIT_EXPECT_EQ(test, AIRY_SCHED_CLASS_INVALID,
			airy_sched_kind(AIRY_SCHED_OP_MAX));
	KUNIT_EXPECT_EQ(test, AIRY_SCHED_CLASS_INVALID,
			airy_sched_kind(AIRY_SCHED_OP_MAX + 1u));
	KUNIT_EXPECT_EQ(test, AIRY_SCHED_CLASS_INVALID,
			airy_sched_kind(0xffffffffu));
}

static void airy_sched_serve_degraded_test(struct kunit *test)
{
	__u32 op;

	/*
	 * A recognised operation reaches the second answer: the
	 * policy/budget/latency/priority/vtime/yield backend it names is a
	 * milestone M3 deliverable, so the entry degrades it with
	 * -AIRY_ENOTSUP rather than standing in for it. The answer must
	 * never be AIRY_EOK, which would report a backend that does not
	 * exist.
	 */
	for (op = AIRY_SCHED_SET_POLICY;
	     op < (__u32)AIRY_SCHED_OP_MAX; op++)
		KUNIT_ASSERT_EQ_MSG(test, -AIRY_ENOTSUP,
				    airy_sched_serve(op),
				    "op %u not degraded", op);
}

static void airy_sched_serve_invalid_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_sched_serve(0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_serve(AIRY_SCHED_OP_MAX));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_serve(AIRY_SCHED_OP_MAX + 1u));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_sched_serve(0xffffffffu));
}

static void airy_sched_serve_priority_test(struct kunit *test)
{
	/*
	 * Fail-closed ordering: validation governs the answer, so the op
	 * space is classified before the degradation answer is reached.
	 * The first op and the value below the exclusive ceiling are
	 * degraded, while the value below the first op and the ceiling
	 * itself are refused with -AIRY_EINVAL. The two magnitudes are
	 * distinct on purpose, which is what lets a caller tell a
	 * malformed request from an unavailable feature.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP,
			airy_sched_serve(AIRY_SCHED_SET_POLICY));
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP,
			airy_sched_serve(AIRY_SCHED_OP_MAX - 1u));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_sched_serve(0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_serve(AIRY_SCHED_OP_MAX));
}

static struct kunit_case airy_sched_cases[] = {
	KUNIT_CASE(airy_sched_kind_accept_test),
	KUNIT_CASE(airy_sched_kind_reject_test),
	KUNIT_CASE(airy_sched_serve_degraded_test),
	KUNIT_CASE(airy_sched_serve_invalid_test),
	KUNIT_CASE(airy_sched_serve_priority_test),
	{}
};

static struct kunit_suite airy_sched_suite = {
	.name = "airy_sched_syscall_550",
	.test_cases = airy_sched_cases,
};

kunit_test_suites(&airy_sched_suite);

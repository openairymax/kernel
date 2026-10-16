// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_rovol_test.c — KUnit coverage for the syscall 549 MemoryRoVol
 * control entry defined in airy_rovol.c.
 *
 * airy_rovol_serve() is pure: it reads no kernel state, takes no lock
 * and depends on neither current nor a caller-owned object, so the suite
 * drives it directly and needs no init or exit hook. It checks the
 * boundary contract: every [SC] airy_rovol_op is recognised and answered
 * with the explicit -AIRY_ENOTSUP degradation registered for milestone
 * M5, while every other op value is refused fail-closed with
 * -AIRY_EINVAL before the degradation answer is reached, so a malformed
 * request is never told its feature is merely missing.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/memory_types.h>

#include "airy_rovol.h"

static void airy_rovol_kind_accept_test(struct kunit *test)
{
	__u32 op;

	/*
	 * Every defined [SC] operation is recognised. Scanning the space
	 * keeps airy_rovol_kind() and the enum in step as it grows, and
	 * pins the lower bound: AIRY_ROVOL_SNAPSHOT is a live op, not a
	 * reserved zero.
	 */
	for (op = AIRY_ROVOL_SNAPSHOT;
	     op < (__u32)AIRY_ROVOL_OP_MAX; op++)
		KUNIT_ASSERT_EQ_MSG(test, AIRY_ROVOL_CLASS_OP,
				    airy_rovol_kind(op),
				    "op %u not classified OP", op);
}

static void airy_rovol_kind_reject_test(struct kunit *test)
{
	/* Zero sits below the first op, so it is a contract violation. */
	KUNIT_EXPECT_EQ(test, AIRY_ROVOL_CLASS_INVALID,
			airy_rovol_kind(0));
	/* The enum's exclusive ceiling is not itself an operation. */
	KUNIT_EXPECT_EQ(test, AIRY_ROVOL_CLASS_INVALID,
			airy_rovol_kind(AIRY_ROVOL_OP_MAX));
	KUNIT_EXPECT_EQ(test, AIRY_ROVOL_CLASS_INVALID,
			airy_rovol_kind(AIRY_ROVOL_OP_MAX + 1u));
	KUNIT_EXPECT_EQ(test, AIRY_ROVOL_CLASS_INVALID,
			airy_rovol_kind(0xffffffffu));
}

static void airy_rovol_serve_degraded_test(struct kunit *test)
{
	__u32 op;

	/*
	 * A recognised operation reaches the second answer: the
	 * snapshot/restore/migrate/staging backend it names is a milestone
	 * M5 deliverable, so the entry degrades it with -AIRY_ENOTSUP
	 * rather than standing in for it. The answer must never be
	 * AIRY_EOK, which would report a backend that does not exist.
	 */
	for (op = AIRY_ROVOL_SNAPSHOT;
	     op < (__u32)AIRY_ROVOL_OP_MAX; op++)
		KUNIT_ASSERT_EQ_MSG(test, -AIRY_ENOTSUP,
				    airy_rovol_serve(op),
				    "op %u not degraded", op);
}

static void airy_rovol_serve_invalid_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_rovol_serve(0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_rovol_serve(AIRY_ROVOL_OP_MAX));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_rovol_serve(AIRY_ROVOL_OP_MAX + 1u));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_rovol_serve(0xffffffffu));
}

static void airy_rovol_serve_priority_test(struct kunit *test)
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
			airy_rovol_serve(AIRY_ROVOL_SNAPSHOT));
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP,
			airy_rovol_serve(AIRY_ROVOL_OP_MAX - 1u));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_rovol_serve(0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_rovol_serve(AIRY_ROVOL_OP_MAX));
}

static struct kunit_case airy_rovol_cases[] = {
	KUNIT_CASE(airy_rovol_kind_accept_test),
	KUNIT_CASE(airy_rovol_kind_reject_test),
	KUNIT_CASE(airy_rovol_serve_degraded_test),
	KUNIT_CASE(airy_rovol_serve_invalid_test),
	KUNIT_CASE(airy_rovol_serve_priority_test),
	{}
};

static struct kunit_suite airy_rovol_suite = {
	.name = "airy_rovol_syscall_549",
	.test_cases = airy_rovol_cases,
};

kunit_test_suites(&airy_rovol_suite);

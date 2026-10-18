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
 *
 * airy_sched_ctl() adds the two text arguments. An undefined op must be
 * refused before either pointer is touched, which the NULL-argument
 * cases below prove deterministically on every architecture. The text
 * policy itself lives in airy_sched_chk(), which takes kernel memory
 * and is therefore driven with stack strings; its UTF-8 boundary matrix
 * is owned by the airy_utf8_charset suite and only the integration
 * points are repeated here.
 *
 * The copy-fault path of airy_sched_arg() has no KUnit case: UML does
 * not recover from a fault on an unmapped user address, so driving it
 * with an unreadable pointer would panic the test kernel rather than
 * return -AIRY_EFAULT.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/sched.h>

#include "airy_sched.h"

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

static void airy_sched_ctl_invalid_op_test(struct kunit *test)
{
	/*
	 * The op space is classified before either text pointer is read:
	 * NULL arguments do not turn an undefined op into a copy fault.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_ctl(0, NULL, NULL));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_ctl(AIRY_SCHED_OP_MAX, NULL, NULL));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_sched_ctl(0xffffffffu, NULL, NULL));
}

static void airy_sched_chk_ok_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_sched_chk(""));
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_sched_chk("cpu.max"));
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_sched_chk("/sys/fs/cgroup/\xe4\xb8\xad"));
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_sched_chk("latency-\xf0\x9f\x98\x80"));
}

static void airy_sched_chk_fault_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_sched_chk(NULL));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID,
			airy_sched_chk("cpu.\xc2"));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_SURROGATE,
			airy_sched_chk("cpu.\xed\xa0\x80"));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_BOM,
			airy_sched_chk("cpu.\xef\xbb\xbf"));
}

static struct kunit_case airy_sched_cases[] = {
	KUNIT_CASE(airy_sched_serve_degraded_test),
	KUNIT_CASE(airy_sched_serve_invalid_test),
	KUNIT_CASE(airy_sched_serve_priority_test),
	KUNIT_CASE(airy_sched_ctl_invalid_op_test),
	KUNIT_CASE(airy_sched_chk_ok_test),
	KUNIT_CASE(airy_sched_chk_fault_test),
	{}
};

static struct kunit_suite airy_sched_suite = {
	.name = "airy_sched_syscall_550",
	.test_cases = airy_sched_cases,
};

kunit_test_suites(&airy_sched_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lockdown_test.c — KUnit coverage for the Airymax lockdown ladder
 * (B-05).
 *
 * The ladder is the single monotonic state machine every agent-facing
 * interface consults, so these cases pin its whole contract: the level
 * only rises, a same-level request is a no-op, an out-of-range request
 * is refused, the name parser accepts exactly the four published names,
 * the gate closes all three interfaces from EARLY on, and the
 * security_locked_down() answer follows the per-reason table at each
 * level.  Every case starts from AIRY_LOCK_NONE through the test-only
 * reset, so the suite does not depend on the boot configuration.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include <airymax/airy_lockdown.h>

static void lock_none(struct kunit *test)
{
	airy_lock_clr();

	KUNIT_EXPECT_EQ(test, AIRY_LOCK_NONE, airy_lock_get());
}

static void lock_raise(struct kunit *test)
{
	airy_lock_clr();

	KUNIT_EXPECT_EQ(test, 0, airy_lock_set(AIRY_LOCK_EARLY,
					       AIRY_LOCK_BY_CMDLINE));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_EARLY, airy_lock_get());
	KUNIT_EXPECT_EQ(test, 0, airy_lock_set(AIRY_LOCK_FULL,
					       AIRY_LOCK_BY_SECFS));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_FULL, airy_lock_get());
}

static void lock_no_lower(struct kunit *test)
{
	airy_lock_clr();
	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_FULL,
					       AIRY_LOCK_BY_CONFIG));

	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_set(AIRY_LOCK_EARLY,
						    AIRY_LOCK_BY_SECFS));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_FULL, airy_lock_get());
}

static void lock_same(struct kunit *test)
{
	airy_lock_clr();
	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_LATE,
					       AIRY_LOCK_BY_CONFIG));

	KUNIT_EXPECT_EQ(test, 0, airy_lock_set(AIRY_LOCK_LATE,
					       AIRY_LOCK_BY_SECFS));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_LATE, airy_lock_get());
}

static void lock_bad(struct kunit *test)
{
	airy_lock_clr();

	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_set(AIRY_LOCK_MAX,
						    AIRY_LOCK_BY_SECFS));
	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_set(AIRY_LOCK_EARLY,
						    AIRY_LOCK_TRIGGER_MAX));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_NONE, airy_lock_get());
}

static void lock_names(struct kunit *test)
{
	u8 level = AIRY_LOCK_MAX;

	KUNIT_EXPECT_EQ(test, 0, airy_lock_arg("none", &level));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_NONE, level);
	KUNIT_EXPECT_EQ(test, 0, airy_lock_arg("early", &level));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_EARLY, level);
	KUNIT_EXPECT_EQ(test, 0, airy_lock_arg("late", &level));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_LATE, level);
	KUNIT_EXPECT_EQ(test, 0, airy_lock_arg("full", &level));
	KUNIT_EXPECT_EQ(test, AIRY_LOCK_FULL, level);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_lock_arg("sealed", &level));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_lock_arg(NULL, &level));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_lock_arg("full", NULL));
}

static void lock_gate(struct kunit *test)
{
	airy_lock_clr();

	KUNIT_EXPECT_EQ(test, 0, airy_lock_gate(AIRY_LOCK_IF_CAP_GRANT));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_gate(AIRY_LOCK_IF_ROVOL));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_gate(AIRY_LOCK_IF_SCHED));

	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_EARLY,
					       AIRY_LOCK_BY_SECFS));
	KUNIT_EXPECT_EQ(test, -AIRY_ELOCKDOWN,
			airy_lock_gate(AIRY_LOCK_IF_CAP_GRANT));
	KUNIT_EXPECT_EQ(test, -AIRY_ELOCKDOWN,
			airy_lock_gate(AIRY_LOCK_IF_ROVOL));
	KUNIT_EXPECT_EQ(test, -AIRY_ELOCKDOWN,
			airy_lock_gate(AIRY_LOCK_IF_SCHED));
}

static void lock_early(struct kunit *test)
{
	airy_lock_clr();
	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_EARLY,
					       AIRY_LOCK_BY_SECFS));

	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_KEXEC));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_DEBUGFS));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_XFRM_SECRET));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_NONE));
}

static void lock_late(struct kunit *test)
{
	airy_lock_clr();
	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_LATE,
					       AIRY_LOCK_BY_SECFS));

	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_KEXEC));
	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_DEBUGFS));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_XFRM_SECRET));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_NONE));
}

static void lock_full(struct kunit *test)
{
	airy_lock_clr();
	KUNIT_ASSERT_EQ(test, 0, airy_lock_set(AIRY_LOCK_FULL,
					       AIRY_LOCK_BY_SECFS));

	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_KEXEC));
	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_DEBUGFS));
	KUNIT_EXPECT_EQ(test, -EPERM, airy_lock_down(LOCKDOWN_XFRM_SECRET));
	KUNIT_EXPECT_EQ(test, 0, airy_lock_down(LOCKDOWN_NONE));
}

static struct kunit_case airy_lock_cases[] = {
	KUNIT_CASE(lock_none),
	KUNIT_CASE(lock_raise),
	KUNIT_CASE(lock_no_lower),
	KUNIT_CASE(lock_same),
	KUNIT_CASE(lock_bad),
	KUNIT_CASE(lock_names),
	KUNIT_CASE(lock_gate),
	KUNIT_CASE(lock_early),
	KUNIT_CASE(lock_late),
	KUNIT_CASE(lock_full),
	{}
};

static struct kunit_suite airy_lock_suite = {
	.name = "airy_lockdown",
	.test_cases = airy_lock_cases,
};

kunit_test_suites(&airy_lock_suite);

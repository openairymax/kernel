// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_probe_test.c — KUnit coverage for the agentrt presence probe (A-39).
 *
 * agentrt treats the existence of /proc/sys/agentrt/present as proof that
 * the kernel fastpath is live, so the probe must not advertise readiness
 * before every Airy init step has run and must withdraw it on failure.
 * These cases pin the state machine behind the file: absent until init,
 * ready afterwards, idempotent re-init, absent again after exit, then
 * publishable once more.  KUnit runs before procfs is mounted, so the file
 * is not opened here; airy_probe_val() returns the same value that the proc
 * handler serialises.
 */

#include <kunit/test.h>

#include "airy_probe.h"

#ifdef CONFIG_SYSCTL
#define PROBE_READY	AIRY_PROBE_READY
#else
#define PROBE_READY	AIRY_PROBE_ABSENT
#endif

static void probe_absent(struct kunit *test)
{
	airy_probe_exit();

	KUNIT_EXPECT_EQ(test, AIRY_PROBE_ABSENT, airy_probe_val());
}

static void probe_ready(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, 0, airy_probe_init());
	KUNIT_EXPECT_EQ(test, PROBE_READY, airy_probe_val());
}

static void probe_idem(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, 0, airy_probe_init());
	KUNIT_ASSERT_EQ(test, 0, airy_probe_init());
	KUNIT_EXPECT_EQ(test, PROBE_READY, airy_probe_val());
}

static void probe_cycle(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, 0, airy_probe_init());
	airy_probe_exit();
	KUNIT_EXPECT_EQ(test, AIRY_PROBE_ABSENT, airy_probe_val());

	KUNIT_ASSERT_EQ(test, 0, airy_probe_init());
	KUNIT_EXPECT_EQ(test, PROBE_READY, airy_probe_val());
}

static struct kunit_case airy_probe_cases[] = {
	KUNIT_CASE(probe_absent),
	KUNIT_CASE(probe_ready),
	KUNIT_CASE(probe_idem),
	KUNIT_CASE(probe_cycle),
	{}
};

static struct kunit_suite airy_probe_suite = {
	.name = "airy_probe_presence",
	.test_cases = airy_probe_cases,
};

kunit_test_suites(&airy_probe_suite);

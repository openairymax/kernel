// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_sysctl_test.c — KUnit coverage for capability observation.
 *
 * kernel.airy.cap_used reports how many slots hold a badge, and the
 * geometry entries report the compile-time ABI constants.  KUnit runs
 * before procfs is mounted, so the entries are not opened here; the
 * cases exercise the counting helper that the read handler serialises
 * and the init/exit contract of the sysctl tree.
 *
 * Occupancy is checked as a delta against the live table: earlier
 * suites may leave registrations behind, so the cases must not assume
 * an otherwise empty table.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"
#include "airy_cap_sysctl.h"

#define TEST_USED_AGENT		1000u
#define TEST_DERIVE_AGENT	1001u

struct cap_used_ctx {
	struct airy_cap_slot saved[2];
	unsigned int base;
};

static int cap_used_test_init(struct kunit *test)
{
	struct cap_used_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	ctx->saved[0] = agent_caps[TEST_USED_AGENT];
	ctx->saved[1] = agent_caps[TEST_DERIVE_AGENT];
	memset(&agent_caps[TEST_USED_AGENT], 0, sizeof(agent_caps[0]));
	memset(&agent_caps[TEST_DERIVE_AGENT], 0, sizeof(agent_caps[0]));

	ctx->base = airy_cap_used();
	return 0;
}

static void cap_used_test_exit(struct kunit *test)
{
	struct cap_used_ctx *ctx = test->priv;

	if (!ctx)
		return;

	agent_caps[TEST_USED_AGENT] = ctx->saved[0];
	agent_caps[TEST_DERIVE_AGENT] = ctx->saved[1];
}

static void cap_used_counts(struct kunit *test)
{
	struct cap_used_ctx *ctx = test->priv;
	__u64 badge = AIRY_BADGE_COMPILE(1, 0x12345678u, AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, ctx->base, airy_cap_used());

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_USED_AGENT, badge));
	KUNIT_EXPECT_EQ(test, ctx->base + 1, airy_cap_used());

	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_USED_AGENT, TEST_DERIVE_AGENT,
					AIRY_CAP_OP_COPY, 0));
	KUNIT_EXPECT_EQ(test, ctx->base + 2, airy_cap_used());

	airy_cap_unreg(TEST_USED_AGENT);
	KUNIT_EXPECT_EQ(test, ctx->base + 1, airy_cap_used());
}

static void cap_used_overflow(struct kunit *test)
{
	struct cap_used_ctx *ctx = test->priv;
	__u64 badge = AIRY_BADGE_COMPILE(1, 0xCAFEBABEu, AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_cap_register(AIRY_CAP_MAX_AGENTS, badge));
	KUNIT_EXPECT_EQ(test, ctx->base, airy_cap_used());
}

static void cap_sysctl_cycle(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, 0, airy_cap_sysctl_init());
	KUNIT_ASSERT_EQ(test, 0, airy_cap_sysctl_init());
	airy_cap_sysctl_exit();
	KUNIT_ASSERT_EQ(test, 0, airy_cap_sysctl_init());
}

static struct kunit_case airy_cap_sysctl_cases[] = {
	KUNIT_CASE(cap_used_counts),
	KUNIT_CASE(cap_used_overflow),
	KUNIT_CASE(cap_sysctl_cycle),
	{}
};

static struct kunit_suite airy_cap_sysctl_suite = {
	.name = "airy_cap_sysctl",
	.init = cap_used_test_init,
	.exit = cap_used_test_exit,
	.test_cases = airy_cap_sysctl_cases,
};

kunit_test_suites(&airy_cap_sysctl_suite);

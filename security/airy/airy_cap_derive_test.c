// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_derive_test.c — KUnit regression for the P1-10 COPY downgrade fix.
 *
 * P1-10 added optional permission demotion to the COPY derivation path:
 * when new_perms != 0, the destination perms become new_perms & src->perms
 * (seL4 maskCapRights semantics), so a COPY can never mint a permission
 * the source does not hold.  These tests verify that COPY cannot grant
 * AIRY_CAP_PERM_DERIVE (the seL4 Grant analogue) when the source lacks it,
 * and that permissions decrease monotonically across derivation.
 *
 * airy_cap_derive() is non-static (declared in airy_cap.h), so the test
 * links against airy_cap_derive.o within the airy module without including
 * the .c file.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"

#define TEST_SRC_AGENT	1020u
#define TEST_DST_AGENT	1021u

struct cap_derive_ctx {
	struct airy_cap_slot saved_src;
	struct airy_cap_slot saved_dst;
};

static int cap_derive_test_init(struct kunit *test)
{
	struct cap_derive_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save the real slots so production agent_caps state is untouched. */
	ctx->saved_src = agent_caps[TEST_SRC_AGENT];
	ctx->saved_dst = agent_caps[TEST_DST_AGENT];

	/* Zero the test slots so airy_cap_register() sees them empty. */
	memset(&agent_caps[TEST_SRC_AGENT], 0, sizeof(struct airy_cap_slot));
	memset(&agent_caps[TEST_DST_AGENT], 0, sizeof(struct airy_cap_slot));

	return 0;
}

static void cap_derive_test_exit(struct kunit *test)
{
	struct cap_derive_ctx *ctx = test->priv;

	if (!ctx)
		return;
	agent_caps[TEST_SRC_AGENT] = ctx->saved_src;
	agent_caps[TEST_DST_AGENT] = ctx->saved_dst;
}

static void register_src(struct kunit *test, __u16 perms)
{
	__u64 badge = AIRY_BADGE_COMPILE(1, 0xA5A5A5A5u, perms);

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_SRC_AGENT, badge));
}

static void copy_cannot_mint_derive_perm_test(struct kunit *test)
{
	__u16 new_perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_DERIVE;
	int ret;

	/* Source holds SEND+RECV but NOT DERIVE (the seL4 Grant analogue). */
	register_src(test, AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV);

	/* COPY requests SEND+DERIVE; DERIVE must be masked out because the
	 * source does not hold it (P1-10: perms = new_perms & src->perms). */
	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, new_perms);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u16)AIRY_CAP_PERM_SEND,
			agent_caps[TEST_DST_AGENT].perms);
	/* The Grant-analogue (DERIVE) must NOT be minted. */
	KUNIT_EXPECT_FALSE(test,
		agent_caps[TEST_DST_AGENT].perms & AIRY_CAP_PERM_DERIVE);
}

static void copy_new_perms_zero_clones_source_test(struct kunit *test)
{
	__u16 src_perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_KILL;
	int ret;

	register_src(test, src_perms);

	/* new_perms == 0 means clone unchanged (backward compatible). */
	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, src_perms,
			agent_caps[TEST_DST_AGENT].perms);
}

static void copy_subset_perms_monotonic_test(struct kunit *test)
{
	__u16 src_perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV |
			  AIRY_CAP_PERM_KILL;
	__u16 new_perms = AIRY_CAP_PERM_RECV | AIRY_CAP_PERM_FILE_OPEN;
	int ret;

	register_src(test, src_perms);

	/* COPY with a subset request: result = new_perms & src_perms, so
	 * FILE_OPEN (not in src) is dropped and permissions decrease. */
	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, new_perms);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u16)AIRY_CAP_PERM_RECV,
			agent_caps[TEST_DST_AGENT].perms);
	KUNIT_EXPECT_LE(test, (unsigned int)agent_caps[TEST_DST_AGENT].perms,
			(unsigned int)src_perms);
}

static void copy_preserves_epoch_and_randtag_test(struct kunit *test)
{
	__u64 src_badge, dst_badge;
	int ret;

	register_src(test, AIRY_CAP_PERM_SEND);

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, AIRY_CAP_PERM_SEND);
	KUNIT_EXPECT_EQ(test, 0, ret);

	src_badge = agent_caps[TEST_SRC_AGENT].badge;
	dst_badge = agent_caps[TEST_DST_AGENT].badge;
	/* Epoch and randtag are inherited (only perms may be demoted). */
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_BADGE_EPOCH(src_badge),
			(unsigned long long)AIRY_BADGE_EPOCH(dst_badge));
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_BADGE_RANDTAG(src_badge),
			(unsigned long long)AIRY_BADGE_RANDTAG(dst_badge));
}

static struct kunit_case airy_cap_derive_cases[] = {
	KUNIT_CASE(copy_cannot_mint_derive_perm_test),
	KUNIT_CASE(copy_new_perms_zero_clones_source_test),
	KUNIT_CASE(copy_subset_perms_monotonic_test),
	KUNIT_CASE(copy_preserves_epoch_and_randtag_test),
	{}
};

static struct kunit_suite airy_cap_derive_suite = {
	.name = "airy_cap_derive_p1_10",
	.init = cap_derive_test_init,
	.exit = cap_derive_test_exit,
	.test_cases = airy_cap_derive_cases,
};

kunit_test_suites(&airy_cap_derive_suite);

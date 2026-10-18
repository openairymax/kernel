// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_derive_test.c — KUnit coverage for CNode derivation.
 *
 * COPY/MINT are checked for the P1-10 demotion rule (a copy never
 * mints a permission the source lacks) and for MDB linkage. MOVE is
 * checked to preserve the source's tree position, carry its derived
 * subtree, and keep an irrevocable marker. DELETE is checked to
 * detach its children as new roots without cascading. REVOKE proves
 * each link by bumping the descendants' epoch, and ROTATE is checked
 * to recompile the badge around a fresh random tag.
 *
 * airy_cap_derive() is non-static (airy_cap.h), so the suite links
 * against airy_cap_derive.o inside the airy module.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"

#define TEST_PARENT_AGENT	1016u
#define TEST_CHILD_AGENT	1017u
#define TEST_SIBLING_AGENT	1018u
#define TEST_SRC_AGENT		1019u
#define TEST_DST_AGENT		1020u

#define TEST_BASE_AGENT		TEST_PARENT_AGENT
#define TEST_NR_AGENTS		5

struct cap_derive_ctx {
	struct airy_cap_slot saved[TEST_NR_AGENTS];
};

static int cap_derive_test_init(struct kunit *test)
{
	struct cap_derive_ctx *ctx;
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save the real slots so production agent_caps state is untouched. */
	for (i = 0; i < TEST_NR_AGENTS; i++) {
		ctx->saved[i] = agent_caps[TEST_BASE_AGENT + i];
		memset(&agent_caps[TEST_BASE_AGENT + i], 0,
		       sizeof(struct airy_cap_slot));
	}

	return 0;
}

static void cap_derive_test_exit(struct kunit *test)
{
	struct cap_derive_ctx *ctx = test->priv;
	int i;

	if (!ctx)
		return;

	for (i = 0; i < TEST_NR_AGENTS; i++)
		agent_caps[TEST_BASE_AGENT + i] = ctx->saved[i];
}

static int register_agent(__u32 agent, __u16 perms)
{
	__u64 badge = AIRY_BADGE_COMPILE(1, 0xA5A5A5A5u, perms);

	return airy_cap_register(agent, badge);
}

/* ─── COPY ─────────────────────────────────────────────────────────────── */

static void copy_cannot_mint_derive_perm_test(struct kunit *test)
{
	__u16 new_perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_DERIVE;
	int ret;

	/* Source holds SEND+RECV but NOT DERIVE (the seL4 Grant analogue). */
	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT,
				       AIRY_CAP_PERM_SEND |
				       AIRY_CAP_PERM_RECV));

	/*
	 * COPY requests SEND+DERIVE; DERIVE must be masked out because the
	 * source does not hold it (P1-10: perms = new_perms & src->perms).
	 */
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

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, src_perms));

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

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, src_perms));

	/*
	 * COPY with a subset request: result = new_perms & src_perms, so
	 * FILE_OPEN (not in src) is dropped and permissions decrease.
	 */
	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, new_perms);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u16)AIRY_CAP_PERM_RECV,
			agent_caps[TEST_DST_AGENT].perms);
	KUNIT_EXPECT_LE(test,
			(unsigned int)agent_caps[TEST_DST_AGENT].perms,
			(unsigned int)src_perms);
}

static void copy_preserves_epoch_and_randtag_test(struct kunit *test)
{
	__u64 src_badge, dst_badge;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_COPY, AIRY_CAP_PERM_SEND);
	KUNIT_EXPECT_EQ(test, 0, ret);

	src_badge = agent_caps[TEST_SRC_AGENT].badge;
	dst_badge = agent_caps[TEST_DST_AGENT].badge;
	/* Epoch and randtag are inherited (only perms may be demoted). */
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)AIRY_BADGE_EPOCH(src_badge),
			(unsigned long long)AIRY_BADGE_EPOCH(dst_badge));
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)AIRY_BADGE_RANDTAG(src_badge),
			(unsigned long long)AIRY_BADGE_RANDTAG(dst_badge));
}

/* ─── MINT ─────────────────────────────────────────────────────────────── */

static void mint_links_child_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	__u16 src_perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, src_perms));

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_MINT,
			      AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_DERIVE);
	KUNIT_EXPECT_EQ(test, 0, ret);
	/* MINT always demotes, even when new_perms carries extra bits. */
	KUNIT_EXPECT_EQ(test, (__u16)AIRY_CAP_PERM_SEND, dst->perms);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_SRC_AGENT, dst->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)1, dst->generation);
	KUNIT_EXPECT_EQ(test, (__u16)1, dst->revocable);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_DST_AGENT, src->first_child);
}

/* ─── MOVE ─────────────────────────────────────────────────────────────── */

static void move_root_becomes_root_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	__u64 badge;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));
	badge = src->badge;

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, badge, dst->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, dst->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)0, dst->generation);
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)src->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->agent_id);
}

static void move_child_keeps_parent_test(struct kunit *test)
{
	struct airy_cap_slot *parent = &agent_caps[TEST_PARENT_AGENT];
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_SRC_AGENT,
					AIRY_CAP_OP_COPY, 0));
	/* A sibling keeps the parent's child chain non-trivial. */
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT,
					TEST_SIBLING_AGENT,
					AIRY_CAP_OP_COPY, 0));

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_PARENT_AGENT, dst->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)1, dst->generation);
	KUNIT_EXPECT_EQ(test, (__u16)1, dst->revocable);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_DST_AGENT, parent->first_child);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_SIBLING_AGENT,
			dst->next_sibling);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_PARENT_AGENT,
			agent_caps[TEST_SIBLING_AGENT].parent_agent);

	/* The re-linked dst must still be reached by the parent's REVOKE. */
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, 0,
					AIRY_CAP_OP_REVOKE, 0));
	KUNIT_EXPECT_EQ(test, (__u16)2, dst->epoch);
}

static void move_carries_children_test(struct kunit *test)
{
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_SRC_AGENT,
					AIRY_CAP_OP_COPY, 0));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_SRC_AGENT, TEST_CHILD_AGENT,
					AIRY_CAP_OP_COPY, 0));

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_CHILD_AGENT, dst->first_child);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_DST_AGENT, child->parent_agent);
	/* Depth is preserved: the child keeps its position below dst. */
	KUNIT_EXPECT_EQ(test, (__u16)2, child->generation);

	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_DST_AGENT, 0,
					AIRY_CAP_OP_REVOKE, 0));
	KUNIT_EXPECT_EQ(test, (__u16)2, child->epoch);
}

static void move_keeps_irrevocable_test(struct kunit *test)
{
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_SRC_AGENT,
					AIRY_CAP_OP_COPY, 0));
	WRITE_ONCE(agent_caps[TEST_SRC_AGENT].revocable, 0);

	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_DST_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u16)0, dst->revocable);

	/* An irrevocable capability survives its parent's revocation. */
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, 0,
					AIRY_CAP_OP_REVOKE, 0));
	KUNIT_EXPECT_EQ(test, (__u16)1, dst->epoch);
}

/* ─── DELETE ───────────────────────────────────────────────────────────── */

static void delete_promotes_children_test(struct kunit *test)
{
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_SRC_AGENT,
					AIRY_CAP_OP_COPY, 0));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_SRC_AGENT, TEST_CHILD_AGENT,
					AIRY_CAP_OP_COPY, 0));

	ret = airy_cap_derive(TEST_SRC_AGENT, 0, AIRY_CAP_OP_DELETE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)0, child->generation);
	KUNIT_EXPECT_NE(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)child->badge);

	/* DELETE does not cascade: the promoted root keeps its epoch. */
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, 0,
					AIRY_CAP_OP_REVOKE, 0));
	KUNIT_EXPECT_EQ(test, (__u16)1, child->epoch);
}

static void delete_clears_slot_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));

	ret = airy_cap_derive(TEST_SRC_AGENT, 0, AIRY_CAP_OP_DELETE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)src->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->agent_id);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->flags);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->randtag);
	KUNIT_EXPECT_EQ(test, (__u16)0, src->perms);
	KUNIT_EXPECT_EQ(test, (__u16)0, src->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->first_child);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->next_sibling);
	KUNIT_EXPECT_EQ(test, (__u16)0, src->generation);
	KUNIT_EXPECT_EQ(test, (__u16)0, src->revocable);
}

/* ─── ROTATE ───────────────────────────────────────────────────────────── */

static void rotate_recompiles_badge_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	__u64 old_badge;
	__u16 perms = AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, perms));
	old_badge = src->badge;

	ret = airy_cap_derive(TEST_SRC_AGENT, 0, AIRY_CAP_OP_ROTATE, 0);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_NE(test, (unsigned long long)old_badge,
			(unsigned long long)src->badge);
	KUNIT_EXPECT_EQ(test, (__u16)perms, src->perms);
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)AIRY_BADGE_EPOCH(old_badge),
			(unsigned long long)AIRY_BADGE_EPOCH(src->badge));
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)AIRY_BADGE_RANDTAG(src->badge),
			(unsigned long long)src->randtag);
}

static struct kunit_case airy_cap_derive_cases[] = {
	KUNIT_CASE(copy_cannot_mint_derive_perm_test),
	KUNIT_CASE(copy_new_perms_zero_clones_source_test),
	KUNIT_CASE(copy_subset_perms_monotonic_test),
	KUNIT_CASE(copy_preserves_epoch_and_randtag_test),
	KUNIT_CASE(mint_links_child_test),
	KUNIT_CASE(move_root_becomes_root_test),
	KUNIT_CASE(move_child_keeps_parent_test),
	KUNIT_CASE(move_carries_children_test),
	KUNIT_CASE(move_keeps_irrevocable_test),
	KUNIT_CASE(delete_promotes_children_test),
	KUNIT_CASE(delete_clears_slot_test),
	KUNIT_CASE(rotate_recompiles_badge_test),
	{}
};

static struct kunit_suite airy_cap_derive_suite = {
	.name = "airy_cap_derive",
	.init = cap_derive_test_init,
	.exit = cap_derive_test_exit,
	.test_cases = airy_cap_derive_cases,
};

kunit_test_suites(&airy_cap_derive_suite);

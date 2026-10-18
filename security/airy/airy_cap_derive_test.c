// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_derive_test.c — KUnit coverage for CNode derivation.
 *
 * COPY/MINT verify the P1-10 demotion rule (a copy never mints a
 * permission the source lacks) and MDB linkage. MOVE preserves the
 * source's tree position, carries its derived subtree and requires an
 * empty destination. DELETE promotes children to roots without
 * cascading. REVOKE bumps descendant epochs, including a 65-level
 * chain; ROTATE recompiles the badge around a fresh tag. unreg()
 * clears the slot, cascades over revocable descendants, promotes them
 * to roots and spares irrevocable capabilities.
 *
 * airy_cap_derive() is non-static, so the suite links against
 * airy_cap_derive.o inside the airy module.
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

#define TEST_CHAIN_BASE		900u
#define TEST_CHAIN_DEPTH	65

struct cap_derive_ctx {
	struct airy_cap_slot saved[TEST_NR_AGENTS];
	struct airy_cap_slot chain[TEST_CHAIN_DEPTH];
};

static void slots_snapshot(__u32 base, unsigned int nr,
			   struct airy_cap_slot *dst)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		dst[i] = agent_caps[base + i];
		memset(&agent_caps[base + i], 0, sizeof(agent_caps[0]));
	}
}

static void slots_restore(__u32 base, unsigned int nr,
			  const struct airy_cap_slot *src)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		agent_caps[base + i] = src[i];
}

static int cap_derive_test_init(struct kunit *test)
{
	struct cap_derive_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save the real slots so production agent_caps state is untouched. */
	slots_snapshot(TEST_BASE_AGENT, TEST_NR_AGENTS, ctx->saved);
	slots_snapshot(TEST_CHAIN_BASE, TEST_CHAIN_DEPTH, ctx->chain);

	return 0;
}

static void cap_derive_test_exit(struct kunit *test)
{
	struct cap_derive_ctx *ctx = test->priv;

	if (!ctx)
		return;

	slots_restore(TEST_BASE_AGENT, TEST_NR_AGENTS, ctx->saved);
	slots_restore(TEST_CHAIN_BASE, TEST_CHAIN_DEPTH, ctx->chain);
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

static void move_requires_empty_dst_test(struct kunit *test)
{
	struct airy_cap_slot *root = &agent_caps[TEST_PARENT_AGENT];
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
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

	/*
	 * A destination inside the source's subtree already owns a
	 * badge, so the empty-slot rule rejects it before any link is
	 * rewritten.  Constraint I2 (no cycles in the MDB) therefore
	 * follows from the slot-ownership check.
	 */
	ret = airy_cap_derive(TEST_PARENT_AGENT, TEST_CHILD_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, -AIRY_EEXIST, ret);
	ret = airy_cap_derive(TEST_SRC_AGENT, TEST_CHILD_AGENT,
			      AIRY_CAP_OP_MOVE, 0);
	KUNIT_EXPECT_EQ(test, -AIRY_EEXIST, ret);

	KUNIT_EXPECT_NE(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)root->badge);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_SRC_AGENT, root->first_child);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_PARENT_AGENT, src->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_CHILD_AGENT, src->first_child);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_SRC_AGENT, child->parent_agent);

	/* A rejected MOVE must leave the tree walkable end to end. */
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, 0,
					AIRY_CAP_OP_REVOKE, 0));
	KUNIT_EXPECT_EQ(test, (__u16)2, root->epoch);
	KUNIT_EXPECT_EQ(test, (__u16)2, src->epoch);
	KUNIT_EXPECT_EQ(test, (__u16)2, child->epoch);
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

/* ─── UNREG ────────────────────────────────────────────────────────────── */

static void unreg_skips_unbound_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	__u64 badge;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));
	badge = src->badge;

	/* Agent 0 never owns a slot; out-of-range IDs must be ignored. */
	airy_cap_unreg(0);
	airy_cap_unreg(AIRY_CAP_MAX_AGENTS);

	KUNIT_EXPECT_EQ(test, badge, src->badge);
	KUNIT_EXPECT_EQ(test, (__u16)1, src->epoch);
}

static void unreg_clears_slot_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));

	airy_cap_unreg(TEST_SRC_AGENT);
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

	/* A second release of the same ID must be a no-op. */
	airy_cap_unreg(TEST_SRC_AGENT);
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)src->badge);
}

static void unreg_revokes_subtree_test(struct kunit *test)
{
	struct airy_cap_slot *parent = &agent_caps[TEST_PARENT_AGENT];
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	struct airy_cap_slot *grand = &agent_caps[TEST_SIBLING_AGENT];

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_CHILD_AGENT,
					AIRY_CAP_OP_COPY, 0));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_CHILD_AGENT, TEST_SIBLING_AGENT,
					AIRY_CAP_OP_COPY, 0));

	airy_cap_unreg(TEST_PARENT_AGENT);

	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)parent->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, parent->agent_id);

	/* Direct child: revoked, badge kept, promoted to a root. */
	KUNIT_EXPECT_EQ(test, (__u16)2, child->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->randtag);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)0, child->generation);
	KUNIT_EXPECT_NE(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)child->badge);

	/* Grandchild keeps its position below the surviving child. */
	KUNIT_EXPECT_EQ(test, (__u16)2, grand->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)TEST_CHILD_AGENT, grand->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)2, grand->generation);
}

static void unreg_spares_irrevocable_test(struct kunit *test)
{
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_PARENT_AGENT,
				       AIRY_CAP_PERM_SEND));
	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_PARENT_AGENT, TEST_CHILD_AGENT,
					AIRY_CAP_OP_COPY, 0));
	WRITE_ONCE(child->revocable, 0);

	airy_cap_unreg(TEST_PARENT_AGENT);

	/*
	 * The irrevocable capability survives, but must no longer name
	 * the released parent as its derivation source.
	 */
	KUNIT_EXPECT_EQ(test, (__u16)1, child->epoch);
	KUNIT_EXPECT_NE(test, (__u32)0, child->randtag);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)0, child->generation);
}

/*
 * A chain deeper than the typical derivation depth must be revoked
 * end to end: the walk uses an explicit stack, so depth is bounded by
 * the slot count rather than by the kernel stack.
 */
static void revoke_deep_chain_test(struct kunit *test)
{
	unsigned int i;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_CHAIN_BASE, AIRY_CAP_PERM_SEND));
	for (i = 1; i < TEST_CHAIN_DEPTH; i++) {
		KUNIT_ASSERT_EQ(test, 0,
				airy_cap_derive(TEST_CHAIN_BASE + i - 1,
						TEST_CHAIN_BASE + i,
						AIRY_CAP_OP_COPY, 0));
	}

	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_derive(TEST_CHAIN_BASE, 0,
					AIRY_CAP_OP_REVOKE, 0));

	for (i = 0; i < TEST_CHAIN_DEPTH; i++) {
		KUNIT_EXPECT_EQ(test, (__u16)2,
				agent_caps[TEST_CHAIN_BASE + i].epoch);
		KUNIT_EXPECT_EQ(test, (__u32)0,
				agent_caps[TEST_CHAIN_BASE + i].randtag);
	}
}

/*
 * Agent 0 is the unbound sentinel: the three operations that install a
 * badge must refuse it exactly as airy_cap_register() does, and a
 * rejected derivation must leave both slots untouched.
 */
static void derive_rejects_unbound_dst_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_SRC_AGENT];
	__u64 badge;

	KUNIT_ASSERT_EQ(test, 0,
			register_agent(TEST_SRC_AGENT, AIRY_CAP_PERM_SEND));
	badge = src->badge;

	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_cap_derive(TEST_SRC_AGENT, 0,
					AIRY_CAP_OP_COPY, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_cap_derive(TEST_SRC_AGENT, 0,
					AIRY_CAP_OP_MINT,
					AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_cap_derive(TEST_SRC_AGENT, 0,
					AIRY_CAP_OP_MOVE, 0));

	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)agent_caps[0].badge);
	KUNIT_EXPECT_EQ(test, badge, src->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, src->first_child);
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
	KUNIT_CASE(move_requires_empty_dst_test),
	KUNIT_CASE(delete_promotes_children_test),
	KUNIT_CASE(delete_clears_slot_test),
	KUNIT_CASE(rotate_recompiles_badge_test),
	KUNIT_CASE(unreg_skips_unbound_test),
	KUNIT_CASE(unreg_clears_slot_test),
	KUNIT_CASE(unreg_revokes_subtree_test),
	KUNIT_CASE(unreg_spares_irrevocable_test),
	KUNIT_CASE(revoke_deep_chain_test),
	KUNIT_CASE(derive_rejects_unbound_dst_test),
	{}
};

static struct kunit_suite airy_cap_derive_suite = {
	.name = "airy_cap_derive",
	.init = cap_derive_test_init,
	.exit = cap_derive_test_exit,
	.test_cases = airy_cap_derive_cases,
};

kunit_test_suites(&airy_cap_derive_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_lifecycle_test.c — KUnit coverage for capability lifetimes.
 *
 * The derivation suite covers the MDB shape each operation produces.
 * This suite covers what the two validation paths, airy_cap_badge_ok()
 * (fastpath) and airy_cap_check() (slowpath), report for a live badge
 * and after every operation that must stale it.  Each case registers
 * through airy_cap_register() and then observes the slot directly, so
 * register, derive and check are exercised end to end instead of
 * testing the validators against hand-written slot state.
 *
 * Slots 1002-1005 are reserved for this suite; no other KUnit file
 * uses them.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"

#define TEST_ROOT_AGENT		1002u
#define TEST_CHILD_AGENT	1003u
#define TEST_SPARE_AGENT	1004u
#define TEST_DST_AGENT		1005u

#define TEST_BASE_AGENT		TEST_ROOT_AGENT
#define TEST_NR_AGENTS		4

#define TEST_EPOCH		1u
#define TEST_TAG		0x3C3C3C3Cu
#define TEST_PERMS		(AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV)

struct cap_life_ctx {
	struct airy_cap_slot saved[TEST_NR_AGENTS];
};

static int cap_life_test_init(struct kunit *test)
{
	struct cap_life_ctx *ctx;
	unsigned int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save the real slots so production agent_caps state is untouched. */
	for (i = 0; i < TEST_NR_AGENTS; i++) {
		ctx->saved[i] = agent_caps[TEST_BASE_AGENT + i];
		memset(&agent_caps[TEST_BASE_AGENT + i], 0,
		       sizeof(agent_caps[0]));
	}

	return 0;
}

static void cap_life_test_exit(struct kunit *test)
{
	struct cap_life_ctx *ctx = test->priv;
	unsigned int i;

	if (!ctx)
		return;

	for (i = 0; i < TEST_NR_AGENTS; i++)
		agent_caps[TEST_BASE_AGENT + i] = ctx->saved[i];
}

static __u64 life_badge(__u16 perms)
{
	return AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_TAG, perms);
}

static int life_register(__u32 agent, __u16 perms)
{
	return airy_cap_register(agent, life_badge(perms));
}

/* ─── Registration ─────────────────────────────────────────────────────── */

static void register_badge_live_test(struct kunit *test)
{
	struct airy_cap_slot *slot = &agent_caps[TEST_ROOT_AGENT];
	__u64 badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	badge = slot->badge;

	/* Both validation paths accept the badge the slot was built from. */
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(badge, TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_check(TEST_ROOT_AGENT, TEST_PERMS));

	/* A permission the badge never carried is refused, not forged. */
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
		airy_cap_badge_ok(badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_KILL));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
		airy_cap_check(TEST_ROOT_AGENT, AIRY_CAP_PERM_KILL));
}

/* ─── REVOKE ───────────────────────────────────────────────────────────── */

static void revoke_kills_subtree_test(struct kunit *test)
{
	struct airy_cap_slot *root = &agent_caps[TEST_ROOT_AGENT];
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	__u64 root_badge, child_badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, TEST_CHILD_AGENT,
				AIRY_CAP_OP_COPY, 0));
	root_badge = root->badge;
	child_badge = child->badge;

	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, 0,
				AIRY_CAP_OP_REVOKE, 0));

	/* The cascading revoke bumps epoch and clears the random tag. */
	KUNIT_EXPECT_EQ(test, (__u16)(TEST_EPOCH + 1), root->epoch);
	KUNIT_EXPECT_EQ(test, (__u16)(TEST_EPOCH + 1), child->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)0, root->randtag);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->randtag);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_badge_ok(root_badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_badge_ok(child_badge, TEST_CHILD_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_check(TEST_ROOT_AGENT, AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_check(TEST_CHILD_AGENT, AIRY_CAP_PERM_SEND));
}

/* ─── ROTATE ───────────────────────────────────────────────────────────── */

static void rotate_stales_old_tag_test(struct kunit *test)
{
	struct airy_cap_slot *slot = &agent_caps[TEST_ROOT_AGENT];
	__u64 old_badge, new_badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	old_badge = slot->badge;

	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, 0,
				AIRY_CAP_OP_ROTATE, 0));
	new_badge = slot->badge;

	/* Only the random tag changes: epoch and permissions survive. */
	KUNIT_EXPECT_NE(test, (unsigned long long)old_badge,
			(unsigned long long)new_badge);
	KUNIT_EXPECT_EQ(test, (__u16)TEST_EPOCH, slot->epoch);
	KUNIT_EXPECT_EQ(test, (__u16)TEST_PERMS, slot->perms);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
		airy_cap_badge_ok(old_badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(new_badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_check(TEST_ROOT_AGENT, TEST_PERMS));
}

/* ─── UNREG ────────────────────────────────────────────────────────────── */

static void unreg_kills_child_test(struct kunit *test)
{
	struct airy_cap_slot *root = &agent_caps[TEST_ROOT_AGENT];
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	__u64 child_badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, TEST_CHILD_AGENT,
				AIRY_CAP_OP_COPY, 0));
	child_badge = child->badge;

	airy_cap_unreg(TEST_ROOT_AGENT);

	/* The terminating agent loses its slot outright. */
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)root->badge);
	KUNIT_EXPECT_EQ(test, (__u32)0, root->agent_id);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
		airy_cap_check(TEST_ROOT_AGENT, TEST_PERMS));

	/*
	 * Its revocable child keeps the slot but loses the authority
	 * and is promoted to an MDB root before the index is recycled.
	 */
	KUNIT_EXPECT_EQ(test, (__u16)(TEST_EPOCH + 1), child->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->randtag);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->parent_agent);
	KUNIT_EXPECT_EQ(test, (__u16)0, child->generation);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_badge_ok(child_badge, TEST_CHILD_AGENT,
				  AIRY_CAP_PERM_SEND));

	KUNIT_EXPECT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
}

/* ─── DELETE ───────────────────────────────────────────────────────────── */

static void delete_recycles_slot_test(struct kunit *test)
{
	struct airy_cap_slot *root = &agent_caps[TEST_ROOT_AGENT];
	struct airy_cap_slot *child = &agent_caps[TEST_CHILD_AGENT];
	__u64 root_badge, child_badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, TEST_CHILD_AGENT,
				AIRY_CAP_OP_COPY, 0));
	root_badge = root->badge;
	child_badge = child->badge;

	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, 0,
				AIRY_CAP_OP_DELETE, 0));

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_badge_ok(root_badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
		airy_cap_check(TEST_ROOT_AGENT, TEST_PERMS));

	/* DELETE does not cascade: the child survives as a valid root. */
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(child_badge, TEST_CHILD_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, (__u16)TEST_EPOCH, child->epoch);
	KUNIT_EXPECT_EQ(test, (__u32)0, child->parent_agent);
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_check(TEST_CHILD_AGENT, TEST_PERMS));

	KUNIT_EXPECT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
}

/* ─── LOOKUP ───────────────────────────────────────────────────────────── */

static void lookup_slot_contract_test(struct kunit *test)
{
	/* The sentinel, an out-of-range ID and an empty slot are absent. */
	KUNIT_EXPECT_PTR_EQ(test, NULL, airy_cap_lookup(0));
	KUNIT_EXPECT_PTR_EQ(test, NULL,
			    airy_cap_lookup(AIRY_CAP_MAX_AGENTS));
	KUNIT_EXPECT_PTR_EQ(test, NULL, airy_cap_lookup(TEST_SPARE_AGENT));

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_EXPECT_PTR_EQ(test, &agent_caps[TEST_ROOT_AGENT],
			    airy_cap_lookup(TEST_ROOT_AGENT));
}

/* ─── MOVE ─────────────────────────────────────────────────────────────── */

static void move_rebinds_badge_test(struct kunit *test)
{
	struct airy_cap_slot *src = &agent_caps[TEST_ROOT_AGENT];
	struct airy_cap_slot *dst = &agent_caps[TEST_DST_AGENT];
	__u64 badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	badge = src->badge;

	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, TEST_DST_AGENT,
				AIRY_CAP_OP_MOVE, 0));

	/*
	 * The badge text is unchanged but its binding moves: it becomes
	 * stale for the source index and valid for the destination.
	 */
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_CAP_NULL,
			(unsigned long long)src->badge);
	KUNIT_EXPECT_EQ(test, badge, dst->badge);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
		airy_cap_badge_ok(badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(badge, TEST_DST_AGENT,
				  AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
		airy_cap_check(TEST_ROOT_AGENT, TEST_PERMS));
	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_check(TEST_DST_AGENT, TEST_PERMS));
}

/* ─── MUTATE ───────────────────────────────────────────────────────────── */

static void mutate_shrinks_perms_test(struct kunit *test)
{
	struct airy_cap_slot *slot = &agent_caps[TEST_ROOT_AGENT];
	__u16 shrunk = AIRY_CAP_PERM_SEND;
	__u64 old_badge;

	KUNIT_ASSERT_EQ(test, 0, life_register(TEST_ROOT_AGENT, TEST_PERMS));
	old_badge = slot->badge;

	KUNIT_ASSERT_EQ(test, 0,
		airy_cap_derive(TEST_ROOT_AGENT, 0,
				AIRY_CAP_OP_MUTATE, shrunk));

	/* MUTATE rewrites badge and perms; epoch and tag are preserved. */
	KUNIT_EXPECT_EQ(test, (unsigned long long)AIRY_BADGE_EPOCH(old_badge),
			(unsigned long long)AIRY_BADGE_EPOCH(slot->badge));
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)AIRY_BADGE_RANDTAG(old_badge),
			(unsigned long long)AIRY_BADGE_RANDTAG(slot->badge));
	KUNIT_EXPECT_EQ(test, (__u16)shrunk, slot->perms);
	KUNIT_EXPECT_EQ(test, (unsigned long long)life_badge(shrunk),
			(unsigned long long)slot->badge);

	KUNIT_EXPECT_EQ(test, 0,
		airy_cap_badge_ok(slot->badge, TEST_ROOT_AGENT, shrunk));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
		airy_cap_badge_ok(slot->badge, TEST_ROOT_AGENT,
				  AIRY_CAP_PERM_RECV));
	KUNIT_EXPECT_EQ(test, 0, airy_cap_check(TEST_ROOT_AGENT, shrunk));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
		airy_cap_check(TEST_ROOT_AGENT, AIRY_CAP_PERM_RECV));
}

static struct kunit_case airy_cap_lifecycle_cases[] = {
	KUNIT_CASE(register_badge_live_test),
	KUNIT_CASE(revoke_kills_subtree_test),
	KUNIT_CASE(rotate_stales_old_tag_test),
	KUNIT_CASE(unreg_kills_child_test),
	KUNIT_CASE(delete_recycles_slot_test),
	KUNIT_CASE(lookup_slot_contract_test),
	KUNIT_CASE(move_rebinds_badge_test),
	KUNIT_CASE(mutate_shrinks_perms_test),
	{}
};

static struct kunit_suite airy_cap_lifecycle_suite = {
	.name = "airy_cap_lifecycle",
	.init = cap_life_test_init,
	.exit = cap_life_test_exit,
	.test_cases = airy_cap_lifecycle_cases,
};

kunit_test_suites(&airy_cap_lifecycle_suite);

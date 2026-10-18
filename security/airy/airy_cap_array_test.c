// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_array_test.c — KUnit coverage for capability slot registration.
 *
 * Pins the index contract of airy_cap_register(): agent 0 is the MDB
 * unbound sentinel and must be rejected without touching the slot,
 * out-of-range IDs must report overflow, and an occupied slot must
 * report EEXIST without overwriting the badge it already holds.  A
 * successful registration is checked to decode the badge into the
 * per-slot fields the fastpath compares against.
 *
 * The suite snapshots the probe slots and empties them, so it neither
 * depends on nor disturbs production capability state.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/types.h>

#include "airy_cap.h"

#define TEST_UNBOUND_AGENT	0u
#define TEST_BASE_AGENT		1021u
#define TEST_NR_AGENTS		2

#define TEST_EPOCH		3u
#define TEST_RANDTAG		0x5A5A5A5Au
#define TEST_PERMS		(AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV)

struct cap_array_ctx {
	struct airy_cap_slot saved[TEST_NR_AGENTS];
};

static struct airy_cap_slot *probe_slot(unsigned int i)
{
	return &agent_caps[TEST_BASE_AGENT + i];
}

static int cap_array_test_init(struct kunit *test)
{
	struct cap_array_ctx *ctx;
	unsigned int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	for (i = 0; i < TEST_NR_AGENTS; i++) {
		ctx->saved[i] = *probe_slot(i);
		memset(probe_slot(i), 0, sizeof(*probe_slot(i)));
	}

	return 0;
}

static void cap_array_test_exit(struct kunit *test)
{
	struct cap_array_ctx *ctx = test->priv;
	unsigned int i;

	if (!ctx)
		return;

	for (i = 0; i < TEST_NR_AGENTS; i++)
		*probe_slot(i) = ctx->saved[i];
}

/* ─── Registration index contract ─────────────────────────────────────── */

static void register_rejects_unbound_test(struct kunit *test)
{
	__u64 badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
					 AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_cap_register(TEST_UNBOUND_AGENT, badge));

	/* The sentinel slot must stay empty: no partial write. */
	KUNIT_EXPECT_EQ(test, (__u64)AIRY_CAP_NULL,
			READ_ONCE(agent_caps[TEST_UNBOUND_AGENT].badge));
	KUNIT_EXPECT_EQ(test, 0u,
			READ_ONCE(agent_caps[TEST_UNBOUND_AGENT].agent_id));
}

static void register_rejects_overflow_test(struct kunit *test)
{
	__u64 badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
					 AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_cap_register(AIRY_CAP_MAX_AGENTS, badge));
}

static void register_rejects_occupied_test(struct kunit *test)
{
	__u64 badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
					 AIRY_CAP_PERM_SEND);

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_BASE_AGENT, badge));
	KUNIT_EXPECT_EQ(test, -AIRY_EEXIST,
			airy_cap_register(TEST_BASE_AGENT, badge));
	KUNIT_EXPECT_EQ(test, badge,
			READ_ONCE(agent_caps[TEST_BASE_AGENT].badge));
}

static void register_decodes_badge_test(struct kunit *test)
{
	__u64 badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG, TEST_PERMS);
	struct airy_cap_slot *slot = probe_slot(1);

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_BASE_AGENT + 1, badge));

	KUNIT_EXPECT_EQ(test, badge, READ_ONCE(slot->badge));
	KUNIT_EXPECT_EQ(test, TEST_BASE_AGENT + 1, READ_ONCE(slot->agent_id));
	KUNIT_EXPECT_EQ(test, (__u16)TEST_PERMS, READ_ONCE(slot->perms));
	KUNIT_EXPECT_EQ(test, (__u32)TEST_RANDTAG, READ_ONCE(slot->randtag));
	KUNIT_EXPECT_EQ(test, (__u16)TEST_EPOCH, READ_ONCE(slot->epoch));
}

static struct kunit_case cap_array_cases[] = {
	KUNIT_CASE(register_rejects_unbound_test),
	KUNIT_CASE(register_rejects_overflow_test),
	KUNIT_CASE(register_rejects_occupied_test),
	KUNIT_CASE(register_decodes_badge_test),
	{}
};

static struct kunit_suite cap_array_suite = {
	.name = "airy_cap_array",
	.init = cap_array_test_init,
	.exit = cap_array_test_exit,
	.test_cases = cap_array_cases,
};

kunit_test_suites(&cap_array_suite);

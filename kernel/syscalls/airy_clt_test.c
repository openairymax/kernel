// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_clt_test.c — KUnit coverage for the syscall 551 phase record
 * defined in airy_clt.c.
 *
 * The record is pure kernel state with no dependency on current and no
 * caller-owned lock, so the suite drives the 551 entry airy_clt_serve()
 * and its write half airy_clt_notify() directly, observing both through
 * airy_clt_query(). It checks the boundary contract: every [SC]
 * CoreLoopThree phase is accepted as notified without transition
 * ordering, the reserved operation space is refused fail-closed before
 * the identity is examined, a negative identity is refused with -EINVAL,
 * and an out-of-table identity is refused with -AIRY_ECAP_OVERFLOW.
 *
 * One reserved slot is parked for the run and restored on exit so the
 * suite leaves the table exactly as it found it.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>

#include "airy_clt.h"

/*
 * The record is only reachable through the 551 API, so the suite parks
 * the last agent slot (1023) — not claimed by any other suite — and
 * restores its live value on exit.
 */
#define AIRY_CLT_TEST_AGENT	1023u

struct airy_clt_ctx {
	__u32 saved_phase;
};

static int airy_clt_test_init(struct kunit *test)
{
	struct airy_clt_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &ctx->saved_phase));

	return 0;
}

static void airy_clt_test_exit(struct kunit *test)
{
	struct airy_clt_ctx *ctx = test->priv;

	if (!ctx)
		return;

	/* The parked slot holds a valid phase, so the restore must succeed. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_clt_notify(AIRY_CLT_TEST_AGENT, ctx->saved_phase));
}

static void airy_clt_initial_unset_test(struct kunit *test)
{
	__u32 phase = 0;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &phase));

	/* A slot nothing has notified must never read as AIRY_COG_PERCEPT. */
	KUNIT_EXPECT_EQ(test, AIRY_CLT_PHASE_UNSET, phase);
}

static void airy_clt_phase_accept_test(struct kunit *test)
{
	unsigned int phase;

	/*
	 * Every [SC] phase round-trips, and the classifier agrees the value
	 * belongs to the phase half of the 551 argument. Scanning the space
	 * keeps the record and airy_clt_kind() in step as the enum grows.
	 */
	for (phase = 0; phase < AIRY_COG_PHASE_MAX; phase++) {
		__u32 out = AIRY_CLT_PHASE_UNSET;

		KUNIT_ASSERT_EQ_MSG(test, AIRY_CLT_CLASS_PHASE,
				    airy_clt_kind(phase),
				    "phase %u not classified PHASE", phase);
		KUNIT_ASSERT_EQ_MSG(test, AIRY_EOK,
				    airy_clt_notify(AIRY_CLT_TEST_AGENT, phase),
				    "phase %u refused", phase);
		KUNIT_ASSERT_EQ(test, AIRY_EOK,
				airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
		KUNIT_EXPECT_EQ_MSG(test, phase, out,
				    "phase %u not echoed", phase);
	}
}

static void airy_clt_phase_order_free_test(struct kunit *test)
{
	__u32 out = 0;

	/*
	 * The CoreLoopThree sequence belongs to the module F kthread, not to
	 * this table, so a backwards or skipped step must still be recorded
	 * as notified rather than refused here.
	 */
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_notify(AIRY_CLT_TEST_AGENT, AIRY_COG_ACT));
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_ACT, out);

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_notify(AIRY_CLT_TEST_AGENT, AIRY_COG_PERCEPT));
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_PERCEPT, out);
}

static void airy_clt_reserved_kind_test(struct kunit *test)
{
	/* The kthread-class space module F owns is never a phase. */
	KUNIT_EXPECT_EQ(test, AIRY_CLT_CLASS_RESERVED,
			airy_clt_kind(AIRY_COG_PHASE_MAX));
	KUNIT_EXPECT_EQ(test, AIRY_CLT_CLASS_RESERVED,
			airy_clt_kind(AIRY_COG_PHASE_MAX + 1u));
	KUNIT_EXPECT_EQ(test, AIRY_CLT_CLASS_RESERVED,
			airy_clt_kind(0xffffffffu));
}

static void airy_clt_notify_reject_test(struct kunit *test)
{
	__u32 out = AIRY_CLT_PHASE_UNSET;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_notify(AIRY_CLT_TEST_AGENT, AIRY_COG_THINK));

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_clt_notify(-1, AIRY_COG_THINK));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_clt_notify(AIRY_CAP_MAX_AGENTS, AIRY_COG_THINK));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_clt_notify(AIRY_CAP_MAX_AGENTS + 100,
					AIRY_COG_THINK));

	/* A refused notification must leave the parked slot untouched. */
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_THINK, out);
}

static void airy_clt_notify_last_agent_test(struct kunit *test)
{
	__u32 out = 0;

	/* The ceiling is inclusive: MAX_AGENTS - 1 is a live identity. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_clt_notify(AIRY_CAP_MAX_AGENTS - 1,
					AIRY_COG_ACT));
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CAP_MAX_AGENTS - 1, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_ACT, out);
}

static void airy_clt_query_reject_test(struct kunit *test)
{
	__u32 out = AIRY_CLT_PHASE_UNSET;

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_clt_query(AIRY_CLT_TEST_AGENT, NULL));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_clt_query(-1, &out));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_clt_query(AIRY_CAP_MAX_AGENTS, &out));

	/* @phase is written only on success. */
	KUNIT_EXPECT_EQ(test, AIRY_CLT_PHASE_UNSET, out);
}

static void airy_clt_serve_phase_test(struct kunit *test)
{
	__u32 out = AIRY_CLT_PHASE_UNSET;

	/* The entry decision accepts every [SC] phase and records it. */
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_serve(AIRY_CLT_TEST_AGENT, AIRY_COG_THINK));
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_THINK, out);
}

static void airy_clt_serve_reserved_test(struct kunit *test)
{
	__u32 out = AIRY_CLT_PHASE_UNSET;

	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_serve(AIRY_CLT_TEST_AGENT, AIRY_COG_ACT));

	/* A reserved kthread-class op is refused, never recorded. */
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_clt_serve(AIRY_CLT_TEST_AGENT, AIRY_COG_PHASE_MAX));
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_clt_serve(AIRY_CLT_TEST_AGENT, 0xffffffffu));

	/* The refused op must leave the parked slot untouched. */
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_clt_query(AIRY_CLT_TEST_AGENT, &out));
	KUNIT_EXPECT_EQ(test, AIRY_COG_ACT, out);
}

static void airy_clt_serve_identity_test(struct kunit *test)
{
	/* A phase op still carries the notify identity contract. */
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_clt_serve(-1, AIRY_COG_PERCEPT));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_clt_serve(AIRY_CAP_MAX_AGENTS, AIRY_COG_PERCEPT));
}

static void airy_clt_serve_priority_test(struct kunit *test)
{
	/*
	 * Fail-closed ordering: the phase space is classified before the
	 * identity is examined, so a reserved op with an invalid identity
	 * answers -AIRY_ECOG_PHASE rather than the identity error.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_clt_serve(-1, AIRY_COG_PHASE_MAX));
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_clt_serve(AIRY_CAP_MAX_AGENTS, AIRY_COG_PHASE_MAX));
}

static struct kunit_case airy_clt_cases[] = {
	KUNIT_CASE(airy_clt_initial_unset_test),
	KUNIT_CASE(airy_clt_phase_accept_test),
	KUNIT_CASE(airy_clt_phase_order_free_test),
	KUNIT_CASE(airy_clt_reserved_kind_test),
	KUNIT_CASE(airy_clt_notify_reject_test),
	KUNIT_CASE(airy_clt_notify_last_agent_test),
	KUNIT_CASE(airy_clt_query_reject_test),
	KUNIT_CASE(airy_clt_serve_phase_test),
	KUNIT_CASE(airy_clt_serve_reserved_test),
	KUNIT_CASE(airy_clt_serve_identity_test),
	KUNIT_CASE(airy_clt_serve_priority_test),
	{}
};

static struct kunit_suite airy_clt_suite = {
	.name = "airy_clt_syscall_551",
	.init = airy_clt_test_init,
	.exit = airy_clt_test_exit,
	.test_cases = airy_clt_cases,
};

kunit_test_suites(&airy_clt_suite);

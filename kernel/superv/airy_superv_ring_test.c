// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_ring_test.c — KUnit coverage for the supervisor-driven
 * ring state transitions implemented in airy_superv_ring.c.
 *
 * Pins the error precedence (malformed target before readiness), the
 * readiness gate, the miss path that reports -AIRY_EIPC_CONTEXT, the
 * hit path that freezes or thaws current's ring, and the thaw rule
 * that retires every badge only when a ring actually reopens.  Cases
 * bind current's own security blob to a test agent and restore it
 * afterwards, so no task lookup helper and no live supervisor are
 * needed.
 */

#include <kunit/test.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define SV_TEST_AGENT	1021u

struct sv_fix {
	__u32 saved_id;
	void *saved_ring;
	struct airy_ipc_ring_freeze_state *ring;
};

static struct airy_task_sec *sv_tsec(void)
{
	return current->security + airy_blob_sizes.lbs_task;
}

static void sv_fix_begin(struct kunit *test, struct sv_fix *fix)
{
	struct airy_task_sec *sec = sv_tsec();

	fix->saved_id = sec->agent_id;
	fix->saved_ring = sec->ipc_ring;
	fix->ring = kzalloc(sizeof(*fix->ring), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fix->ring);
}

static void sv_fix_end(struct sv_fix *fix)
{
	struct airy_task_sec *sec = sv_tsec();

	sec->agent_id = fix->saved_id;
	sec->ipc_ring = fix->saved_ring;
	kfree(fix->ring);
}

static void sv_freeze_arg(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_freeze(&ctx, 0, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_freeze(&ctx, AIRY_CAP_MAX_AGENTS, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_freeze(&ctx, AIRY_CAP_MAX_AGENTS + 1, 0));
}

static void sv_freeze_gate(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec = sv_tsec();
	__u32 saved_id = sec->agent_id;

	sec->agent_id = 0;
	memset(&ctx, 0, sizeof(ctx));

	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_sv_freeze(NULL, 1, 0));
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_sv_freeze(&ctx, 1, 0));

	KUNIT_EXPECT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT, airy_sv_freeze(&ctx, 1, 0));

	sec->agent_id = saved_id;
}

static void sv_freeze_miss(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec = sv_tsec();
	__u32 saved_id = sec->agent_id;

	sec->agent_id = 0;
	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT,
			airy_sv_freeze(&ctx, SV_TEST_AGENT,
				       AIRY_FAULT_ABNORMAL_CAP));

	sec->agent_id = saved_id;
}

static void sv_freeze_hit(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec;
	struct sv_fix fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	sv_fix_begin(test, &fix);
	sec = sv_tsec();
	sec->agent_id = SV_TEST_AGENT;
	sec->ipc_ring = fix.ring;

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_freeze(&ctx, SV_TEST_AGENT,
				       AIRY_FAULT_ABNORMAL_CAP));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(fix.ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_ABNORMAL_CAP,
			fix.ring->freeze_reason);
	KUNIT_EXPECT_NE(test, 0, fix.ring->freeze_timestamp);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_fastpath_check(fix.ring));

	sv_fix_end(&fix);
}

static void sv_freeze_idem(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec;
	struct sv_fix fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	sv_fix_begin(test, &fix);
	sec = sv_tsec();
	sec->agent_id = SV_TEST_AGENT;
	sec->ipc_ring = fix.ring;

	KUNIT_EXPECT_EQ(test, 0, airy_sv_freeze(&ctx, SV_TEST_AGENT,
					       AIRY_FAULT_CAP_FORGED));
	KUNIT_EXPECT_EQ(test, 0, airy_sv_freeze(&ctx, SV_TEST_AGENT,
					       AIRY_FAULT_CAP_FORGED));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(fix.ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED, fix.ring->freeze_reason);

	sv_fix_end(&fix);
}

static void sv_thaw_arg(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_thaw(&ctx, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_thaw(&ctx, AIRY_CAP_MAX_AGENTS));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_thaw(&ctx, AIRY_CAP_MAX_AGENTS + 1));
}

static void sv_thaw_gate(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec = sv_tsec();
	__u32 saved_id = sec->agent_id;

	sec->agent_id = 0;
	memset(&ctx, 0, sizeof(ctx));

	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_sv_thaw(NULL, 1));
	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_sv_thaw(&ctx, 1));

	KUNIT_EXPECT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT, airy_sv_thaw(&ctx, 1));

	sec->agent_id = saved_id;
}

static void sv_thaw_miss(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec = sv_tsec();
	__u32 saved_id = sec->agent_id;
	int epoch;

	sec->agent_id = 0;
	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	epoch = atomic_read(&airy_cap_global_epoch);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT,
			airy_sv_thaw(&ctx, SV_TEST_AGENT));

	/*
	 * A command that names no ring must not retire the badges of the
	 * whole system; the probe pass exists for exactly this case.
	 */
	KUNIT_EXPECT_EQ(test, epoch, atomic_read(&airy_cap_global_epoch));

	sec->agent_id = saved_id;
}

static void sv_thaw_live(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec;
	struct sv_fix fix;
	int epoch;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	sv_fix_begin(test, &fix);
	sec = sv_tsec();
	sec->agent_id = SV_TEST_AGENT;
	sec->ipc_ring = fix.ring;

	epoch = atomic_read(&airy_cap_global_epoch);
	KUNIT_EXPECT_EQ(test, 0, airy_sv_thaw(&ctx, SV_TEST_AGENT));
	KUNIT_EXPECT_FALSE(test, READ_ONCE(fix.ring->frozen));
	KUNIT_EXPECT_EQ(test, epoch, atomic_read(&airy_cap_global_epoch));

	sv_fix_end(&fix);
}

static void sv_thaw_hit(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec;
	struct sv_fix fix;
	int epoch;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	sv_fix_begin(test, &fix);
	sec = sv_tsec();
	sec->agent_id = SV_TEST_AGENT;
	sec->ipc_ring = fix.ring;

	KUNIT_ASSERT_EQ(test, 0, airy_sv_freeze(&ctx, SV_TEST_AGENT,
					       AIRY_FAULT_RING_CORRUPT));
	epoch = atomic_read(&airy_cap_global_epoch);

	KUNIT_EXPECT_EQ(test, 0, airy_sv_thaw(&ctx, SV_TEST_AGENT));
	KUNIT_EXPECT_FALSE(test, READ_ONCE(fix.ring->frozen));
	KUNIT_EXPECT_EQ(test, 0, fix.ring->freeze_reason);
	KUNIT_EXPECT_EQ(test, 0, fix.ring->freeze_timestamp);
	KUNIT_EXPECT_EQ(test, 0, airy_ipc_fastpath_check(fix.ring));
	KUNIT_EXPECT_EQ(test, epoch + 1, atomic_read(&airy_cap_global_epoch));

	sv_fix_end(&fix);
}

static void sv_thaw_idem(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct airy_task_sec *sec;
	struct sv_fix fix;
	int epoch;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	sv_fix_begin(test, &fix);
	sec = sv_tsec();
	sec->agent_id = SV_TEST_AGENT;
	sec->ipc_ring = fix.ring;

	KUNIT_ASSERT_EQ(test, 0, airy_sv_freeze(&ctx, SV_TEST_AGENT,
					       AIRY_FAULT_TIMEOUT));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_thaw(&ctx, SV_TEST_AGENT));
	epoch = atomic_read(&airy_cap_global_epoch);

	KUNIT_EXPECT_EQ(test, 0, airy_sv_thaw(&ctx, SV_TEST_AGENT));
	KUNIT_EXPECT_EQ(test, epoch, atomic_read(&airy_cap_global_epoch));

	sv_fix_end(&fix);
}

static struct kunit_case airy_sv_ring_cases[] = {
	KUNIT_CASE(sv_freeze_arg),
	KUNIT_CASE(sv_freeze_gate),
	KUNIT_CASE(sv_freeze_miss),
	KUNIT_CASE(sv_freeze_hit),
	KUNIT_CASE(sv_freeze_idem),
	KUNIT_CASE(sv_thaw_arg),
	KUNIT_CASE(sv_thaw_gate),
	KUNIT_CASE(sv_thaw_miss),
	KUNIT_CASE(sv_thaw_live),
	KUNIT_CASE(sv_thaw_hit),
	KUNIT_CASE(sv_thaw_idem),
	{}
};

static struct kunit_suite airy_sv_ring_suite = {
	.name = "airy_sv_ring",
	.test_cases = airy_sv_ring_cases,
};

kunit_test_suites(&airy_sv_ring_suite);

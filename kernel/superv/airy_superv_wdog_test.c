// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_wdog_test.c — KUnit coverage for the macro_d liveness
 * guard implemented in airy_superv_wdog.c.
 *
 * Pins the arming rule (a system that never ran macro_d is never
 * contained), the strict deadline, the latch that makes containment
 * happen once per loss, the rearm on a fresh pulse, the disarm on
 * reset, and the containment itself: every supervised ring frozen,
 * every badge retired and the fault reported.  Timestamps are injected
 * through airy_wdog_at(), so no case waits for a real timeout.
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

#define SV_WA		1022u
#define SV_WBASE	1000000000ULL

struct sv_wdog_fix {
	__u32 saved_id;
	void *saved_ring;
	struct airy_cap_slot saved;
	struct airy_ipc_ring_freeze_state *ring;
};

static struct airy_task_sec *sv_wsec(void)
{
	return current->security + airy_blob_sizes.lbs_task;
}

static int sv_wdog_init(struct kunit *test)
{
	struct sv_wdog_fix *fix;
	struct airy_task_sec *sec = sv_wsec();

	fix = kunit_kzalloc(test, sizeof(*fix), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fix);

	fix->ring = kzalloc(sizeof(*fix->ring), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fix->ring);

	fix->saved_id = sec->agent_id;
	fix->saved_ring = sec->ipc_ring;
	fix->saved = agent_caps[SV_WA];

	sec->agent_id = SV_WA;
	sec->ipc_ring = fix->ring;
	test->priv = fix;

	airy_wdog_reset();
	airy_fev_reset();

	return 0;
}

static void sv_wdog_exit(struct kunit *test)
{
	struct sv_wdog_fix *fix = test->priv;
	struct airy_task_sec *sec = sv_wsec();

	if (!fix)
		return;

	airy_wdog_reset();

	sec->agent_id = fix->saved_id;
	sec->ipc_ring = fix->saved_ring;
	agent_caps[SV_WA] = fix->saved;
	kfree(fix->ring);
}

static bool sv_fev_has(__u32 code)
{
	struct airy_fault_event ev;

	while (!airy_fev_fetch(&ev)) {
		if (ev.fault_code == code && !ev.agent_id)
			return true;
	}

	return false;
}

static void sv_wdog_off(struct kunit *test)
{
	__u64 at = SV_WBASE + 100 * AIRY_WDOG_TMO_NS;

	KUNIT_EXPECT_FALSE(test, airy_wdog_late(at));
	KUNIT_EXPECT_FALSE(test, airy_wdog_fire(at));
}

static void sv_wdog_edge(struct kunit *test)
{
	airy_wdog_at(SV_WBASE);

	KUNIT_EXPECT_FALSE(test, airy_wdog_late(SV_WBASE));
	KUNIT_EXPECT_FALSE(test, airy_wdog_late(SV_WBASE + AIRY_WDOG_TMO_NS));
	KUNIT_EXPECT_TRUE(test,
			  airy_wdog_late(SV_WBASE + AIRY_WDOG_TMO_NS + 1));
}

static void sv_wdog_latch(struct kunit *test)
{
	__u64 late_at = SV_WBASE + AIRY_WDOG_TMO_NS + 1;
	__u64 next = late_at + AIRY_WDOG_TMO_NS + 1;

	airy_wdog_at(SV_WBASE);

	KUNIT_EXPECT_TRUE(test, airy_wdog_fire(late_at));
	KUNIT_EXPECT_FALSE(test, airy_wdog_late(late_at));
	KUNIT_EXPECT_FALSE(test, airy_wdog_fire(late_at));

	airy_wdog_at(late_at);
	KUNIT_EXPECT_FALSE(test, airy_wdog_late(late_at));

	airy_wdog_at(next);
	KUNIT_EXPECT_FALSE(test,
			   airy_wdog_late(next + AIRY_WDOG_TMO_NS));
}

static void sv_wdog_reset_case(struct kunit *test)
{
	__u64 late_at = SV_WBASE + AIRY_WDOG_TMO_NS + 1;

	airy_wdog_at(SV_WBASE);
	KUNIT_EXPECT_TRUE(test, airy_wdog_late(late_at));

	airy_wdog_reset();

	KUNIT_EXPECT_FALSE(test, airy_wdog_late(late_at));
	KUNIT_EXPECT_FALSE(test, airy_wdog_fire(late_at));
}

static void sv_wdog_hit(struct kunit *test)
{
	struct sv_wdog_fix *fix = test->priv;
	int epoch = atomic_read(&airy_cap_global_epoch);

	airy_wdog_at(SV_WBASE);
	KUNIT_EXPECT_TRUE(test,
			  airy_wdog_fire(SV_WBASE + AIRY_WDOG_TMO_NS + 1));

	KUNIT_EXPECT_TRUE(test, READ_ONCE(fix->ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_DOUBLE_FAULT,
			READ_ONCE(fix->ring->freeze_reason));
	KUNIT_EXPECT_EQ(test, epoch + 1, atomic_read(&airy_cap_global_epoch));
	KUNIT_EXPECT_TRUE(test, sv_fev_has(AIRY_FAULT_DOUBLE_FAULT));
}

static void sv_wdog_all(struct kunit *test)
{
	struct sv_wdog_fix *fix = test->priv;

	KUNIT_EXPECT_EQ(test, 0, airy_sv_frz_all(AIRY_FAULT_DOUBLE_FAULT));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(fix->ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_DOUBLE_FAULT,
			READ_ONCE(fix->ring->freeze_reason));
}

static struct kunit_case airy_sv_wdog_cases[] = {
	KUNIT_CASE(sv_wdog_off),
	KUNIT_CASE(sv_wdog_edge),
	KUNIT_CASE(sv_wdog_latch),
	KUNIT_CASE(sv_wdog_reset_case),
	KUNIT_CASE(sv_wdog_hit),
	KUNIT_CASE(sv_wdog_all),
	{}
};

static struct kunit_suite airy_sv_wdog_suite = {
	.name = "airy_sv_wdog",
	.init = sv_wdog_init,
	.exit = sv_wdog_exit,
	.test_cases = airy_sv_wdog_cases,
};

kunit_test_suites(&airy_sv_wdog_suite);

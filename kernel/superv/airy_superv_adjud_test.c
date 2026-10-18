// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_adjud_test.c — KUnit coverage for the verdict executor
 * implemented in airy_superv_adjud.c.
 *
 * Pins the argument precedence, the readiness gate, the miss path and
 * the state each verdict leaves in the security blob.  A kthread
 * stands in for an agent task so the cases observe real task state;
 * they assert on the blob, the nice value and the ring, never on the
 * thread's scheduling state, because a kernel thread never enters the
 * stopped state a user task would.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/sched.h>
#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define SV_TEST_AGENT	1014u

struct sv_adjud_fix {
	struct task_struct *worker;
	struct airy_task_sec *sec;
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_cap_slot saved;
};

static int sv_worker(void *arg)
{
	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
	}

	return 0;
}

/*
 * sv_fix_free - detach the fixture from the worker, then reap it.
 *
 * The blob is cleared before kthread_stop(): do_exit() runs
 * security_task_free(), which would otherwise release the ring and the
 * capability slot a second time.
 */
static void sv_fix_free(void *data)
{
	struct sv_adjud_fix *fix = data;

	fix->sec->agent_id = 0;
	fix->sec->agent_state = AIRY_AGENT_INACTIVE;
	fix->sec->ipc_ring = NULL;
	if (fix->worker)
		kthread_stop(fix->worker);
	kfree(fix->ring);
	agent_caps[SV_TEST_AGENT] = fix->saved;
}

static int sv_fix_new(struct kunit *test, struct sv_adjud_fix **out)
{
	struct sv_adjud_fix *fix;
	int ret;

	fix = kunit_kzalloc(test, sizeof(*fix), GFP_KERNEL);
	if (!fix)
		return -ENOMEM;

	fix->ring = kzalloc(sizeof(*fix->ring), GFP_KERNEL);
	if (!fix->ring)
		return -ENOMEM;

	fix->worker = kthread_create(sv_worker, NULL, "airy_sv_adjud");
	if (IS_ERR(fix->worker)) {
		ret = PTR_ERR(fix->worker);
		fix->worker = NULL;
		kfree(fix->ring);
		return ret;
	}

	fix->sec = fix->worker->security + airy_blob_sizes.lbs_task;
	fix->saved = agent_caps[SV_TEST_AGENT];
	memset(&agent_caps[SV_TEST_AGENT], 0, sizeof(agent_caps[0]));

	ret = kunit_add_action_or_reset(test, sv_fix_free, fix);
	if (ret)
		return ret;

	*out = fix;
	return 0;
}

static void sv_fix_bind(struct sv_adjud_fix *fix)
{
	fix->sec->agent_id = SV_TEST_AGENT;
	fix->sec->ipc_ring = fix->ring;
}

static void sv_adjud_arg(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_sv_adjud(&ctx, 0, AIRY_ADJUD_WARN, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_adjud(&ctx, AIRY_CAP_MAX_AGENTS,
				      AIRY_ADJUD_WARN, 0));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_sv_adjud(&ctx, SV_TEST_AGENT, AIRY_ADJUD_NR, 0));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_NR + 1u, 0));
}

static void sv_adjud_gate(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			airy_sv_adjud(NULL, SV_TEST_AGENT,
				      AIRY_ADJUD_WARN, 0));
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_WARN, 0));
}

static void sv_adjud_miss(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_WARN, 0));
}

static void sv_adjud_warn(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_WARN, AIRY_FAULT_TIMEOUT));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_INACTIVE,
			READ_ONCE(fix->sec->agent_state));
	KUNIT_EXPECT_EQ(test, 0, task_nice(fix->worker));
}

static void sv_adjud_degrade(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_DEGRADE, AIRY_FAULT_TIMEOUT));
	KUNIT_EXPECT_EQ(test, MAX_NICE, task_nice(fix->worker));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_INACTIVE,
			READ_ONCE(fix->sec->agent_state));
}

static void sv_adjud_pause(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_PAUSE, AIRY_FAULT_TIMEOUT));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_STOPPED,
			READ_ONCE(fix->sec->agent_state));
}

static void sv_adjud_resume(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_ASSERT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_PAUSE, AIRY_FAULT_TIMEOUT));
	KUNIT_ASSERT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_DEGRADE, AIRY_FAULT_TIMEOUT));

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_RESUME, 0));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_READY,
			READ_ONCE(fix->sec->agent_state));
	KUNIT_EXPECT_EQ(test, 0, task_nice(fix->worker));

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_RESUME, 0));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_READY,
			READ_ONCE(fix->sec->agent_state));
}

static void sv_adjud_resume_idle(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_ASSERT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_DEGRADE, AIRY_FAULT_TIMEOUT));

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_RESUME, 0));
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_INACTIVE,
			READ_ONCE(fix->sec->agent_state));
	KUNIT_EXPECT_EQ(test, 0, task_nice(fix->worker));
}

static void sv_adjud_terminate(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_ASSERT_EQ(test, 0,
			airy_cap_register(SV_TEST_AGENT,
					  AIRY_BADGE_COMPILE(0, 0x1234u,
							     AIRY_CAP_PERM_ALL)));

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_TERMINATE,
				      AIRY_FAULT_CAP_LEAK));
	KUNIT_EXPECT_EQ(test, AIRY_CAP_NULL,
			agent_caps[SV_TEST_AGENT].badge);
	KUNIT_EXPECT_TRUE(test, READ_ONCE(fix->ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_LEAK,
			fix->ring->freeze_reason);
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_DEAD,
			READ_ONCE(fix->sec->agent_state));
}

static void sv_adjud_term_idem(struct kunit *test)
{
	struct airy_sv_ctx ctx;
	struct sv_adjud_fix *fix;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_ASSERT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_ASSERT_EQ(test, 0, sv_fix_new(test, &fix));
	sv_fix_bind(fix);

	KUNIT_ASSERT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_TERMINATE,
				      AIRY_FAULT_CAP_FORGED));

	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_adjud(&ctx, SV_TEST_AGENT,
				      AIRY_ADJUD_TERMINATE,
				      AIRY_FAULT_CAP_FORGED));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED,
			fix->ring->freeze_reason);
	KUNIT_EXPECT_EQ(test, AIRY_AGENT_DEAD,
			READ_ONCE(fix->sec->agent_state));
}

static struct kunit_case airy_sv_adjud_cases[] = {
	KUNIT_CASE(sv_adjud_arg),
	KUNIT_CASE(sv_adjud_gate),
	KUNIT_CASE(sv_adjud_miss),
	KUNIT_CASE(sv_adjud_warn),
	KUNIT_CASE(sv_adjud_degrade),
	KUNIT_CASE(sv_adjud_pause),
	KUNIT_CASE(sv_adjud_resume),
	KUNIT_CASE(sv_adjud_resume_idle),
	KUNIT_CASE(sv_adjud_terminate),
	KUNIT_CASE(sv_adjud_term_idem),
	{}
};

static struct kunit_suite airy_sv_adjud_suite = {
	.name = "airy_sv_adjud",
	.test_cases = airy_sv_adjud_cases,
};

kunit_test_suites(&airy_sv_adjud_suite);

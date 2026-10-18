// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_exec_test.c — KUnit coverage for the [IND] command entry
 * implemented in airy_superv_exec.c.
 *
 * Pins the order in which the entry refuses a command (shape, gate,
 * authority), the fact that authority is read from current rather than
 * from the command, and the dispatch paths.  The suite binds
 * current's own security blob to a test agent and installs a matching
 * badge in the agent's capability slot, so no live supervisor, ring or
 * worker task is needed.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time64.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>
#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define SV_XA		1006u
#define SV_XMISS	1007u
#define SV_XTAG		0x0BADC0DEu
#define SV_XEPOCH	1u

struct sv_exec_fix {
	__u32 saved_id;
	void *saved_ring;
	struct airy_cap_slot saved;
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_sv_ctx ctx;
};

static struct airy_task_sec *sv_sec(void)
{
	return current->security + airy_blob_sizes.lbs_task;
}

static int sv_exec_init(struct kunit *test)
{
	struct sv_exec_fix *fix;
	struct airy_task_sec *sec = sv_sec();

	fix = kunit_kzalloc(test, sizeof(*fix), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fix);

	fix->ring = kzalloc(sizeof(*fix->ring), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fix->ring);

	fix->saved_id = sec->agent_id;
	fix->saved_ring = sec->ipc_ring;
	fix->saved = agent_caps[SV_XA];
	memset(&agent_caps[SV_XA], 0, sizeof(agent_caps[0]));

	agent_caps[SV_XA].epoch = SV_XEPOCH;
	agent_caps[SV_XA].randtag = SV_XTAG;
	agent_caps[SV_XA].perms = AIRY_CAP_PERM_SUPERVISE;

	sec->agent_id = SV_XA;
	sec->ipc_ring = fix->ring;
	test->priv = fix;

	return airy_sv_start(&fix->ctx);
}

static void sv_exec_exit(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_task_sec *sec = sv_sec();

	if (!fix)
		return;

	sec->agent_id = fix->saved_id;
	sec->ipc_ring = fix->saved_ring;
	agent_caps[SV_XA] = fix->saved;
	kfree(fix->ring);
	airy_wdog_reset();
}

static __u64 sv_badge(__u16 perms)
{
	return AIRY_BADGE_COMPILE(SV_XEPOCH, SV_XTAG, perms);
}

static struct airy_superv_cmd sv_cmd(__u32 opcode, __u32 agent_id,
				     __u32 adjud)
{
	struct airy_superv_cmd cmd = {
		.opcode		= opcode,
		.agent_id	= agent_id,
		.adjud		= adjud,
		.reason		= AIRY_FAULT_CAP_FORGED,
	};

	return cmd;
}

static void sv_exec_null(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, NULL));
}

static void sv_exec_shape(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_SEND, SV_XA, 0);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE,
			airy_sv_exec(0, &fix->ctx, &cmd));

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, AIRY_CAP_MAX_AGENTS,
		     AIRY_ADJUD_WARN);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW,
			airy_sv_exec(0, &fix->ctx, &cmd));

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, SV_XA, AIRY_ADJUD_NR);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_exec(0, &fix->ctx, &cmd));

	cmd = sv_cmd(AIRY_IPC_OP_UNFREEZE, SV_XA, AIRY_ADJUD_DEGRADE);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_exec(0, &fix->ctx, &cmd));
}

static void sv_exec_gate(struct kunit *test)
{
	struct airy_sv_ctx idle;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, SV_XA, AIRY_ADJUD_WARN);
	memset(&idle, 0, sizeof(idle));

	KUNIT_EXPECT_EQ(test, -EAGAIN, airy_sv_exec(0, NULL, &cmd));
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &idle, &cmd));
}

static void sv_exec_forged(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, SV_XA, AIRY_ADJUD_WARN);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			airy_sv_exec(AIRY_BADGE_COMPILE(SV_XEPOCH, 0xDEADBEEFu,
						       AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_sv_exec(AIRY_BADGE_COMPILE(SV_XEPOCH + 1, SV_XTAG,
						       AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));
}

static void sv_exec_perm(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, SV_XA, AIRY_ADJUD_WARN);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SEND),
				     &fix->ctx, &cmd));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_NONE),
				     &fix->ctx, &cmd));
}

static void sv_exec_adjud(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, SV_XA, AIRY_ADJUD_WARN);
	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));

	cmd.agent_id = SV_XMISS;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));
}

static void sv_exec_unfrz(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_UNFREEZE, SV_XA, 0);
	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));
	KUNIT_EXPECT_FALSE(test, READ_ONCE(fix->ring->frozen));

	cmd.agent_id = SV_XMISS;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CONTEXT,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));
}

static void sv_exec_beat(struct kunit *test)
{
	struct sv_exec_fix *fix = test->priv;
	struct airy_superv_cmd cmd;
	__u64 now;

	cmd = sv_cmd(AIRY_IPC_OP_HEARTBEAT, 0, 0);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SEND),
				     &fix->ctx, &cmd));
	KUNIT_EXPECT_EQ(test, 0,
			airy_sv_exec(sv_badge(AIRY_CAP_PERM_SUPERVISE),
				     &fix->ctx, &cmd));

	now = ktime_get_mono_fast_ns();
	KUNIT_EXPECT_FALSE(test, airy_wdog_late(now));
	KUNIT_EXPECT_TRUE(test,
			  airy_wdog_late(now + AIRY_WDOG_TMO_NS + NSEC_PER_SEC));
}

static struct kunit_case airy_sv_exec_cases[] = {
	KUNIT_CASE(sv_exec_null),
	KUNIT_CASE(sv_exec_shape),
	KUNIT_CASE(sv_exec_gate),
	KUNIT_CASE(sv_exec_forged),
	KUNIT_CASE(sv_exec_perm),
	KUNIT_CASE(sv_exec_adjud),
	KUNIT_CASE(sv_exec_unfrz),
	KUNIT_CASE(sv_exec_beat),
	{}
};

static struct kunit_suite airy_sv_exec_suite = {
	.name = "airy_sv_exec",
	.init = sv_exec_init,
	.exit = sv_exec_exit,
	.test_cases = airy_sv_exec_cases,
};

kunit_test_suites(&airy_sv_exec_suite);

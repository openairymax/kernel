// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_proto_test.c — KUnit coverage for the [IND] supervisor
 * protocol contract in airy_superv_proto.c.
 *
 * Pins two invariants the freeze and adjudication slices rely on: a
 * context only accepts commands after airy_sv_start() publishes
 * RUNNING, and airy_sv_cmd_chk() rejects every malformed macro_d
 * command shape before the target slot or ring is touched. The check
 * is pure, so the cases need no live supervisor, ring or task.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>

#include "airy_superv.h"

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

static void sv_start_null(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_start(NULL));
}

static void sv_start_ok(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, 0, airy_sv_start(&ctx));
	KUNIT_EXPECT_EQ(test, AIRY_SV_RUNNING, ctx.state);
	KUNIT_EXPECT_TRUE(test, airy_sv_ready(&ctx));
}

static void sv_ready_state(struct kunit *test)
{
	struct airy_sv_ctx ctx;

	KUNIT_EXPECT_FALSE(test, airy_sv_ready(NULL));

	memset(&ctx, 0, sizeof(ctx));
	KUNIT_EXPECT_EQ(test, AIRY_SV_IDLE, ctx.state);
	KUNIT_EXPECT_FALSE(test, airy_sv_ready(&ctx));
}

static void sv_global_ctx(struct kunit *test)
{
	KUNIT_EXPECT_NOT_NULL(test, airy_sv_ctx());
}

static void sv_chk_null(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_cmd_chk(NULL));
}

static void sv_chk_adjud(struct kunit *test)
{
	struct airy_superv_cmd cmd;
	__u32 adjud;

	for (adjud = AIRY_ADJUD_WARN; adjud < AIRY_ADJUD_NR; adjud++) {
		cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, 1, adjud);
		KUNIT_EXPECT_EQ(test, 0, airy_sv_cmd_chk(&cmd));
	}

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, 1, AIRY_ADJUD_NR);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_cmd_chk(&cmd));
}

static void sv_chk_unfrz(struct kunit *test)
{
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_UNFREEZE, 1, 0);
	KUNIT_EXPECT_EQ(test, 0, airy_sv_cmd_chk(&cmd));

	cmd = sv_cmd(AIRY_IPC_OP_UNFREEZE, 1, AIRY_ADJUD_DEGRADE);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_cmd_chk(&cmd));
}

static void sv_chk_agent(struct kunit *test)
{
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, AIRY_CAP_MAX_AGENTS - 1,
		     AIRY_ADJUD_WARN);
	KUNIT_EXPECT_EQ(test, 0, airy_sv_cmd_chk(&cmd));

	cmd = sv_cmd(AIRY_IPC_OP_ADJUDICATE, AIRY_CAP_MAX_AGENTS,
		     AIRY_ADJUD_WARN);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW, airy_sv_cmd_chk(&cmd));
}

static void sv_chk_opcode(struct kunit *test)
{
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_SEND, 1, 0);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_sv_cmd_chk(&cmd));

	cmd = sv_cmd(AIRY_IPC_OP_FREEZE, 1, 0);
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_sv_cmd_chk(&cmd));
}

static void sv_chk_beat(struct kunit *test)
{
	struct airy_superv_cmd cmd;

	cmd = sv_cmd(AIRY_IPC_OP_HEARTBEAT, 0, 0);
	KUNIT_EXPECT_EQ(test, 0, airy_sv_cmd_chk(&cmd));

	cmd = sv_cmd(AIRY_IPC_OP_HEARTBEAT, 1, 0);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_cmd_chk(&cmd));

	cmd = sv_cmd(AIRY_IPC_OP_HEARTBEAT, 0, AIRY_ADJUD_DEGRADE);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_sv_cmd_chk(&cmd));
}

static struct kunit_case airy_sv_proto_cases[] = {
	KUNIT_CASE(sv_start_null),
	KUNIT_CASE(sv_start_ok),
	KUNIT_CASE(sv_ready_state),
	KUNIT_CASE(sv_global_ctx),
	KUNIT_CASE(sv_chk_null),
	KUNIT_CASE(sv_chk_adjud),
	KUNIT_CASE(sv_chk_unfrz),
	KUNIT_CASE(sv_chk_beat),
	KUNIT_CASE(sv_chk_agent),
	KUNIT_CASE(sv_chk_opcode),
	{}
};

static struct kunit_suite airy_sv_proto_suite = {
	.name = "airy_sv_proto",
	.test_cases = airy_sv_proto_cases,
};

kunit_test_suites(&airy_sv_proto_suite);

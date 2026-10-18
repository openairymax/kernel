// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm_test.c — KUnit regression for the P1-4 Badge-validation fix.
 *
 * P1-4 added symmetric Badge validation to the task_kill and file_open
 * LSM hooks: a registered agent (agent_id != 0) must hold a live
 * capability carrying AIRY_CAP_PERM_KILL / AIRY_CAP_PERM_FILE_OPEN,
 * otherwise the hook denies with -EPERM / -EACCES.  These tests
 * exercise both hooks directly via #include "airy_lsm.c" (the hooks are
 * static), pin the airy_cap_badge_ok() inline that underpins the
 * fastpath, and cover the airy_cap_check() slowpath slot validation
 * including revoked capabilities.
 *
 * airy_lsm.o is dropped from the airy module when CONFIG_AIRY_KUNIT=y so
 * that DEFINE_LSM(airy) and the hook table remain single-defined.
 */

#include <kunit/test.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/lsm_hooks.h>
#include <linux/io_uring.h>
#include <asm/unaligned.h>

#include "airy_cap.h"

/* Pull the static airy_task_kill/airy_file_open hooks into this TU. */
#include "airy_lsm.c"

#define TEST_AGENT	1022u

struct lsm_test_ctx {
	__u32 saved_agent_id;
	__u32 saved_agent_state;
	__u32 saved_fault_count;
	__u32 saved_frozen_reason;
	bool saved_paranoid;
	void *saved_ipc_ring;
	struct airy_ipc_ring_freeze_state *test_ring;
	struct airy_cap_slot saved_slot;
};

static struct airy_task_sec *current_sec(void)
{
	return current->security + airy_blob_sizes.lbs_task;
}

static int airy_lsm_test_init(struct kunit *test)
{
	struct lsm_test_ctx *ctx;
	struct airy_task_sec *sec;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save current's airy blob fields we will mutate. */
	KUNIT_ASSERT_NOT_NULL(test, current->security);
	sec = current_sec();
	ctx->saved_agent_id = sec->agent_id;
	ctx->saved_agent_state = sec->agent_state;
	ctx->saved_fault_count = sec->fault_count;
	ctx->saved_frozen_reason = sec->frozen_reason;
	ctx->saved_ipc_ring = sec->ipc_ring;
	ctx->saved_paranoid = READ_ONCE(airy_security_paranoid);

	/* Save and zero the test agent's capability slot. */
	ctx->saved_slot = agent_caps[TEST_AGENT];
	memset(&agent_caps[TEST_AGENT], 0, sizeof(struct airy_cap_slot));

	return 0;
}

static void airy_lsm_test_exit(struct kunit *test)
{
	struct lsm_test_ctx *ctx = test->priv;
	struct airy_task_sec *sec;

	if (!ctx)
		return;
	sec = current_sec();
	sec->agent_id = ctx->saved_agent_id;
	sec->agent_state = ctx->saved_agent_state;
	sec->fault_count = ctx->saved_fault_count;
	sec->frozen_reason = ctx->saved_frozen_reason;
	sec->ipc_ring = ctx->saved_ipc_ring;
	WRITE_ONCE(airy_security_paranoid, ctx->saved_paranoid);
	agent_caps[TEST_AGENT] = ctx->saved_slot;

	/* Ring allocated by a test, never by the production hooks. */
	kfree(ctx->test_ring);
}

static void register_agent(struct kunit *test, __u16 perms)
{
	__u64 badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, perms);

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_AGENT, badge));
}

/* ── IPC freeze-state helpers ───────────────────────────────────────── */

static struct task_struct *fake_task(struct kunit *test, unsigned int flags)
{
	struct task_struct *task;
	void *blob;

	task = kunit_kzalloc(test, sizeof(*task), GFP_KERNEL);
	blob = kunit_kzalloc(test,
			     airy_blob_sizes.lbs_task +
				     sizeof(struct airy_task_sec),
			     GFP_KERNEL);
	if (!task || !blob)
		return NULL;

	task->security = blob;
	task->flags = flags;
	return task;
}

static struct airy_ipc_ring_freeze_state *attach_ring(struct kunit *test)
{
	struct lsm_test_ctx *ctx = test->priv;
	struct airy_ipc_ring_freeze_state *ring;

	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring)
		return NULL;

	ctx->test_ring = ring;
	current_sec()->ipc_ring = ring;
	return ring;
}

/* ── airy_cap_badge_ok inline (core of P1-4) ────────────────────────── */

static void badge_ok_valid_returns_zero_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 1;
	agent_caps[TEST_AGENT].randtag = 0x1234ABCD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, 0,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_perm_missing_returns_error_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 1;
	agent_caps[TEST_AGENT].randtag = 0x1234ABCD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_SEND;

	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_SEND);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_epoch_mismatch_returns_error_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 2;
	agent_caps[TEST_AGENT].randtag = 0x1234ABCD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_randtag_mismatch_returns_error_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 1;
	agent_caps[TEST_AGENT].randtag = 0xDEAD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

/* ── constant-time primitives (SSoT §12.2.1) ────────────────────────── */

static void ct_eq32_matches_equality_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_eq32(0U, 0U));
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_eq32(0xFFFFFFFFU, 0xFFFFFFFFU));
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_eq32(0x1234ABCDU, 0x1234ABCDU));
	KUNIT_EXPECT_EQ(test, 0U, airy_ct_eq32(0U, 0x80000000U));
	KUNIT_EXPECT_EQ(test, 0U, airy_ct_eq32(0U, 1U));
	KUNIT_EXPECT_EQ(test, 0U, airy_ct_eq32(0x1234ABCDU, 0x1234ABCEU));
}

static void ct_perm_requires_all_bits_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_perm(0x3U, 0x3U));
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_perm(0x7U, 0x3U));
	KUNIT_EXPECT_EQ(test, 1U, airy_ct_perm(0U, 0U));
	KUNIT_EXPECT_EQ(test, 0U, airy_ct_perm(0x1U, 0x3U));
	KUNIT_EXPECT_EQ(test, 0U, airy_ct_perm(0U, 0x1U));
}

static void badge_ok_epoch_precedes_randtag_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 7;
	agent_caps[TEST_AGENT].randtag = 0xDEAD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_SEND;

	badge = AIRY_BADGE_COMPILE(3, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_randtag_precedes_perm_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 3;
	agent_caps[TEST_AGENT].randtag = 0xDEAD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_SEND;

	badge = AIRY_BADGE_COMPILE(3, 0x1234ABCDu, AIRY_CAP_PERM_SEND);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_agent_out_of_range_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
			airy_cap_badge_ok(0, AIRY_CAP_MAX_AGENTS, 0));
}

/* ── paranoid mode (SSoT §12.2.3) ────────────────────────────────────── */

static void badge_ok_paranoid_valid_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 1;
	agent_caps[TEST_AGENT].randtag = 0x1234ABCD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	WRITE_ONCE(airy_security_paranoid, true);
	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, 0,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_paranoid_epoch_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 2;
	agent_caps[TEST_AGENT].randtag = 0x1234ABCD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	WRITE_ONCE(airy_security_paranoid, true);
	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

static void badge_ok_paranoid_forged_test(struct kunit *test)
{
	__u64 badge;

	agent_caps[TEST_AGENT].epoch = 1;
	agent_caps[TEST_AGENT].randtag = 0xDEAD;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_KILL;

	WRITE_ONCE(airy_security_paranoid, true);
	badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_KILL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			airy_cap_badge_ok(badge, TEST_AGENT,
					  AIRY_CAP_PERM_KILL));
}

/* ── task_kill hook (P1-4) ──────────────────────────────────────────── */

static void task_kill_without_kill_perm_denied_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain kill with a badge that LACKS KILL → must deny. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV);

	ret = airy_task_kill(current, NULL, 0, NULL);
	KUNIT_EXPECT_EQ(test, -EPERM, ret);
}

static void task_kill_with_kill_perm_allowed_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain kill with a badge that HAS KILL → must allow. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_KILL);

	ret = airy_task_kill(current, NULL, 0, NULL);
	KUNIT_EXPECT_EQ(test, 0, ret);
}

static void task_kill_unregistered_agent_skipped_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();
	int ret;

	/*
	 * agent_id == 0 means unregistered; badge check is skipped for
	 * backward compatibility (init/kernel threads).
	 */
	sec->agent_id = 0;
	sec->agent_state = AIRY_AGENT_RUNNING;

	ret = airy_task_kill(current, NULL, 0, NULL);
	KUNIT_EXPECT_EQ(test, 0, ret);
}

/* ── file_open hook (P1-4) ──────────────────────────────────────────── */

static void file_open_without_perm_denied_test(struct kunit *test)
{
	struct file file = { .f_mode = FMODE_READ };
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain open with a badge that LACKS FILE_OPEN → must deny. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_SEND);

	ret = airy_file_open(&file);
	KUNIT_EXPECT_EQ(test, -EACCES, ret);
}

static void file_open_with_perm_allowed_test(struct kunit *test)
{
	struct file file = { .f_mode = FMODE_READ };
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain open with a badge that HAS FILE_OPEN → must allow. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_FILE_OPEN);

	ret = airy_file_open(&file);
	KUNIT_EXPECT_EQ(test, 0, ret);
}

/* ── airy_cap_check slowpath slot validation ─────────────────────────── */

static void cap_check_live_slot_allows_test(struct kunit *test)
{
	register_agent(test, AIRY_CAP_PERM_KILL | AIRY_CAP_PERM_FILE_OPEN);

	KUNIT_EXPECT_EQ(test, 0,
			airy_cap_check(TEST_AGENT,
				       AIRY_CAP_PERM_KILL |
					       AIRY_CAP_PERM_FILE_OPEN));
}

static void cap_check_missing_perm_denied_test(struct kunit *test)
{
	register_agent(test, AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_cap_check(TEST_AGENT, AIRY_CAP_PERM_KILL));
}

static void cap_check_revoked_denied_test(struct kunit *test)
{
	register_agent(test, AIRY_CAP_PERM_KILL);

	/*
	 * Mirror airy_cap_revoke_subtree(): epoch is bumped and randtag
	 * cleared while badge and perms stay untouched.  The stale
	 * permission bits must not keep the capability alive.
	 */
	agent_caps[TEST_AGENT].epoch = 2;
	agent_caps[TEST_AGENT].randtag = 0;

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_cap_check(TEST_AGENT, AIRY_CAP_PERM_KILL));
}

static void cap_check_empty_slot_denied_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
			airy_cap_check(TEST_AGENT, AIRY_CAP_PERM_NONE));
}

static void cap_check_out_of_range_denied_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING,
			airy_cap_check(AIRY_CAP_MAX_AGENTS,
				       AIRY_CAP_PERM_NONE));
}

static void task_kill_after_revoke_denied_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();

	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_KILL);
	agent_caps[TEST_AGENT].epoch = 2;
	agent_caps[TEST_AGENT].randtag = 0;

	KUNIT_EXPECT_EQ(test, -EPERM, airy_task_kill(current, NULL, 0, NULL));
}

static void file_open_after_revoke_denied_test(struct kunit *test)
{
	struct file file = { .f_mode = FMODE_READ };
	struct airy_task_sec *sec = current_sec();

	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_FILE_OPEN);
	agent_caps[TEST_AGENT].epoch = 2;
	agent_caps[TEST_AGENT].randtag = 0;

	KUNIT_EXPECT_EQ(test, -EACCES, airy_file_open(&file));
}

static void uring_cmd_opcode_gate_test(struct kunit *test)
{
	struct io_uring_cmd cmd = { };

	/*
	 * Values outside the [SC] opcode space are malformed requests:
	 * they are refused before any phase runs, so no per-agent state
	 * is touched and no fault is reported against the caller.
	 */
	cmd.cmd_op = 0x0000;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE,
			airy_uring_cmd_check(&cmd));

	/* A non-zero high half would truncate onto SEND under a blind cast. */
	cmd.cmd_op = 0x00010000u | AIRY_IPC_OP_SEND;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE,
			airy_uring_cmd_check(&cmd));

	/*
	 * CTL opcodes belong to syscall 548. This plane answers
	 * -AIRY_ENOTSUP, mirroring 548's refusal of DATA and BOOT so that
	 * every opcode has exactly one serving entry point.
	 */
	cmd.cmd_op = AIRY_IPC_OP_FREEZE;
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP, airy_uring_cmd_check(&cmd));

	cmd.cmd_op = AIRY_IPC_OP_CAP_RESPONSE;
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP, airy_uring_cmd_check(&cmd));
}

/* ── IPC freeze-state lifecycle ─────────────────────────────────────── */

static void task_alloc_creates_ring_test(struct kunit *test)
{
	struct task_struct *task = fake_task(test, 0);
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_task_sec *sec;

	KUNIT_ASSERT_NOT_NULL(test, task);
	KUNIT_EXPECT_EQ(test, 0, airy_task_alloc(task, 0));

	sec = task->security + airy_blob_sizes.lbs_task;
	ring = sec->ipc_ring;
	KUNIT_ASSERT_NOT_NULL(test, ring);
	KUNIT_EXPECT_FALSE(test, ring->frozen);

	airy_task_free(task);
}

static void task_alloc_skips_kthread_test(struct kunit *test)
{
	struct task_struct *task = fake_task(test, PF_KTHREAD);
	struct airy_task_sec *sec;

	KUNIT_ASSERT_NOT_NULL(test, task);
	KUNIT_EXPECT_EQ(test, 0, airy_task_alloc(task, 0));

	sec = task->security + airy_blob_sizes.lbs_task;
	KUNIT_EXPECT_NULL(test, sec->ipc_ring);

	airy_task_free(task);
}

static void task_free_releases_ring_test(struct kunit *test)
{
	struct task_struct *task = fake_task(test, 0);
	struct airy_task_sec *sec;

	KUNIT_ASSERT_NOT_NULL(test, task);
	KUNIT_ASSERT_EQ(test, 0, airy_task_alloc(task, 0));

	sec = task->security + airy_blob_sizes.lbs_task;
	KUNIT_ASSERT_NOT_NULL(test, sec->ipc_ring);

	airy_task_free(task);
	KUNIT_EXPECT_NULL(test, sec->ipc_ring);
}

static void uring_cmd_frozen_ring_rejected_test(struct kunit *test)
{
	struct io_uring_cmd cmd = { };
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_task_sec *sec = current_sec();
	__u32 faults_before;

	ring = attach_ring(test);
	KUNIT_ASSERT_NOT_NULL(test, ring);

	airy_ipc_freeze_ring(ring, AIRY_FAULT_CAP_FORGED);

	faults_before = READ_ONCE(sec->fault_count);
	cmd.cmd_op = AIRY_IPC_OP_SEND;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_uring_cmd_check(&cmd));

	/*
	 * A frozen ring is a plain error, not a new violation: the fault
	 * counter must not move or a suspended agent would keep feeding
	 * the die_notifier with every rejected command.
	 */
	KUNIT_EXPECT_EQ(test, faults_before, READ_ONCE(sec->fault_count));
}

static void security_fault_freezes_ring_test(struct kunit *test)
{
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_task_sec *sec = current_sec();
	__u32 faults_before;

	sec->agent_id = TEST_AGENT;
	ring = attach_ring(test);
	KUNIT_ASSERT_NOT_NULL(test, ring);

	faults_before = READ_ONCE(sec->fault_count);
	airy_security_fault(TEST_AGENT, AIRY_FAULT_CAP_FORGED);

	KUNIT_EXPECT_TRUE(test, READ_ONCE(ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED,
			READ_ONCE(ring->freeze_reason));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED,
			READ_ONCE(sec->frozen_reason));
	KUNIT_EXPECT_EQ(test, faults_before + 1,
			READ_ONCE(sec->fault_count));
}

static void uring_cmd_perm_fault_is_abnormal_test(struct kunit *test)
{
	struct io_uring_cmd cmd = { };
	struct airy_ipc_ring_freeze_state *ring;
	struct airy_task_sec *sec = current_sec();
	__u64 badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, AIRY_CAP_PERM_RECV);
	__u32 faults_before;

	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_AGENT, badge));

	ring = attach_ring(test);
	KUNIT_ASSERT_NOT_NULL(test, ring);

	faults_before = READ_ONCE(sec->fault_count);
	cmd.cmd_op = AIRY_IPC_OP_SEND;
	put_unaligned_le64(badge, &cmd.pdu[0]);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM,
			airy_uring_cmd_check(&cmd));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(ring->frozen));
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_ABNORMAL_CAP,
			READ_ONCE(ring->freeze_reason));
	KUNIT_EXPECT_EQ(test, faults_before + 1,
			READ_ONCE(sec->fault_count));
}

static struct kunit_case airy_lsm_cases[] = {
	KUNIT_CASE(badge_ok_valid_returns_zero_test),
	KUNIT_CASE(badge_ok_perm_missing_returns_error_test),
	KUNIT_CASE(badge_ok_epoch_mismatch_returns_error_test),
	KUNIT_CASE(badge_ok_randtag_mismatch_returns_error_test),
	KUNIT_CASE(ct_eq32_matches_equality_test),
	KUNIT_CASE(ct_perm_requires_all_bits_test),
	KUNIT_CASE(badge_ok_epoch_precedes_randtag_test),
	KUNIT_CASE(badge_ok_randtag_precedes_perm_test),
	KUNIT_CASE(badge_ok_agent_out_of_range_test),
	KUNIT_CASE(badge_ok_paranoid_valid_test),
	KUNIT_CASE(badge_ok_paranoid_epoch_test),
	KUNIT_CASE(badge_ok_paranoid_forged_test),
	KUNIT_CASE(task_kill_without_kill_perm_denied_test),
	KUNIT_CASE(task_kill_with_kill_perm_allowed_test),
	KUNIT_CASE(task_kill_unregistered_agent_skipped_test),
	KUNIT_CASE(file_open_without_perm_denied_test),
	KUNIT_CASE(file_open_with_perm_allowed_test),
	KUNIT_CASE(cap_check_live_slot_allows_test),
	KUNIT_CASE(cap_check_missing_perm_denied_test),
	KUNIT_CASE(cap_check_revoked_denied_test),
	KUNIT_CASE(cap_check_empty_slot_denied_test),
	KUNIT_CASE(cap_check_out_of_range_denied_test),
	KUNIT_CASE(task_kill_after_revoke_denied_test),
	KUNIT_CASE(file_open_after_revoke_denied_test),
	KUNIT_CASE(uring_cmd_opcode_gate_test),
	KUNIT_CASE(task_alloc_creates_ring_test),
	KUNIT_CASE(task_alloc_skips_kthread_test),
	KUNIT_CASE(task_free_releases_ring_test),
	KUNIT_CASE(uring_cmd_frozen_ring_rejected_test),
	KUNIT_CASE(security_fault_freezes_ring_test),
	KUNIT_CASE(uring_cmd_perm_fault_is_abnormal_test),
	{}
};

static struct kunit_suite airy_lsm_suite = {
	.name = "airy_lsm_p1_4",
	.init = airy_lsm_test_init,
	.exit = airy_lsm_test_exit,
	.test_cases = airy_lsm_cases,
};

kunit_test_suites(&airy_lsm_suite);

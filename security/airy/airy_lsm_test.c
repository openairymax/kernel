// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm_test.c — KUnit regression for the P1-4 Badge-validation fix.
 *
 * P1-4 added symmetric Badge validation to the task_kill and file_open
 * LSM hooks: a registered agent (agent_id != 0) must hold
 * AIRY_CAP_PERM_KILL / AIRY_CAP_PERM_FILE_OPEN in its badge, otherwise
 * the hook denies with -EPERM / -EACCES.  These tests exercise both
 * hooks directly via #include "airy_lsm.c" (the hooks are static) and
 * also pin the airy_cap_badge_ok() inline that underpins the check.
 *
 * airy_lsm.o is dropped from the airy module when CONFIG_AIRY_KUNIT=y so
 * that DEFINE_LSM(airy) and the hook table remain single-defined.
 */

#include <kunit/test.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/lsm_hooks.h>
#include <linux/io_uring.h>

#include "airy_cap.h"

/* Pull the static airy_task_kill/airy_file_open hooks into this TU. */
#include "airy_lsm.c"

#define TEST_AGENT	1022u

struct lsm_test_ctx {
	__u32 saved_agent_id;
	__u32 saved_agent_state;
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

	if (!airy_enabled)
		kunit_skip(test, "airy LSM disabled (airy.enabled=0)");

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Save current's airy blob fields we will mutate. */
	KUNIT_ASSERT_NOT_NULL(test, current->security);
	sec = current_sec();
	ctx->saved_agent_id = sec->agent_id;
	ctx->saved_agent_state = sec->agent_state;

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
	agent_caps[TEST_AGENT] = ctx->saved_slot;
}

static void register_agent(struct kunit *test, __u16 perms)
{
	__u64 badge = AIRY_BADGE_COMPILE(1, 0x1234ABCDu, perms);

	KUNIT_ASSERT_EQ(test, 0, airy_cap_register(TEST_AGENT, badge));
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

	/* agent_id == 0 means unregistered; badge check is skipped for
	 * backward compatibility (init/kernel threads). */
	sec->agent_id = 0;
	sec->agent_state = AIRY_AGENT_RUNNING;

	ret = airy_task_kill(current, NULL, 0, NULL);
	KUNIT_EXPECT_EQ(test, 0, ret);
}

/* ── file_open hook (P1-4) ──────────────────────────────────────────── */

static void file_open_without_perm_denied_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain open with a badge that LACKS FILE_OPEN → must deny. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_SEND);

	ret = airy_file_open(NULL);
	KUNIT_EXPECT_EQ(test, -EACCES, ret);
}

static void file_open_with_perm_allowed_test(struct kunit *test)
{
	struct airy_task_sec *sec = current_sec();
	int ret;

	/* Cross-domain open with a badge that HAS FILE_OPEN → must allow. */
	sec->agent_id = TEST_AGENT;
	sec->agent_state = AIRY_AGENT_RUNNING;
	register_agent(test, AIRY_CAP_PERM_FILE_OPEN);

	ret = airy_file_open(NULL);
	KUNIT_EXPECT_EQ(test, 0, ret);
}

static struct kunit_case airy_lsm_cases[] = {
	KUNIT_CASE(badge_ok_valid_returns_zero_test),
	KUNIT_CASE(badge_ok_perm_missing_returns_error_test),
	KUNIT_CASE(badge_ok_epoch_mismatch_returns_error_test),
	KUNIT_CASE(badge_ok_randtag_mismatch_returns_error_test),
	KUNIT_CASE(task_kill_without_kill_perm_denied_test),
	KUNIT_CASE(task_kill_with_kill_perm_allowed_test),
	KUNIT_CASE(task_kill_unregistered_agent_skipped_test),
	KUNIT_CASE(file_open_without_perm_denied_test),
	KUNIT_CASE(file_open_with_perm_allowed_test),
	{}
};

static struct kunit_suite airy_lsm_suite = {
	.name = "airy_lsm_p1_4",
	.init = airy_lsm_test_init,
	.exit = airy_lsm_test_exit,
	.test_cases = airy_lsm_cases,
};

kunit_test_suites(&airy_lsm_suite);

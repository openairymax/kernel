// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_fault_test.c — KUnit coverage for the security fault
 * observer implemented in airy_superv_fault.c.
 *
 * Drives the real airy_die_chain instead of the static callback, so a
 * regression in registration is caught as well: if the Micro-Supervisor
 * late_initcall did not subscribe, no detail reaches the fault event
 * ring and the cases fail. Each case resets the ring first, so the
 * observations do not depend on the order the suite runs in.
 */

#include <kunit/test.h>
#include <linux/notifier.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define SV_FAULT_AGENT	1008u
#define SV_FAULT_ALIEN	1009u
#define SV_FAULT_TS	0x1122334455667788ULL

static void sv_fault_chk(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_CAP_FORGED));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_CAP_LEAK));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_RING_CORRUPT));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_TIMEOUT));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_ABNORMAL_CAP));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_VM_FAULT));
	KUNIT_EXPECT_TRUE(test, airy_fault_ok(AIRY_FAULT_DOUBLE_FAULT));

	KUNIT_EXPECT_FALSE(test, airy_fault_ok(0));
	KUNIT_EXPECT_FALSE(test, airy_fault_ok(0x1000));
	KUNIT_EXPECT_FALSE(test, airy_fault_ok(0x1010));
	KUNIT_EXPECT_FALSE(test, airy_fault_ok(0xFFFF));
}

static void sv_fault_post(struct kunit *test)
{
	struct airy_fault_rec rec = {
		.agent_id = SV_FAULT_AGENT,
		.fault_code = AIRY_FAULT_CAP_FORGED,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, rec.fault_code, &rec);

	KUNIT_ASSERT_EQ(test, 0, airy_fev_fetch(&ev));
	KUNIT_EXPECT_EQ(test, SV_FAULT_AGENT, ev.agent_id);
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED, ev.fault_code);
	KUNIT_EXPECT_EQ(test, SV_FAULT_TS, ev.timestamp_ns);
	KUNIT_EXPECT_EQ(test, AIRY_FEV_RING_ID_NONE, ev.ring_id);
}

/*
 * sv_fault_alien - the reported agent need not be the running task.
 *
 * This is the regression for the identity bug: the chain used to carry
 * current instead of the offending agent, so a fault raised from a
 * supervisor context named the wrong agent.
 */
static void sv_fault_alien(struct kunit *test)
{
	struct airy_fault_rec rec = {
		.agent_id = SV_FAULT_ALIEN,
		.fault_code = AIRY_FAULT_RING_CORRUPT,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, rec.fault_code, &rec);

	KUNIT_ASSERT_EQ(test, 0, airy_fev_fetch(&ev));
	KUNIT_EXPECT_EQ(test, SV_FAULT_ALIEN, ev.agent_id);
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_RING_CORRUPT, ev.fault_code);
}

static void sv_fault_send(struct kunit *test)
{
	struct airy_fault_event ev;

	airy_fev_reset();
	airy_security_fault(SV_FAULT_AGENT, AIRY_FAULT_CAP_FORGED);

	KUNIT_ASSERT_EQ(test, 0, airy_fev_fetch(&ev));
	KUNIT_EXPECT_EQ(test, SV_FAULT_AGENT, ev.agent_id);
	KUNIT_EXPECT_EQ(test, AIRY_FAULT_CAP_FORGED, ev.fault_code);
}

static void sv_fault_mismatch(struct kunit *test)
{
	struct airy_fault_rec rec = {
		.agent_id = SV_FAULT_AGENT,
		.fault_code = AIRY_FAULT_CAP_FORGED,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, AIRY_FAULT_TIMEOUT, &rec);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static void sv_fault_unknown(struct kunit *test)
{
	struct airy_fault_rec rec = {
		.agent_id = SV_FAULT_AGENT,
		.fault_code = 0x1010,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, rec.fault_code, &rec);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static void sv_fault_bad_id(struct kunit *test)
{
	struct airy_fault_rec zero = {
		.agent_id = 0,
		.fault_code = AIRY_FAULT_TIMEOUT,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_rec over = {
		.agent_id = AIRY_CAP_MAX_AGENTS,
		.fault_code = AIRY_FAULT_TIMEOUT,
		.timestamp_ns = SV_FAULT_TS,
	};
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, zero.fault_code, &zero);
	atomic_notifier_call_chain(&airy_die_chain, over.fault_code, &over);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static void sv_fault_null(struct kunit *test)
{
	struct airy_fault_event ev;

	airy_fev_reset();
	atomic_notifier_call_chain(&airy_die_chain, AIRY_FAULT_TIMEOUT, NULL);

	KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_fetch(&ev));
}

static struct kunit_case airy_sv_fault_cases[] = {
	KUNIT_CASE(sv_fault_chk),
	KUNIT_CASE(sv_fault_post),
	KUNIT_CASE(sv_fault_alien),
	KUNIT_CASE(sv_fault_send),
	KUNIT_CASE(sv_fault_mismatch),
	KUNIT_CASE(sv_fault_unknown),
	KUNIT_CASE(sv_fault_bad_id),
	KUNIT_CASE(sv_fault_null),
	{}
};

static struct kunit_suite airy_sv_fault_suite = {
	.name = "airy_sv_fault",
	.test_cases = airy_sv_fault_cases,
};

kunit_test_suites(&airy_sv_fault_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_lifecycle_test.c — KUnit coverage for the agent state machine.
 *
 * Every assertion below goes through airy_task_state_transition() and the
 * real airy_agent_state_change tracepoint: legitimate edges must move the
 * descriptor and emit exactly one event carrying the committed state
 * values, while every illegal edge must fail with -EINVAL, leave the
 * descriptor untouched and emit nothing.  The event stream is captured
 * with a tracepoint probe rather than a mock, so a regression in either
 * the transition table or the emission point fails the suite.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/airymax/sched.h>

#include <airymax/airy_task.h>
#include <airymax/airy_trace.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)

#include <trace/events/airy.h>

struct state_evt {
	u32	agent_id;
	u32	prev;
	u32	next;
	u32	reason;
};

struct state_cap {
	struct state_evt evt[32];
	unsigned int	 nr;
};

static void state_probe(void *data, u32 agent_id, u32 prev_state,
			u32 next_state, u32 reason)
{
	struct state_cap *cap = data;

	if (cap->nr < ARRAY_SIZE(cap->evt))
		cap->evt[cap->nr] = (struct state_evt) {
			.agent_id = agent_id,
			.prev = prev_state,
			.next = next_state,
			.reason = reason,
		};
	cap->nr++;
}

static void state_probe_off(void *data)
{
	tracepoint_probe_unregister(&__tracepoint_airy_agent_state_change,
				    state_probe, data);
}

static struct state_cap *state_capture(struct kunit *test)
{
	struct state_cap *cap;
	int ret;

	cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cap);

	ret = tracepoint_probe_register(&__tracepoint_airy_agent_state_change,
					state_probe, cap);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, state_probe_off, cap));
	return cap;
}

static int state_test_init(struct kunit *test)
{
	struct airy_task_desc *desc;

	desc = kunit_kzalloc(test, sizeof(*desc), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, desc);
	KUNIT_ASSERT_EQ(test, 0, airy_task_desc_init(desc));
	test->priv = desc;
	return 0;
}

static void desc_init_sets_contract_defaults_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;

	KUNIT_EXPECT_EQ(test, (u32)AIRY_TASK_MAGIC, desc->magic);
	KUNIT_EXPECT_EQ(test, (u32)(AIRY_PRIO_MAX / 2), desc->prio);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_SCHED_POLICY_EEVDF,
			desc->sched_policy);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_WEIGHT_MIN, desc->weight);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, desc->state);
	KUNIT_EXPECT_EQ(test, (u64)0, desc->vtime);
	KUNIT_EXPECT_TRUE(test, airy_task_desc_valid(desc));

	KUNIT_EXPECT_EQ(test, 0, airy_task_desc_init(desc));
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, desc->state);
}

static void desc_init_rejects_corrupt_magic_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;

	desc->magic = 0xdeadbeef;
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_task_desc_init(desc));
	KUNIT_EXPECT_FALSE(test, airy_task_desc_valid(desc));
	KUNIT_EXPECT_EQ(test, (u32)0xdeadbeef, desc->magic);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_task_desc_init(NULL));
}

static void spawn_to_running_emits_one_event_per_edge_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;
	struct state_cap *cap = state_capture(test);
	static const enum airy_agent_state path[] = {
		AIRY_AGENT_SPAWNING, AIRY_AGENT_READY, AIRY_AGENT_RUNNING,
		AIRY_AGENT_STOPPING, AIRY_AGENT_STOPPED, AIRY_AGENT_DEAD,
	};
	static const enum airy_trace_reason why[] = {
		AIRY_TRACE_REASON_INIT, AIRY_TRACE_REASON_PLAN_READY,
		AIRY_TRACE_REASON_DISPATCH, AIRY_TRACE_REASON_SUPERVISE_SUSPEND,
		AIRY_TRACE_REASON_SUPERVISE_SUSPEND,
		AIRY_TRACE_REASON_SUPERVISE_TERMINATE,
	};
	u32 i;

	desc->agent_id = 7;
	for (i = 0; i < ARRAY_SIZE(path); i++)
		KUNIT_ASSERT_EQ(test, 0,
				airy_task_state_transition(desc, path[i], why[i]));

	KUNIT_ASSERT_EQ(test, (unsigned int)ARRAY_SIZE(path), cap->nr);
	for (i = 0; i < ARRAY_SIZE(path); i++) {
		KUNIT_EXPECT_EQ(test, (u32)7, cap->evt[i].agent_id);
		KUNIT_EXPECT_EQ(test, (u32)why[i], cap->evt[i].reason);
		KUNIT_EXPECT_EQ(test, (u32)path[i], cap->evt[i].next);
		KUNIT_EXPECT_EQ(test, i ? (u32)path[i - 1] :
				(u32)AIRY_AGENT_INACTIVE, cap->evt[i].prev);
	}
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_DEAD, desc->state);
}

static void blocked_round_trip_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;
	struct state_cap *cap = state_capture(test);

	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_SPAWNING,
						   AIRY_TRACE_REASON_INIT));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_READY,
						   AIRY_TRACE_REASON_PLAN_READY));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_RUNNING,
						   AIRY_TRACE_REASON_DISPATCH));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_BLOCKED,
						   AIRY_TRACE_REASON_IPC_WAIT));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_READY,
						   AIRY_TRACE_REASON_IPC_RECV));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_RUNNING,
						   AIRY_TRACE_REASON_DISPATCH));

	KUNIT_ASSERT_EQ(test, 6u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_RUNNING, cap->evt[3].prev);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_BLOCKED, cap->evt[3].next);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_TRACE_REASON_IPC_WAIT,
			cap->evt[3].reason);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_BLOCKED, cap->evt[4].prev);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_READY, cap->evt[4].next);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_RUNNING, cap->evt[5].next);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_RUNNING, desc->state);
}

static void illegal_edges_are_rejected_silently_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;
	struct state_cap *cap = state_capture(test);

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_RUNNING,
						   AIRY_TRACE_REASON_DISPATCH));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_DEAD,
						   AIRY_TRACE_REASON_SUPERVISE_TERMINATE));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_STOPPED,
						   AIRY_TRACE_REASON_INIT));
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, desc->state);
	KUNIT_EXPECT_EQ(test, 0u, cap->nr);

	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_SPAWNING,
						   AIRY_TRACE_REASON_INIT));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_RUNNING,
						   AIRY_TRACE_REASON_DISPATCH));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_BLOCKED,
						   AIRY_TRACE_REASON_IPC_WAIT));
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_SPAWNING, desc->state);
	KUNIT_EXPECT_EQ(test, 1u, cap->nr);
}

static void dead_is_terminal_until_reaped_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;
	struct state_cap *cap = state_capture(test);

	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_SPAWNING,
						   AIRY_TRACE_REASON_INIT));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_READY,
						   AIRY_TRACE_REASON_PLAN_READY));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_RUNNING,
						   AIRY_TRACE_REASON_DISPATCH));
	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_DEAD,
						   AIRY_TRACE_REASON_SUPERVISE_TERMINATE));

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_READY,
						   AIRY_TRACE_REASON_IPC_RECV));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_DEAD,
						   AIRY_TRACE_REASON_SUPERVISE_TERMINATE));
	KUNIT_EXPECT_EQ(test, 4u, cap->nr);

	KUNIT_ASSERT_EQ(test, 0,
			airy_task_state_transition(desc, AIRY_AGENT_INACTIVE,
						   AIRY_TRACE_REASON_SUPERVISE_TERMINATE));
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, desc->state);
	KUNIT_EXPECT_EQ(test, 5u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_DEAD, cap->evt[4].prev);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, cap->evt[4].next);
}

static void reason_bounds_are_enforced_test(struct kunit *test)
{
	struct airy_task_desc *desc = test->priv;
	struct state_cap *cap = state_capture(test);

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(desc, AIRY_AGENT_SPAWNING,
						   AIRY_TRACE_REASON_MAX));
	KUNIT_EXPECT_EQ(test, (u32)AIRY_AGENT_INACTIVE, desc->state);
	KUNIT_EXPECT_EQ(test, 0u, cap->nr);
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_task_state_transition(NULL, AIRY_AGENT_SPAWNING,
						   AIRY_TRACE_REASON_INIT));
}

static void state_names_cover_all_states_test(struct kunit *test)
{
	static const char * const want[] = {
		"INACTIVE", "SPAWNING", "READY", "RUNNING",
		"BLOCKED", "STOPPING", "STOPPED", "DEAD",
	};
	unsigned int i;

	for (i = 0; i < AIRY_AGENT_STATE_MAX; i++)
		KUNIT_EXPECT_STREQ(test, want[i],
				   airy_task_state_name(
					   (enum airy_agent_state)i));
	KUNIT_EXPECT_STREQ(test, "UNKNOWN",
			   airy_task_state_name(AIRY_AGENT_STATE_MAX));
}

static struct kunit_case airy_task_lifecycle_cases[] = {
	KUNIT_CASE(desc_init_sets_contract_defaults_test),
	KUNIT_CASE(desc_init_rejects_corrupt_magic_test),
	KUNIT_CASE(spawn_to_running_emits_one_event_per_edge_test),
	KUNIT_CASE(blocked_round_trip_test),
	KUNIT_CASE(illegal_edges_are_rejected_silently_test),
	KUNIT_CASE(dead_is_terminal_until_reaped_test),
	KUNIT_CASE(reason_bounds_are_enforced_test),
	KUNIT_CASE(state_names_cover_all_states_test),
	{}
};

static struct kunit_suite airy_task_lifecycle_suite = {
	.name = "airy_task_lifecycle",
	.init = state_test_init,
	.test_cases = airy_task_lifecycle_cases,
};

kunit_test_suites(&airy_task_lifecycle_suite);

#endif /* CONFIG_AIRY_AGENT_TRACING */

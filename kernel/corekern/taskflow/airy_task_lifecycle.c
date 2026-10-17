// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_lifecycle.c — Airymax agent 8-state lifecycle state machine.
 *
 * Uses the [SC] enum airy_agent_state from <linux/airymax/sched.h>
 * (INACTIVE → SPAWNING → READY → RUNNING → BLOCKED → STOPPING →
 * STOPPED → DEAD) and enforces legal transitions between them on the
 * struct airy_task_desc that carries the agent identity.  Every
 * accepted transition emits one airy_agent_state_change event from the
 * committed state value, so the traced stream cannot drift from the
 * in-kernel state.  State names go out via airy_task_state_name().
 *
 * SSoT: docs/AirymaxOS/30-interfaces/10-sc-sched-extension.md §2
 *       docs/AirymaxOS/90-observability/08-agent-tracing.md §7.1
 */

#include <linux/errno.h>
#include <linux/array_size.h>
#include <linux/build_bug.h>

#include <linux/airymax/sched.h>

#include <airymax/airy_task.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

/*
 * Agent lifecycle states are defined by the [SC] enum airy_agent_state
 * in <linux/airymax/sched.h> (single source of truth).  The eight states
 * are: INACTIVE, SPAWNING, READY, RUNNING, BLOCKED, STOPPING, STOPPED,
 * DEAD.  No local enum redefinition is needed here.
 */

static const char * const airy_task_state_names[] = {
	[AIRY_AGENT_INACTIVE] = "INACTIVE",
	[AIRY_AGENT_SPAWNING] = "SPAWNING",
	[AIRY_AGENT_READY]    = "READY",
	[AIRY_AGENT_RUNNING]  = "RUNNING",
	[AIRY_AGENT_BLOCKED]  = "BLOCKED",
	[AIRY_AGENT_STOPPING] = "STOPPING",
	[AIRY_AGENT_STOPPED]  = "STOPPED",
	[AIRY_AGENT_DEAD]     = "DEAD",
};

/*
 * The name table is indexed by the [SC] enum after a single range check,
 * so a state added to sched.h without a matching name here would return
 * NULL from airy_task_state_name() instead of a traceable label.
 */
static_assert(ARRAY_SIZE(airy_task_state_names) == AIRY_AGENT_STATE_MAX,
	      "task state name table must cover every [SC] agent state");

/* ─── State name lookup ──────────────────────────────────────────────── */
const char *airy_task_state_name(enum airy_agent_state state)
{
	unsigned int idx = (unsigned int)state;

	if (idx >= AIRY_AGENT_STATE_MAX)
		return "UNKNOWN";
	return airy_task_state_names[idx];
}

/*
 * ─── State transition validation ──────────────────────────────────────
 *
 * The legal transition table lives in SSoT 10-sc-sched-extension.md §2.2
 * and is enforced per target state below.  DEAD is terminal for in-flight
 * agents until reaped; INACTIVE is the recycle point, so the same agent_id
 * slot may be reused by a new fork.
 */
int airy_task_state_transition(struct airy_task_desc *desc,
			       enum airy_agent_state next,
			       enum airy_trace_reason reason)
{
	enum airy_agent_state cur;

	if (!airy_task_desc_valid(desc))
		return -EINVAL;

	cur = (enum airy_agent_state)desc->state;
	if (cur >= AIRY_AGENT_STATE_MAX || reason >= AIRY_TRACE_REASON_MAX)
		return -EINVAL;

	/* DEAD is terminal — only transition is reaping to INACTIVE. */
	if (cur == AIRY_AGENT_DEAD && next != AIRY_AGENT_INACTIVE)
		return -EINVAL;

	switch (next) {
	case AIRY_AGENT_SPAWNING:
		/* Only INACTIVE may spawn. */
		if (cur != AIRY_AGENT_INACTIVE)
			return -EINVAL;
		break;
	case AIRY_AGENT_READY:
		/*
		 * SPAWNING completes exec; BLOCKED wakes from IPC/IO;
		 * STOPPED is thawed by SIGCONT (adjudicated recovery).
		 */
		if (cur != AIRY_AGENT_SPAWNING && cur != AIRY_AGENT_BLOCKED &&
		    cur != AIRY_AGENT_STOPPED)
			return -EINVAL;
		break;
	case AIRY_AGENT_RUNNING:
		/* Only READY may be picked by the scheduler. */
		if (cur != AIRY_AGENT_READY)
			return -EINVAL;
		break;
	case AIRY_AGENT_BLOCKED:
		/* Only RUNNING may block on IPC/IO. */
		if (cur != AIRY_AGENT_RUNNING)
			return -EINVAL;
		break;
	case AIRY_AGENT_STOPPING:
		/*
		 * Micro-Supervisor may freeze a RUNNING or BLOCKED agent
		 * by sending SIGSTOP (abnormal condition detected).
		 */
		if (cur != AIRY_AGENT_RUNNING && cur != AIRY_AGENT_BLOCKED)
			return -EINVAL;
		break;
	case AIRY_AGENT_STOPPED:
		/* STOPPING → STOPPED when SIGSTOP takes effect. */
		if (cur != AIRY_AGENT_STOPPING)
			return -EINVAL;
		break;
	case AIRY_AGENT_DEAD:
		/*
		 * STOPPED may be adjudicated to termination;
		 * RUNNING may be killed by SIGKILL (fatal);
		 * SPAWNING/READY/BLOCKED/STOPPING may also be killed.
		 */
		if (cur == AIRY_AGENT_INACTIVE || cur == AIRY_AGENT_DEAD)
			return -EINVAL;
		break;
	case AIRY_AGENT_INACTIVE:
		/* Only DEAD may be reaped to INACTIVE (recycle). */
		if (cur != AIRY_AGENT_DEAD)
			return -EINVAL;
		break;
	default:
		/* AIRY_AGENT_STATE_MAX is not a state. */
		return -EINVAL;
	}

	desc->state = next;
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_agent_state_change(desc->agent_id, cur, next, reason);
#endif
	return 0;
}

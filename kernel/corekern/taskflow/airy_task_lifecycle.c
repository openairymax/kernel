// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_lifecycle.c — Airymax agent 8-state lifecycle state machine.
 *
 * Uses the [SC] enum airy_agent_state from <linux/airymax/sched.h>
 * (INACTIVE → SPAWNING → READY → RUNNING → BLOCKED → STOPPING →
 * STOPPED → DEAD) and enforces legal transitions between them.
 * State names are exposed via airy_task_state_name() for observability.
 *
 * SSoT: docs/AirymaxOS/30-interfaces/10-sc-sched-extension.md §2
 */

#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/airymax/sched.h>

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

/* ─── State name lookup ──────────────────────────────────────────────── */
const char *airy_task_state_name(enum airy_agent_state state)
{
	unsigned int idx = (unsigned int)state;

	if (idx >= AIRY_AGENT_STATE_MAX)
		return "UNKNOWN";
	return airy_task_state_names[idx];
}

/* ─── State transition validation ──────────────────────────────────────
 *
 * Legal transitions per SSoT 10-sc-sched-extension.md §2.2:
 *
 *   INACTIVE → SPAWNING  (fork)
 *   SPAWNING → READY     (exec complete)
 *   READY    → RUNNING   (scheduler picks)
 *   RUNNING  → BLOCKED   (IPC/IO wait)
 *   BLOCKED  → READY     (wakeup)
 *   RUNNING  → STOPPING  (Micro-Supervisor SIGSTOP, abnormal)
 *   BLOCKED  → STOPPING  (Micro-Supervisor SIGSTOP, abnormal)
 *   STOPPING → STOPPED   (SIGSTOP takes effect)
 *   STOPPED  → READY     (SIGCONT, adjudicated recovery)
 *   STOPPED  → DEAD      (adjudicated termination)
 *   RUNNING  → DEAD      (kill SIGKILL, fatal)
 *   DEAD     → INACTIVE  (waitpid, recycling)
 *
 * DEAD is terminal for in-flight agents until reaped; INACTIVE is the
 * recycle point (the same agent_id slot may be reused for a new fork).
 */
int airy_task_state_transition(enum airy_agent_state *state,
			       enum airy_agent_state next)
{
	enum airy_agent_state cur;

	if (!state)
		return -EINVAL;

	cur = *state;

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
		return -EINVAL;
	}

	*state = next;
	return 0;
}

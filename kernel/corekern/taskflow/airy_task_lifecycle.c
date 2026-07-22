// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_lifecycle.c — Airymax agent 8-state lifecycle state machine.
 *
 * Uses the [SC] enum airy_agent_state from <linux/airymax/sched.h>
 * (INIT → RUNNING → SLEEPING → BLOCKED → FROZEN → TERMINATING →
 * DEAD → ZOMBIE) and enforces legal transitions between them.
 * State names are exposed via airy_task_state_name() for observability.
 */

#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/airymax/sched.h>

/*
 * Agent lifecycle states are defined by the [SC] enum airy_agent_state
 * in <linux/airymax/sched.h> (single source of truth).  The eight states
 * are: INIT, RUNNING, SLEEPING, BLOCKED, FROZEN, TERMINATING, DEAD,
 * ZOMBIE.  No local enum redefinition is needed here.
 */

static const char * const airy_task_state_names[] = {
	[AIRY_AGENT_INIT]        = "INIT",
	[AIRY_AGENT_RUNNING]     = "RUNNING",
	[AIRY_AGENT_SLEEPING]    = "SLEEPING",
	[AIRY_AGENT_BLOCKED]     = "BLOCKED",
	[AIRY_AGENT_FROZEN]      = "FROZEN",
	[AIRY_AGENT_TERMINATING] = "TERMINATING",
	[AIRY_AGENT_DEAD]        = "DEAD",
	[AIRY_AGENT_ZOMBIE]      = "ZOMBIE",
};

/* ─── State name lookup ──────────────────────────────────────────────── */
const char *airy_task_state_name(enum airy_agent_state state)
{
	unsigned int idx = (unsigned int)state;

	if (idx >= AIRY_AGENT_STATE_MAX)
		return "UNKNOWN";
	return airy_task_state_names[idx];
}

/* ─── State transition validation ────────────────────────────────────── */
int airy_task_state_transition(enum airy_agent_state *state,
			       enum airy_agent_state next)
{
	enum airy_agent_state cur;

	if (!state)
		return -EINVAL;

	cur = *state;

	/* DEAD and ZOMBIE are terminal — no transitions out. */
	if (cur == AIRY_AGENT_DEAD || cur == AIRY_AGENT_ZOMBIE)
		return -EINVAL;

	switch (next) {
	case AIRY_AGENT_RUNNING:
		/*
		 * INIT completes spawning; SLEEPING wakes, BLOCKED
		 * finishes I/O, FROZEN is thawed by the Supervisor.
		 */
		if (cur != AIRY_AGENT_INIT && cur != AIRY_AGENT_SLEEPING &&
		    cur != AIRY_AGENT_BLOCKED && cur != AIRY_AGENT_FROZEN)
			return -EINVAL;
		break;
	case AIRY_AGENT_SLEEPING:
		if (cur != AIRY_AGENT_RUNNING)
			return -EINVAL;
		break;
	case AIRY_AGENT_BLOCKED:
		if (cur != AIRY_AGENT_RUNNING)
			return -EINVAL;
		break;
	case AIRY_AGENT_FROZEN:
		/* Supervisor may freeze a RUNNING or BLOCKED agent. */
		if (cur != AIRY_AGENT_RUNNING && cur != AIRY_AGENT_BLOCKED)
			return -EINVAL;
		break;
	case AIRY_AGENT_TERMINATING:
		/* Any initialised, non-terminal state may terminate. */
		if (cur == AIRY_AGENT_INIT)
			return -EINVAL;
		break;
	case AIRY_AGENT_DEAD:
		if (cur != AIRY_AGENT_TERMINATING)
			return -EINVAL;
		break;
	case AIRY_AGENT_ZOMBIE:
		if (cur != AIRY_AGENT_DEAD)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	*state = next;
	return 0;
}

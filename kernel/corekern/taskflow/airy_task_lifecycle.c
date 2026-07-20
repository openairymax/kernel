// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_lifecycle.c — Airymax agent 8-state lifecycle state machine.
 *
 * Defines the eight lifecycle states (INACTIVE → SPAWNING → READY →
 * RUNNING → BLOCKED → SUSPENDED → TERMINATING → DEAD) and enforces
 * legal transitions between them.  State names are exposed via
 * airy_task_state_name() for observability.
 */

#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/airymax/sched.h>

/* ─── Lifecycle state enumeration ────────────────────────────────────── */
enum airy_task_state {
	AIRY_TASK_INACTIVE	= 0,
	AIRY_TASK_SPAWNING	= 1,
	AIRY_TASK_READY		= 2,
	AIRY_TASK_RUNNING	= 3,
	AIRY_TASK_BLOCKED	= 4,
	AIRY_TASK_SUSPENDED	= 5,
	AIRY_TASK_TERMINATING	= 6,
	AIRY_TASK_DEAD		= 7,
	AIRY_TASK_STATE_MAX
};

static const char * const airy_task_state_names[] = {
	[AIRY_TASK_INACTIVE]	= "INACTIVE",
	[AIRY_TASK_SPAWNING]	= "SPAWNING",
	[AIRY_TASK_READY]	= "READY",
	[AIRY_TASK_RUNNING]	= "RUNNING",
	[AIRY_TASK_BLOCKED]	= "BLOCKED",
	[AIRY_TASK_SUSPENDED]	= "SUSPENDED",
	[AIRY_TASK_TERMINATING]	= "TERMINATING",
	[AIRY_TASK_DEAD]	= "DEAD",
};

/* ─── State name lookup ──────────────────────────────────────────────── */
const char *airy_task_state_name(enum airy_task_state state)
{
	unsigned int idx = (unsigned int)state;

	if (idx >= AIRY_TASK_STATE_MAX)
		return "UNKNOWN";
	return airy_task_state_names[idx];
}

/* ─── State transition validation ────────────────────────────────────── */
int airy_task_state_transition(enum airy_task_state *state,
			       enum airy_task_state next)
{
	enum airy_task_state cur;

	if (!state)
		return -EINVAL;

	cur = *state;

	/* DEAD is terminal — no transitions out. */
	if (cur == AIRY_TASK_DEAD)
		return -EINVAL;

	switch (next) {
	case AIRY_TASK_SPAWNING:
		if (cur != AIRY_TASK_INACTIVE)
			return -EINVAL;
		break;
	case AIRY_TASK_READY:
		if (cur != AIRY_TASK_SPAWNING && cur != AIRY_TASK_RUNNING &&
		    cur != AIRY_TASK_BLOCKED && cur != AIRY_TASK_SUSPENDED)
			return -EINVAL;
		break;
	case AIRY_TASK_RUNNING:
		if (cur != AIRY_TASK_READY)
			return -EINVAL;
		break;
	case AIRY_TASK_BLOCKED:
		if (cur != AIRY_TASK_RUNNING)
			return -EINVAL;
		break;
	case AIRY_TASK_SUSPENDED:
		if (cur != AIRY_TASK_RUNNING && cur != AIRY_TASK_READY)
			return -EINVAL;
		break;
	case AIRY_TASK_TERMINATING:
		if (cur == AIRY_TASK_INACTIVE)
			return -EINVAL;
		break;
	case AIRY_TASK_DEAD:
		if (cur != AIRY_TASK_TERMINATING)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	*state = next;
	return 0;
}

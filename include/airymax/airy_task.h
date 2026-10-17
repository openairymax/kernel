/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Kernel-internal surface of the Airymax taskflow: initialisation and
 * validation of the [SC] struct airy_task_desc, and the agent 8-state
 * lifecycle machine that runs on it. The descriptor carries both the
 * agent identity and the lifecycle state, and taskflow is its single
 * in-kernel writer, so every accepted transition emits one
 * airy_agent_state_change event from the committed state value
 * (include/trace/events/airy.h) instead of a parallel copy of it.
 *
 * SSoT: 30-interfaces/10-sc-sched-extension.md §2, §6.1;
 *       90-observability/08-agent-tracing.md §7.1.
 */

#ifndef _AIRY_TASK_H
#define _AIRY_TASK_H

#include <linux/types.h>

#include <linux/airymax/sched.h>
#include <airymax/airy_trace.h>

/* Descriptor lifecycle (kernel/corekern/taskflow/airy_task_desc.c). */
/**
 * airy_task_desc_init - initialise a task descriptor in place
 * @desc: descriptor to initialise; must be writable
 *
 * Return: 0 on success; -EINVAL when @desc is NULL or its magic shows
 *         corruption.
 */
int airy_task_desc_init(struct airy_task_desc *desc);

/**
 * airy_task_desc_valid - test whether a descriptor is initialised
 * @desc: descriptor to test
 *
 * Return: true when @desc is non-NULL and carries AIRY_TASK_MAGIC.
 */
bool airy_task_desc_valid(const struct airy_task_desc *desc);

/* State machine (kernel/corekern/taskflow/airy_task_lifecycle.c). */
/**
 * airy_task_state_name - name of a lifecycle state for observability
 * @state: state to name
 *
 * Return: the constant state name, or "UNKNOWN" when @state is out of
 *         the [SC] range.
 */
const char *airy_task_state_name(enum airy_agent_state state);

/**
 * airy_task_state_transition - commit a lifecycle transition
 * @desc: descriptor whose state is advanced
 * @next: requested next state
 * @reason: trigger for the transition, from enum airy_trace_reason
 *
 * Validates @next against the current state per the [SC] transition
 * table, commits it, and emits airy_agent_state_change. On failure
 * @desc is left untouched.
 *
 * Return: 0 when the transition is committed; -EINVAL when @desc is
 *         uninitialised, a state lies outside the [SC] range, or the
 *         transition is illegal.
 */
int airy_task_state_transition(struct airy_task_desc *desc,
			       enum airy_agent_state next,
			       enum airy_trace_reason reason);

#endif /* _AIRY_TASK_H */

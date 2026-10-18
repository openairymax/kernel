// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_freeze.c — freeze every IPC ring owned by an agent.
 *
 * A FREEZE command names an agent, not a task, and an agent may span
 * several tasks with one ring each.  Rings are located by walking the
 * process list and matching the agent id in the task blob; there is no
 * agent id to task index that would have to track fork and exit.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §3.5
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

/*
 * sv_ring_freeze - freeze one task's ring when the task is @agent_id.
 * @task: task under the RCU walk; its lifetime is pinned by the caller
 * @agent_id: agent whose rings are being frozen
 * @reason: AIRY_FAULT_* code recorded in the ring
 *
 * Return: true when a ring was frozen; false when the task belongs to
 *         another agent or owns no ring.
 */
static bool sv_ring_freeze(struct task_struct *task, __u32 agent_id,
			   __u32 reason)
{
	struct airy_ipc_ring_freeze_state *ring;

	/*
	 * The idle task and tasks created before the LSM was active may
	 * still carry a NULL blob; they own no agent and no ring.
	 */
	if (!task->security)
		return false;

	if (airy_agent_id(task) != agent_id)
		return false;

	/*
	 * Membership in the process list keeps the task_struct valid
	 * under RCU but does not stop an exiting task from reaching
	 * security_task_free(), which releases the ring.  Pinning the
	 * task across the lookup keeps the ring allocation alive for the
	 * store below.
	 */
	get_task_struct(task);
	ring = airy_ipc_ring_for_task(task);
	if (ring)
		airy_ipc_freeze_ring(ring, reason);
	put_task_struct(task);

	return ring != NULL;
}

/**
 * airy_sv_freeze - freeze every IPC ring owned by an agent
 * @ctx: protocol context; commands are refused unless it is RUNNING
 * @agent_id: target agent; zero is the unbound sentinel and is refused
 * @reason: AIRY_FAULT_* code recorded in each ring and in the event
 *
 * Malformed commands are rejected before the readiness gate: a bad
 * target is a caller bug whether or not the layer is up, and reporting
 * it as -EAGAIN would hide the real fault.  The walk runs under
 * rcu_read_lock() because for_each_process_thread() does not take the
 * task list lock.
 *
 * Return: 0 when at least one ring was frozen, else the negated error
 *         documented on the declaration.
 */
int airy_sv_freeze(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 reason)
{
	struct task_struct *g, *t;
	__u32 nr_frozen = 0;

	if (!agent_id)
		return -EINVAL;
	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return -AIRY_ECAP_OVERFLOW;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	rcu_read_lock();
	for_each_process_thread(g, t)
		nr_frozen += sv_ring_freeze(t, agent_id, reason);
	rcu_read_unlock();

	if (!nr_frozen)
		return -AIRY_EIPC_CONTEXT;

	airy_eventfd_signal_fault(reason, agent_id, ktime_get_mono_fast_ns());

	return 0;
}

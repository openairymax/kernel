// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_task.c — locate the tasks that belong to a supervised agent.
 *
 * A supervisor command names an agent, not a task, and an agent may
 * span several tasks. There is no agent id to task index in the kernel,
 * so the tasks are located by walking the process list and matching the
 * agent id in each task's security blob. This keeps fork and exit free
 * of bookkeeping that would have to stay in step with the walk.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §3.5
 */

#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <airymax/airy_agent.h>

#include "airy_superv.h"

int airy_sv_id_chk(__u32 agent_id)
{
	if (unlikely(!agent_id))
		return -EINVAL;
	if (unlikely(agent_id >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_OVERFLOW;

	return 0;
}

/*
 * sv_task_match - does @task belong to @agent_id?
 * @task: task under the RCU walk
 * @agent_id: agent whose tasks are being collected
 *
 * The idle task and tasks created before the LSM was active may still
 * carry a NULL blob; they own no agent and no ring.
 */
static bool sv_task_match(const struct task_struct *task, __u32 agent_id)
{
	if (!task->security)
		return false;

	return airy_agent_id(task) == agent_id;
}

unsigned int airy_sv_walk(__u32 agent_id, airy_sv_task_fn fn, void *arg)
{
	struct task_struct *g, *t;
	unsigned int hits = 0;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (!sv_task_match(t, agent_id))
			continue;

		/*
		 * Membership in the process list keeps the task_struct
		 * valid under RCU but does not stop an exiting task from
		 * reaching security_task_free(), which releases the ring.
		 * Pinning the task across the callback keeps every blob
		 * member alive for the access inside it.
		 */
		get_task_struct(t);
		fn(t, arg);
		put_task_struct(t);
		hits++;
	}
	rcu_read_unlock();

	return hits;
}

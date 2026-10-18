// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_ring.c — supervisor-driven IPC ring state transitions.
 *
 * A supervisor command names an agent, not a task, and an agent may
 * span several tasks with one ring each.  Rings are located by walking
 * the process list and matching the agent id in the task blob; there
 * is no agent id to task index that would have to track fork and exit.
 *
 * Freeze and thaw both flip ring->frozen, so they share one lock: a
 * thaw that interleaved with a freeze could erase a freeze that had
 * already been reported to the supervisor as successful.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §3.5
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "../ipc/airy_ipc_capability.h"
#include "airy_superv.h"

/**
 * enum sv_ring_op - action applied to every matching ring
 * @SV_RING_PROBE: leave matching rings untouched
 * @SV_RING_FREEZE: freeze with the reason supplied by the command
 * @SV_RING_THAW: clear the frozen flag and its metadata
 */
enum sv_ring_op {
	SV_RING_PROBE,
	SV_RING_FREEZE,
	SV_RING_THAW,
};

/**
 * struct sv_ring_stat - what a walk found
 * @rings: matching rings owned by the agent
 * @frozen: of those, the ones frozen before the action was applied
 */
struct sv_ring_stat {
	__u32 rings;
	__u32 frozen;
};

static DEFINE_MUTEX(sv_ring_lock);

/*
 * sv_target_chk - reject agent ids outside the supervised range.
 * @agent_id: id copied from the command
 *
 * Zero is the unbound sentinel: a task that never joined an agent
 * carries it, so a command naming zero can never match.  The upper
 * bound keeps every use of the id inside agent_caps[].
 *
 * Return: 0 when @agent_id names a possible agent.
 */
static int sv_target_chk(__u32 agent_id)
{
	if (!agent_id)
		return -EINVAL;
	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return -AIRY_ECAP_OVERFLOW;

	return 0;
}

/*
 * sv_ring_match - does @task belong to @agent_id?
 * @task: task under the RCU walk
 * @agent_id: agent whose rings are being collected
 *
 * The idle task and tasks created before the LSM was active may still
 * carry a NULL blob; they own no agent and no ring.
 */
static bool sv_ring_match(struct task_struct *task, __u32 agent_id)
{
	if (!task->security)
		return false;

	return airy_agent_id(task) == agent_id;
}

static void sv_ring_act(struct airy_ipc_ring_freeze_state *ring,
			enum sv_ring_op op, __u32 reason)
{
	switch (op) {
	case SV_RING_FREEZE:
		airy_ipc_freeze_ring(ring, reason);
		break;
	case SV_RING_THAW:
		airy_ipc_thaw_ring(ring);
		break;
	default:
		break;
	}
}

/*
 * sv_ring_walk - apply @op to every ring owned by @agent_id.
 * @agent_id: agent whose rings are visited
 * @op: action to apply
 * @reason: fault code recorded by a freeze; ignored otherwise
 *
 * The returned frozen count is sampled before @op runs, so a probe
 * sees the live count and a freeze sees the rings frozen beforehand.
 *
 * Return: the number of matching and frozen rings.
 */
static struct sv_ring_stat sv_ring_walk(__u32 agent_id, enum sv_ring_op op,
					__u32 reason)
{
	struct sv_ring_stat stat = { };
	struct task_struct *g, *t;
	struct airy_ipc_ring_freeze_state *ring;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (!sv_ring_match(t, agent_id))
			continue;

		/*
		 * Membership in the process list keeps the task_struct
		 * valid under RCU but does not stop an exiting task from
		 * reaching security_task_free(), which releases the ring.
		 * Pinning the task across the lookup keeps the ring
		 * allocation alive for the access below.
		 */
		get_task_struct(t);
		ring = airy_ipc_ring_for_task(t);
		if (ring) {
			if (READ_ONCE(ring->frozen))
				stat.frozen++;
			sv_ring_act(ring, op, reason);
			stat.rings++;
		}
		put_task_struct(t);
	}
	rcu_read_unlock();

	return stat;
}

int airy_sv_freeze(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 reason)
{
	struct sv_ring_stat stat;
	int ret = sv_target_chk(agent_id);

	if (ret)
		return ret;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	mutex_lock(&sv_ring_lock);
	stat = sv_ring_walk(agent_id, SV_RING_FREEZE, reason);
	mutex_unlock(&sv_ring_lock);

	if (!stat.rings)
		return -AIRY_EIPC_CONTEXT;

	airy_eventfd_signal_fault(reason, agent_id, ktime_get_mono_fast_ns());

	return 0;
}

int airy_sv_thaw(struct airy_sv_ctx *ctx, __u32 agent_id)
{
	struct sv_ring_stat stat;
	int ret = sv_target_chk(agent_id);

	if (ret)
		return ret;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	mutex_lock(&sv_ring_lock);
	stat = sv_ring_walk(agent_id, SV_RING_PROBE, 0);

	if (!stat.rings) {
		mutex_unlock(&sv_ring_lock);
		return -AIRY_EIPC_CONTEXT;
	}

	/*
	 * Retire every outstanding badge before any ring reopens: a ring
	 * that resumed first would accept a message stamped with the very
	 * badge this thaw is meant to invalidate.
	 *
	 * An agent whose rings are all live is already running.  There is
	 * nothing to reopen, so the epoch is left untouched rather than
	 * revoking every badge in the system for a redundant command.
	 */
	if (stat.frozen) {
		airy_cap_epoch_bump_all();
		sv_ring_walk(agent_id, SV_RING_THAW, 0);
	}

	mutex_unlock(&sv_ring_lock);

	return 0;
}

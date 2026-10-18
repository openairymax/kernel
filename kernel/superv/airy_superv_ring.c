// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_ring.c — supervisor-driven IPC ring state transitions.
 *
 * A supervisor command names an agent, not a task, and an agent may
 * span several tasks with one ring each. The matching tasks come from
 * airy_sv_walk(); this file decides what happens to their rings.  A
 * lost macro_d has no agent to name, so the same machinery also runs
 * system-wide through airy_sv_frz_all().
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
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>

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
 * struct sv_ring_req - one ring operation and what the walk found
 * @op: action applied to every matching ring
 * @reason: fault code recorded by a freeze; ignored otherwise
 * @rings: matching rings owned by the agent
 * @frozen: of those, the ones frozen before the action was applied
 */
struct sv_ring_req {
	enum sv_ring_op op;
	__u32 reason;
	__u32 rings;
	__u32 frozen;
};

static DEFINE_MUTEX(sv_ring_lock);

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

static void sv_ring_task(struct task_struct *task, void *arg)
{
	struct sv_ring_req *req = arg;
	struct airy_ipc_ring_freeze_state *ring;

	ring = airy_ipc_ring_for_task(task);
	if (!ring)
		return;

	if (READ_ONCE(ring->frozen))
		req->frozen++;
	sv_ring_act(ring, req->op, req->reason);
	req->rings++;
}

/*
 * sv_ring_run - apply one ring operation to an agent or to all agents
 * @agent_id: target agent; ignored when @all is set
 * @all: apply the operation to every supervised task
 * @op: action applied to each matching ring
 * @reason: fault code recorded by a freeze
 *
 * Return: 0 when at least one ring matched; -AIRY_EIPC_CONTEXT
 *         otherwise.
 */
static int sv_ring_run(__u32 agent_id, bool all, enum sv_ring_op op,
		       __u32 reason)
{
	struct sv_ring_req req = {
		.op = op,
		.reason = reason,
	};

	mutex_lock(&sv_ring_lock);
	if (all)
		airy_sv_each(sv_ring_task, &req);
	else
		airy_sv_walk(agent_id, sv_ring_task, &req);
	mutex_unlock(&sv_ring_lock);

	return req.rings ? 0 : -AIRY_EIPC_CONTEXT;
}

int airy_sv_frz(__u32 agent_id, __u32 reason)
{
	int ret = airy_sv_id_chk(agent_id);

	if (ret)
		return ret;

	return sv_ring_run(agent_id, false, SV_RING_FREEZE, reason);
}

int airy_sv_frz_all(__u32 reason)
{
	return sv_ring_run(0, true, SV_RING_FREEZE, reason);
}

int airy_sv_freeze(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 reason)
{
	int ret = airy_sv_id_chk(agent_id);

	if (ret)
		return ret;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	ret = airy_sv_frz(agent_id, reason);
	if (ret)
		return ret;

	airy_eventfd_signal_fault(reason, agent_id, ktime_get_mono_fast_ns());

	return 0;
}

int airy_sv_thaw(struct airy_sv_ctx *ctx, __u32 agent_id)
{
	struct sv_ring_req probe = { .op = SV_RING_PROBE };
	struct sv_ring_req thaw = { .op = SV_RING_THAW };
	int ret = airy_sv_id_chk(agent_id);

	if (ret)
		return ret;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	mutex_lock(&sv_ring_lock);
	airy_sv_walk(agent_id, sv_ring_task, &probe);

	if (!probe.rings) {
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
	if (probe.frozen) {
		airy_cap_epoch_bump_all();
		airy_sv_walk(agent_id, sv_ring_task, &thaw);
	}

	mutex_unlock(&sv_ring_lock);

	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_adjud.c — apply a supervisor verdict to an agent.
 *
 * The verdict names an agent, not a task. Every task that carries the
 * agent id is transitioned, so a multi-threaded agent cannot keep one
 * thread running after its siblings were paused or killed.
 *
 * TERMINATE contains before it kills: the badge is retired and the
 * rings are frozen first, then the tasks are marked DEAD and signalled.
 * A task therefore never runs with a badge that has already been
 * revoked, and no peer can feed it through a ring after the verdict.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §1.4
 */

#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/sched.h>
#include <airymax/airy_agent.h>
#include <airymax/airy_trace.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define SV_NICE_DEGRADED	MAX_NICE
#define SV_NICE_NEUTRAL		0

/**
 * struct sv_adjud_req - one verdict handed to every matching task
 * @adjud: one of &enum airy_adjud
 * @reason: diagnostic context recorded in the trace event
 */
struct sv_adjud_req {
	__u32 adjud;
	__u32 reason;
};

static DEFINE_MUTEX(sv_adjud_lock);

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
static const enum airy_superv_action sv_act_map[AIRY_ADJUD_NR] = {
	[AIRY_ADJUD_WARN]	= AIRY_SUPERV_ACTION_WARN,
	[AIRY_ADJUD_DEGRADE]	= AIRY_SUPERV_ACTION_DEGRADE,
	[AIRY_ADJUD_PAUSE]	= AIRY_SUPERV_ACTION_PAUSE,
	[AIRY_ADJUD_TERMINATE]	= AIRY_SUPERV_ACTION_TERMINATE,
	[AIRY_ADJUD_RESUME]	= AIRY_SUPERV_ACTION_RESUME,
};
#endif

static struct airy_task_sec *sv_sec(struct task_struct *task)
{
	return task->security + airy_blob_sizes.lbs_task;
}

static void sv_resume_task(struct task_struct *task, struct airy_task_sec *sec)
{
	if (task_nice(task) == SV_NICE_DEGRADED)
		set_user_nice(task, SV_NICE_NEUTRAL);

	if (READ_ONCE(sec->agent_state) != AIRY_AGENT_STOPPED)
		return;

	WRITE_ONCE(sec->agent_state, AIRY_AGENT_READY);
	send_sig(SIGCONT, task, 1);
}

static void sv_act_task(struct task_struct *task, void *arg)
{
	struct sv_adjud_req *req = arg;
	struct airy_task_sec *sec = sv_sec(task);

	switch (req->adjud) {
	case AIRY_ADJUD_WARN:
		break;
	case AIRY_ADJUD_DEGRADE:
		set_user_nice(task, SV_NICE_DEGRADED);
		break;
	case AIRY_ADJUD_PAUSE:
		WRITE_ONCE(sec->agent_state, AIRY_AGENT_STOPPED);
		send_sig(SIGSTOP, task, 1);
		break;
	case AIRY_ADJUD_TERMINATE:
		WRITE_ONCE(sec->agent_state, AIRY_AGENT_DEAD);
		send_sig(SIGKILL, task, 1);
		break;
	case AIRY_ADJUD_RESUME:
		sv_resume_task(task, sec);
		break;
	default:
		break;
	}
}

/*
 * sv_contain - retire the agent's authority before its tasks die.
 * @agent_id: target agent, already validated by the caller
 * @reason: fault code recorded in each ring
 *
 * A task that has already exited owns no ring, so the context error is
 * expected here and deliberately dropped: containment is best effort,
 * the kill below is what makes the verdict final.
 */
static void sv_contain(__u32 agent_id, __u32 reason)
{
	airy_cap_unreg(agent_id);
	airy_sv_frz(agent_id, reason);
}

static void sv_report(__u32 agent_id, __u32 adjud, __u32 reason)
{
	if (adjud == AIRY_ADJUD_WARN)
		pr_info_ratelimited("airy: agent %u warned (reason %u)\n",
				    agent_id, reason);

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_superv_enforce(agent_id, sv_act_map[adjud], reason);
#endif
}

int airy_sv_adjud(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 adjud,
		  __u32 reason)
{
	struct sv_adjud_req req = { .adjud = adjud, .reason = reason };
	unsigned int tasks;
	int ret = airy_sv_id_chk(agent_id);

	if (ret)
		return ret;
	if (adjud >= AIRY_ADJUD_NR)
		return -EINVAL;
	if (!airy_sv_ready(ctx))
		return -EAGAIN;

	/*
	 * One verdict at a time: a PAUSE racing a TERMINATE could leave a
	 * task STOPPED with its badge already retired. The ring lock is
	 * taken inside sv_contain(), so the order is adjud -> ring and
	 * never the reverse.
	 */
	mutex_lock(&sv_adjud_lock);
	if (adjud == AIRY_ADJUD_TERMINATE)
		sv_contain(agent_id, reason);

	tasks = airy_sv_walk(agent_id, sv_act_task, &req);
	mutex_unlock(&sv_adjud_lock);

	if (!tasks)
		return -AIRY_EIPC_CONTEXT;

	sv_report(agent_id, adjud, reason);

	return 0;
}

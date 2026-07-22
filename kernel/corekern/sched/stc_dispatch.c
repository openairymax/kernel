// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_dispatch.c — sched_tac dispatch to native Linux scheduling classes.
 *
 * Maps an Airymax sched_tac policy onto a native Linux scheduling class
 * (SCHED_DEADLINE / SCHED_FIFO / SCHED_NORMAL(EEVDF) / SCHED_BATCH),
 * records the dispatch via stc_stats, logs the mapping, and applies the
 * scheduling class via sched_set_scheduler().
 */

#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/err.h>
#include <linux/airymax/sched.h>

#include "stc_policy.h"

/* ─── sched_set_scheduler() — declared extern, not invoked here ──────── */
extern int sched_set_scheduler(struct task_struct *p, int policy,
			       const struct sched_param *param);

/* ─── Map stc policy → native Linux SCHED_* policy ───────────────────── */
static int stc_policy_to_linux(unsigned int policy)
{
	switch (policy) {
	case AIRY_SCHED_POLICY_DEADLINE:
		return SCHED_DEADLINE;
	case AIRY_SCHED_POLICY_FIFO:
		return SCHED_FIFO;
	case AIRY_SCHED_POLICY_EEVDF:
		return SCHED_NORMAL;	/* EEVDF is the default for SCHED_NORMAL */
	case AIRY_SCHED_POLICY_BESTEFFORT:
		return SCHED_BATCH;
	default:
		return -EINVAL;
	}
}

static const char *stc_linux_policy_name(int linux_policy)
{
	switch (linux_policy) {
	case SCHED_DEADLINE:	return "SCHED_DEADLINE";
	case SCHED_FIFO:	return "SCHED_FIFO";
	case SCHED_NORMAL:	return "SCHED_NORMAL(EEVDF)";
	case SCHED_BATCH:	return "SCHED_BATCH";
	default:		return "SCHED_UNKNOWN";
	}
}

/* ─── Dispatch enqueue ───────────────────────────────────────────────── */
int stc_dispatch_enqueue(struct task_struct *tsk, enum airy_sched_policy policy)
{
	unsigned int pol = (unsigned int)policy;
	int linux_policy;
	int ret;
	const char *stc_name;
	struct sched_param param = { .sched_priority = 0 };

	if (!tsk)
		return -EINVAL;

	linux_policy = stc_policy_to_linux(pol);
	if (linux_policy < 0) {
		pr_warn_ratelimited("stc_dispatch: unknown policy %u\n", pol);
		return -EINVAL;
	}

	stc_name = stc_policy_name(policy);

	pr_info("stc_dispatch: %s → %s (pid=%d comm=%s)\n",
		stc_name, stc_linux_policy_name(linux_policy),
		tsk->pid, tsk->comm);

	stc_stats_record_dispatch(policy);

	/*
	 * Apply the resolved scheduling class via sched_set_scheduler().
	 * SCHED_FIFO requires a non-zero RT priority in [1, MAX_RT_PRIO-1];
	 * all other policies (SCHED_NORMAL, SCHED_BATCH, SCHED_DEADLINE)
	 * expect sched_priority == 0.
	 */
	param.sched_priority = (linux_policy == SCHED_FIFO) ? 1 : 0;

	ret = sched_set_scheduler(tsk, linux_policy, &param);
	if (ret) {
		pr_warn_ratelimited("stc_dispatch: sched_set_scheduler(%s) failed: %d (pid=%d)\n",
				    stc_linux_policy_name(linux_policy),
				    ret, tsk->pid);
		return ret;
	}

	return 0;
}

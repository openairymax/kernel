// SPDX-License-Identifier: GPL-2.0-only
/*
 * AirymaxOS ALK cognition phase record behind syscall 551.
 *
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 551 carries one `phase` argument that is a unified operation code:
 * 0/1/2 are the [SC] CoreLoopThree phases PERCEPT/THINK/ACT of
 * cognition_types.h; from AIRY_COG_PHASE_MAX upwards it is a
 * kthread-class operation owned by module F, which this release does
 * not implement. The record keeps only what 551 promises: the phase an
 * agent last notified. See airy_clt.h for the contract SSoT.
 *
 * A record is a single aligned __u32, so notify and query use
 * READ_ONCE()/WRITE_ONCE() without a lock: no multi-field invariant and
 * no read-modify-write, as airy_cap_epoch_bump() does for its lone
 * epoch. Zero-fill would alias AIRY_COG_PERCEPT, so the table is
 * seeded to AIRY_CLT_PHASE_UNSET at late init.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/syscalls.h>

#include "airy_clt.h"
#include "airy_sysabi.h"

/* ─── Per-agent phase record ──────────────────────────────────────────── */

static __u32 airy_clt_phases[AIRY_CAP_MAX_AGENTS];

static int __init airy_clt_init(void)
{
	unsigned int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++)
		WRITE_ONCE(airy_clt_phases[i], AIRY_CLT_PHASE_UNSET);

	return 0;
}
late_initcall(airy_clt_init);

/**
 * airy_clt_notify - Record a CoreLoopThree phase notification.
 * @task_id: Target cognition agent identity.
 * @phase:   CoreLoopThree phase (AIRY_COG_PERCEPT/THINK/ACT).
 *
 * Write side of the phase record behind syscall 551. @phase is stored
 * exactly as notified: the caller has already answered the reserved
 * operation space with -AIRY_ECOG_PHASE, and no transition state is kept
 * because the CoreLoopThree sequence belongs to the module F kthread,
 * not to this table.
 *
 * Return: AIRY_EOK on success; -EINVAL when @task_id is negative;
 *         -AIRY_ECAP_OVERFLOW when @task_id is outside the agent table.
 */
__must_check int airy_clt_notify(int task_id, __u32 phase)
{
	if (unlikely(task_id < 0))
		return -EINVAL;

	if (unlikely(task_id >= AIRY_CAP_MAX_AGENTS)) {
		pr_debug_ratelimited("airy_clt_notify: task=%d out of range (MAX=%u)\n",
				     task_id, AIRY_CAP_MAX_AGENTS);
		return -AIRY_ECAP_OVERFLOW;
	}

	WRITE_ONCE(airy_clt_phases[task_id], phase);

	return AIRY_EOK;
}

/**
 * airy_clt_query - Read back the last notified phase of a task.
 * @task_id: Target cognition agent identity.
 * @phase:   Out-parameter receiving the recorded phase.
 *
 * Read side of the phase record, and the observation hook KUnit uses to
 * prove what airy_clt_notify() stored. @phase is written only on success;
 * AIRY_CLT_PHASE_UNSET means the task has never notified a phase.
 *
 * Return: AIRY_EOK on success; -EINVAL when @phase is NULL or @task_id is
 *         negative; -AIRY_ECAP_OVERFLOW when @task_id is out of range.
 */
__must_check int airy_clt_query(int task_id, __u32 *phase)
{
	if (unlikely(!phase))
		return -EINVAL;

	if (unlikely(task_id < 0))
		return -EINVAL;

	if (unlikely(task_id >= AIRY_CAP_MAX_AGENTS)) {
		pr_debug_ratelimited("airy_clt_query: task=%d out of range (MAX=%u)\n",
				     task_id, AIRY_CAP_MAX_AGENTS);
		return -AIRY_ECAP_OVERFLOW;
	}

	*phase = READ_ONCE(airy_clt_phases[task_id]);

	return AIRY_EOK;
}

/* ─── Syscall 551 entry policy ────────────────────────────────────────── */

/**
 * airy_clt_serve - Serve the phase half of syscall 551.
 * @task_id: Target cognition agent identity.
 * @phase:   Unified 551 operation code.
 *
 * Validates @phase before anything else, so a value reserved for the
 * module F kthread (AIRY_COG_PHASE_MAX and upwards) is refused with
 * -AIRY_ECOG_PHASE without the phase table or the identity being
 * examined. Only a CoreLoopThree phase is handed to airy_clt_notify(),
 * which owns the identity range check and the write.
 *
 * Return: AIRY_EOK on success; -AIRY_ECOG_PHASE when @phase is reserved;
 *         otherwise what airy_clt_notify() returns.
 */
__must_check int airy_clt_serve(int task_id, __u32 phase)
{
	int ret = airy_op_check(AIRY_SYS_CLT_NOTIFY, phase);

	if (unlikely(ret))
		return ret;

	return airy_clt_notify(task_id, phase);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_stats.c — sched_tac dispatch statistics.
 *
 * Maintains a global atomic counter of stc_dispatch_enqueue() invocations
 * plus a per-policy breakdown, queryable via stc_stats_read().
 */

#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/bug.h>
#include <linux/array_size.h>
#include <linux/airymax/sched.h>

#include "stc_policy.h"

/* ─── Statistics counters ────────────────────────────────────────────── */
static atomic_t stc_dispatch_count = ATOMIC_INIT(0);
static atomic_t stc_policy_count[4] = {
	ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0)
};

/* ─── Record a dispatch event ────────────────────────────────────────── */
void stc_stats_record_dispatch(enum airy_sched_policy policy)
{
	unsigned int idx = (unsigned int)policy;

	atomic_inc(&stc_dispatch_count);

	if (idx < ARRAY_SIZE(stc_policy_count))
		atomic_inc(&stc_policy_count[idx]);
}

/* ─── Read aggregate dispatch count ──────────────────────────────────── */
int stc_stats_read(void)
{
	return atomic_read(&stc_dispatch_count);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_mcs_map.c — seL4 MCS (Mixed-Criticality Systems) semantic mapping.
 *
 * Translates seL4 MCS criticality flags into Linux kernel primitives:
 * scheduling policy and GFP allocation hints.  The returned int encodes
 * the native SCHED_* policy in the low 16 bits and a GFP mask hint in
 * the high 16 bits.
 */

#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/airymax/sched.h>

/* ─── seL4 MCS criticality flag bits (userspace contract) ────────────── */
#define STC_MCS_FLAG_REALTIME		0x01	/* Hard real-time criticality */
#define STC_MCS_FLAG_HIGH		0x02	/* High criticality */
#define STC_MCS_FLAG_NORMAL		0x04	/* Normal criticality */
#define STC_MCS_FLAG_BACKGROUND		0x08	/* Background / best-effort */
#define STC_MCS_FLAG_PREEMPT		0x10	/* Explicitly preemptible */
#define STC_MCS_FLAG_ATOMIC		0x20	/* Non-preemptible region */

/* ─── MCS → Linux scheduling policy + GFP hint ───────────────────────── */
int stc_mcs_to_linux(int mcs_flags)
{
	int linux_policy;
	gfp_t gfp;

	if (mcs_flags & STC_MCS_FLAG_REALTIME) {
		linux_policy = SCHED_DEADLINE;
		gfp = GFP_ATOMIC | __GFP_HIGH;
	} else if (mcs_flags & STC_MCS_FLAG_HIGH) {
		linux_policy = SCHED_FIFO;
		gfp = GFP_KERNEL | __GFP_HIGH;
	} else if (mcs_flags & STC_MCS_FLAG_NORMAL) {
		linux_policy = SCHED_NORMAL;
		gfp = GFP_KERNEL;
	} else {
		linux_policy = SCHED_BATCH;
		gfp = GFP_KERNEL | __GFP_NORETRY;
	}

	/*
	 * Atomic/non-preemptible requests always get GFP_ATOMIC so the
	 * allocator never sleeps inside a critical region.
	 */
	if (mcs_flags & STC_MCS_FLAG_ATOMIC)
		gfp = GFP_ATOMIC;

	return (int)(((unsigned int)gfp << 16) | (linux_policy & 0xffff));
}

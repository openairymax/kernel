/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_policy.h — Internal header for the sched_tac policy taxonomy.
 *
 * Exports the airy_sched_policy enum and the function prototypes shared
 * across stc_policy.c, stc_dispatch.c, and stc_stats.c. The numeric
 * values intentionally match the [SC] AIRY_SCHED_POLICY_* macros defined
 * in <linux/airymax/sched.h> so the two naming schemes are
 * interchangeable at the UAPI boundary.
 */

#ifndef _STC_POLICY_H
#define _STC_POLICY_H

#include <linux/airymax/sched.h>

/* Forward declaration — full definition in <linux/sched.h> */
struct task_struct;

/* ─── sched_tac policy enumeration ───────────────────────────────────── */
enum airy_sched_policy {
	STC_POLICY_REALTIME    = AIRY_SCHED_POLICY_DEADLINE,   /* 1 → SCHED_DEADLINE */
	STC_POLICY_INTERACTIVE = AIRY_SCHED_POLICY_FIFO,       /* 2 → SCHED_FIFO     */
	STC_POLICY_AGENT       = AIRY_SCHED_POLICY_EEVDF,      /* 3 → EEVDF          */
	STC_POLICY_BATCH       = AIRY_SCHED_POLICY_BESTEFFORT, /* 4 → SCHED_BATCH    */
	STC_POLICY_MAX
};

/* ─── Function prototypes ────────────────────────────────────────────── */
const char *stc_policy_name(enum airy_sched_policy policy);
void stc_stats_record_dispatch(enum airy_sched_policy policy);
int stc_stats_read(void);
int stc_dispatch_enqueue(struct task_struct *tsk,
			 enum airy_sched_policy policy);

#endif /* _STC_POLICY_H */

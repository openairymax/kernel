// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_policy.c — sched_tac policy taxonomy (4 classes).
 *
 * Defines the four Airymax scheduling policies (stc_realtime,
 * stc_interactive, stc_agent, stc_batch) and their canonical name
 * strings.  The numeric values intentionally match the [SC]
 * AIRY_SCHED_POLICY_* macros so the two naming schemes are
 * interchangeable at the UAPI boundary.
 */

#include <linux/printk.h>
#include <linux/airymax/sched.h>

#include "stc_policy.h"

/* ─── sched_tac policy name table ────────────────────────────────────── */
static const char * const stc_policy_names[] = {
	[STC_POLICY_REALTIME]    = "stc_realtime",
	[STC_POLICY_INTERACTIVE] = "stc_interactive",
	[STC_POLICY_AGENT]       = "stc_agent",
	[STC_POLICY_BATCH]       = "stc_batch",
};

/* ─── Policy name lookup ─────────────────────────────────────────────── */
const char *stc_policy_name(enum airy_sched_policy policy)
{
	unsigned int idx = (unsigned int)policy;

	if (idx >= STC_POLICY_MAX)
		return "stc_unknown";
	return stc_policy_names[idx];
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_eventfd_superv.c — Micro-Supervisor eventfd notification delegator.
 *
 * Thin wrapper that delegates eventfd-based fault signalling to the
 * LSM module's airy_eventfd_signal_fault().
 *
 * Renamed from airy_eventfd.c to airy_eventfd_superv.c per OS-STD-001
 * to resolve the name clash with security/airy/airy_eventfd.c.
 */

#include <linux/eventfd.h>
#include <linux/printk.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── Delegates (declared in security/airy/airy_cap.h) ────────────────── */
extern void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
				      __u64 timestamp);

/* ─── Superv-side Wrappers ────────────────────────────────────────────── */

int airy_superv_eventfd_register(struct eventfd_ctx *ctx)
{
	/* Delegates to LSM airy_eventfd_register() */
	extern int airy_eventfd_register(struct eventfd_ctx *ctx);
	int ret = airy_eventfd_register(ctx);

	if (ret)
		pr_warn_ratelimited("airy_superv: eventfd register failed: %d\n", ret);
	return ret;
}

void airy_superv_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
				      __u64 timestamp)
{
	airy_eventfd_signal_fault(fault_code, agent_id, timestamp);
}

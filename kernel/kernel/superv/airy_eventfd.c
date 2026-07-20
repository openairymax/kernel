/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_eventfd.c — Micro-Supervisor eventfd notification delegator.
 *
 * Thin wrapper that delegates eventfd-based fault signalling to the
 * LSM module's airy_eventfd_signal_fault().
 */

#include <linux/eventfd.h>
#include <airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── Delegates (declared in security/airy/airy_cap.h) ────────────────── */
extern void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
				      __u64 timestamp);

/* ─── Superv-side Wrappers ────────────────────────────────────────────── */

void airy_superv_eventfd_register(struct eventfd_ctx *ctx)
{
	/* Delegates to LSM airy_eventfd_register() */
	extern int airy_eventfd_register(struct eventfd_ctx *ctx);
	airy_eventfd_register(ctx);
}

void airy_superv_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
				      __u64 timestamp)
{
	airy_eventfd_signal_fault(fault_code, agent_id, timestamp);
}

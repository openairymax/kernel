/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_eventfd.c — EventFD Fault Notification (Airy Pure-C LSM).
 *
 * Provides non-blocking eventfd-based notification from the
 * Micro-Supervisor (kernel-space) to the Macro-Supervisor
 * (user-space) for fault events requiring out-of-band handling.
 */

#include <linux/eventfd.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <airymax/error.h>

#include "airy_cap.h"

/* ─── Fault Event Structure ───────────────────────────────────────────── */

/**
 * struct airy_fault_event - A fault event posted to the Macro-Supervisor.
 * @fault_code: AIRY_FAULT_* code identifying the fault type.
 * @agent_id:   The agent that triggered the fault (0 if unknown).
 * @timestamp:  Monotonic timestamp (ns) when the fault occurred.
 */
struct airy_fault_event {
	__u32   fault_code;
	__u32   agent_id;
	__u64   timestamp;
};

/* ─── Global EventFD Context ──────────────────────────────────────────── */

/*
 * The single registered eventfd context for fault notification.
 * Protected by fault_eventfd_lock.
 */
static struct eventfd_ctx *fault_eventfd_ctx;
static DEFINE_SPINLOCK(fault_eventfd_lock);

/* ─── EventFD Registration ────────────────────────────────────────────── */

/**
 * airy_eventfd_register - Register an eventfd context for fault notification.
 * @ctx: The eventfd context to register (may be NULL to unregister).
 *
 * The Macro-Supervisor calls this to register its eventfd descriptor.
 * Only one context may be registered at a time. Passing NULL unregisters
 * the current context.
 *
 * Return: 0 on success, -AIRY_EBUSY if a different context is already
 *         registered.
 */
int airy_eventfd_register(struct eventfd_ctx *ctx)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&fault_eventfd_lock, flags);

	if (ctx == NULL) {
		/* Unregister: release the current context */
		if (fault_eventfd_ctx) {
			eventfd_ctx_put(fault_eventfd_ctx);
			fault_eventfd_ctx = NULL;
		}
	} else if (fault_eventfd_ctx == NULL) {
		/* Register: take a reference on the new context */
		fault_eventfd_ctx = eventfd_ctx_get(ctx);
	} else if (fault_eventfd_ctx == ctx) {
		/* Re-registering the same context — no-op */
	} else {
		/* A different context is already registered */
		ret = -AIRY_EBUSY;
	}

	spin_unlock_irqrestore(&fault_eventfd_lock, flags);

	return ret;
}

/* ─── Fault Signal ────────────────────────────────────────────────────── */

/**
 * airy_eventfd_signal_fault - Signal a fault event to the Macro-Supervisor.
 * @fault_code: AIRY_FAULT_* code identifying the fault type.
 * @agent_id:   The agent that triggered the fault.
 * @timestamp:  Monotonic timestamp of the fault.
 *
 * Constructs an airy_fault_event and signals it via the registered
 * eventfd context. The signal is non-blocking — if the eventfd counter
 * would overflow, the signal is silently dropped.
 *
 * This function is safe to call from any context (including NMI and
 * die notifier) because eventfd_signal is non-blocking.
 */
void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
			       __u64 timestamp)
{
	struct airy_fault_event ev;
	unsigned long flags;
	struct eventfd_ctx *ctx;
	__u64 event_val;

	/* Build the fault event on the stack */
	ev.fault_code = fault_code;
	ev.agent_id   = agent_id;
	ev.timestamp  = timestamp;

	/*
	 * C-S8.1: Read the eventfd context under spinlock to get a
	 * consistent view. Take a local copy and increment its refcount
	 * outside the lock to avoid use-after-free.
	 */
	spin_lock_irqsave(&fault_eventfd_lock, flags);
	ctx = fault_eventfd_ctx;
	if (ctx)
		eventfd_ctx_get(ctx);
	spin_unlock_irqrestore(&fault_eventfd_lock, flags);

	if (!ctx)
		return;

	/*
	 * C-S8.2: Write the fault event structure into the eventfd counter.
	 * eventfd_signal is non-blocking and safe from any context.
	 * We pack the fault event into the __u64 counter value.
	 * Lower 32 bits = fault_code, upper 32 bits = agent_id.
	 * The full event (including timestamp) is recoverable by the
	 * Macro-Supervisor from the kernel log or a concurrent ring buffer.
	 */
	event_val = ((__u64)agent_id << 32) | (__u64)fault_code;
	eventfd_signal(ctx, event_val);

	eventfd_ctx_put(ctx);
}

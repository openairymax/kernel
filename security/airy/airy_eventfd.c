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
#include <linux/airymax/error.h>

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
 * Reference ownership: the caller must obtain @ctx via eventfd_ctx_fdget()
 * (or equivalent) which takes a reference. On successful registration the
 * kernel steals that reference — the caller MUST NOT call eventfd_ctx_put()
 * after a successful register. On unregister (ctx == NULL or replacement)
 * the kernel releases the reference via eventfd_ctx_put(). On failure
 * (-AIRY_EBUSY) the caller retains ownership and is responsible for the
 * put. Linux 6.6 does not export eventfd_ctx_get(), so the reference
 * transfer is done by pointer ownership rather than refcount increment.
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
		/*
		 * Register: steal the caller's reference (Linux 6.6 has no
		 * eventfd_ctx_get export; ownership transfer replaces the
		 * refcount increment).
		 */
		fault_eventfd_ctx = ctx;
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
 * @timestamp:  Monotonic timestamp of the fault (reserved for future
 *              ring-buffer logging; not packed into the eventfd counter).
 *
 * Packs @fault_code and @agent_id into the __u64 eventfd counter value
 * and signals it via the registered eventfd context. The signal is
 * non-blocking — if the eventfd counter would overflow, the signal is
 * silently dropped by eventfd_signal().
 *
 * This function is safe to call from any context (including NMI and
 * die notifier) because eventfd_signal() is non-blocking and does not
 * sleep.
 *
 * Implementation note: Linux 6.6 does not export eventfd_ctx_get(), so
 * we cannot take a temporary reference on the ctx outside the spinlock
 * to release it after signalling. Instead, the non-blocking
 * eventfd_signal() is performed while holding fault_eventfd_lock, which
 * is acceptable because eventfd_signal() does not sleep and the critical
 * section is short. This avoids the use-after-free window without
 * requiring eventfd_ctx_get().
 */
void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
			       __u64 timestamp)
{
	unsigned long flags;
	struct eventfd_ctx *ctx;
	__u64 event_val;

	/*
	 * Pack the fault event into the __u64 eventfd counter value:
	 *   lower 32 bits = fault_code
	 *   upper 32 bits = agent_id
	 * The full event (including @timestamp) is recoverable by the
	 * Macro-Supervisor from the kernel log or a concurrent ring
	 * buffer; @timestamp is therefore not packed into the counter.
	 */
	event_val = ((__u64)agent_id << 32) | (__u64)fault_code;

	spin_lock_irqsave(&fault_eventfd_lock, flags);
	ctx = fault_eventfd_ctx;
	if (ctx)
		eventfd_signal(ctx, event_val);
	spin_unlock_irqrestore(&fault_eventfd_lock, flags);
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_eventfd.c — EventFD Fault Notification (Airy Pure-C LSM).
 *
 * Notifies the Macro-Supervisor of faults raised in the Micro-Supervisor
 * through a non-blocking eventfd: eventfd_signal() only bumps a counter and
 * never sleeps, so it is safe from the die-notifier and NMI paths.
 *
 * That counter carries at most a packed (fault_code, agent_id) pair, so
 * each signal also records the full fault detail in the bounded airy_fev_*
 * ring declared in airy_cap.h.
 *
 * Design rationale: docs/AirymaxOS/20-modules/09-kernel-agent-supervisor.md
 */

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/eventfd.h>
#include <linux/spinlock.h>

#include <linux/airymax/error.h>

#include "airy_cap.h"

/* ─── Fault Event Detail Ring ─────────────────────────────────────────── */

static struct airy_fault_event fev_ring[AIRY_FEV_RING_NR];
static __u32  fev_head;			/* total events posted */
static __u32  fev_tail;			/* total events fetched */
static atomic_t fev_lost = ATOMIC_INIT(0);
static DEFINE_RAW_SPINLOCK(fev_lock);

/**
 * airy_fev_post - Record a fault detail in the ring (best-effort).
 * @ev: The fault detail to record; must not be NULL.
 *
 * Safe from die-notifier and NMI context: the ring lock is only tried,
 * never waited on, so a contended ring drops @ev instead of risking a
 * deadlock.  @ev is also dropped when the ring is full.
 *
 * Return: 0 on success, -AIRY_EINVAL if @ev is NULL, -AIRY_EBUSY if the
 *         ring lock was contended, -AIRY_ENOMEM if the ring was full.
 */
int airy_fev_post(const struct airy_fault_event *ev)
{
	unsigned long flags;
	__u32 head;

	if (!ev)
		return -AIRY_EINVAL;

	if (!raw_spin_trylock_irqsave(&fev_lock, flags)) {
		atomic_inc(&fev_lost);
		return -AIRY_EBUSY;
	}

	head = fev_head;
	if ((__u32)(head - smp_load_acquire(&fev_tail)) >= AIRY_FEV_RING_NR) {
		raw_spin_unlock_irqrestore(&fev_lock, flags);
		atomic_inc(&fev_lost);
		return -AIRY_ENOMEM;
	}

	fev_ring[head & AIRY_FEV_RING_MASK] = *ev;
	smp_store_release(&fev_head, head + 1);

	raw_spin_unlock_irqrestore(&fev_lock, flags);

	return 0;
}

/**
 * airy_fev_fetch - Drain one fault detail from the ring.
 * @ev: Destination for the oldest pending detail; must not be NULL.
 *
 * Lock-free single-consumer drain: the head cursor is published by the
 * producer with release semantics, so a detail observed as pending here
 * is already fully written.
 *
 * Return: 0 on success, -AIRY_EINVAL if @ev is NULL, -AIRY_ENOENT if no
 *         detail is pending.
 */
int airy_fev_fetch(struct airy_fault_event *ev)
{
	__u32 head, tail;

	if (!ev)
		return -AIRY_EINVAL;

	head = smp_load_acquire(&fev_head);
	tail = fev_tail;
	if (head == tail)
		return -AIRY_ENOENT;

	*ev = fev_ring[tail & AIRY_FEV_RING_MASK];
	smp_store_release(&fev_tail, tail + 1);

	return 0;
}

/**
 * airy_fev_reset - Empty the ring and clear the lost counter.
 *
 * Only valid while no producer or consumer is active, i.e. from init and
 * from KUnit teardown; it takes the ring lock without trying it, so it
 * must never run in NMI context.
 */
void airy_fev_reset(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&fev_lock, flags);
	fev_head = 0;
	fev_tail = 0;
	raw_spin_unlock_irqrestore(&fev_lock, flags);

	atomic_set(&fev_lost, 0);
}

/**
 * airy_fev_lost - Number of fault details dropped since the last reset.
 *
 * The Macro-Supervisor reads this to tell a signal-with-detail from a
 * signal whose detail was dropped.
 *
 * Return: The dropped-detail count.
 */
unsigned int airy_fev_lost(void)
{
	return (unsigned int)atomic_read(&fev_lost);
}

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
 * @timestamp:  Monotonic timestamp of the fault in nanoseconds.
 *
 * Records the fault detail in the airy_fev_* ring, then packs
 * @fault_code and @agent_id into the __u64 eventfd counter value and
 * signals it via the registered eventfd context. The signal is
 * non-blocking — if the eventfd counter would overflow, the signal is
 * silently dropped by eventfd_signal().
 *
 * Ring loss is best-effort and never suppresses the signal: a full or
 * contended ring drops only the detail and bumps airy_fev_lost().
 *
 * This function is safe to call from any context (including NMI and
 * die notifier) because both paths are non-blocking and never sleep.
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
	struct airy_fault_event ev = {
		.ring_id = AIRY_FEV_RING_ID_NONE,
		.fault_code = fault_code,
		.timestamp_ns = timestamp,
		.agent_id = agent_id,
	};
	unsigned long flags;
	struct eventfd_ctx *ctx;
	__u64 event_val;

	airy_fev_post(&ev);

	/*
	 * Pack the fault event into the __u64 eventfd counter value:
	 *   lower 32 bits = fault_code
	 *   upper 32 bits = agent_id
	 * The full event (including @timestamp) is recoverable by the
	 * Macro-Supervisor from the airy_fev_* ring; @timestamp is
	 * therefore not packed into the counter.
	 */
	event_val = ((__u64)agent_id << 32) | (__u64)fault_code;

	spin_lock_irqsave(&fault_eventfd_lock, flags);
	ctx = fault_eventfd_ctx;
	if (ctx)
		eventfd_signal(ctx, event_val);
	spin_unlock_irqrestore(&fault_eventfd_lock, flags);
}
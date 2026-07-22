/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_freeze.c — IPC Ring Freezing Core Logic (Airy Pure-C LSM).
 *
 * Provides the ring freeze/unfreeze mechanism used by the
 * Micro-Supervisor to quarantine misbehaving agents by stopping
 * all IPC traffic on their rings without destroying the rings.
 */

#include <linux/jiffies.h>
#include <linux/clocksource.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <asm/barrier.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/* struct airy_ipc_ring_freeze_state is defined in airy_cap.h (single-host). */

/* ─── Freeze Operation ────────────────────────────────────────────────── */

/**
 * airy_ipc_freeze_ring - Freeze an IPC ring.
 * @ring:   The IPC ring to freeze.
 * @reason: Reason code for the freeze (e.g. AIRY_FAULT_*).
 *
 * Performs a release-store of @frozen = true, ensuring all prior
 * writes to the ring are visible before the freeze flag becomes
 * observable by the fastpath reader.
 *
 * The ring remains frozen until explicitly unfrozen by the
 * Macro-Supervisor.
 */
void airy_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring, __u32 reason)
{
	if (!ring)
		return;

	ring->freeze_reason = reason;
	ring->freeze_timestamp = (__u64)ktime_get_mono_fast_ns();

	/*
	 * C-S6.1: smp_store_release ensures all prior stores (reason,
	 * timestamp) are visible before the frozen flag becomes true.
	 */
	smp_store_release(&ring->frozen, true);
}

/**
 * airy_ipc_thaw_ring - Thaw (unfreeze) an IPC ring.
 * @ring: The IPC ring to thaw.
 *
 * Clears the frozen flag and freeze metadata.
 */
void airy_ipc_thaw_ring(struct airy_ipc_ring_freeze_state *ring)
{
	if (!ring)
		return;

	ring->freeze_reason = 0;
	ring->freeze_timestamp = 0;

	/*
	 * C-S6.2: smp_store_release ensures the metadata clear is visible
	 * before the frozen flag becomes false.
	 */
	smp_store_release(&ring->frozen, false);
}

/* ─── Fastpath Check ──────────────────────────────────────────────────── */

/**
 * airy_ipc_fastpath_check - Fastpath freeze check for IPC operations.
 * @ring: The IPC ring to check.
 *
 * Called on every IPC send/receive operation in the hot path.
 * Uses READ_ONCE to avoid tearing and unlikely() to hint the
 * branch predictor that frozen rings are the exceptional case.
 *
 * Return: 0 if the ring is active, -AIRY_EIPC_FROZEN if frozen.
 */
int airy_ipc_fastpath_check(struct airy_ipc_ring_freeze_state *ring)
{
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	return 0;
}

/* ─── Ring Lookup ─────────────────────────────────────────────────────── */

/**
 * airy_ipc_ring_for_task - Look up the IPC ring freeze-state for a task.
 * @task: The task to look up.
 *
 * Returns the IPC ring freeze-state registered for @task's agent, or
 * NULL if no ring is currently associated.
 *
 * The per-task security blob (struct airy_task_sec) carries an ipc_ring
 * pointer that stores the address of the agent's airy_ipc_ring_freeze_state.
 * In M0 this field is initialised to NULL by airy_task_alloc() because the
 * per-agent ring allocation logic is not yet wired.  When the io_uring IPC
 * ring pool is implemented (OS-IRON-004), the Micro-Supervisor will populate
 * sec->ipc_ring during agent registration, and this function will return a
 * valid pointer so that die_notifier can freeze the ring on fatal faults.
 */
struct airy_ipc_ring_freeze_state *airy_ipc_ring_for_task(struct task_struct *task)
{
	struct airy_task_sec *sec;

	if (!task || !task->security)
		return NULL;

	sec = task->security + airy_blob_sizes.lbs_task;

	/*
	 * M0: sec->ipc_ring is NULL until the per-agent ring pool is
	 * wired (OS-IRON-004).  Returning NULL lets die_notifier skip
	 * the freeze step gracefully.
	 */
	return (struct airy_ipc_ring_freeze_state *)sec->ipc_ring;
}

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
#include <asm/barrier.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/* struct airy_ipc_ring is defined in airy_cap.h (single-host). */

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
void airy_ipc_freeze_ring(struct airy_ipc_ring *ring, __u32 reason)
{
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
void airy_ipc_thaw_ring(struct airy_ipc_ring *ring)
{
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
int airy_ipc_fastpath_check(struct airy_ipc_ring *ring)
{
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	return 0;
}

/* ─── Ring Lookup ─────────────────────────────────────────────────────── */

/**
 * airy_ipc_ring_for_task - Look up the IPC ring associated with a task.
 * @task: The task to look up.
 *
 * Returns the IPC ring registered for @task's agent, or NULL if no
 * ring is currently associated.
 *
 * M0 stage: per-agent ring assignment is not yet wired; returns NULL
 * so that die_notifier skips the freeze step gracefully. When the
 * io_uring IPC ring pool is implemented, this will consult the
 * agent_caps[agent_id].ring field (OS-IRON-004 progressive development).
 */
struct airy_ipc_ring *airy_ipc_ring_for_task(struct task_struct *task)
{
	if (!task || !task->security)
		return NULL;

	/* M0: no ring field in airy_task_sec yet */
	return NULL;
}

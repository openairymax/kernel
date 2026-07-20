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
#include <asm/barrier.h>
#include <airymax/error.h>

#include "airy_cap.h"

/* ─── IPC Ring Structure ──────────────────────────────────────────────── */

/**
 * struct airy_ipc_ring - An IPC ring buffer between two agents.
 * @frozen:           Whether the ring is currently frozen.
 * @freeze_reason:    Reason code for the freeze (0 if not frozen).
 * @freeze_timestamp: Monotonic timestamp (ns) when the ring was frozen.
 */
struct airy_ipc_ring {
	bool    frozen;
	__u32   freeze_reason;
	__u64   freeze_timestamp;
};

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

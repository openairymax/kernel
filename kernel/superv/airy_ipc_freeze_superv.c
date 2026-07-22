/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_freeze_superv.c — Micro-Supervisor IPC ring freeze delegator.
 *
 * Thin wrapper that delegates ring freeze / thaw operations to the
 * LSM module's airy_ipc_freeze_ring() and airy_ipc_thaw_ring().
 *
 * Renamed from airy_ipc_freeze.c to airy_ipc_freeze_superv.c per OS-STD-001
 * to resolve the name clash with security/airy/airy_ipc_freeze.c.
 */

#include <asm/barrier.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* struct airy_ipc_ring_freeze_state is defined in airy_cap.h (single-host). */

/* ─── Delegates (declared in security/airy/) ──────────────────────────── */
extern void airy_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring,
				__u32 reason);
extern void airy_ipc_thaw_ring(struct airy_ipc_ring_freeze_state *ring);

/* ─── Superv-side Wrappers ────────────────────────────────────────────── */

void airy_superv_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring,
				 __u32 reason)
{
	airy_ipc_freeze_ring(ring, reason);
}

void airy_superv_ipc_thaw_ring(struct airy_ipc_ring_freeze_state *ring)
{
	airy_ipc_thaw_ring(ring);
}

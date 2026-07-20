/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_freeze.c — Micro-Supervisor IPC ring freeze delegator.
 *
 * Thin wrapper that delegates ring freeze / thaw operations to the
 * LSM module's airy_ipc_freeze_ring() and airy_ipc_thaw_ring().
 */

#include <asm/barrier.h>
#include <airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── IPC Ring (matching LSM definition) ──────────────────────────────── */

struct airy_ipc_ring {
	bool    frozen;
	__u32   freeze_reason;
	__u64   freeze_timestamp;
};

/* ─── Delegates (declared in security/airy/) ──────────────────────────── */
extern void airy_ipc_freeze_ring(struct airy_ipc_ring *ring, __u32 reason);
extern void airy_ipc_thaw_ring(struct airy_ipc_ring *ring);

/* ─── Superv-side Wrappers ────────────────────────────────────────────── */

void airy_superv_ipc_freeze_ring(struct airy_ipc_ring *ring, __u32 reason)
{
	airy_ipc_freeze_ring(ring, reason);
}

void airy_superv_ipc_thaw_ring(struct airy_ipc_ring *ring)
{
	airy_ipc_thaw_ring(ring);
}

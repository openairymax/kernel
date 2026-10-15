// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Hot-path send: a single unlikely() check on the ring's frozen flag,
 * then delegation to airy_ipc_ring_post(). Not an IPC entry point:
 * the only legal entry is the io_uring IORING_OP_URING_CMD path, after
 * the LSM five-phase check has validated the Badge (C-S9).
 *
 * Design rationale: docs/AirymaxOS/30-interfaces/07-ipc-fastpath.md
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

/* ─── Fast-path send ─────────────────────────────────────────────────── */
/*
 * Post a message to the IPC ring after the caller has validated the
 * agent's Badge via C-S9 (airy_cap_badge_ok).  See the file-level
 * comment above for the full Badge decision path.
 *
 * ring:  destination ring (must be initialised via airy_ipc_ring_init)
 * hdr:   message header to post (caller ensures valid magic/payload)
 *
 * Returns 0 on success, -EINVAL for null arguments, -AIRY_EIPC_FROZEN
 * if the ring is administratively frozen.
 */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr)
{
	if (!ring || !hdr)
		return -EINVAL;

	/* Fast path: bail out immediately if the ring is quiesced.
	 * Return -AIRY_EIPC_FROZEN (not generic -EAGAIN) so userland can
	 * distinguish "ring administratively frozen" from "transient retry".
	 *
	 * This is the ONLY safety gate in the fastpath: the caller has
	 * already passed C-S9 Badge validation (see file-level comment),
	 * so a valid badge reaching this point is authoritative.  The
	 * frozen check catches the race where the Micro-Supervisor
	 * suspends the agent between C-S9 and ring_post.
	 */
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	/* Delegate to ring_post() which performs the actual slot write.
	 * ring_post() re-checks frozen (defence in depth) and validates
	 * magic before writing. */
	return airy_ipc_ring_post(ring, hdr);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Implements the hot-path send: a single unlikely() check on the ring's
 * frozen flag, then delegation to airy_ipc_ring_post().  This is the
 * fast-path entry point for AIRY_IPC_OP_SEND.
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

/* ─── Fast-path send ─────────────────────────────────────────────────── */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr)
{
	if (!ring || !hdr)
		return -EINVAL;

	/* Fast path: bail out immediately if the ring is quiesced.
	 * Return -AIRY_EIPC_FROZEN (not generic -EAGAIN) so userland can
	 * distinguish "ring administratively frozen" from "transient retry".
	 */
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	return airy_ipc_ring_post(ring, hdr);
}

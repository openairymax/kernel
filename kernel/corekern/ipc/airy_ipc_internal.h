/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_internal.h — internal shared declarations for the Airymax
 * corekern IPC subdirectory.
 *
 * Defines struct airy_ipc_ring and declares the ring/fastpath/zero-copy
 * entry points shared across airy_ipc_ring.c, airy_ipc_fastpath.c,
 * airy_ipc_zero_copy.c and airy_uring_cmd.c.
 */

#ifndef _AIRY_IPC_INTERNAL_H
#define _AIRY_IPC_INTERNAL_H

#include <linux/types.h>
#include <linux/airymax/ipc.h>

struct vm_area_struct;
struct page;
struct io_uring_cmd;

/* ─── Ring Buffer ────────────────────────────────────────────────────── */
struct airy_ipc_ring {
	u32	head;		/* producer cursor (next write slot) */
	u32	tail;		/* consumer cursor (next read slot)  */
	u32	mask;		/* capacity-1 (ring size must be 2^N) */
	u32	frozen;		/* non-zero when ring is quiesced    */
};

int airy_ipc_ring_init(struct airy_ipc_ring *ring, u32 entries);
int airy_ipc_ring_post(struct airy_ipc_ring *ring,
		       const struct airy_ipc_msg_hdr *hdr);

/* ─── Fastpath ──────────────────────────────────────────────────────── */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr);

/* ─── Zero-copy ─────────────────────────────────────────────────────── */
int airy_ipc_zero_copy_register(unsigned long base, size_t len);
int airy_ipc_zero_copy_map(struct vm_area_struct *vma, struct page **pages,
			   unsigned long nr_pages);

/* ─── io_uring command entry ────────────────────────────────────────── */
int airy_uring_cmd_handle(struct io_uring_cmd *ioucmd);

#endif /* _AIRY_IPC_INTERNAL_H */

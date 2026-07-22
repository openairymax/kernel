// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_ring.c — Airymax IPC ring buffer management.
 *
 * Implements a power-of-2 single-producer/single-consumer ring with a
 * frozen flag for quiescing.  The cursor state lives in struct
 * airy_ipc_ring (defined in airy_ipc_internal.h); message headers are
 * stored in the slots[] array allocated by airy_ipc_ring_init().
 */

#include <linux/printk.h>
#include <linux/bug.h>
#include <linux/log2.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_internal.h"

/* ─── Ring initialisation ────────────────────────────────────────────── */
int airy_ipc_ring_init(struct airy_ipc_ring *ring, u32 entries)
{
	if (!ring)
		return -EINVAL;

	/* Capacity must be a power of two so mask = entries - 1 works. */
	if (!is_power_of_2(entries) || entries < 2)
		return -EINVAL;

	ring->head   = 0;
	ring->tail   = 0;
	ring->mask   = entries - 1;
	ring->frozen = 0;

	/* Allocate the message header storage array (one slot per entry). */
	ring->slots = kcalloc(entries, sizeof(*ring->slots), GFP_KERNEL);
	if (!ring->slots)
		return -ENOMEM;

	pr_info("airy_ipc_ring: initialised ring with %u entries\n", entries);
	return 0;
}

/* ─── Tear down a ring and free its message storage ──────────────────── */
void airy_ipc_ring_destroy(struct airy_ipc_ring *ring)
{
	if (!ring)
		return;

	kfree(ring->slots);
	ring->slots = NULL;
}

/* ─── Post a message header to the ring ──────────────────────────────── */
int airy_ipc_ring_post(struct airy_ipc_ring *ring,
		       const struct airy_ipc_msg_hdr *hdr)
{
	u32 next;

	if (!ring || !hdr || !ring->slots)
		return -EINVAL;

	if (READ_ONCE(ring->frozen))
		return -EAGAIN;

	if (hdr->magic != AIRY_IPC_MAGIC) {
		pr_warn_ratelimited("airy_ipc_ring: bad magic 0x%08x\n",
				    hdr->magic);
		return -EINVAL;
	}

	/* Single-producer advance: head only moves forward by one slot. */
	next = (ring->head + 1) & ring->mask;
	if (next == ring->tail) {
		pr_warn_ratelimited("airy_ipc_ring: ring full (head=%u tail=%u)\n",
				    ring->head, ring->tail);
		return -ENOSPC;
	}

	/* Store the message header into the current slot before advancing. */
	memcpy(&ring->slots[ring->head], hdr, sizeof(*hdr));
	ring->head = next;
	return 0;
}

/* ─── Consume a message header from the ring ────────────────────────── */
int airy_ipc_ring_consume(struct airy_ipc_ring *ring,
			  struct airy_ipc_msg_hdr *out)
{
	u32 next;

	if (!ring || !out || !ring->slots)
		return -EINVAL;

	/* Ring empty: head == tail. */
	if (ring->head == ring->tail)
		return -ENOMSG;

	if (READ_ONCE(ring->frozen))
		return -EAGAIN;

	/* Single-consumer advance: tail only moves forward by one slot. */
	memcpy(out, &ring->slots[ring->tail], sizeof(*out));
	next = (ring->tail + 1) & ring->mask;
	ring->tail = next;

	return 0;
}

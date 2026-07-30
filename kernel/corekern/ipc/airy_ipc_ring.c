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
#include <linux/atomic.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

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
		return -AIRY_EIPC_FROZEN;

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

	/* Store the message header into the current slot before advancing.
	 *
	 * smp_store_release() pairs with smp_load_acquire() in
	 * airy_ipc_ring_consume().  It ensures the memcpy (data store)
	 * is visible before the head advance (index store) on
	 * weakly-ordered architectures (ARM64, etc.).  Without this
	 * barrier, the consumer could see the new head before the data,
	 * reading stale/uninitialised memory.
	 */
	memcpy(&ring->slots[ring->head], hdr, sizeof(*hdr));
	smp_store_release(&ring->head, next);
	return 0;
}

/* ─── Consume a message header from the ring ────────────────────────── */
int airy_ipc_ring_consume(struct airy_ipc_ring *ring,
			  struct airy_ipc_msg_hdr *out)
{
	u32 next;

	if (!ring || !out || !ring->slots)
		return -EINVAL;

	/*
	 * Skip cancelled messages.  cancelBadgedSends() zeroes the magic
	 * field of cancelled slots; the consumer must advance past them
	 * without returning their data.  This loop is bounded by the ring
	 * capacity, so it always terminates.
	 *
	 * We re-check head on each iteration because the producer may add
	 * new (non-cancelled) messages while we are skipping.
	 */
	for (;;) {
		__u32 tail = ring->tail;

		/* Ring empty? */
		if (smp_load_acquire(&ring->head) == tail)
			return -ENOMSG;

		if (READ_ONCE(ring->frozen))
			return -AIRY_EIPC_FROZEN;

		/* If magic != 0 the slot holds a valid message. */
		if (READ_ONCE(ring->slots[tail].magic) != 0)
			break;

		/* Cancelled slot — advance tail past it. */
		next = (tail + 1) & ring->mask;
		ring->tail = next;
	}

	/*
	 * smp_load_acquire() above pairs with smp_store_release() in
	 * airy_ipc_ring_post().  It ensures the head read is ordered
	 * before the subsequent memcpy (data read), preventing the
	 * consumer from reading stale/uninitialised slot data on
	 * weakly-ordered architectures (ARM64, etc.).
	 */

	/* Single-consumer advance: tail only moves forward by one slot. */
	memcpy(out, &ring->slots[ring->tail], sizeof(*out));
	next = (ring->tail + 1) & ring->mask;
	ring->tail = next;

	return 0;
}

/* ─── Cancel all pending sends with a specific badge (P1-8) ─────────── */
/*
 * Walk the ring's pending region (tail..head) and cancel every message
 * whose capability_badge matches @badge.  Cancellation is performed by
 * zeroing the slot's magic field; airy_ipc_ring_consume() skips slots
 * with magic == 0.
 *
 * This is the agentrt-linux equivalent of seL4's cancelBadgedSends
 * (endpoint.c:476-489), which removes all pending send operations on
 * an endpoint that were made with a given badge.  It is invoked when a
 * badge is revoked (airy_cap_derive REVOKE) to ensure that messages
 * posted with the now-invalid badge are never delivered.
 *
 * Concurrency: the ring is SPSC, but this function may be called by a
 * third party (the Micro-Supervisor or revocation path).  We snapshot
 * head (acquire) and tail (READ_ONCE) to determine the pending range.
 * Writes to slot->magic use WRITE_ONCE, which is safe because:
 *   - The producer only writes to slots[head] (outside our scan range).
 *   - The consumer reads slots[tail] then advances tail; if we zero a
 *     slot's magic while the consumer is mid-memcpy, the consumer
 *     still returns the original valid message (magic was non-zero
 *     when it decided to read the slot).  The zeroed magic only
 *     matters on the next consume pass.
 *
 * Returns the number of messages cancelled (0 = no match), or
 * -EINVAL if @ring is NULL or uninitialised.
 */
int airy_ipc_cancel_badged_sends(struct airy_ipc_ring *ring, __u64 badge)
{
	u32 head, tail, i;
	int cancelled = 0;

	if (!ring || !ring->slots)
		return -EINVAL;

	/* Snapshot the pending region [tail, head). */
	head = smp_load_acquire(&ring->head);
	tail = READ_ONCE(ring->tail);

	pr_debug_ratelimited("airy_ipc_cancel_badged_sends: ring=%p badge=0x%016llx head=%u tail=%u\n",
		ring, (unsigned long long)badge, head, tail);

	for (i = tail; i != head; i = (i + 1) & ring->mask) {
		struct airy_ipc_msg_hdr *slot = &ring->slots[i];

		if (READ_ONCE(slot->capability_badge) == badge) {
			pr_debug_ratelimited("airy_ipc_cancel_badged_sends: cancelling slot=%u badge=0x%016llx\n",
				i, (unsigned long long)badge);
			WRITE_ONCE(slot->magic, 0);
			cancelled++;
		}
	}

	pr_debug_ratelimited("airy_ipc_cancel_badged_sends: cancelled %d message(s)\n",
		cancelled);
	return cancelled;
}

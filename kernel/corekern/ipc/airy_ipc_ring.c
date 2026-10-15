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

	/* Capacity must be a power of two so mask = entries - 1 works, and
	 * must not exceed the shared ceiling so a single ring cannot pin an
	 * unbounded amount of memory.
	 */
	if (!is_power_of_2(entries) || entries < 2 ||
	    entries > AIRY_IPC_RING_MAX_ENTRIES)
		return -EINVAL;

	ring->head   = 0;
	ring->tail   = 0;
	ring->mask   = entries - 1;
	ring->frozen = 0;

	/* Fresh occupancy accounting: no backlog, no rejections yet. */
	ring->peak_depth = 0;
	ring->full_count = 0;

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
/*
 * Returns 0 on success, -EINVAL for null/invalid arguments,
 * -AIRY_EIPC_FROZEN (C-S0) if the ring is administratively frozen,
 * -AIRY_EIPC_MAGIC (C-S1) if the header magic is not 'ARE1', or
 * -AIRY_EIPC_KFIFO (C-S6) when the ring is exactly full.
 */
int airy_ipc_ring_post(struct airy_ipc_ring *ring,
		       const struct airy_ipc_msg_hdr *hdr)
{
	u32 next, tail, depth;

	if (!ring || !hdr || !ring->slots)
		return -EINVAL;

	if (READ_ONCE(ring->frozen))
		return -AIRY_EIPC_FROZEN;

	if (hdr->magic != AIRY_IPC_MAGIC) {
		pr_warn_ratelimited("airy_ipc_ring: bad magic 0x%08x\n",
				    hdr->magic);
		return -AIRY_EIPC_MAGIC;
	}

	/* Single-producer advance: head only moves forward by one slot. */
	next = (ring->head + 1) & ring->mask;

	/*
	 * The fullness check reads the consumer-owned tail with acquire
	 * semantics, pairing with the smp_store_release() that
	 * airy_ipc_ring_consume() uses to publish tail.  This orders the
	 * subsequent slot store after the observed tail, so the producer
	 * never overwrites a slot the consumer has not yet finished
	 * reading on weakly-ordered architectures (ARM64, etc.).
	 */
	tail = smp_load_acquire(&ring->tail);
	if (next == tail) {
		/* The nightly monitor fails the run on any full rejection. */
		WRITE_ONCE(ring->full_count, ring->full_count + 1);
		pr_warn_ratelimited("airy_ipc_ring: ring full (head=%u tail=%u)\n",
				    ring->head, tail);
		return -AIRY_EIPC_KFIFO;
	}

	/*
	 * Occupancy after this post.  The producer is the only writer of
	 * the high-water mark, so a WRITE_ONCE() read-modify-write keeps
	 * it accurate without additional locking.
	 */
	depth = (next - tail) & ring->mask;
	if (depth > READ_ONCE(ring->peak_depth))
		WRITE_ONCE(ring->peak_depth, depth);

	/* Store the message header into the current slot before advancing. */
	memcpy(&ring->slots[ring->head], hdr, sizeof(*hdr));

	/*
	 * smp_store_release() pairs with smp_load_acquire() in
	 * airy_ipc_ring_consume().  It ensures the memcpy (data store)
	 * is visible before the head advance (index store) on
	 * weakly-ordered architectures (ARM64, etc.).  Without this
	 * barrier, the consumer could see the new head before the data,
	 * reading stale/uninitialised memory.
	 */
	smp_store_release(&ring->head, next);
	return 0;
}

/* ─── Consume a message header from the ring ────────────────────────── */
int airy_ipc_ring_consume(struct airy_ipc_ring *ring,
			  struct airy_ipc_msg_hdr *out)
{
	__u32 tail;

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
		tail = READ_ONCE(ring->tail);

		/* Ring empty? */
		if (smp_load_acquire(&ring->head) == tail)
			return -ENOMSG;

		if (READ_ONCE(ring->frozen))
			return -AIRY_EIPC_FROZEN;

		/* If magic != 0 the slot holds a valid message. */
		if (READ_ONCE(ring->slots[tail].magic) != 0)
			break;

		/* Cancelled slot — advance tail past it. */
		smp_store_release(&ring->tail, (tail + 1) & ring->mask);
	}

	/*
	 * smp_load_acquire() above pairs with smp_store_release() in
	 * airy_ipc_ring_post().  It ensures the head read is ordered
	 * before the subsequent memcpy (data read), preventing the
	 * consumer from reading stale/uninitialised slot data on
	 * weakly-ordered architectures (ARM64, etc.).
	 */

	/* Single-consumer advance: tail only moves forward by one slot. */
	memcpy(out, &ring->slots[tail], sizeof(*out));

	/*
	 * smp_store_release() publishes the slot read above before the tail
	 * advance and pairs with the smp_load_acquire() in
	 * airy_ipc_ring_post()'s fullness check, mirroring the head-side
	 * pairing.
	 */
	smp_store_release(&ring->tail, (tail + 1) & ring->mask);

	return 0;
}

/* ─── Cancel all pending sends with a specific badge (P1-8) ─────────── */
/*
 * Walk the ring's pending region (tail..head) and cancel every message
 * whose capability_badge matches @badge.  Cancellation is performed by
 * zeroing the slot's magic field; airy_ipc_ring_consume() skips slots
 * with magic == 0.
 *
 * This is the agent-linux equivalent of seL4's cancelBadgedSends
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

	pr_debug_ratelimited("%s: ring=%p badge=0x%016llx head=%u tail=%u\n",
		__func__, ring, (unsigned long long)badge, head, tail);

	for (i = tail; i != head; i = (i + 1) & ring->mask) {
		struct airy_ipc_msg_hdr *slot = &ring->slots[i];

		if (READ_ONCE(slot->capability_badge) == badge) {
			pr_debug_ratelimited("%s: cancelling slot=%u badge=0x%016llx\n",
				__func__, i, (unsigned long long)badge);
			WRITE_ONCE(slot->magic, 0);
			cancelled++;
		}
	}

	pr_debug_ratelimited("%s: cancelled %d message(s)\n",
		__func__, cancelled);
	return cancelled;
}

/* ─── Ring depth statistics (nightly monitor source) ─────────────────── */
/*
 * Sample the ring occupancy for the nightly ring-depth monitor
 * (docs 80-testing §9.3: warn above 80% of capacity, fail the run on
 * any full rejection).  pct is depth/entries*100: entries is the
 * declared capacity, so a full ring (depth == entries - 1) reads 99,
 * never 100.
 *
 * Returns 0 and fills @out, or -EINVAL if @ring, @out or @ring->slots
 * is NULL: an uninitialised ring has no capacity to divide by.
 */
int airy_ipc_ring_depth_stats(struct airy_ipc_ring *ring,
			      struct airy_ipc_ring_depth *out)
{
	u32 head, tail, entries;

	if (!ring || !out || !ring->slots)
		return -EINVAL;

	/*
	 * A monitor needs each cursor to be a coherent, tear-free load
	 * and nothing more.  Unlike cancelBadgedSends() this path reads
	 * no slot data, so it takes no acquire barrier and READ_ONCE()
	 * suffices to keep the read KCSAN-atomic.
	 */
	head = READ_ONCE(ring->head);
	tail = READ_ONCE(ring->tail);
	entries = ring->mask + 1;

	out->entries = entries;
	out->depth = (head - tail) & ring->mask;
	out->pct = out->depth * 100 / entries;
	out->peak_depth = READ_ONCE(ring->peak_depth);
	out->full_count = READ_ONCE(ring->full_count);

	return 0;
}

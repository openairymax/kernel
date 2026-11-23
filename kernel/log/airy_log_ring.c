// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_ring.c — A-ULP 128-byte fixed-record lock-free ring buffer.
 *
 * Backed by alloc_pages(GFP_KERNEL) so the ring can be mmap()-ed into
 * agent address spaces for zero-copy streaming. Producers reserve a
 * slot via cmpxchg on head, fill the record, publish the slot through
 * its release-ordered sequence word, then advance committed_head over
 * the contiguous published prefix. Consumers read committed_head with
 * acquire semantics and never write shared state.
 * The shared header and the ring state live in airy_log_internal.h so
 * that the KUnit suite observes the same contract as the producers.
 *
 * Design rationale: docs/AirymaxOS/40-dataflows/05-ring-buffer-logging.md
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/eventfd.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/log_types.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

#include "airy_log_internal.h"

/* ─── Initialise a ring of at least @size bytes ────────────────────────
 * Allocates contiguous physical pages, places the ring header at the
 * start, and computes a power-of-two record capacity from the usable
 * space that remains after the header.
 */
int airy_log_ring_init(struct airy_log_ring *ring, size_t size)
{
	struct airy_log_ring_header *hdr;
	size_t usable, cap;

	if (!ring || size < PAGE_SIZE)
		return -EINVAL;

	ring->order = get_order(size);
	if (ring->order >= MAX_ORDER)
		return -EINVAL;

	ring->size  = PAGE_SIZE << ring->order;
	ring->pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, ring->order);
	if (!ring->pages)
		return -ENOMEM;

	ring->kaddr = page_address(ring->pages);
	ring->efd   = NULL;
	spin_lock_init(&ring->efd_lock);
	atomic64_set(&ring->overrun, 0);
	atomic64_set(&ring->writes, 0);

	/* Records start after the header; capacity must be a power of 2. */
	usable = ring->size - sizeof(struct airy_log_ring_header);
	cap    = usable / AIRY_LOG_RECORD_SIZE;
	if (cap < 2) {
		__free_pages(ring->pages, ring->order);
		ring->pages = NULL;
		ring->kaddr = NULL;
		return -EINVAL;
	}
	cap = rounddown_pow_of_two(cap);

	hdr = (struct airy_log_ring_header *)ring->kaddr;
	hdr->head          = 0;
	hdr->committed_head = 0;
	hdr->tail          = 0;
	hdr->capacity      = (__u32)cap;
	hdr->record_size   = AIRY_LOG_RECORD_SIZE;
	hdr->frozen        = 0;
	hdr->pad           = 0;

	return 0;
}

/* ─── Reserve a 128 B slot (producer side) ─────────────────────────────
 * Atomically claims the next slot by incrementing head via cmpxchg.
 * head is the reserve position — it advances BEFORE the record body
 * is written, so consumers must not read it directly; they observe
 * committed_head instead.  When the ring is full the earliest slot is
 * dropped by moving tail forward to head - capacity + 1.  tail is
 * owned by producers only: consumers keep a private cursor, so no
 * write race exists between the two sides.
 * Returns a pointer to the record for the caller to fill, or NULL
 * when the ring is frozen.  @pos receives the reservation position
 * required by airy_log_commit(); @overrun reports a dropped slot.
 */
struct airy_log_record *airy_log_reserve(struct airy_log_ring *ring, __u64 *pos,
					 bool *overrun)
{
	struct airy_log_ring_header *hdr;
	bool dropped = false;
	__u64 head, tail, want;
	__u32 idx;

	if (!ring || !ring->kaddr)
		return NULL;

	hdr = ring->kaddr;

	/* unlikely: 99 %+ of the time the ring is not frozen.
	 * Pairs with the smp_store_release() in airy_log_ring_freeze().
	 */
	if (unlikely(READ_ONCE(hdr->frozen)))
		return NULL;	/* caller falls back to printk_safe */

	do {
		head = smp_load_acquire(&hdr->head);
		tail = smp_load_acquire(&hdr->tail);

		dropped = head - tail >= hdr->capacity;
		if (dropped) {
			want = head - hdr->capacity + 1;
			if (want > tail)
				cmpxchg(&hdr->tail, tail, want);
		}

		idx = head % hdr->capacity;
	} while (cmpxchg(&hdr->head, head, head + 1) != head);

	if (dropped)
		atomic64_inc(&ring->overrun);
	if (overrun)
		*overrun = dropped;
	if (pos)
		*pos = head;

	/* Record data starts AFTER the header. */
	return (struct airy_log_record *)
		(ring->kaddr + sizeof(*hdr) + idx * hdr->record_size);
}

/* ─── Commit a reserved slot (producer side) ───────────────────────────
 * Publishes the 128-byte record by writing its reservation position into
 * the slot sequence word with release semantics, then advances
 * committed_head across the contiguous published prefix.  A producer
 * that finishes early can publish slots behind a slower one; the scan
 * simply stops at the first unpublished slot, so consumers never observe
 * a hole or a half-written record.  cmpxchg makes the advance safe when
 * several producers publish concurrently.
 * Consumers MUST read committed_head (smp_load_acquire), never head.
 * Notifies the Logger Daemon via non-blocking eventfd_signal().
 */
void airy_log_commit(struct airy_log_ring *ring, __u64 pos)
{
	struct airy_log_ring_header *hdr;
	struct airy_log_record *rec;
	__u64 done;

	if (!ring || !ring->kaddr)
		return;

	hdr = ring->kaddr;
	rec = (struct airy_log_record *)
		(ring->kaddr + sizeof(*hdr) +
		 (pos % hdr->capacity) * hdr->record_size);

	/* Publish this slot: body writes become visible before the marker.
	 * The marker stores pos + 1 so that a freshly zeroed slot (0) is
	 * never mistaken for a published record at position 0.
	 */
	airy_log_slot_pub(rec, pos + 1);

	for (;;) {
		done = smp_load_acquire(&hdr->committed_head);
		rec = (struct airy_log_record *)
			(ring->kaddr + sizeof(*hdr) +
			 (done % hdr->capacity) * hdr->record_size);
		if (airy_log_slot_seq(rec) != done + 1)
			break;
		if (cmpxchg(&hdr->committed_head, done, done + 1) != done)
			continue;
	}

	atomic64_inc(&ring->writes);

	/* Non-blocking eventfd notification to Logger Daemon. */
	if (ring->efd)
		eventfd_signal(ring->efd);
}

/* ─── Fastpath: reserve + fill + commit (~50–100 ns) ───────────────────
 * The three-step fastpath from design §3.1: reserve a slot, fill the
 * fixed fields and memcpy the raw payload, then commit.  No formatting
 * is performed — the payload is raw binary for the Logger Daemon to
 * parse asynchronously.
 */
int airy_log_write(struct airy_log_ring *ring,
		   __u16 level, __u16 facility,
		   const void *payload, __u32 payload_len)
{
	struct airy_log_record *rec;
	struct timespec64 ts;
	bool overrun;
	__u64 pos;
	__u32 len;

	if (!ring || !payload)
		return -EINVAL;

	/* 1. reserve 128 B slot (~10 ns) */
	rec = airy_log_reserve(ring, &pos, &overrun);
	if (unlikely(!rec))
		return -AIRY_ELOG_FULL;

	/* 2. fill fields + memcpy raw binary payload (~20 ns) */
	rec->magic        = AIRY_LOG_MAGIC;
	rec->level        = level;
	rec->facility     = facility;
	ktime_get_real_ts64(&ts);
	rec->timestamp_ns = timespec64_to_ns(&ts);
	rec->caller_id    = (__u32)current->pid;
	rec->payload_len  = min_t(__u32, payload_len,
				  (__u32)sizeof(rec->payload));
	len = rec->payload_len;
	memcpy(rec->payload, payload, rec->payload_len);

	/* 3. commit + eventfd notify (~10 ns) */
	airy_log_commit(ring, pos);
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_ring_buffer_write(level, len, overrun);
#endif
	return 0;
}

/* ─── mmap the ring into user space (Logger Daemon) ────────────────────
 * Maps the backing pages so the Logger Daemon can read the ring header
 * and records zero-copy.  VM_DONTEXPAND prevents the VMA from growing
 * and VM_DONTDUMP excludes it from core dumps.
 */
int airy_log_ring_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct airy_log_ring *ring;

	if (!f || !vma)
		return -EINVAL;

	ring = f->private_data;
	if (!ring || !ring->pages)
		return -EINVAL;

	if (vma->vm_pgoff)
		return -EINVAL;
	if (vma->vm_end - vma->vm_start > ring->size)
		return -EINVAL;

	vm_flags_set(vma, VM_SHARED | VM_DONTEXPAND | VM_DONTDUMP);

	return remap_pfn_range(vma, vma->vm_start,
			       page_to_pfn(ring->pages),
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

/* ─── Register an eventfd for consumer notification ────────────────────
 * Replaces any previously registered eventfd, dropping its context
 * reference so that a re-registration does not leak the old one.  The
 * swap is serialised by efd_lock so that concurrent registrations
 * cannot race and leak a context.
 */
int airy_log_ring_register_eventfd(struct airy_log_ring *ring, int efd)
{
	struct eventfd_ctx *ctx, *old;

	if (!ring)
		return -EINVAL;

	ctx = eventfd_ctx_fdget(efd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	spin_lock(&ring->efd_lock);
	old = ring->efd;
	ring->efd = ctx;
	spin_unlock(&ring->efd_lock);

	if (old)
		eventfd_ctx_put(old);
	return 0;
}

/* ─── Freeze the ring (Micro-Supervisor panic path) ────────────────────
 * Sets the frozen flag so airy_log_reserve() returns NULL and producers
 * fall back to the printk_safe NMI-safe path.
 */
void airy_log_ring_freeze(struct airy_log_ring *ring)
{
	struct airy_log_ring_header *hdr;

	if (!ring || !ring->kaddr)
		return;

	hdr = ring->kaddr;
	smp_store_release(&hdr->frozen, 1);
}

/* ─── Release backing pages and eventfd context ──────────────────────── */
void airy_log_ring_destroy(struct airy_log_ring *ring)
{
	if (!ring)
		return;

	if (ring->efd) {
		eventfd_ctx_put(ring->efd);
		ring->efd = NULL;
	}

	if (ring->pages) {
		__free_pages(ring->pages, ring->order);
		ring->pages = NULL;
	}

	ring->kaddr = NULL;
	ring->size  = 0;
	ring->order = 0;
}

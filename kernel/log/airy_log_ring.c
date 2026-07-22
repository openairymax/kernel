// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_log_ring.c — A-ULP 128-byte fixed-record lock-free ring buffer.
 *
 * Backed by alloc_pages(GFP_KERNEL) so the ring can be mmap()-ed into
 * agent address spaces for zero-copy log streaming.  Records are
 * fixed-size (128 bytes, struct airy_log_record) and accessed via a
 * reserve/commit two-phase model with atomic head/tail indices.
 *
 * Memory layout:
 *
 *   +─────────────────────────── kaddr (page-aligned) ────────────+
 *   |  airy_log_ring_header (40 B)  |  record[0] | record[1] | …  |
 *   +──────────────────────────────────────────────────────────────+
 *
 * Producers reserve a slot by atomically incrementing head (cmpxchg),
 * fill the 128-byte record, then publish it by copying head into
 * committed_head via smp_store_release().  Consumers read
 * committed_head with smp_load_acquire() — never head — so that only
 * fully-written records become visible; head advances at reserve time
 * (before the record body is filled), whereas committed_head advances
 * at commit time (after the body is filled).  Consumers advance tail
 * after processing.  When the ring is full the oldest record is
 * overwritten.
 *
 * Design: docs/AirymaxOS/40-dataflows/05-ring-buffer-logging.md §1–§4
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

/* ─── Ring buffer header (lives at the start of the mmap region) ────────
 * Placed at ring->kaddr so both kernel-space and the user-space Logger
 * Daemon (via mmap) share the same atomic indices.
 */
struct airy_log_ring_header {
	__u64	head;		/* producer reserve position (atomic)   */
	__u64	committed_head;	/* producer commit position (atomic)  */
	__u64	tail;		/* consumer read position (atomic)     */
	__u32	capacity;	/* ring capacity (record count, pow-2) */
	__u32	record_size;	/* single record size (128 B)          */
	__u32	frozen;		/* freeze flag (Micro-Supervisor sets) */
	__u32	pad;		/* alignment padding                   */
};

/* ─── Ring buffer state ──────────────────────────────────────────────── */
struct airy_log_ring {
	struct page	 *pages;	/* backing physical pages            */
	void		 *kaddr;		/* kernel virtual address            */
	size_t		  size;		/* total ring size (page-aligned)    */
	unsigned int	  order;		/* alloc_pages() order               */
	struct eventfd_ctx *efd;		/* eventfd for Logger Daemon notify  */
	spinlock_t	  efd_lock;	/* serialises eventfd registration   */
};

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
 * committed_head instead (published in airy_log_commit()).  If the
 * ring is full the oldest record is overwritten by advancing tail
 * (tail conceptually tracks committed_head from the consumer side).
 * Returns a pointer to the record for the caller to fill, or NULL
 * when the ring is frozen.
 */
struct airy_log_record *airy_log_reserve(struct airy_log_ring *ring)
{
	struct airy_log_ring_header *hdr;
	__u64 head, tail;
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

		/* Ring full: overwrite the oldest record (advance tail). */
		if (head - tail >= hdr->capacity)
			smp_store_release(&hdr->tail, tail + 1);

		idx = head % hdr->capacity;
	} while (cmpxchg(&hdr->head, head, head + 1) != head);

	/* Record data starts AFTER the header. */
	return (struct airy_log_record *)
		(ring->kaddr + sizeof(*hdr) + idx * hdr->record_size);
}

/* ─── Commit a reserved slot (producer side) ───────────────────────────
 * Publishes the 128-byte record by advancing committed_head to the
 * current reserve position (head).  head was already incremented
 * atomically in airy_log_reserve(); the release store here acts as the
 * publish barrier so that the record body (written between reserve and
 * commit) is visible to consumers before committed_head advances.
 * Consumers MUST read committed_head (smp_load_acquire), never head:
 * head advances at reserve time, before the record body is filled.
 * Notifies the Logger Daemon via non-blocking eventfd_signal().
 */
void airy_log_commit(struct airy_log_ring *ring, struct airy_log_record *rec)
{
	struct airy_log_ring_header *hdr;
	__u64 pos;

	if (!ring || !ring->kaddr || !rec)
		return;

	hdr = ring->kaddr;

	/*
	 * Snapshot the reserve position and publish it as committed.
	 * smp_store_release() ensures the 128-byte record write (done by
	 * the caller between airy_log_reserve() and here) is visible
	 * before committed_head advances, pairing with the consumer's
	 * smp_load_acquire() on committed_head.
	 */
	pos = READ_ONCE(hdr->head);
	smp_store_release(&hdr->committed_head, pos);

	/* Non-blocking eventfd notification to Logger Daemon. */
	if (ring->efd)
		eventfd_signal(ring->efd, 1);
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

	if (!ring || !payload)
		return -EINVAL;

	/* 1. reserve 128 B slot (~10 ns) */
	rec = airy_log_reserve(ring);
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
	memcpy(rec->payload, payload, rec->payload_len);

	/* 3. commit + eventfd notify (~10 ns) */
	airy_log_commit(ring, rec);
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

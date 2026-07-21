/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_log_ring.c — A-ULP 128-byte fixed-record ring buffer.
 *
 * Backed by alloc_pages() so the ring can be mmap()-ed into agent
 * address spaces for zero-copy log streaming.  Records are fixed-size
 * (128 bytes, struct airy_log_record) so head/tail advance by element
 * index rather than byte offset.
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mmzone.h>
#include <linux/airymax/log_types.h>

/* ─── Ring buffer state ───────────────────────────────────────────────── */
struct airy_log_ring {
	unsigned int head;
	unsigned int tail;
	unsigned int mask;	/* capacity - 1 */
	unsigned int count;
	struct airy_log_record *records;
	struct page *pages;	/* backing pages, for __free_pages() */
	unsigned int order;	/* alloc_pages() order */
};

/* ─── Initialise a ring of (1 << size_bits) bytes ─────────────────────── */
int airy_log_ring_init(struct airy_log_ring *ring, unsigned int size_bits)
{
	struct page *pages;
	size_t size_bytes;
	size_t num_records;

	if (!ring || size_bits > MAX_ORDER)
		return -EINVAL;

	size_bytes = (size_t)1 << size_bits;
	if (size_bytes < sizeof(struct airy_log_record))
		return -EINVAL;

	num_records = size_bytes / sizeof(struct airy_log_record);
	if (num_records == 0 || (num_records & (num_records - 1)))
		return -EINVAL;	/* capacity must be a power of two */

	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, size_bits);
	if (!pages)
		return -ENOMEM;

	ring->records = (struct airy_log_record *)page_address(pages);
	ring->pages   = pages;
	ring->order   = size_bits;
	ring->mask    = (unsigned int)num_records - 1;
	ring->head    = 0;
	ring->tail    = 0;
	ring->count   = 0;

	return 0;
}

/* ─── Push a record; -ENOSPC when full ────────────────────────────────── */
int airy_log_ring_push(struct airy_log_ring *ring,
		       const struct airy_log_record *rec)
{
	unsigned int idx;

	if (!ring || !rec || !ring->records)
		return -EINVAL;
	if (ring->count > ring->mask)
		return -ENOSPC;

	idx = ring->tail & ring->mask;
	ring->records[idx] = *rec;
	ring->tail++;
	ring->count++;
	return 0;
}

/* ─── Pop a record; -ENOENT when empty ────────────────────────────────── */
int airy_log_ring_pop(struct airy_log_ring *ring, struct airy_log_record *rec)
{
	unsigned int idx;

	if (!ring || !rec || !ring->records)
		return -EINVAL;
	if (ring->count == 0)
		return -ENOENT;

	idx = ring->head & ring->mask;
	*rec = ring->records[idx];
	ring->head++;
	ring->count--;
	return 0;
}

/* ─── Release backing pages ───────────────────────────────────────────── */
void airy_log_ring_destroy(struct airy_log_ring *ring)
{
	if (!ring || !ring->pages)
		return;

	__free_pages(ring->pages, ring->order);
	ring->pages   = NULL;
	ring->records = NULL;
	ring->head    = 0;
	ring->tail    = 0;
	ring->count   = 0;
	ring->mask    = 0;
	ring->order   = 0;
}

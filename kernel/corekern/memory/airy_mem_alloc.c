// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_mem_alloc.c — Airymax kernel memory allocation helpers.
 *
 * Wraps alloc_pages(GFP_KERNEL) for agent-private memory that is later
 * mapped to userspace via mmap (see airy_ipc_zero_copy_map).  No DMA
 * coherent memory is used — per ALK-6.6 constraint, only alloc_pages +
 * mmap style mapping is permitted.
 */

#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/errno.h>

/* ─── Page allocation ────────────────────────────────────────────────── */
struct page *airy_mem_alloc_pages(size_t size)
{
	unsigned int order;

	if (!size)
		return NULL;

	order = get_order(size);
	if (order > MAX_ORDER) {
		pr_warn_ratelimited("airy_mem_alloc: size %zu → order %u > MAX_ORDER\n",
				    size, order);
		return NULL;
	}

	return alloc_pages(GFP_KERNEL, order);
}

/* ─── Page free ──────────────────────────────────────────────────────── */
void airy_mem_free_pages(struct page *page, size_t size)
{
	unsigned int order;

	if (!page)
		return;

	order = get_order(size);
	__free_pages(page, order);
}

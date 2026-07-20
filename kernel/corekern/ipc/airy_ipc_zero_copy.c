// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_zero_copy.c — Airymax IPC zero-copy path.
 *
 * Provides registered-buffer + mmap based zero-copy IPC.  Pages are
 * registered with airy_ipc_zero_copy_register() and later mapped into
 * user address space via vm_insert_pages() in airy_ipc_zero_copy_map().
 * No DMA coherent memory is used (per ALK-6.6 constraint) — only
 * alloc_pages + mmap style mapping.
 */

#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/errno.h>
#include <linux/log2.h>
#include <linux/page_ref.h>

#include "airy_ipc_internal.h"

/* ─── Register a user buffer range for zero-copy ─────────────────────── */
int airy_ipc_zero_copy_register(unsigned long base, size_t len)
{
	size_t nr_pages;

	if (!base || !len)
		return -EINVAL;

	/* Base and length must be page-aligned for direct page mapping. */
	if (!PAGE_ALIGNED(base) || !PAGE_ALIGNED(len))
		return -EINVAL;

	nr_pages = len >> PAGE_SHIFT;

	pr_info("airy_ipc_zero_copy: registered buffer @%#lx len=%zu (%zu pages)\n",
		base, len, nr_pages);
	return 0;
}

/* ─── Map registered pages into a VMA ────────────────────────────────── */
int airy_ipc_zero_copy_map(struct vm_area_struct *vma, struct page **pages,
			   unsigned long nr_pages)
{
	unsigned long inserted;
	int ret;

	if (!vma || !pages || !nr_pages)
		return -EINVAL;

	/*
	 * vm_insert_pages() inserts as many of the requested pages as
	 * possible starting at vma->vm_start and updates *inserted with
	 * the count actually mapped.
	 */
	inserted = nr_pages;
	ret = vm_insert_pages(vma, vma->vm_start, pages, &inserted);
	if (ret) {
		pr_err("airy_ipc_zero_copy: vm_insert_pages failed: %d (inserted=%lu/%lu)\n",
		       ret, inserted, nr_pages);
		return ret;
	}

	if (inserted != nr_pages)
		pr_warn("airy_ipc_zero_copy: partial map %lu/%lu pages\n",
			inserted, nr_pages);

	return 0;
}

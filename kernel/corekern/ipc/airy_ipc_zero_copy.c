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
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "airy_ipc_internal.h"

/* ─── Registered-buffer tracking ────────────────────────────────────── */

/**
 * struct airy_zero_copy_region - A registered user buffer for zero-copy IPC.
 * @list:     Linkage in the global airy_zero_copy_regions list.
 * @uaddr:    User-space base address (page-aligned).
 * @size:     Buffer length in bytes (page-aligned).
 * @agent_id: Owning agent identifier.
 * @token:    Unique lookup token returned to userspace at registration time.
 */
struct airy_zero_copy_region {
	struct list_head list;
	void           *uaddr;
	size_t          size;
	__u32           agent_id;
	__u64           token;
};

static LIST_HEAD(airy_zero_copy_regions);
static DEFINE_SPINLOCK(airy_zero_copy_lock);

/* ─── Register a user buffer range for zero-copy ─────────────────────── */
int airy_ipc_zero_copy_register(unsigned long base, size_t len,
				__u32 agent_id, __u64 token)
{
	struct airy_zero_copy_region *reg;
	size_t nr_pages;

	if (!base || !len)
		return -EINVAL;

	/* Base and length must be page-aligned for direct page mapping. */
	if (!PAGE_ALIGNED(base) || !PAGE_ALIGNED(len))
		return -EINVAL;

	nr_pages = len >> PAGE_SHIFT;

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg)
		return -ENOMEM;

	reg->uaddr    = (void *)base;
	reg->size     = len;
	reg->agent_id = agent_id;
	reg->token    = token;

	spin_lock(&airy_zero_copy_lock);
	list_add_tail(&reg->list, &airy_zero_copy_regions);
	spin_unlock(&airy_zero_copy_lock);

	pr_info("airy_ipc_zero_copy: registered buffer @%#lx len=%zu (%zu pages) agent=%u token=%#llx\n",
		base, len, nr_pages, agent_id, token);
	return 0;
}

/* ─── Unregister a buffer by token ──────────────────────────────────── */
int airy_ipc_zero_copy_unregister(__u64 token)
{
	struct airy_zero_copy_region *reg, *tmp;

	spin_lock(&airy_zero_copy_lock);
	list_for_each_entry_safe(reg, tmp, &airy_zero_copy_regions, list) {
		if (reg->token == token) {
			list_del(&reg->list);
			spin_unlock(&airy_zero_copy_lock);
			kfree(reg);
			return 0;
		}
	}
	spin_unlock(&airy_zero_copy_lock);

	return -ENOENT;
}

/* ─── Map registered pages into a VMA ────────────────────────────────── */
int airy_ipc_zero_copy_map(struct vm_area_struct *vma, __u64 token,
			   struct page **pages, unsigned long nr_pages)
{
	struct airy_zero_copy_region *reg;
	bool found = false;
	unsigned long inserted;
	int ret;

	if (!vma || !pages || !nr_pages)
		return -EINVAL;

	/* Look up the registered region by token. */
	spin_lock(&airy_zero_copy_lock);
	list_for_each_entry(reg, &airy_zero_copy_regions, list) {
		if (reg->token == token) {
			found = true;
			break;
		}
	}
	spin_unlock(&airy_zero_copy_lock);

	if (!found) {
		pr_warn_ratelimited("airy_ipc_zero_copy: no region for token=%#llx\n",
				    token);
		return -ENOENT;
	}

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

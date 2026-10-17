/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_internal.h — internal surface of the A-ULP ring buffer.
 *
 * Declares the producer/consumer contract that airy_log_ring.c
 * implements and that the KUnit suite exercises: the shared header
 * placed at the start of the mmap()-able region, the ring state, and
 * the reserve/fill/commit fastpath. None of this is exported to
 * modules; the ring is driven from inside the kernel and observed
 * from user space through the mmap region only.
 *
 * SSoT: 40-dataflows/05-ring-buffer-logging.md §3.
 */

#ifndef _AIRY_LOG_INTERNAL_H
#define _AIRY_LOG_INTERNAL_H

#include <linux/spinlock_types.h>
#include <linux/types.h>

#include <linux/airymax/log_types.h>

struct eventfd_ctx;
struct file;
struct page;
struct vm_area_struct;

/*
 * Ring buffer header, placed at the start of the backing pages so that
 * kernel producers and the user-space Logger Daemon (via mmap) share
 * one set of indices.
 */
struct airy_log_ring_header {
	__u64	head;		/* producer reserve position (atomic)   */
	__u64	committed_head;	/* producer commit position (atomic)    */
	__u64	tail;		/* consumer read position (atomic)      */
	__u32	capacity;	/* ring capacity (record count, pow-2)  */
	__u32	record_size;	/* single record size (128 B)           */
	__u32	frozen;		/* freeze flag (Micro-Supervisor sets)  */
	__u32	pad;		/* alignment padding                    */
};

struct airy_log_ring {
	struct page	  *pages;	/* backing physical pages          */
	void		  *kaddr;	/* kernel virtual address          */
	size_t		   size;	/* total ring size (page-aligned)  */
	unsigned int	   order;	/* alloc_pages() order             */
	struct eventfd_ctx *efd;	/* eventfd for Logger Daemon       */
	spinlock_t	   efd_lock;	/* serialises efd registration     */
};

int airy_log_ring_init(struct airy_log_ring *ring, size_t size);
struct airy_log_record *airy_log_reserve(struct airy_log_ring *ring,
					 bool *overrun);
void airy_log_commit(struct airy_log_ring *ring, struct airy_log_record *rec);
int airy_log_write(struct airy_log_ring *ring, __u16 level, __u16 facility,
		   const void *payload, __u32 payload_len);
int airy_log_ring_mmap(struct file *f, struct vm_area_struct *vma);
int airy_log_ring_register_eventfd(struct airy_log_ring *ring, int efd);
void airy_log_ring_freeze(struct airy_log_ring *ring);
void airy_log_ring_destroy(struct airy_log_ring *ring);

#endif /* _AIRY_LOG_INTERNAL_H */

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_internal.h — A-ULP 日志环的内核内部接口。
 *
 * 共享头结构与 ABI 由 uapi/linux/airymax/log_ring.h 定义，内核生产者、
 * Logger Daemon 与 KUnit 套件看到的是同一份契约，避免两侧各自维护
 * 偏移量。这里只补充内核侧的状态、发布辅助函数与生产者 API。
 *
 * 发布协议：槽位偏移 120 的 8 字节保留区被复用为发布序号，写入值为
 * 「预留位置 + 1」，因此刚清零的槽位（0）不会被误认为位置 0 的记录。
 * 生产者填完记录体后以 release 语义写入该序号，任一生产者再向前扫描
 * 连续已发布槽位并推进 committed_head，消费者因此不会看到半条记录。
 * tail 由生产者独占推进（表示最早尚未被覆盖的槽位），消费者只维护
 * 自己的私有游标，两侧因此不存在写竞争。
 *
 * SSoT: docs-linux/40-dataflows/05-ring-buffer-logging.md §3。
 */

#ifndef _AIRY_LOG_INTERNAL_H
#define _AIRY_LOG_INTERNAL_H

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/spinlock_types.h>
#include <linux/stddef.h>
#include <linux/types.h>

#include <linux/airymax/log_ring.h>
#include <linux/airymax/log_types.h>

struct eventfd_ctx;
struct file;
struct page;
struct vm_area_struct;

struct airy_log_ring {
	struct page	  *pages;	/* 后备物理页			*/
	void		  *kaddr;	/* 内核虚拟地址			*/
	size_t		   size;	/* 环总大小（页对齐）		*/
	unsigned int	   order;	/* alloc_pages() 阶数		*/
	struct eventfd_ctx *efd;	/* 通知 Logger Daemon 的 eventfd */
	spinlock_t	   efd_lock;	/* 串行化 eventfd 注册		*/
	atomic64_t	   overrun;	/* 因环满被覆盖的槽位数		*/
	atomic64_t	   writes;	/* 已提交的记录总数			*/
};

static_assert(offsetof(struct airy_log_record, reserved) % sizeof(__u64) == 0,
	      "log record sequence word must stay 8-byte aligned");

/* 槽位发布序号复用记录尾部的保留区，偏移固定为 120（8 字节对齐）。 */
static inline __u64 airy_log_slot_seq(const struct airy_log_record *rec)
{
	const __u64 *seq = (const __u64 *)(const void *)rec->reserved;

	return smp_load_acquire(seq);
}

static inline void airy_log_slot_pub(struct airy_log_record *rec, __u64 pos)
{
	__u64 *seq = (__u64 *)(void *)rec->reserved;

	smp_store_release(seq, pos);
}

int airy_log_ring_init(struct airy_log_ring *ring, size_t size);
struct airy_log_record *airy_log_reserve(struct airy_log_ring *ring, __u64 *pos,
					 bool *overrun);
void airy_log_commit(struct airy_log_ring *ring, __u64 pos);
int airy_log_write(struct airy_log_ring *ring, __u16 level, __u16 facility,
		   const void *payload, __u32 payload_len);
int airy_log_ring_mmap(struct file *f, struct vm_area_struct *vma);
int airy_log_ring_register_eventfd(struct airy_log_ring *ring, int efd);
void airy_log_ring_freeze(struct airy_log_ring *ring);
void airy_log_ring_destroy(struct airy_log_ring *ring);

/* 全局环：设备节点、printk 桥与内核写者共用同一实例。 */
struct airy_log_ring *airy_log_global(void);

#endif /* _AIRY_LOG_INTERNAL_H */

/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-ULP 日志环的用户态 ABI：mmap 布局、几何查询与通知事件注册。
 *
 * 共享头放在映射区起始处，内核生产者与 Logger Daemon 共用同一组
 * 索引：head 为预留位置，committed_head 为连续已发布位置，tail 为
 * 最早仍未被覆盖的槽位。tail 由生产者推进，消费者只读并维护自己的
 * 私有游标——这样多消费者之间无需任何写竞争。
 *
 * SSoT: docs-linux/40-dataflows/05-ring-buffer-logging.md §3、§4。
 */

#ifndef _UAPI_LINUX_AIRYMAX_LOG_RING_H
#define _UAPI_LINUX_AIRYMAX_LOG_RING_H

#include <linux/airymax/uapi_compat.h>
#include <linux/ioctl.h>

#include <linux/airymax/log_types.h>

#define AIRY_LOG_RING_ABI	1
#define AIRY_LOG_DEV_PATH	"/dev/airy_log"
#define AIRY_LOG_DEV_NAME	"airy_log"

struct airy_log_ring_header {
	__u64	head;		/* 生产者预留位置（原子）		*/
	__u64	committed_head;	/* 连续已发布位置（原子）		*/
	__u64	tail;		/* 最早仍有效槽位（生产者推进）		*/
	__u32	capacity;	/* 槽位数（2 的幂）			*/
	__u32	record_size;	/* 单条记录大小（128 B）		*/
	__u32	frozen;		/* 冻结标志，写者停止发布		*/
	__u32	pad;		/* 对齐填充				*/
};

struct airy_log_geom {
	__u32	abi;		/* ABI 版本				*/
	__u32	capacity;	/* 槽位数				*/
	__u32	record_size;	/* 单条记录大小				*/
	__u32	hdr_size;	/* 共享头大小，记录区起始偏移		*/
	__u64	ring_bytes;	/* 可映射的总字节数			*/
};

#define AIRY_LOG_IOC_MAGIC	'A'
#define AIRY_LOG_IOC_EFD	_IOW(AIRY_LOG_IOC_MAGIC, 0x40, __s32)
#define AIRY_LOG_IOC_GEOM	_IOR(AIRY_LOG_IOC_MAGIC, 0x41, \
				     struct airy_log_geom)
#define AIRY_LOG_IOC_FREEZE	_IO(AIRY_LOG_IOC_MAGIC, 0x42)

#endif /* _UAPI_LINUX_AIRYMAX_LOG_RING_H */

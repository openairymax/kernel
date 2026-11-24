/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * mem.h — 记忆分层计量的用户态 ABI。
 *
 * 口径见 docs-linux/90-observability/09-memory-monitoring.md：
 *   四层分别是 L1 工作记忆、L2 会话记忆、L3 持久记忆、L4 模式记忆。
 *   内核只保存事实：计数、累计延迟、窗口内最大延迟、占用量，以及
 *   配额与由此算出的 ppm 比例；处置（压缩、驱逐、拒绝写入）由
 *   macro_d 依据 /proc/airy/agents/<id>/memory_stats 决策。
 *
 *   延迟以「窗口内最大值」作为 p99 上界：内核不做分位数估算，读者
 *   需要精确分位数时由 mem_d 在用户态按窗口采样计算。
 *
 *   比例一律 ppm，超额时饱和到 U32_MAX；配额为 0 表示未设限。
 */

#ifndef _UAPI_LINUX_AIRYMAX_MEM_H
#define _UAPI_LINUX_AIRYMAX_MEM_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AIRY_MEM_ABI		1

#define AIRY_MEM_L1		1U
#define AIRY_MEM_L2		2U
#define AIRY_MEM_L3		3U
#define AIRY_MEM_L4		4U
#define AIRY_MEM_LEVELS		4U

/* 观测窗口与单次上报上限：后者防止一次上报把累计值推到回绕。 */
#define AIRY_MEM_WINDOW_NS	60000000000ULL
#define AIRY_MEM_DELTA_MAX	(1ULL << 40)

/* 配额以 KiB 计；默认档位在没有监督配置时保证观测面可读。 */
#define AIRY_MEM_QUOTA_DEFAULT	4194304ULL

#define AIRY_MEM_NORMAL		0U
#define AIRY_MEM_SOFT		1U
#define AIRY_MEM_DEGRADE	2U
#define AIRY_MEM_EXCEED		3U
#define AIRY_MEM_SOFT_PPM	800000U
#define AIRY_MEM_DEGRADE_PPM	950000U

/**
 * struct airy_mem_delta - 一层记忆的增量上报
 * @agent_id: 上报方 Agent 号
 * @level: AIRY_MEM_L1..L4
 * @access: 访问次数
 * @hit: 命中次数
 * @lat_sum_ns: 累计访问延迟
 * @lat_max_ns: 观测窗口内最大延迟，作为 p99 上界
 * @evict: 驱逐或过期淘汰次数
 * @fill_ns: 回填、解压或重建的累计耗时
 * @page_in: 页/块调入次数
 * @page_out: 页/块调出次数
 * @read_bytes: 下层读字节数
 * @write_bytes: 下层写字节数
 * @pat_add: 模式或索引新增条数
 * @pat_drop: 模式或索引淘汰条数
 *
 * 与当前层无关的字段必须为 0；内核不做猜测，按原义累计。
 */
struct airy_mem_delta {
	__u32 agent_id;
	__u8 level;
	__u8 pad[3];
	__u64 access;
	__u64 hit;
	__u64 lat_sum_ns;
	__u64 lat_max_ns;
	__u64 evict;
	__u64 fill_ns;
	__u64 page_in;
	__u64 page_out;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 pat_add;
	__u64 pat_drop;
};

/**
 * struct airy_mem_gauge - 一层记忆的占用量
 * @agent_id: 上报方 Agent 号
 * @level: AIRY_MEM_L1..L4
 * @used_kb: 当前占用，以 KiB 计
 */
struct airy_mem_gauge {
	__u32 agent_id;
	__u8 level;
	__u8 pad[3];
	__u64 used_kb;
};

/**
 * struct airy_mem_quota - Agent 的记忆总配额
 * @agent_id: 目标 Agent 号
 * @quota_kb: 总配额，以 KiB 计；0 表示未设限
 */
struct airy_mem_quota {
	__u32 agent_id;
	__u32 pad;
	__u64 quota_kb;
};

/**
 * struct airy_mem_stats - 一次查询的结果
 * @agent_id: Agent 号
 * @alert_state: AIRY_MEM_NORMAL / SOFT / DEGRADE / EXCEED
 * @used_kb: 四层占用之和
 * @quota_kb: 总配额
 * @usage_ppm: used_kb / quota_kb 的 ppm 值
 * @updated_ns: 最近一次上报的单调时间
 */
struct airy_mem_stats {
	__u32 agent_id;
	__u32 alert_state;
	__u64 used_kb;
	__u64 quota_kb;
	__u32 usage_ppm;
	__u32 pad;
	__u64 updated_ns;
};

_Static_assert(sizeof(struct airy_mem_delta) == 104, "airy_mem_delta layout");
_Static_assert(sizeof(struct airy_mem_gauge) == 16, "airy_mem_gauge layout");
_Static_assert(sizeof(struct airy_mem_quota) == 16, "airy_mem_quota layout");
_Static_assert(sizeof(struct airy_mem_stats) == 40, "airy_mem_stats layout");

#define AIRY_MEM_IOC_REPORT	_IOW(0xB8, 1, struct airy_mem_delta)
#define AIRY_MEM_IOC_GAUGE	_IOW(0xB8, 2, struct airy_mem_gauge)
#define AIRY_MEM_IOC_QUOTA	_IOW(0xB8, 3, struct airy_mem_quota)
#define AIRY_MEM_IOC_QUERY	_IOWR(0xB8, 4, struct airy_mem_stats)

#endif /* _UAPI_LINUX_AIRYMAX_MEM_H */

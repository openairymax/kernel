/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_mem.h — 记忆分层计量的内核内部结构。
 *
 * 计量表按 Agent 组织，每个 Agent 下再分四层。窗口滚动只清「窗口内
 * 最大延迟」，累计计数与占用不受影响；KUnit 因此可以直接构造记录、
 * 推进时间并断言进位，不需要 procfs 或设备上下文。
 */

#ifndef _AIRY_MEM_H
#define _AIRY_MEM_H

#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/airymax/mem.h>

/**
 * struct mem_level - 一层记忆的累计事实
 * @access: 访问次数
 * @hit: 命中次数
 * @lat_sum: 累计访问延迟
 * @lat_max: 窗口内最大延迟，滚动清零
 * @evict: 淘汰次数
 * @fill: 回填累计耗时
 * @page_in: 调入次数
 * @page_out: 调出次数
 * @read_bytes: 下层读字节数
 * @write_bytes: 下层写字节数
 * @pat_add: 模式新增条数
 * @pat_drop: 模式淘汰条数
 * @used_kb: 当前占用
 */
struct mem_level {
	u64 access;
	u64 hit;
	u64 lat_sum;
	u64 lat_max;
	u64 evict;
	u64 fill;
	u64 page_in;
	u64 page_out;
	u64 read_bytes;
	u64 write_bytes;
	u64 pat_add;
	u64 pat_drop;
	u64 used_kb;
};

/**
 * struct mem_agent - 一个 Agent 的记忆计量记录
 * @de: Agent 目录，发布成功后置位
 * @agent_id: Agent 号
 * @win_start: 观测窗口起点
 * @updated: 最近一次上报时间
 * @quota_kb: 总配额，0 表示未设限
 * @lv: 下标 1..AIRY_MEM_LEVELS 对应 L1..L4
 */
struct mem_agent {
	struct proc_dir_entry *de;
	u32 agent_id;
	u64 win_start;
	u64 updated;
	u64 quota_kb;
	struct mem_level lv[AIRY_MEM_LEVELS + 1];
};

u32 airy_mem_alert(u64 used, u64 quota);
u64 airy_mem_total(const struct mem_agent *a);
void airy_mem_roll(struct mem_agent *a, u64 now);
void airy_mem_apply(struct mem_agent *a, const struct airy_mem_delta *d,
		    u64 now);
void airy_mem_set(struct mem_agent *a, const struct airy_mem_gauge *g);
int __init airy_mem_init(void);

#endif /* _AIRY_MEM_H */

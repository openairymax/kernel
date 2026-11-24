/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_token.h — token 计量的内核内部结构。
 *
 * 计量只有一张表：每个 Agent 一条记录，累计四类计数、60 秒窗口与预算窗口。
 * 累计与窗口的推进收在 airy_tok_add()，上报路径与 KUnit 走同一段代码，
 * 测试因此不需要搭设备就能覆盖进位与回绕。
 */

#ifndef _AIRY_TOKEN_H
#define _AIRY_TOKEN_H

#include <linux/types.h>

#include <linux/airymax/token.h>

struct proc_dir_entry;

/**
 * struct tok_agent - 一个 Agent 的计量记录
 * @de: /proc/airy/agents/<id> 目录项；PROC_FS 关闭时为空
 * @agent_id: Agent 标识，与 xarray 索引一致
 * @input: 累计输入
 * @output: 累计输出
 * @cache_hit: 累计缓存复用
 * @reasoning: 累计推理
 * @win_tokens: 当前 60 秒窗口新增量
 * @win_start: 窗口起点（monotonic ns）
 * @bused: 当前预算窗口已用量
 * @bstart: 预算窗口起点（monotonic ns）
 * @budget: 预算上限
 * @alert: 缓存的告警档位
 * @updated: 最近一次上报时间
 */
struct tok_agent {
	struct proc_dir_entry *de;
	u32 agent_id;
	u64 input;
	u64 output;
	u64 cache_hit;
	u64 reasoning;
	u64 win_tokens;
	u64 win_start;
	u64 bused;
	u64 bstart;
	u64 budget;
	u32 alert;
	u64 updated;
};

/* ppm 比例；分母为 0 时返回 0。 */
u32 airy_tok_ratio(u64 num, u64 den);

/* 预算档位：used/budget 的比例落在哪个告警区间。 */
u32 airy_tok_alert(u64 used, u64 budget);

/* 推进窗口并累加一次增量；调用方负责串行化。 */
void airy_tok_add(struct tok_agent *a, const struct airy_token_delta *d,
		  u64 now);

int __init airy_token_init(void);

#endif /* _AIRY_TOKEN_H */

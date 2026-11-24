/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Airymax token meter — [SC] shared contract header.
 *
 * 内核只保存事实：四类计数、60 秒观测窗口、1 小时预算窗口。消耗方
 * 通过 /dev/airy_token 的 REPORT 上报增量，读取方通过 QUERY 或
 * /proc/airy/agents/<id>/token_stats 取得快照。处置（提示优化、降级、
 * 终止）由 macro_d 依据 alert_state 决定，内核不跨层回调监管路径。
 *
 * 口径：四类计数互不重叠，total 是其和；比例一律 ppm（百万分之一），
 * 便于用户态避免浮点。
 *
 * 写入权限：持有目标 Agent badge（AIRY_CAP_PERM_SEND）者只能上报自己；
 * 调整预算需要调用者自身的 AIRY_CAP_PERM_SUPERVISE；具备 CAP_SYS_PTRACE
 * 的监督进程两者皆可，用于抹平早期引导阶段尚无 badge 的空窗。
 * /dev/airy_token 允许任意本地进程打开，写路径由上面的能力判定把关；
 * QUERY 与 /proc/airy/agents/<id>/token_stats 的 0444 视图同权。
 *
 * 设计依据：docs-linux/90-observability/07-token-efficiency.md
 */

#ifndef _UAPI_AIRYMAX_TOKEN_H
#define _UAPI_AIRYMAX_TOKEN_H

#include <linux/types.h>

/* 契约版本；字段增删必须递增，读者据此判断布局。 */
#define AIRY_TOKEN_ABI			1

/* 观测窗口 60 秒，预算窗口 1 小时。 */
#define AIRY_TOKEN_WINDOW_NS		60000000000ULL
#define AIRY_TOKEN_BUDGET_WINDOW_NS	3600000000000ULL

/* 新 Agent 的默认预算；监督进程可随时改写。 */
#define AIRY_TOKEN_BUDGET_DEFAULT	100000000ULL

/* 单次上报中每类计数的上限，超出视为脏数据。 */
#define AIRY_TOKEN_DELTA_MAX		16777216U

/* 告警档位：正常 / 达到 80% / 达到或超过 100%。 */
#define AIRY_TOKEN_NORMAL		0U
#define AIRY_TOKEN_SOFT			1U
#define AIRY_TOKEN_HARD			2U

/* 档位阈值，ppm。 */
#define AIRY_TOKEN_SOFT_PPM		800000U
#define AIRY_TOKEN_HARD_PPM		1000000U

/**
 * struct airy_token_delta - 一次计量的增量
 * @agent_id: 产生消耗的 Agent；必须在 [0, AIRY_CAP_MAX_AGENTS)
 * @input: 输入 token 数
 * @output: 输出 token 数
 * @cache_hit: 命中缓存而复用的 token 数
 * @reasoning: 推理链消耗的 token 数
 * @pad: 对齐保留，必须为 0；使 32 位与 64 位布局一致
 * @ts_ns: 生产者取样的 CLOCK_MONOTONIC 时间；0 或早于当前窗口时由内核取当前时间
 */
struct airy_token_delta {
	__u32 agent_id;
	__u32 input;
	__u32 output;
	__u32 cache_hit;
	__u32 reasoning;
	__u32 pad;
	__u64 ts_ns;
};

/**
 * struct airy_token_stats - 一个 Agent 的计量快照
 * @agent_id: Agent 标识
 * @alert_state: AIRY_TOKEN_NORMAL / SOFT / HARD
 * @input_total: 累计输入
 * @output_total: 累计输出
 * @cache_hit_total: 累计缓存复用
 * @reasoning_total: 累计推理
 * @total: 四类之和
 * @window_tokens: 当前 60 秒窗口的新增量
 * @budget_tokens: 当前预算上限
 * @budget_used: 当前预算窗口已用量
 * @cache_ratio_ppm: cache_hit / (input + cache_hit)
 * @output_input_ppm: output / input
 * @overhead_ppm: reasoning / (input + output)
 * @budget_ratio_ppm: budget_used / budget_tokens
 * @updated_ns: 最近一次上报的 CLOCK_MONOTONIC 时间
 */
struct airy_token_stats {
	__u32 agent_id;
	__u32 alert_state;
	__u64 input_total;
	__u64 output_total;
	__u64 cache_hit_total;
	__u64 reasoning_total;
	__u64 total;
	__u64 window_tokens;
	__u64 budget_tokens;
	__u64 budget_used;
	__u32 cache_ratio_ppm;
	__u32 output_input_ppm;
	__u32 overhead_ppm;
	__u32 budget_ratio_ppm;
	__u64 updated_ns;
};

/**
 * struct airy_token_budget - 设定一个 Agent 的预算上限
 * @agent_id: 目标 Agent
 * @pad: 对齐保留，必须为 0
 * @tokens: 新的上限；0 无效
 */
struct airy_token_budget {
	__u32 agent_id;
	__u32 pad;
	__u64 tokens;
};

#define AIRY_TOKEN_STATS_SIZE	96
#define AIRY_TOKEN_DELTA_SIZE	32
#define AIRY_TOKEN_BUDGET_SIZE	16

_Static_assert(sizeof(struct airy_token_stats) == AIRY_TOKEN_STATS_SIZE,
	       "airy_token_stats layout changed");
_Static_assert(sizeof(struct airy_token_delta) == AIRY_TOKEN_DELTA_SIZE,
	       "airy_token_delta layout changed");
_Static_assert(sizeof(struct airy_token_budget) == AIRY_TOKEN_BUDGET_SIZE,
	       "airy_token_budget layout changed");

#define AIRY_TOKEN_IOC_MAGIC	0xB7

/* 上报一次增量；参数为 struct airy_token_delta。 */
#define AIRY_TOKEN_IOC_REPORT	\
	_IOW(AIRY_TOKEN_IOC_MAGIC, 1, struct airy_token_delta)

/* 读取快照；入参 agent_id 有效，出参写入完整结构。 */
#define AIRY_TOKEN_IOC_QUERY	\
	_IOWR(AIRY_TOKEN_IOC_MAGIC, 2, struct airy_token_stats)

/* 设定预算；参数为 struct airy_token_budget。 */
#define AIRY_TOKEN_IOC_BUDGET	\
	_IOW(AIRY_TOKEN_IOC_MAGIC, 3, struct airy_token_budget)

#endif /* _UAPI_AIRYMAX_TOKEN_H */

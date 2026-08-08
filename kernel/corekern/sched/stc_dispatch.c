// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_dispatch.c — sched_tac dispatch to native Linux scheduling classes.
 *
 * Maps an Airymax sched_tac policy onto a native Linux scheduling class
 * (SCHED_DEADLINE / SCHED_FIFO / SCHED_NORMAL(EEVDF) / SCHED_BATCH),
 * records the dispatch via stc_stats, logs the mapping, and applies the
 * scheduling class via sched_setattr().
 *
 * seL4 MCS semantic mapping (10-sc-sched-extension.md §3):
 *   scBudget  ↔ sched_runtime   (CPU time budget per period)
 *   scPeriod  ↔ sched_deadline  (replenishment period)
 *
 * THINK phase (variable-length LLM inference, 100ms–10s) maps to
 * SCHED_NORMAL(EEVDF) with cgroup v2 cpu.max bandwidth isolation,
 * avoiding SCHED_DEADLINE's CBS WCET assumption mismatch (K9-3 fix).
 * PERCEPT/ACT phases (short, predictable) use SCHED_DEADLINE or SCHED_FIFO.
 */

#include <linux/printk.h>
#include <linux/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/airymax/sched.h>

#include "stc_policy.h"

/* ─── sched_setattr() — kernel-internal, EXPORT_SYMBOL_GPL ──────────── */
extern int sched_setattr(struct task_struct *p, const struct sched_attr *attr);

/* ─── MCS budget/period defaults (nanoseconds) ──────────────────────────
 * PERCEPT/ACT phases are short and predictable: 10ms budget, 100ms period.
 * THINK phase uses EEVDF (not SCHED_DEADLINE), so DEADLINE defaults are
 * unused for THINK.  The user-space Macro-Supervisor may override these
 * via AIRY_SYS_SCHED_CTL (syscall 550) at runtime.
 */
#define AIRY_MCS_PERCEPT_BUDGET_NS    (10  * NSEC_PER_MSEC)  /* 10ms */
#define AIRY_MCS_PERCEPT_PERIOD_NS    (100 * NSEC_PER_MSEC)  /* 100ms */
#define AIRY_MCS_ACT_BUDGET_NS        (10  * NSEC_PER_MSEC)  /* 10ms */
#define AIRY_MCS_ACT_PERIOD_NS        (100 * NSEC_PER_MSEC)  /* 100ms */

/* ─── 机制/策略边界声明 (E6) ────────────────────────────────────────────
 *
 * stc_policy_to_linux() 是**纯机制**（mechanism）：仅把 Airymax 策略
 * 编号映射为 Linux 原生调度类，不做任何调度决策——不选择策略、不
 * 计算预算/期限、不比较优先级。对齐 seL4 "内核零策略" 哲学
 * （ES-SEL4-04：机制与策略分离）：
 *
 *   - 机制（内核，本文件）：策略编号 → SCHED_* 调度类映射 + sched_attr
 *     构造 + sched_setattr() 注入。所有可能产生副作用的决策均无。
 *   - 策略（用户态，sched_tac）：策略类别选择（stc_realtime/
 *     stc_interactive/stc_agent/stc_batch）、budget/period 数值、阶段
 *     映射（PERCEPT/ACT/THINK），由用户态 sched_tac 通过
 *     AIRY_SYS_SCHED_CTL（syscall 550）注入，经 capability 校验
 *     （fastpath C-S9）后到达本机制层。
 *
 * 边界验证：内核态不存在任何策略决策代码路径；policy 参数由
 * [SC] sched.h AIRY_SCHED_POLICY_* 枚举承载（E7：UAPI 唯一数值源）。
 */

/* ─── Map stc policy → native Linux SCHED_* policy ───────────────────── */
static int stc_policy_to_linux(unsigned int policy)
{
	switch (policy) {
	case AIRY_SCHED_POLICY_DEADLINE:
		return SCHED_DEADLINE;
	case AIRY_SCHED_POLICY_FIFO:
		return SCHED_FIFO;
	case AIRY_SCHED_POLICY_EEVDF:
		return SCHED_NORMAL;	/* EEVDF is the default for SCHED_NORMAL */
	case AIRY_SCHED_POLICY_BESTEFFORT:
		return SCHED_BATCH;
	default:
		return -EINVAL;
	}
}

static const char *stc_linux_policy_name(int linux_policy)
{
	switch (linux_policy) {
	case SCHED_DEADLINE:	return "SCHED_DEADLINE";
	case SCHED_FIFO:	return "SCHED_FIFO";
	case SCHED_NORMAL:	return "SCHED_NORMAL(EEVDF)";
	case SCHED_BATCH:	return "SCHED_BATCH";
	default:		return "SCHED_UNKNOWN";
	}
}

/* ─── Build sched_attr for the given policy ────────────────────────────
 *
 * Replaces the broken sched_param + sched_set_scheduler() approach.
 * SCHED_DEADLINE requires sched_runtime/deadline/period (MCS mapping),
 * which sched_param cannot carry — sched_setattr() + sched_attr is the
 * only correct API (K9-3 fix).
 */
static int stc_build_attr(struct sched_attr *attr, unsigned int policy)
{
	memset(attr, 0, sizeof(*attr));
	attr->size = sizeof(*attr);

	switch (policy) {
	case AIRY_SCHED_POLICY_DEADLINE:
		/*
		 * SCHED_DEADLINE with seL4 MCS semantic mapping:
		 *   scBudget  → sched_runtime
		 *   scPeriod  → sched_deadline = sched_period
		 *
		 * Used for PERCEPT/ACT phases (short, predictable).
		 * THINK phase should use AIRY_SCHED_POLICY_EEVDF instead
		 * to avoid CBS WCET mismatch with variable-length LLM
		 * inference (K9-3).
		 */
		attr->sched_policy   = SCHED_DEADLINE;
		attr->sched_runtime  = AIRY_MCS_PERCEPT_BUDGET_NS;
		attr->sched_deadline = AIRY_MCS_PERCEPT_PERIOD_NS;
		attr->sched_period   = AIRY_MCS_PERCEPT_PERIOD_NS;
		break;

	case AIRY_SCHED_POLICY_FIFO:
		attr->sched_policy   = SCHED_FIFO;
		attr->sched_priority = 1;  /* RT priority [1, MAX_RT_PRIO-1] */
		break;

	case AIRY_SCHED_POLICY_EEVDF:
		/*
		 * THINK phase: SCHED_NORMAL(EEVDF) for variable-length LLM
		 * inference (100ms–10s).  Bandwidth isolation via cgroup v2
		 * cpu.max is configured by the user-space Macro-Supervisor
		 * (K9-3 fix).  EEVDF's weighted-fair scheduling naturally
		 * handles variable-length workloads without WCET assumptions.
		 */
		attr->sched_policy = SCHED_NORMAL;
		attr->sched_nice   = 0;
		break;

	case AIRY_SCHED_POLICY_BESTEFFORT:
		attr->sched_policy = SCHED_BATCH;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/* ─── Dispatch enqueue ───────────────────────────────────────────────── */
int stc_dispatch_enqueue(struct task_struct *tsk, enum airy_sched_policy policy)
{
	unsigned int pol = (unsigned int)policy;
	struct sched_attr attr;
	int linux_policy;
	int ret;
	const char *stc_name;

	if (!tsk)
		return -EINVAL;

	linux_policy = stc_policy_to_linux(pol);
	if (linux_policy < 0) {
		pr_warn_ratelimited("stc_dispatch: unknown policy %u\n", pol);
		return -EINVAL;
	}

	stc_name = stc_policy_name(policy);

	pr_debug_ratelimited("stc_dispatch: %s → %s (pid=%d comm=%s)\n",
		stc_name, stc_linux_policy_name(linux_policy),
		tsk->pid, tsk->comm);

	stc_stats_record_dispatch(policy);

	/* Build sched_attr with seL4 MCS semantic mapping */
	ret = stc_build_attr(&attr, pol);
	if (ret) {
		pr_warn_ratelimited("stc_dispatch: stc_build_attr failed for policy %u\n", pol);
		return ret;
	}

	/*
	 * Apply the scheduling class via sched_setattr().
	 * SCHED_DEADLINE requires sched_runtime/deadline/period (MCS mapping).
	 * SCHED_FIFO requires sched_priority in [1, MAX_RT_PRIO-1].
	 * SCHED_NORMAL/SCHED_BATCH expect sched_priority == 0.
	 */
	ret = sched_setattr(tsk, &attr);
	if (ret) {
		pr_warn_ratelimited("stc_dispatch: sched_setattr(%s) failed: %d (pid=%d)\n",
				    stc_linux_policy_name(linux_policy),
				    ret, tsk->pid);
		return ret;
	}

	return 0;
}

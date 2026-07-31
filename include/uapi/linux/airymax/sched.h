/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-ULS (Unified Lifecycle Supervision Framework) — [SC] shared contract header.
 *
 * Task descriptor with magic 0x41475453 ('AGTS'), vtime Q16.16 fixed-point,
 * and sched_tac parameters (SCHED_DEADLINE/SCHED_FIFO/EEVDF + seL4 MCS mapping).
 */

#ifndef _UAPI_AIRYMAX_SCHED_H
#define _UAPI_AIRYMAX_SCHED_H

#include <linux/airymax/uapi_compat.h>
#include <linux/airymax/lsm_types.h>

/* ─── Task Descriptor Magic ──────────────────────────────────────────── */
#define AIRY_TASK_MAGIC         0x41475453u /* 'AGTS' */

/* ─── Agent Capacity ─────────────────────────────────────────────────── */
/*
 * Maximum number of agents is defined by the capability table size
 * AIRY_CAP_MAX_AGENTS in <linux/airymax/lsm_types.h> (single source
 * of truth per [SC] single-host principle). sched.h re-exports it
 * here for scheduling-domain consumers.
 */

/* ─── Task Priority Range ────────────────────────────────────────────── */
#define AIRY_PRIO_MIN           0
#define AIRY_PRIO_MAX           139

/* ─── Default Scheduling Parameters ──────────────────────────────────── */
#define AIRY_SLICE_DFL          20      /* Default timeslice (ms) */
#define AIRY_WEIGHT_MIN         1
#define AIRY_WEIGHT_MAX         10000

/* ─── vtime: Q16.16 fixed-point for EEVDF virtual time ────────────────── */
typedef __s32 airy_vtime_t;

#define AIRY_VTIME_ONE          (1 << 16)  /* 1.0 in Q16.16 */

static inline airy_vtime_t airy_vtime_decay(airy_vtime_t vtime, __u32 weight)
{
	/*
	 * User-space vtime approximation (NOT the kernel EEVDF internal
	 * algorithm). The kernel's EEVDF uses vruntime += delta_exec *
	 * NICE_0_LOAD / load_weight with actual execution time delta_exec;
	 * this UAPI helper uses the default slice constant AIRY_SLICE_DFL
	 * for precomputed table consumers that need a static estimate.
	 * Real EEVDF scheduling happens in kernel/sched/fair.c and is not
	 * exposed through this UAPI.
	 */
	return vtime + (AIRY_SLICE_DFL * AIRY_VTIME_ONE) /
	       (weight ? weight : 1);
}

/* ─── Task Descriptor ────────────────────────────────────────────────── */
/*
 * Field ordering: 64-bit fields are grouped after the header word to
 * guarantee natural 8-byte alignment without padding. 32-bit fields
 * occupy the tail. Total size = 64 bytes (verified by _Static_assert).
 */
struct airy_task_desc {
	__u32       magic;          /* offset 0:  AIRY_TASK_MAGIC */
	__u16       prio;           /* offset 4:  priority [0,139] */
	__u16       _pad;           /* offset 6:  alignment padding */
	__u64       runtime_ns;     /* offset 8:  runtime budget (ns) */
	__u64       deadline_ns;    /* offset 16: deadline (ns) */
	__u64       period_ns;      /* offset 24: period (ns) */
	airy_vtime_t vtime;         /* offset 32: virtual time Q16.16 */
	__u32       agent_id;       /* offset 36: agent identifier [0,1023] */
	__u32       sched_policy;   /* offset 40: SCHED_DEADLINE/FIFO/OTHER */
	__u32       weight;         /* offset 44: EEVDF weight */
	__u32       state;          /* offset 48: agent lifecycle state */
	__u8        _reserved[12];  /* offset 52: reserved (underscore-prefixed per OS-IRON-014 naming convention) */
} AIRY_ALIGNED(64);

_Static_assert(sizeof(struct airy_task_desc) == 64,
	       "airy_task_desc must be exactly 64 bytes");

/* ─── Agent Lifecycle States (8 states, SSoT-aligned) ──────────────────
 * SSoT: docs/AirymaxOS/30-interfaces/10-sc-sched-extension.md §2.1
 *
 * sched_tac 核心成果：8 态与 Linux 进程状态天然映射，无需新增内核
 * 调度器状态，仅复用 SCHED_DEADLINE/SCHED_FIFO/EEVDF。状态迁移由
 * Macro-Supervisor 驱动，Micro-Supervisor 仅在检测到异常时触发
 * RUNNING -> STOPPING 的强制迁移。
 */
enum airy_agent_state {
	AIRY_AGENT_INACTIVE = 0,   /* 进程不存在，等待 fork */
	AIRY_AGENT_SPAWNING = 1,   /* fork/exec 中，未就绪 */
	AIRY_AGENT_READY    = 2,   /* TASK_RUNNING，在运行队列等待 */
	AIRY_AGENT_RUNNING  = 3,   /* TASK_RUNNING，正在 CPU 执行 */
	AIRY_AGENT_BLOCKED  = 4,   /* TASK_INTERRUPTIBLE，等待 IPC/IO */
	AIRY_AGENT_STOPPING = 5,   /* SIGSTOP 发送中，正在冻结 IPC */
	AIRY_AGENT_STOPPED  = 6,   /* TASK_STOPPED，已冻结，待裁决 */
	AIRY_AGENT_DEAD     = 7,   /* EXIT_ZOMBIE，等待 waitpid 回收 */
	AIRY_AGENT_STATE_MAX
};

/* ─── sched_tac Policy Identifiers ───────────────────────────────────── */
#define AIRY_SCHED_POLICY_DEADLINE   1
#define AIRY_SCHED_POLICY_FIFO       2
#define AIRY_SCHED_POLICY_EEVDF      3
#define AIRY_SCHED_POLICY_BESTEFFORT 4

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, sched_tac three-tier scheduling is
 * unavailable and all agents fall back to Linux 6.6 default EEVDF
 * (SCHED_NORMAL + nice). Only AIRY_TASK_MAGIC and AIRY_CAP_MAX_AGENTS
 * (re-exported via lsm_types.h) are authoritative in fallback mode.
 * See [DSL] §2.2 and §4.1.3.
 */
#ifdef AIRY_SC_FALLBACK
	/* All sched_tac policies collapse to EEVDF default. */
	#define AIRY_DSL_SCHED_POLICY_DEADLINE   AIRY_SCHED_POLICY_EEVDF
	#define AIRY_DSL_SCHED_POLICY_FIFO       AIRY_SCHED_POLICY_EEVDF
	#define AIRY_DSL_SCHED_POLICY_EEVDF      AIRY_SCHED_POLICY_EEVDF
	#define AIRY_DSL_SCHED_POLICY_BESTEFFORT AIRY_SCHED_POLICY_EEVDF
	#define AIRY_DSL_SCHED_POLICIES          1  /* Only EEVDF retained */

	/* vtime decay collapses to identity (no weighted decay in fallback). */
	#define AIRY_DSL_VTIME_DECAY(vtime, weight)  (vtime)

	#warning "AIRY_SC_FALLBACK active: sched.h degraded to EEVDF default only, sched_tac three-tier unavailable"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_SCHED_H */

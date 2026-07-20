/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
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
	 * EEVDF virtual time decay: vtime += slice / weight.
	 * For precomputed tables, approximate as integer math.
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
	__u8        reserved[12];   /* offset 52: reserved */
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct airy_task_desc) == 64,
	       "airy_task_desc must be exactly 64 bytes");

/* ─── Agent Lifecycle States (8 states) ──────────────────────────────── */
enum airy_agent_state {
	AIRY_AGENT_INIT        = 0,  /* Initializing */
	AIRY_AGENT_RUNNING     = 1,  /* Running */
	AIRY_AGENT_SLEEPING    = 2,  /* Sleeping (voluntary) */
	AIRY_AGENT_BLOCKED     = 3,  /* Blocked (I/O or IPC wait) */
	AIRY_AGENT_FROZEN      = 4,  /* Frozen by Supervisor */
	AIRY_AGENT_TERMINATING = 5,  /* Graceful termination */
	AIRY_AGENT_DEAD        = 6,  /* Terminated */
	AIRY_AGENT_ZOMBIE      = 7,  /* Zombie (awaiting reaping) */
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

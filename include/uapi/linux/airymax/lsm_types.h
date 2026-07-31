/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Pure C LSM type contract — [SC] shared contract header.
 *
 * Defines the type contracts required for the Airy pure-C LSM,
 * including security blob structures and capability check callback.
 */

#ifndef _UAPI_AIRYMAX_LSM_TYPES_H
#define _UAPI_AIRYMAX_LSM_TYPES_H

#include <linux/airymax/uapi_compat.h>

/* ─── LSM Hook Coverage ──────────────────────────────────────────────── */
/*
 * Airy Pure-C LSM registers 7 hooks (uring_cmd, task_alloc, task_free,
 * task_kill, file_open, inode_alloc_security, inode_free_security).
 * The Linux 6.6 LSM framework exposes ~250 hook slots in total;
 * AIRY_LSM_KERNEL_HOOK_TOTAL documents this upper bound for planning,
 * not for array sizing.
 */
#define AIRY_LSM_HOOK_IMPLEMENTED   7    /* Hooks Airy actually registers */
#define AIRY_LSM_KERNEL_HOOK_TOTAL  250  /* Total hooks available in Linux 6.6 LSM framework */

/* ─── Agent Security Context (per-task security blob) ─────────────────── */
struct airy_task_sec {
	__u32   agent_id;         /* Agent identifier [0, AIRY_CAP_MAX_AGENTS] */
	__u32   cap_space_root;   /* Root of capability space (badge ref) */
	__u32   agent_state;      /* Agent lifecycle state */
	__u32   fault_count;      /* Cumulative fault counter */
	__u64   sched_budget_ns;  /* Scheduling budget in nanoseconds */
	__u64   last_heartbeat;   /* Monotonic timestamp of last heartbeat */
	__u32   frozen_reason;    /* Reason code if frozen by Supervisor */
	__u32   _reserved;        /* Alignment */
	void   *ipc_ring;         /* Per-agent IPC ring freeze-state (M1: per-agent) */
};

/* ─── Inode Security Context ──────────────────────────────────────────── */
struct airy_inode_sec {
	__u32   cap_required;     /* Required capability for access */
	__u32   owner_agent;      /* Owning agent ID */
};

/* ─── Capability Slot ──────────────────────────────────────────────────
 *
 * Layout: 80 bytes (24 base + 16 MDB + 40 reserved), AIRY_ALIGNED(64).
 *
 * MDB (Memory Derivation Board) fields enable cascading REVOKE via a
 * left-child right-sibling derivation tree (seL4 CNode alignment, K9-1
 * fix).  parent_agent/first_child/next_sibling form the tree; generation
 * prevents circular derivation; revocable controls whether a parent's
 * REVOKE cascades to this slot.
 *
 * The MDB fields were carved from the original _reserved[56] without
 * breaking UAPI binary compatibility (IRON-001): consumers must not
 * depend on _reserved contents.
 */
struct airy_cap_slot {
	__u64   badge;            /* 64-bit Capability Folding badge */
	__u32   agent_id;         /* Owning agent ID */
	__u32   flags;            /* Slot flags */
	__u32   randtag;          /* Random tag for forgery prevention */
	__u16   perms;            /* Permission bits */
	__u16   epoch;            /* Per-agent epoch for O(1) targeted revocation */
	/* ── MDB derivation tree (cascading REVOKE, K9-1 fix) ── */
	__u32   parent_agent;     /* Derived-from agent ID (0 = root) */
	__u32   first_child;      /* First child agent ID (0 = leaf) */
	__u32   next_sibling;     /* Next sibling agent ID (0 = last child) */
	__u16   generation;       /* Derivation depth (root=0, +1 per MINT/COPY) */
	__u16   revocable;        /* 1 = parent REVOKE cascades to this slot */
	__u8    _reserved[40];    /* Cacheline padding (was 56, -16 for MDB) */
} AIRY_ALIGNED(64);

#define AIRY_CAP_MAX_AGENTS     1024

/* ─── Capability Check Callback Signature ────────────────────────────── */
/*
 * airy_capability_check(badge, required_perm, agent_id) -> airy_err_t
 *
 * Validates whether the agent identified by agent_id has the specified
 * capability with the required permissions.
 */
typedef __s32 (*airy_capability_check_fn)(__u64 badge, __u16 required_perm,
					  __u32 agent_id);

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, the Airy pure-C LSM retains only
 * DEFINE_LSM(airy) minimal skeleton registration. The 7 implemented
 * hooks (uring_cmd, task_alloc, task_free, task_kill, file_open,
 * inode_alloc_security, inode_free_security) collapse to 3 essential
 * hooks (task_alloc, task_free, file_open) — uring_cmd is suspended
 * (IPC degraded), task_kill delegates to the POSIX capability
 * slowpath, and inode_alloc/inode_free become no-ops. AIRY_CAP_MAX_AGENTS
 * is reduced to 64 to lower memory pressure in recovery mode. See [DSL] §2.2.
 *
 * In fallback mode, capability_badge is fixed to 0 (H6), so the
 * capability_check callback always returns 0 (allow) and relies on
 * POSIX capability slowpath for actual enforcement.
 */
#ifdef AIRY_SC_FALLBACK
	#define AIRY_DSL_LSM_HOOK_COUNT      3      /* 3 essential hooks (task_alloc, task_free, file_open) */
	#define AIRY_DSL_CAP_MAX_AGENTS      64     /* Reduced from 1024 */
	#define AIRY_DSL_CAP_CHECK_ALWAYS_ALLOW  0  /* H6: badge=0 → allow */

	/* Minimal DEFINE_LSM(airy) skeleton marker for fallback consumers. */
	#define AIRY_DSL_LSM_NAME            "airy"
	#define AIRY_DSL_LSM_FLAGS           0

	#warning "AIRY_SC_FALLBACK active: lsm_types.h degraded to DEFINE_LSM(airy) minimal skeleton, 7 hooks collapse to 3, AIRY_CAP_MAX_AGENTS=64"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_LSM_TYPES_H */

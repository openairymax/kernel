/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
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

#include <airymax/uapi_compat.h>

/* ─── LSM Hook Coverage ──────────────────────────────────────────────── */
#define AIRY_LSM_HOOK_COUNT     250  /* Total pure-C LSM hooks */

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
};

/* ─── Inode Security Context ──────────────────────────────────────────── */
struct airy_inode_sec {
	__u32   cap_required;     /* Required capability for access */
	__u32   owner_agent;      /* Owning agent ID */
};

/* ─── Capability Slot ────────────────────────────────────────────────── */
struct airy_cap_slot {
	__u64   badge;            /* 64-bit Capability Folding badge */
	__u32   agent_id;         /* Owning agent ID */
	__u32   flags;            /* Slot flags */
	__u32   randtag;          /* Random tag for forgery prevention */
	__u16   perms;            /* Permission bits */
	__u16   _pad;             /* Alignment */
	__u8    _reserved[56];    /* Cacheline padding */
} __attribute__((aligned(64)));

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

#endif /* _UAPI_AIRYMAX_LSM_TYPES_H */

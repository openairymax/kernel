/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap.h — Capability internal header (Airy Pure-C LSM).
 *
 * Defines the internal capability slot structure, global state,
 * and fastpath inline functions for badge validation.
 */

#ifndef _SECURITY_AIRY_CAP_H
#define _SECURITY_AIRY_CAP_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <airymax/lsm_types.h>
#include <airymax/error.h>

/* ─── Badge Field Extraction Macros ────────────────────────────────────── */
/*
 * Badge layout (64-bit):
 *   [63:48]  epoch      (16 bits)
 *   [47:16]  random tag (32 bits)
 *   [15:0]   permissions (16 bits)
 */
#define AIRY_BADGE_EPOCH(b)    (((__u64)(b) >> 48) & 0xFFFFULL)
#define AIRY_BADGE_PERMS(b)    ((__u64)(b) & 0xFFFFULL)
#define AIRY_BADGE_RANDTAG(b)  (((__u64)(b) >> 16) & 0xFFFFFFFFULL)

/* ─── Badge Construction Macro ─────────────────────────────────────────── */
#define AIRY_BADGE_MAKE(epoch, randtag, perms) \
	(((__u64)((epoch) & 0xFFFFULL) << 48) | \
	 (((__u64)(randtag) & 0xFFFFFFFFULL) << 16) | \
	 ((__u64)(perms) & 0xFFFFULL))

/* ─── Capability Slot: 64-byte cacheline-aligned ─────────────────────── */
struct airy_cap_slot {
	__u64   badge;              /* 64-bit Capability Folding badge */
	__u32   agent_id;           /* Owning agent ID */
	__u32   flags;              /* Slot flags */
	__u32   randtag;            /* Random tag for forgery prevention */
	__u16   perms;              /* Permission bits */
	__u16   _pad;               /* Alignment */
	__u8    _reserved[56];      /* Cacheline padding */
} ____cacheline_aligned_in_smp;

/* ─── Global Capability Array: 1024 slots ────────────────────────────── */
#define AIRY_CAP_MAX_AGENTS      1024

extern struct airy_cap_slot agent_caps[AIRY_CAP_MAX_AGENTS];
extern atomic_t              airy_cap_global_epoch;

/* ─── Agent Security Blob (per-task) ──────────────────────────────────── */
struct airy_task_sec {
	__u32   agent_id;
	__u32   cap_space_root;
	__u32   agent_state;
	__u32   fault_count;
	__u64   sched_budget_ns;
	__u64   last_heartbeat;
	__u32   frozen_reason;
	__u32   _reserved;
};

/* ─── LSM Blob Sizes ──────────────────────────────────────────────────── */
extern struct lsm_blob_sizes airy_blob_sizes;

/* ─── Fastpath Inline: C-S9 Badge Validation (~10ns) ─────────────────── */
/*
 * airy_cap_badge_ok — Fastpath inline badge validation.
 *
 * Executes 3 READ_ONCE + bit operations + comparisons.
 * Called from io_uring_cmd fastpath for every IPC message.
 *
 * Returns 0 (AIRY_EOK) if valid, negative error otherwise.
 */
static __always_inline int airy_cap_badge_ok(__u64 badge, __u32 agent_id,
					     __u16 required_perms)
{
	__u64 epoch = AIRY_BADGE_EPOCH(badge);
	__u64 perms = AIRY_BADGE_PERMS(badge);
	__u64 randtag = AIRY_BADGE_RANDTAG(badge);
	__u64 global_epoch;
	__u64 slot_randtag;

	if (unlikely(agent_id >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_MISSING;

	/* C-S9.1: Epoch check — 1 atomic read */
	global_epoch = (__u64)atomic_read(&airy_cap_global_epoch);
	if (unlikely(epoch != global_epoch))
		return -AIRY_ECAP_EPOCH;

	/* C-S9.2: RandomTag check — 1 READ_ONCE from cacheline-aligned slot */
	slot_randtag = (__u64)READ_ONCE(agent_caps[agent_id].randtag);
	if (unlikely(randtag != slot_randtag))
		return -AIRY_ECAP_FORGED;

	/* C-S9.3: Permission check */
	if (unlikely((perms & (__u64)required_perms) != (__u64)required_perms))
		return -AIRY_ECAP_PERM;

	return 0;
}

/* ─── Capability Initialization ───────────────────────────────────────── */
void airy_cap_agent_caps_init(void);

/* ─── Capability Array Operations ─────────────────────────────────────── */
struct airy_cap_slot *airy_cap_lookup(__u32 agent_id);
int airy_cap_register(__u32 agent_id, __u64 badge);

/* ─── Capability Derivation ───────────────────────────────────────────── */
#include <airymax/security_types.h>
int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
		    enum airy_cap_op op, __u16 new_perms);

/* ─── Slowpath Capability Check ───────────────────────────────────────── */
struct io_uring_cmd;
int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);
void airy_security_fault(__u32 agent_id, __u32 fault_code);

#endif /* _SECURITY_AIRY_CAP_H */

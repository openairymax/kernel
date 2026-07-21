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
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

/* ─── Badge Field Macros ─────────────────────────────────────────────────
 * AIRY_BADGE_EPOCH/RANDTAG/PERMS 提取宏和 AIRY_BADGE_COMPILE 构造宏
 * 由 <linux/airymax/ipc.h> 统一定义（[SC] 单一宿主原则）。
 * Badge layout (64-bit):
 *   [63:48]  epoch      (16 bits)
 *   [47:16]  random tag (32 bits)
 *   [15:0]   permissions (16 bits)
 */

/* ─── Global Capability Array: 1024 slots ────────────────────────────── */
/* struct airy_cap_slot, AIRY_CAP_MAX_AGENTS, struct airy_task_sec 由
 * <linux/airymax/lsm_types.h> 统一定义（[SC] 单一宿主原则）。
 * 本头文件通过 #include <linux/airymax/lsm_types.h> 引入这些类型。 */
extern struct airy_cap_slot *agent_caps;
extern atomic_t              airy_cap_global_epoch;

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
#include <linux/airymax/security_types.h>
int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
		    enum airy_cap_op op, __u16 new_perms);

/* ─── IPC Ring Structure (single-host for security/airy + kernel/superv) ─ */
/**
 * struct airy_ipc_ring - An IPC ring buffer between two agents.
 * @frozen:           Whether the ring is currently frozen.
 * @freeze_reason:    Reason code for the freeze (0 if not frozen).
 * @freeze_timestamp: Monotonic timestamp (ns) when the ring was frozen.
 *
 * Defined here (not in a [SC] header) because it is an internal
 * kernel implementation type, not a UAPI contract. Both
 * security/airy/airy_ipc_freeze.c and kernel/superv/airy_ipc_freeze.c
 * include this header to obtain the single definition.
 */
struct airy_ipc_ring {
	bool    frozen;
	__u32   freeze_reason;
	__u64   freeze_timestamp;
};

/* ─── Slowpath Capability Check ───────────────────────────────────────── */
struct io_uring_cmd;
int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);
void airy_security_fault(__u32 agent_id, __u32 fault_code);

/* ─── Micro-Supervisor Supplemental Hook Registration ─────────────────── */
int __init airy_superv_register_hooks(void);

#endif /* _SECURITY_AIRY_CAP_H */

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
static __always_inline __must_check int airy_cap_badge_ok(__u64 badge, __u32 agent_id,
					     __u16 required_perms)
{
	__u64 epoch = AIRY_BADGE_EPOCH(badge);
	__u64 perms = AIRY_BADGE_PERMS(badge);
	__u64 randtag = AIRY_BADGE_RANDTAG(badge);
	__u16 slot_epoch;
	__u32 slot_randtag;

	if (unlikely(agent_id >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_MISSING;

	/* C-S9.1: Per-agent epoch check — 1 READ_ONCE (same cacheline as randtag) */
	slot_epoch = READ_ONCE(agent_caps[agent_id].epoch);
	if (unlikely(epoch != (__u64)slot_epoch))
		return -AIRY_ECAP_EPOCH;

	/* C-S9.2: RandomTag check — 1 READ_ONCE from same cacheline */
	slot_randtag = READ_ONCE(agent_caps[agent_id].randtag);
	if (unlikely(randtag != (__u64)slot_randtag))
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
__must_check int airy_cap_register(__u32 agent_id, __u64 badge);

/* ─── Capability Derivation ───────────────────────────────────────────── */
#include <linux/airymax/security_types.h>
__must_check int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
				 enum airy_cap_op op, __u16 new_perms);
__must_check int airy_cap_rotate(__u32 agent_id);

/* ─── IPC Ring Freeze State (single-host for security/airy + kernel/superv) ─ */
/**
 * struct airy_ipc_ring_freeze_state - Freeze metadata for an IPC ring.
 * @frozen:           Whether the ring is currently frozen.
 * @freeze_reason:    Reason code for the freeze (0 if not frozen).
 * @freeze_timestamp: Monotonic timestamp (ns) when the ring was frozen.
 *
 * This structure holds only the freeze/unfreeze metadata consumed by the
 * Micro-Supervisor quarantine path.  It is deliberately separate from
 * struct airy_ipc_ring (defined in corekern/ipc/airy_ipc_internal.h) which
 * holds the ring-buffer cursors {head, tail, mask, frozen}.  Renamed from
 * struct airy_ipc_ring to resolve a dual-definition conflict with
 * airy_ipc_internal.h — both headers previously defined a type of the same
 * name with incompatible layouts, causing silent memory corruption when a
 * translation unit included both.
 *
 * Defined here (not in a [SC] header) because it is an internal kernel
 * implementation type, not a UAPI contract. Both
 * security/airy/airy_ipc_freeze.c and kernel/superv/airy_ipc_freeze_superv.c
 * include this header to obtain the single definition.
 */
struct airy_ipc_ring_freeze_state {
	bool    frozen;
	__u32   freeze_reason;
	__u64   freeze_timestamp;
};

/* ─── Slowpath Capability Check ───────────────────────────────────────── */
struct io_uring_cmd;
__must_check int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);
void airy_security_fault(__u32 agent_id, __u32 fault_code);

/* ─── Micro-Supervisor Supplemental Hook Registration ─────────────────── */
int __init airy_superv_register_hooks(void);

#endif /* _SECURITY_AIRY_CAP_H */

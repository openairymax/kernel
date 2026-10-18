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
#include <asm/barrier.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include <airymax/airy_agent.h>

#include "airy_consttime.h"

/* ─── Badge Field Macros ─────────────────────────────────────────────────
 * AIRY_BADGE_EPOCH/RANDTAG/PERMS 提取宏和 AIRY_BADGE_COMPILE 构造宏
 * 由 <linux/airymax/ipc.h> 统一定义（[SC] 单一宿主原则）。
 * Badge layout (64-bit):
 *   [63:48]  epoch      (16 bits)
 *   [47:16]  random tag (32 bits)
 *   [15:0]   permissions (16 bits)
 */

/* ─── Epoch Progression ────────────────────────────────────────────────── */
/*
 * airy_epoch_next - advance a 16-bit per-agent epoch.
 *
 * Epoch 0 is reserved: a pristine slot carries epoch 1 so that an
 * all-zero badge can never match an empty slot on the fastpath
 * (airy_ct_perm(x, 0) is true, so a caller requiring no permission
 * bits would otherwise be satisfied by AIRY_CAP_NULL).  A plain +1
 * wraps 0xffff back to the reserved value, so the successor of
 * 0xffff is 1.  Every writer of slot->epoch goes through this
 * helper to keep the reservation intact.
 */
static inline __u16 airy_epoch_next(__u16 epoch)
{
	__u16 next = epoch + 1;

	return next ? next : 1;
}

/* ─── Slot Flags ───────────────────────────────────────────────────────── */
/*
 * AIRY_CAP_FL_REVOKED - the slot lost its authority through REVOKE.
 *
 * REVOKE clears the random tag, so the tag stops being a secret and a
 * badge forged from the surviving epoch and permissions would otherwise
 * pass the fastpath.  The flag is the authoritative "no authority"
 * marker: both validation paths reject the slot while it is set, and
 * every operation that would derive new authority from the slot is
 * refused.  DELETE and airy_cap_unreg() clear the flag by resetting the
 * slot; there is no other path back.
 */
#define AIRY_CAP_FL_REVOKED	0x00000001U

/* ─── Global Capability Array: 1024 slots ────────────────────────────── */
/* struct airy_cap_slot, AIRY_CAP_MAX_AGENTS, struct airy_task_sec 由
 * <linux/airymax/lsm_types.h> 统一定义（[SC] 单一宿主原则）。
 * 本头文件通过 #include <linux/airymax/lsm_types.h> 引入这些类型。
 */
extern struct airy_cap_slot *agent_caps;
extern atomic_t              airy_cap_global_epoch;

/* ─── Paranoid Mode (SSoT §12.2.3) ───────────────────────────────────── */
/*
 * airy_security_paranoid - 侧信道高安全模式开关。
 *
 * 由 kernel/ipc/airy_ipc_capability.c 定义（与 agent_caps[] 同属一个
 * 编译单元），以 boot-time 参数 security_paranoid 暴露，默认关闭。
 * 开启后 fastpath C-S9 在读取槽位前插入投机执行屏障。
 */
extern bool airy_security_paranoid;

/* ─── Per-Bucket Hashed Spinlock Array ───────────────────────────────────
 * Shared lock array protecting agent_caps[].  Both airy_cap_register()
 * (single-slot writes) and airy_cap_derive() (multi-slot derivation)
 * MUST acquire the bucket lock(s) covering the slots they touch.
 * Sharing one lock array across both paths closes the TOCTOU window
 * that existed when register used a separate global spinlock and
 * derive used this bucket array — the two did not mutually exclude,
 * so concurrent register+derive on the same dst slot could double-write.
 *
 * COPY/MINT derive ops acquire the src and dst bucket locks in canonical
 * ascending pointer order; MUTATE/ROTATE acquire only the source bucket.
 * REVOKE, MOVE and DELETE acquire all AIRY_CAP_BUCKET_NR locks because
 * their MDB subtree and parent/child chain updates may touch arbitrary
 * buckets.
 */
#define AIRY_CAP_BUCKET_BITS	6
#define AIRY_CAP_BUCKET_NR	(1U << AIRY_CAP_BUCKET_BITS)
#define AIRY_CAP_BUCKET_MASK	(AIRY_CAP_BUCKET_NR - 1)

extern spinlock_t airy_cap_bucket_locks[AIRY_CAP_BUCKET_NR];

static inline unsigned int airy_cap_bucket(__u32 agent_id)
{
	return agent_id & AIRY_CAP_BUCKET_MASK;
}

/* ─── Fastpath Inline: C-S9 Badge Validation (~10ns) ─────────────────── */
/*
 * airy_cap_badge_ok - Fastpath inline badge validation.
 *
 * Executes 3 READ_ONCE + constant-time comparisons.  Called from the
 * io_uring_cmd fastpath for every IPC message.
 *
 * SSoT §12.2.1: the epoch, random-tag and permission checks always run
 * to completion, and the failure code is selected arithmetically
 * (EPOCH > FORGED > PERM).  No check is skipped based on an earlier
 * result, so the failure path does not reveal which field mismatched.
 *
 * SSoT §12.2.2: the three slot fields are read with READ_ONCE() and a
 * smp_mb() orders them before the verdict is computed.  SSoT §12.2.3:
 * in paranoid mode a speculation fence precedes the slot reads.
 *
 * Returns 0 (AIRY_EOK) if valid, negative error otherwise.
 */
static __always_inline __must_check int airy_cap_badge_ok(__u64 badge, __u32 agent_id,
					     __u16 required_perms)
{
	u32 epoch = (u32)AIRY_BADGE_EPOCH(badge);
	u32 randtag = (u32)AIRY_BADGE_RANDTAG(badge);
	u32 perms = (u32)AIRY_BADGE_PERMS(badge);
	u32 ok_epoch, ok_tag, ok_perm;
	u32 flags, err;

	if (unlikely(agent_id >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_MISSING;

	if (unlikely(READ_ONCE(airy_security_paranoid)))
		airy_ct_fence();

	/* C-S9.1/C-S9.2: per-agent epoch and random tag, same cacheline. */
	flags = READ_ONCE(agent_caps[agent_id].flags);
	ok_epoch = airy_ct_eq32(epoch, READ_ONCE(agent_caps[agent_id].epoch));
	/* A revoked slot cleared its tag, so the tag is no longer secret. */
	ok_epoch &= airy_ct_eq32(0U, flags & AIRY_CAP_FL_REVOKED);
	ok_tag = airy_ct_eq32(randtag, READ_ONCE(agent_caps[agent_id].randtag));
	/* C-S9.2: order slot loads before the verdict is derived. */
	smp_mb();

	/* C-S9.3: permission mask carried by the badge itself. */
	ok_perm = airy_ct_perm(perms, required_perms);

	err = (1U - ok_epoch) * AIRY_ECAP_EPOCH +
	      ok_epoch * ((1U - ok_tag) * AIRY_ECAP_FORGED +
			  ok_tag * (1U - ok_perm) * AIRY_ECAP_PERM);

	if (unlikely(err))
		airy_ct_delay();
	return -(int)err;
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
void airy_cap_unreg(__u32 agent_id);

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

/* ─── Fault Event Detail Ring (SSoT 09-agent-supervisor §5.1) ─────────── */
/*
 * struct airy_fault_event is the detail record the Micro-Supervisor hands
 * to the Macro-Supervisor.  The eventfd counter can only carry a packed
 * (fault_code, agent_id) pair, so the detail is queued in a bounded ring
 * that the Macro-Supervisor drains after the eventfd wakes it.
 *
 * airy_fev_* is the fault-event ring API ("fev" = fault event):
 *   - airy_fev_post()  records a detail; never blocks (NMI/die-safe)
 *   - airy_fev_fetch() drains one detail (single consumer)
 *   - airy_fev_reset() empties the ring; init and test teardown only
 *   - airy_fev_lost()  details dropped because the ring was full or busy
 *
 * Both callers of airy_eventfd_signal_fault() run where blocking is
 * illegal, so post() drops instead of waiting: it returns -AIRY_EBUSY
 * when the ring lock is contended and -AIRY_ENOMEM when the ring is
 * full.  Per SSoT §5.2 that loss is best-effort — the eventfd signal
 * itself is still delivered.
 */
#define AIRY_FEV_RING_NR	64U
#define AIRY_FEV_RING_MASK	(AIRY_FEV_RING_NR - 1U)

/*
 * ring_id used when a fault is not bound to one IPC ring (e.g. an oops
 * freezes every ring).  Matches the SSoT §4.2 example call.
 */
#define AIRY_FEV_RING_ID_NONE	0U

struct airy_fault_event {
	__u32 ring_id;
	__u32 fault_code;
	__u64 timestamp_ns;
	__u32 agent_id;
	__u32 pad;
};

int airy_fev_post(const struct airy_fault_event *ev);
int airy_fev_fetch(struct airy_fault_event *ev);
void airy_fev_reset(void);
unsigned int airy_fev_lost(void);

/* ─── Cross-TU API: IPC Freeze / EventFD / Die-Notify ─────────────────── */
/*
 * Single-host prototypes for symbols consumed across translation units
 * within security/airy and kernel/superv.  Declaring them here (rather
 * than as ad-hoc externs at each call site) removes duplicate prototypes
 * and, more importantly, the silent signature-drift hazard: C does not
 * diagnose a caller whose local extern disagrees with the real
 * definition, so each call site must not be free to redeclare the
 * prototype.
 */
struct task_struct;

void airy_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring, __u32 reason);
void airy_ipc_thaw_ring(struct airy_ipc_ring_freeze_state *ring);
int airy_ipc_fastpath_check(struct airy_ipc_ring_freeze_state *ring);
struct airy_ipc_ring_freeze_state *airy_ipc_ring_for_task(struct task_struct *task);

int airy_eventfd_register(int efd);
void airy_eventfd_unregister(void);
void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
			       __u64 timestamp);

extern struct atomic_notifier_head airy_die_chain;
void __init airy_die_notify_init(void);

/* ─── Slowpath Capability Check ───────────────────────────────────────── */
struct io_uring_cmd;
__must_check int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);
__must_check int airy_cap_check(__u32 agent_id, __u16 required_perms);
void airy_security_fault(__u32 agent_id, __u32 fault_code);

/* ─── Micro-Supervisor Supplemental Hook Registration ─────────────────── */
int __init airy_superv_register_hooks(void);

#endif /* _SECURITY_AIRY_CAP_H */

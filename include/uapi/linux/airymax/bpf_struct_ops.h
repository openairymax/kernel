/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * bpf_struct_ops.h — Supplementary shared contract header (NOT a [SC]
 * core header). Defines struct_ops state machine + common_value layout
 * shared between agentrt userspace BPF loader and agent-linux kernel
 * struct_ops framework.
 *
 * SSoT: docs/AirymaxOS/50-engineering-standards/120-cross-project-code-sharing.md
 *       §2.7 (supplementary shared file, not among the 10 [SC] core
 *       headers listed in OS-IRON-014).
 *
 * Physical host: kernel/include/uapi/linux/airymax/bpf_struct_ops.h
 * Sharing: physical sharing, byte-identical between agentrt and
 *          agent-linux (like [SC] headers but scoped to struct_ops
 *          state synchronisation).
 *
 * Design rationale: sched_tac userspace scheduler reuses this state
 * enum to read the registration state of BPF struct_ops function
 * tables exposed by the kernel, without accessing kernel private data.
 * agentrt userspace policy engine uses it to parse the `state` field
 * of sched_tac/macrosuperv struct_ops tables to decide whether the
 * userspace scheduler is online.
 *
 * v1.0.1: 4-state machine (INIT/REGISTERED/ACTIVE/DRAINING). The state
 *         transitions are kernel-driven; agentrt userspace is read-only
 *         consumer via BTF.
 */

#ifndef _UAPI_AIRYMAX_BPF_STRUCT_OPS_H
#define _UAPI_AIRYMAX_BPF_STRUCT_OPS_H

#include <linux/airymax/uapi_compat.h>

/* ─── struct_ops State Machine (4 states) ──────────────────────────────
 *
 * State transitions (kernel-driven, see kernel/bpf/bpf_struct_ops.c):
 *
 *   INIT  --register()-->  REGISTERED
 *   REGISTERED --activate()-->  ACTIVE
 *   ACTIVE  --drain()-->  DRAINING
 *   DRAINING --unregister()-->  INIT
 *
 * agentrt userspace observes state via BTF (read-only).
 */
enum airy_struct_ops_state {
	AIRY_STRUCT_OPS_INIT        = 0,  /* Allocated, not registered */
	AIRY_STRUCT_OPS_REGISTERED  = 1,  /* register_bpf_struct_ops() done */
	AIRY_STRUCT_OPS_ACTIVE      = 2,  /* Fully live, serving calls */
	AIRY_STRUCT_OPS_DRAINING    = 3,  /* Quiescing, no new calls accepted */
	AIRY_STRUCT_OPS_STATE_MAX
};

/* ─── struct_ops Common Value Layout ───────────────────────────────────
 *
 * Embedded as the first field of every Airymax struct_ops value type
 * (sched_tac function table, macrosuperv hooks, etc.). The kernel
 * bpf_struct_ops framework reads `state` to gate call dispatch.
 *
 * Alignment: __aligned(64) to avoid false sharing across CPUs when
 * the kernel updates `state` and userspace polls it via BTF.
 */
struct bpf_struct_ops_common_val {
	__u32   state;          /* enum airy_struct_ops_state */
	__u32   refcount;       /* kernel-managed reference count */
	__u64   registered_ns;  /* monotonic time of REGISTERED transition */
	__u64   activated_ns;   /* monotonic time of ACTIVE transition */
	__u8    _reserved[32];  /* reserved for future kernel fields */
} AIRY_ALIGNED(64);

_Static_assert(offsetof(struct bpf_struct_ops_common_val, state) == 0,
	       "state must be at offset 0 for BTF read compatibility");
_Static_assert(sizeof(struct bpf_struct_ops_common_val) == 64,
	       "bpf_struct_ops_common_val must be exactly 64 bytes (cache line)");

/* ─── Airymax struct_ops Value Type ────────────────────────────────────
 *
 * Used by sched_tac userspace scheduler and macrosuperv to register
 * BPF struct_ops function tables. The `common` field MUST be first
 * to satisfy the kernel bpf_struct_ops framework layout contract.
 *
 * v1.0.1: sched_tac reuses this value type (not a new type) to avoid
 *         divergent state machines between BPF and non-BPF paths.
 */
struct airy_struct_ops_value {
	struct bpf_struct_ops_common_val common;  /* MUST be first */
	__u32   version;                          /* struct_ops ABI version */
	__u32   flags;                            /* reserved for future use */
	__u8    name[48];                         /* human-readable identifier */
	__u8    _reserved[8];                     /* padding to 128 bytes */
} AIRY_ALIGNED(64);

_Static_assert(offsetof(struct airy_struct_ops_value, common) == 0,
	       "common must be first field for bpf_struct_ops framework");
_Static_assert(sizeof(struct airy_struct_ops_value) == 128,
	       "airy_struct_ops_value must be exactly 128 bytes (2 cache lines)");

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, struct_ops registration is
 * unavailable (CONFIG_BPF=n or BPF disabled). All states collapse to
 * INIT and airy_struct_ops_value is read-only zero. sched_tac falls
 * back to Linux 6.6 default EEVDF (see sched.h [DSL] block).
 */
#ifdef AIRY_SC_FALLBACK
	#define AIRY_DSL_STRUCT_OPS_STATE  AIRY_STRUCT_OPS_INIT
	#define AIRY_DSL_STRUCT_OPS_VALUE_INIT  { \
		.common = { .state = AIRY_STRUCT_OPS_INIT, .refcount = 0, \
			    .registered_ns = 0, .activated_ns = 0, ._reserved = {0} }, \
		.version = 0, .flags = 0, .name = {0}, ._reserved = {0} \
	}

	#warning "AIRY_SC_FALLBACK active: bpf_struct_ops.h degraded — struct_ops registration unavailable, states collapse to INIT"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_BPF_STRUCT_OPS_H */

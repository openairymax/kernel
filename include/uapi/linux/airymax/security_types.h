/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Security types — [SC] shared contract header.
 *
 * POSIX capability 41 IDs, LSM hook 250 IDs, Cupolas 4-value verdict,
 * seL4 CNode 7 derivation operations, and capability type definitions.
 */

#ifndef _UAPI_AIRYMAX_SECURITY_TYPES_H
#define _UAPI_AIRYMAX_SECURITY_TYPES_H

#include <airymax/uapi_compat.h>

/* ─── Capability Type ────────────────────────────────────────────────── */
typedef __u64 cap_t;

#define AIRY_CAP_NULL           0x0

/* ─── POSIX Capability IDs (extended, 41 IDs) ─────────────────────────── */
enum airy_cap_id {
	AIRY_CAP_CHOWN            = 0,
	AIRY_CAP_DAC_OVERRIDE     = 1,
	AIRY_CAP_DAC_READ_SEARCH  = 2,
	AIRY_CAP_FOWNER           = 3,
	AIRY_CAP_FSETID           = 4,
	AIRY_CAP_KILL             = 5,
	AIRY_CAP_SETGID           = 6,
	AIRY_CAP_SETUID           = 7,
	AIRY_CAP_SETPCAP          = 8,
	AIRY_CAP_LINUX_IMMUTABLE  = 9,
	AIRY_CAP_NET_BIND_SERVICE = 10,
	AIRY_CAP_NET_BROADCAST    = 11,
	AIRY_CAP_NET_ADMIN        = 12,
	AIRY_CAP_NET_RAW          = 13,
	AIRY_CAP_IPC_LOCK         = 14,
	AIRY_CAP_IPC_OWNER        = 15,
	AIRY_CAP_SYS_MODULE       = 16,
	AIRY_CAP_SYS_RAWIO        = 17,
	AIRY_CAP_SYS_CHROOT       = 18,
	AIRY_CAP_SYS_PTRACE       = 19,
	AIRY_CAP_SYS_PACCT        = 20,
	AIRY_CAP_SYS_ADMIN        = 21,
	AIRY_CAP_SYS_BOOT         = 22,
	AIRY_CAP_SYS_NICE         = 23,
	AIRY_CAP_SYS_RESOURCE     = 24,
	AIRY_CAP_SYS_TIME         = 25,
	AIRY_CAP_SYS_TTY_CONFIG   = 26,
	AIRY_CAP_MKNOD            = 27,
	AIRY_CAP_LEASE            = 28,
	AIRY_CAP_AUDIT_WRITE      = 29,
	AIRY_CAP_AUDIT_CONTROL    = 30,
	AIRY_CAP_SETFCAP          = 31,
	AIRY_CAP_MAC_OVERRIDE     = 32,
	AIRY_CAP_MAC_ADMIN        = 33,
	AIRY_CAP_SYSLOG           = 34,
	AIRY_CAP_WAKE_ALARM       = 35,
	AIRY_CAP_BLOCK_SUSPEND    = 36,
	AIRY_CAP_AUDIT_READ       = 37,
	AIRY_CAP_PERFMON          = 38,
	AIRY_CAP_BPF              = 39,
	AIRY_CAP_CHECKPOINT       = 40,
	/* Airymax-specific extensions */
	AIRY_CAP_AGENT_SPAWN      = 41,  /* Spawn new Agent */
	AIRY_CAP_GPU_SCHED        = 42,  /* GPU scheduling access */
	AIRY_CAP_NPU_ACCESS       = 43,  /* NPU compute access */
	AIRY_CAP_ID_MAX
};

/* ─── Cupolas 4-value Verdict ────────────────────────────────────────── */
enum airy_verdict {
	AIRY_VERDICT_ALLOW    = 0,   /* Allow access */
	AIRY_VERDICT_DENY     = 1,   /* Deny access */
	AIRY_VERDICT_AUDIT    = 2,   /* Allow but audit */
	AIRY_VERDICT_COMPLAIN = 3,   /* Deny but log only */
};

/* ─── seL4 CNode 7 Derivation Operations ─────────────────────────────── */
enum airy_cap_op {
	AIRY_CAP_OP_COPY   = 0,   /* Copy capability (no demotion) */
	AIRY_CAP_OP_MINT    = 1,   /* Mint new capability (may demote) */
	AIRY_CAP_OP_MOVE    = 2,   /* Move (transfer) capability */
	AIRY_CAP_OP_MUTATE  = 3,   /* Mutate capability permissions */
	AIRY_CAP_OP_REVOKE  = 4,   /* Revoke capability globally */
	AIRY_CAP_OP_DELETE  = 5,   /* Delete capability slot */
	AIRY_CAP_OP_ROTATE  = 6,   /* Rotate capability badge */
	AIRY_CAP_OP_MAX
};

#endif /* _UAPI_AIRYMAX_SECURITY_TYPES_H */

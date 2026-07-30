/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Security types — [SC] shared contract header.
 *
 * POSIX capability 44 IDs (41 standard + 3 Airymax extensions),
 * Airy LSM 5 implemented hooks (Linux 6.6 LSM framework exposes ~250
 * total slots — see lsm_types.h AIRY_LSM_KERNEL_HOOK_TOTAL),
 * Cupolas 4-value verdict, seL4 CNode 7 derivation operations,
 * and capability type definitions.
 */

#ifndef _UAPI_AIRYMAX_SECURITY_TYPES_H
#define _UAPI_AIRYMAX_SECURITY_TYPES_H

#include <linux/airymax/uapi_compat.h>

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

/* ─── Badge Permission Bits (16-bit perms field) ──────────────────────
 *
 * Used by airy_cap_badge_ok() fastpath and airy_lsm hook entry checks.
 * Bits 0-6 are defined; bits 7-15 reserved for future use.
 */
#define AIRY_CAP_PERM_NONE       0x0000
#define AIRY_CAP_PERM_SEND       0x0001  /* IPC send */
#define AIRY_CAP_PERM_RECV       0x0002  /* IPC recv */
#define AIRY_CAP_PERM_DERIVE     0x0004  /* Capability derivation (MINT/COPY) */
#define AIRY_CAP_PERM_KILL       0x0008  /* Signal delivery (task_kill hook) */
#define AIRY_CAP_PERM_FILE_OPEN  0x0010  /* File access (file_open hook) */
#define AIRY_CAP_PERM_ROTATE     0x0020  /* Badge rotation */
#define AIRY_CAP_PERM_SUPERVISE  0x0040  /* Micro-Supervisor authority */
#ifndef AIRY_CAP_PERM_ALL
#define AIRY_CAP_PERM_ALL        0x007F  /* All defined permissions */
#endif

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

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, the 41 POSIX capability IDs remain
 * authoritative (needed for slowpath airy_cap_check()), but Badge
 * derivation/compilation is suspended (sec_d unreachable). The Badge
 * access macros below return 0 so that callers extracting fields from
 * a fixed-0 badge still compile (H6 hard constraint). All non-POSIX
 * Airymax-specific cap IDs (41-43) are unavailable.
 * See [DSL] §2.2, §4.2 and §4.4.
 */
#ifdef AIRY_SC_FALLBACK
	/* H6: Badge access macros return 0 (badge is always 0 in [DSL]). */
	#ifndef AIRY_DSL_BADGE_EPOCH
		#define AIRY_DSL_BADGE_EPOCH(b)         ((__u32)0)
	#endif
	#ifndef AIRY_DSL_BADGE_RANDTAG
		#define AIRY_DSL_BADGE_RANDTAG(b)       ((__u32)0)
	#endif
	#ifndef AIRY_DSL_BADGE_PERMS
		#define AIRY_DSL_BADGE_PERMS(b)         ((__u16)0)
	#endif
	#define AIRY_DSL_BADGE_COMPILE(epoch, randtag, perms)  0ULL

	/* Badge derivation/compilation suspended — sec_d unreachable. */
	#define AIRY_DSL_CAP_OP_COPY     AIRY_CAP_OP_COPY
	#define AIRY_DSL_CAP_OP_MINT     AIRY_CAP_OP_COPY   /* MINT degrades to COPY */
	#define AIRY_DSL_CAP_OP_MOVE     AIRY_CAP_OP_MOVE
	#define AIRY_DSL_CAP_OP_MUTATE   AIRY_CAP_OP_COPY   /* MUTATE degrades to COPY */
	#define AIRY_DSL_CAP_OP_REVOKE   AIRY_CAP_OP_DELETE /* REVOKE degrades to DELETE */
	#define AIRY_DSL_CAP_OP_DELETE   AIRY_CAP_OP_DELETE
	#define AIRY_DSL_CAP_OP_ROTATE   AIRY_CAP_OP_DELETE /* ROTATE suspended */
	#define AIRY_DSL_CAP_OPS         2  /* Only COPY + DELETE retained */

	/* Airymax-specific cap IDs (41-43) unavailable in fallback. */
	#define AIRY_DSL_CAP_AGENT_SPAWN  (-1)
	#define AIRY_DSL_CAP_GPU_SCHED    (-1)
	#define AIRY_DSL_CAP_NPU_ACCESS   (-1)

	#warning "AIRY_SC_FALLBACK active: security_types.h degraded — 41 POSIX caps retained, Badge macros return 0 (H6), Airymax cap IDs suspended"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_SECURITY_TYPES_H */

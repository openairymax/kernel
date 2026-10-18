/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * error.h — A-UEF unified error and fault framework, [SC] shared header.
 *
 * Two disjoint code-spaces: Error (negative int32_t, recoverable,
 * POSIX-compatible — AIRY_E* are positive magnitudes, callers return
 * -AIRY_E*) and Fault (positive __u32, unrecoverable). 本头为 [SC]
 * 契约头，禁止与 agentrt 通用错误码在同一编译单元混用。
 *
 * Design rationale: docs/AirymaxOS/30-interfaces/08-sc-error-contract.md
 */

#ifndef _UAPI_AIRYMAX_ERROR_H
#define _UAPI_AIRYMAX_ERROR_H

#include <linux/airymax/uapi_compat.h>

/* ─── Error type ─────────────────────────────────────────────────────── */
typedef __s32 airy_err_t;

/* ─── Success ────────────────────────────────────────────────────────── */
#define AIRY_EOK              0

/* ─── POSIX-aligned Error Codes (positive magnitudes, return -AIRY_E*) ── */
#define AIRY_EACCES          1     /* Operation not permitted */
#define AIRY_EEXIST          2     /* File exists */
#define AIRY_EFAULT          3     /* Bad address */
#define AIRY_EINTR           4     /* Interrupted system call */
#define AIRY_EINVAL          5     /* Invalid argument */
#define AIRY_EIO             6     /* I/O error */
#define AIRY_EISDIR          7     /* Is a directory */
#define AIRY_ENOENT          8     /* No such file or directory */
#define AIRY_ENOMEM          9     /* Out of memory */
#define AIRY_ENOSPC          10    /* No space left on device */
#define AIRY_ENOTSUP         11    /* Operation not supported */
#define AIRY_EPERM           12    /* Operation not permitted (POSIX) */
#define AIRY_ERANGE          13    /* Result too large */
#define AIRY_EBUSY           16    /* Device or resource busy */
#define AIRY_ECANCELED       19    /* Operation canceled */
#define AIRY_EAGAIN          35    /* Try again */

/* ─── IPC Error Codes (sub-space: 41 to 70) ─────────────────────────────
 * Aligned with fastpath C-S0~C-S12 check chain (see 07-ipc-fastpath.md §5.2
 * and 08-sc-error-contract.md §2.3 — SSoT authority).
 */
#define AIRY_EIPC_MAGIC       41    /* C-S1:  Invalid IPC magic */
#define AIRY_EIPC_OPCODE      42    /* C-S2:  Unknown IPC opcode */
#define AIRY_EIPC_PAYLOAD     43    /* C-S3:  payload_len out of bounds */
#define AIRY_EIPC_HDRSIZE     44    /* C-S4:  Header size != 128 bytes */
#define AIRY_EIPC_RESERVED    45    /* C-S4:  reserved[72] not all zero */
#define AIRY_EIPC_FLAGS       46    /* C-S10: flags invalid (reserved bits nonzero) */
#define AIRY_EIPC_NOTSUPP     47    /* C-S10: opcode/flag not supported (e.g. ENCRYPT/COMPRESS) */
#define AIRY_EIPC_KFIFO       48    /* C-S6:  kfifo enqueue failed */
#define AIRY_EIPC_RECLAIM     49    /* C-S7:  reclaim flag set */
#define AIRY_EIPC_CONTEXT     50    /* C-S8:  context check failed (!in_task) */
#define AIRY_EIPC_CRC32       51    /* C-S12: CRC32 check failed (header[0:52) + payload) */
#define AIRY_EIPC_TIMEOUT     52    /* SLOW_SEND timeout */
#define AIRY_EIPC_FROZEN      53    /* C-S0:  Ring frozen (fastpath freeze check, A-ULS controlled) */
/* [54, 70] reserved */

/* ─── Capability Error Codes (sub-space: 71 to 100) ─────────────────────
 * See 08-sc-error-contract.md §2.4 — SSoT authority.
 */
#define AIRY_ECAP_MISSING     71    /* Capability not found */
#define AIRY_ECAP_REVOKED     72    /* Capability revoked */
#define AIRY_ECAP_EXPIRED     73    /* Capability expired */
#define AIRY_ECAP_MISMATCH    74    /* Capability mismatch */
#define AIRY_ECAP_LSM_DENIED  75    /* Pure-C LSM denied */
#define AIRY_ECAP_RADIX_MISS  76    /* [DSL] radix tree lookup miss */
#define AIRY_ECAP_STATIC_KEY  77    /* [DSL] static_key disabled */

/* Capability Folding Badge validation codes (v1.0.1, C-S9 fastpath) */
#define AIRY_ECAP_BADGE       78    /* Badge invalid / RandomTag mismatch / CAP_CARRY but badge=0 */
#define AIRY_ECAP_EPOCH       79    /* Badge Epoch mismatch (revoked or expired) */
#define AIRY_ECAP_FORGED      80    /* Badge forgery detected (also triggers AIRY_FAULT_CAP_FORGED) */
#define AIRY_ECAP_PERM        81    /* Badge permissions insufficient for opcode */
#define AIRY_ECAP_FROZEN      82    /* Capability badge frozen (badge revocation, A-ULS controlled) */
#define AIRY_ESEC_D_THROTTLED 83    /* sec_d throttle rejected (queue full) */
#define AIRY_ECAP_OVERFLOW    84    /* Capability slot table overflow (agent_id >= AIRY_CAP_MAX_AGENTS) */
/* [85, 100] reserved */

/* ─── Config/Version Error Codes (sub-space: 101 to 120) ────────────────
 * Cross-cutting: configuration version mismatch and schema errors.
 * AIRY_ECFGVERSION is the single non-POSIX code retained in [DSL] mode
 * (see 11-degraded-survival-layer.md §4.1.1).
 */
#define AIRY_ECFGVERSION      101   /* Configuration version mismatch */
#define AIRY_ECFGSCHEMA       102   /* Configuration schema invalid */
#define AIRY_ECFGBASE64       103   /* Base64 decode failure */
#define AIRY_ECFGJSON         104   /* JSON parse failure */
#define AIRY_ECFGIO           105   /* Config I/O error */

/* ─── A-ULS Scheduler/Lifecycle Error Codes (sub-space: 121 to 140) ─────
 * Unified Lifecycle Supervision: sched_tac policy, budget, deadline,
 * and agent lifecycle state transitions.
 */
#define AIRY_ESCHED_POLICY    121   /* Invalid scheduling policy */
#define AIRY_ESCHED_BUDGET    122   /* Runtime budget exceeded */
#define AIRY_ESCHED_DEADLINE  123   /* Deadline missed */
#define AIRY_ESCHED_PERIOD    124   /* Invalid period */
#define AIRY_ESCHED_PRIO      125   /* Invalid priority */
#define AIRY_ESCHED_WEIGHT    126   /* Invalid EEVDF weight */
#define AIRY_ELIFECYCLE_STATE 127   /* Invalid agent lifecycle state */
#define AIRY_ELIFECYCLE_TRANS 128   /* Illegal state transition */
#define AIRY_ELIFECYCLE_AGENT 129   /* Agent not found */
#define AIRY_ELIFECYCLE_ZOMBIE 130  /* Agent in zombie state */

/* ─── MemoryRoVol Error Codes (sub-space: 141 to 160) ───────────────────
 * Memory Roving Volume: tier allocation, PMEM, CXL, page classification.
 */
#define AIRY_EMEM_TIER        141   /* Invalid memory tier */
#define AIRY_EMEM_GFP         142   /* Invalid GFP flags */
#define AIRY_EMEM_PMEM        143   /* PMEM operation failed */
#define AIRY_EMEM_CXL         144   /* CXL operation failed */
#define AIRY_EMEM_PAGE_CLASS  145   /* Invalid page classification */
#define AIRY_EMEM_MMAP        146   /* mmap failed */
#define AIRY_EMEM_ALLOC       147   /* alloc_pages failed */
#define AIRY_EMEM_OOM         148   /* Out of memory (agent-scoped) */

/* ─── A-UCS Cognition Error Codes (sub-space: 161 to 180) ───────────────
 * Unified Cognition Subsystem: CoreLoopThree, Thinkdual, Q16.16.
 */
#define AIRY_ECOG_PHASE       161   /* Invalid cognition phase */
#define AIRY_ECOG_MODE        162   /* Invalid think mode */
#define AIRY_ECOG_Q16         163   /* Q16.16 overflow/underflow */
#define AIRY_ECOG_TIMEOUT     164   /* Cognition loop timeout */
#define AIRY_ECOG_ITERATIONS  165   /* Max think iterations exceeded */
#define AIRY_ECOG_CONFIDENCE  166   /* Confidence threshold not met */

/* ─── A-ULP Log Error Codes (sub-space: 181 to 200) ─────────────────────
 * Unified Logging and Printk: Ring Buffer, persistence, facility.
 */
#define AIRY_ELOG_RING        181   /* Ring Buffer write failed */
#define AIRY_ELOG_FULL        182   /* Ring Buffer full */
#define AIRY_ELOG_LEVEL       183   /* Invalid log level */
#define AIRY_ELOG_FACILITY    184   /* Invalid facility code */
#define AIRY_ELOG_PERSIST     185   /* Log persistence failed */
#define AIRY_ELOG_MAGIC       186   /* Log record magic mismatch */

/* ─── Object/Handle Error Codes (sub-space: 201 to 220) ─────────────────
 * Airymax Object System: handle resolution, reference counting.
 */
#define AIRY_EOBJ_HANDLE      201   /* Invalid object handle */
#define AIRY_EOBJ_REFCOUNT    202   /* Reference count overflow/underflow */
#define AIRY_EOBJ_TYPE        203   /* Object type mismatch */
#define AIRY_EOBJ_GONE        204   /* Object already destroyed */

/* ─── Syscall Error Codes (sub-space: 221 to 240) ───────────────────────
 * Airymax syscall surface: numbering, dispatch, ABI.
 */
#define AIRY_ESYS_NUMBER      221   /* Invalid syscall number */
#define AIRY_ESYS_ARGS        222   /* Invalid syscall arguments */
#define AIRY_ESYS_DISABLED    223   /* Syscall disabled in [DSL] mode */
#define AIRY_ESYS_ABI         224   /* ABI mismatch */

/* ─── Encoding Error Codes (sub-space: 241 to 260) ──────────────────────
 * Strict UTF-8 validation of text crossing a kernel boundary.  The
 * codes name the first illegal sequence so a caller can distinguish a
 * structural fault from a policy refusal without rescanning the input.
 * See 180-i18n/02-encoding-spec.md §7 and 08-sc-error-contract.md.
 */
#define AIRY_EENC_INVALID     241   /* Malformed UTF-8 sequence */
#define AIRY_EENC_OVERLONG    242   /* Overlong encoding */
#define AIRY_EENC_SURROGATE   243   /* UTF-16 surrogate code point */
#define AIRY_EENC_NONCHAR     244   /* Unicode noncharacter */
#define AIRY_EENC_RANGE       245   /* Code point beyond U+10FFFF */
#define AIRY_EENC_BOM         246   /* U+FEFF byte order mark */

/* ─── Lockdown Error Codes (sub-space: 261 to 280) ──────────────────────
 * Policy refusals raised by the Airymax lockdown ladder.  A refusal is
 * not a security violation: callers must propagate the value and must
 * not raise a fault (see 110-security/09-lockdown.md §5).
 */
#define AIRY_ELOCKDOWN        261   /* Interface blocked at the active lockdown level */

/* ─── Reserved Sub-spaces (262 to 300) ───────────────────────────────────
 * Reserved for future Airymax subsystems. Do not allocate without
 * updating docs/AirymaxOS/30-interfaces/08-sc-error-contract.md.
 */

/* ─── Fault Codes (positive __u32) ────────────────────────────────── */
#define AIRY_FAULT_CAP_FORGED        0x1001  /* Badge forgery (security breach) */
#define AIRY_FAULT_CAP_LEAK          0x1002  /* Capability leak detected */
#define AIRY_FAULT_RING_CORRUPT      0x1003  /* IPC ring corruption */
#define AIRY_FAULT_TIMEOUT           0x1004  /* Agent heartbeat timeout */
#define AIRY_FAULT_ABNORMAL_CAP      0x1005  /* Abnormal capability usage */
#define AIRY_FAULT_VM_FAULT          0x1006  /* VM page fault in Agent */
#define AIRY_FAULT_DOUBLE_FAULT      0x100C  /* Macro-Supervisor loss */

/* ─── Helper macros ──────────────────────────────────────────────────── */
#define AIRY_ERR_OK(err)    ((err) == AIRY_EOK)
#define AIRY_ERR_FAIL(err)  ((err) < 0)

/* ─── [DSL] Degraded Survival Layer Fallback Block ────────────────────── */
#ifdef AIRY_SC_FALLBACK
	/*
	 * When [SC] headers are unavailable (boot/rescue mode),
	 * map 38 POSIX codes onto 7 core codes.
	 */
	#define AIRY_DSL_E2BIG        AIRY_EINVAL
	#define AIRY_DSL_ECHILD       AIRY_EINVAL
	#define AIRY_DSL_EDEADLK      AIRY_EBUSY
	#define AIRY_DSL_EDOM         AIRY_EINVAL
	#define AIRY_DSL_EEXIST_S     AIRY_EEXIST
	#define AIRY_DSL_EFBIG        AIRY_EINVAL
	#define AIRY_DSL_EILSEQ       AIRY_EINVAL
	#define AIRY_DSL_EINPROGRESS  AIRY_EAGAIN
	#define AIRY_DSL_EISCONN      AIRY_EBUSY
	#define AIRY_DSL_ELOOP        AIRY_EINVAL
	#define AIRY_DSL_EMFILE       AIRY_ENOMEM
	#define AIRY_DSL_EMLINK       AIRY_ENOMEM
	#define AIRY_DSL_ENAMETOOLONG AIRY_EINVAL
	#define AIRY_DSL_ENFILE       AIRY_ENOMEM
	#define AIRY_DSL_ENODEV       AIRY_EINVAL
	#define AIRY_DSL_ENOEXEC      AIRY_EINVAL
	#define AIRY_DSL_ENOLCK       AIRY_ENOMEM
	#define AIRY_DSL_ENOMSG       AIRY_ECANCELED
	#define AIRY_DSL_ENOTBLK      AIRY_EINVAL
	#define AIRY_DSL_ENOTCONN     AIRY_ECANCELED
	#define AIRY_DSL_ENOTDIR      AIRY_EINVAL
	#define AIRY_DSL_ENOTEMPTY    AIRY_EBUSY
	#define AIRY_DSL_ENOTSOCK     AIRY_EINVAL
	#define AIRY_DSL_ENXIO        AIRY_EINVAL
	#define AIRY_DSL_EOPNOTSUPP   AIRY_ENOTSUP
	#define AIRY_DSL_EOVERFLOW    AIRY_EINVAL
	#define AIRY_DSL_EPIPE        AIRY_ECANCELED
	#define AIRY_DSL_EPROTO       AIRY_EINVAL
	#define AIRY_DSL_EROFS        AIRY_EBUSY
	#define AIRY_DSL_ESPIPE       AIRY_EINVAL
	#define AIRY_DSL_ESRCH        AIRY_EINVAL
	#define AIRY_DSL_ETIMEDOUT    AIRY_ECANCELED
	#define AIRY_DSL_ETXTBSY      AIRY_EBUSY
	#define AIRY_DSL_EWOULDBLOCK  AIRY_EAGAIN
	#define AIRY_DSL_EXDEV        AIRY_EINVAL
	#define AIRY_DSL_ENODATA      AIRY_ECANCELED
	#define AIRY_DSL_ENOSR        AIRY_ENOMEM
	#define AIRY_DSL_ESTALE       AIRY_ECANCELED
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_ERROR_H */

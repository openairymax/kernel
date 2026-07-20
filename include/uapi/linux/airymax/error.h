/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-UEF (Unified Error and Fault Framework) — [SC] shared contract header.
 *
 * Two disjoint code-spaces:
 *   Error  space (negative int32_t): recoverable errors, POSIX-compatible.
 *   Fault  space (positive uint32_t): unrecoverable faults,
 *          hardware/security/invariants.
 *
 * [DSL] fallback block: 38 POSIX codes active when AIRY_SC_FALLBACK is defined,
 * mapping to 5 core codes (EINVAL, ENOMEM, EBUSY, ECANCELED, EAGAIN).
 */

#ifndef _UAPI_AIRYMAX_ERROR_H
#define _UAPI_AIRYMAX_ERROR_H

#include <airymax/uapi_compat.h>

/* ─── Error type ─────────────────────────────────────────────────────── */
typedef __s32 airy_err_t;

/* ─── Success ────────────────────────────────────────────────────────── */
#define AIRY_EOK              0

/* ─── POSIX-aligned Error Codes (negative) ───────────────────────────── */
#define AIRY_EACCES          (-1)     /* Operation not permitted */
#define AIRY_EEXIST          (-2)     /* File exists */
#define AIRY_EFAULT          (-3)     /* Bad address */
#define AIRY_EINTR           (-4)     /* Interrupted system call */
#define AIRY_EINVAL          (-5)     /* Invalid argument */
#define AIRY_EIO             (-6)     /* I/O error */
#define AIRY_EISDIR          (-7)     /* Is a directory */
#define AIRY_ENOENT          (-8)     /* No such file or directory */
#define AIRY_ENOMEM          (-9)     /* Out of memory */
#define AIRY_ENOSPC          (-10)    /* No space left on device */
#define AIRY_ENOTSUP         (-11)    /* Operation not supported */
#define AIRY_EPERM           (-12)    /* Operation not permitted (POSIX) */
#define AIRY_ERANGE          (-13)    /* Result too large */
#define AIRY_EBUSY           (-16)    /* Device or resource busy */
#define AIRY_ECANCELED       (-19)    /* Operation canceled */
#define AIRY_EAGAIN          (-35)    /* Try again */

/* ─── IPC Error Codes (sub-space: -41 to -59) ────────────────────────── */
#define AIRY_EIPC_MAGIC       (-41)    /* Invalid IPC magic */
#define AIRY_EIPC_CHECKSUM    (-42)    /* CRC32 mismatch */
#define AIRY_EIPC_SIZE        (-43)    /* Payload size out of bounds */
#define AIRY_EIPC_RING_FULL   (-44)    /* Ring buffer full */
#define AIRY_EIPC_RING_EMPTY  (-45)    /* Ring buffer empty */
#define AIRY_EIPC_FROZEN      (-46)    /* IPC ring is frozen */
#define AIRY_EIPC_BADGE       (-47)    /* Badge validation failed */
#define AIRY_EIPC_PERM        (-48)    /* Permission denied */
#define AIRY_EIPC_OPCODE      (-49)    /* Unknown IPC opcode */
#define AIRY_EIPC_TIMEOUT     (-52)    /* IPC operation timed out */

/* ─── Capability Error Codes (sub-space: -71 to -89) ─────────────────── */
#define AIRY_ECAP_MISSING     (-71)    /* Capability not found */
#define AIRY_ECAP_EPOCH       (-72)    /* Epoch mismatch (revoked) */
#define AIRY_ECAP_FORGED      (-73)    /* Badge forgery detected */
#define AIRY_ECAP_PERM        (-74)    /* Insufficient capability permissions */
#define AIRY_ECAP_FROZEN      (-75)    /* Agent capability is frozen */
#define AIRY_ECAP_CORRUPT     (-76)    /* Capability slot corrupted */
#define AIRY_ECAP_OVERFLOW    (-77)    /* Capability table overflow */
#define AIRY_ECAP_SYS         (-82)    /* System capability required */

/* ─── Fault Codes (positive uint32_t) ────────────────────────────────── */
#define AIRY_FAULT_CAP_FORGED        0x1001  /* Badge forgery (security breach) */
#define AIRY_FAULT_CAP_LEAK          0x1002  /* Capability leak detected */
#define AIRY_FAULT_RING_CORRUPT      0x1003  /* IPC ring corruption */
#define AIRY_FAULT_TIMEOUT           0x1004  /* Agent heartbeat timeout */
#define AIRY_FAULT_ABNORMAL_CAP      0x1005  /* Abnormal capability usage */
#define AIRY_FAULT_VM_FAULT          0x1006  /* VM page fault in Agent */

/* ─── Helper macros ──────────────────────────────────────────────────── */
#define AIRY_ERR_OK(err)    ((err) == AIRY_EOK)
#define AIRY_ERR_FAIL(err)  ((err) < 0)

/* ─── [DSL] Degraded Survival Layer Fallback Block ────────────────────── */
#ifdef AIRY_SC_FALLBACK
	/*
	 * When [SC] headers are unavailable (boot/rescue mode),
	 * fallback to 5 core POSIX codes mapped from 38 POSIX codes.
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

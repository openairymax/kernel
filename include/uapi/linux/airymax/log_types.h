/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-ULP (Unified Logging and Printk Subsystem) — [SC] shared contract header.
 *
 * Defines the 128-byte fixed log record format, log level enumeration,
 * and printk 8-level mapping for kernel-state logging.
 */

#ifndef _UAPI_AIRYMAX_LOG_TYPES_H
#define _UAPI_AIRYMAX_LOG_TYPES_H

#include <linux/airymax/uapi_compat.h>

/* ─── Magic ──────────────────────────────────────────────────────────── */
#define AIRY_LOG_MAGIC          0x414C4F47  /* 'ALOG' */

/* ─── Log Record: 128-byte fixed format ──────────────────────────────── */
#define AIRY_LOG_RECORD_SIZE    128

struct airy_log_record {
	__u32   magic;              /* offset 0:  AIRY_LOG_MAGIC */
	__u16   level;              /* offset 4:  airy_log_level enum */
	__u16   facility;           /* offset 6:  facility code */
	__u64   timestamp_ns;       /* offset 8:  monotonic ns timestamp */
	__u32   caller_id;          /* offset 16: caller identifier (PID/task_id) */
	__u32   payload_len;        /* offset 20: actual payload length (<=96) */
	__u8    payload[96];        /* offset 24: log message payload */
	__u8    reserved[8];        /* offset 120: reserved for future use */
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct airy_log_record) == AIRY_LOG_RECORD_SIZE,
	       "airy_log_record must be exactly 128 bytes");

/* ─── Log Level Enumeration (5 levels) ────────────────────────────────── */
enum airy_log_level {
	AIRY_LOG_DEBUG   = 0,  /* Debug messages (development only) */
	AIRY_LOG_INFO    = 1,  /* Informational messages */
	AIRY_LOG_WARN    = 2,  /* Warning conditions */
	AIRY_LOG_ERROR   = 3,  /* Error conditions */
	AIRY_LOG_FATAL   = 4,  /* Fatal conditions (system may halt) */
	AIRY_LOG_LEVEL_MAX
};

/* ─── printk 8-level to A-ULP 5-level mapping ────────────────────────── */
/* KERN_EMERG(0) -> FATAL, KERN_ALERT(1) -> FATAL, KERN_CRIT(2) -> FATAL */
/* KERN_ERR(3)   -> ERROR, KERN_WARNING(4) -> WARN */
/* KERN_NOTICE(5)-> INFO,  KERN_INFO(6)     -> INFO */
/* KERN_DEBUG(7) -> DEBUG */

/* ─── Facility Codes ──────────────────────────────────────────────────── */
#define AIRY_LOG_FAC_KERN       0x0001  /* Kernel facility */
#define AIRY_LOG_FAC_USER       0x0002  /* User-space facility */
#define AIRY_LOG_FAC_DAEMON     0x0003  /* Daemon facility */
#define AIRY_LOG_FAC_SECURITY   0x0004  /* Security/Audit facility */
#define AIRY_LOG_FAC_SCHED      0x0005  /* Scheduler facility */
#define AIRY_LOG_FAC_IPC        0x0006  /* IPC facility */
#define AIRY_LOG_FAC_MEMORY     0x0007  /* Memory subsystem facility */

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, A-ULP does not initialize the Ring
 * Buffer and only LOG_FATAL + LOG_ERROR levels are honoured. All other
 * levels are silently mapped to LOG_ERROR so that callers compiling in
 * fallback mode still produce visible output via the printk native path.
 * See docs/AirymaxOS/10-architecture/11-degraded-survival-layer.md §2.2.
 */
#ifdef AIRY_SC_FALLBACK
	#define AIRY_DSL_LOG_DEBUG   AIRY_LOG_ERROR
	#define AIRY_DSL_LOG_INFO    AIRY_LOG_ERROR
	#define AIRY_DSL_LOG_WARN    AIRY_LOG_ERROR
	#define AIRY_DSL_LOG_ERROR   AIRY_LOG_ERROR
	#define AIRY_DSL_LOG_FATAL   AIRY_LOG_FATAL
	#define AIRY_DSL_LOG_LEVELS  2  /* Only FATAL + ERROR retained */

	#warning "AIRY_SC_FALLBACK active: log_types.h degraded to LOG_FATAL+LOG_ERROR only, Ring Buffer disabled"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_LOG_TYPES_H */

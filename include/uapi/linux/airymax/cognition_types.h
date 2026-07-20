/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-UCS (Unified Cognition Subsystem) types — [SC] shared contract header.
 *
 * Q16.16 fixed-point type, CoreLoopThree three-phase cognition loop,
 * and Thinkdual dual-mode reasoning.
 */

#ifndef _UAPI_AIRYMAX_COGNITION_TYPES_H
#define _UAPI_AIRYMAX_COGNITION_TYPES_H

#include <linux/airymax/uapi_compat.h>

/* ─── Q16.16 Fixed-Point ─────────────────────────────────────────────── */
typedef __s32 airy_q16_t;

#define AIRY_Q16_ONE            (1 << 16)  /* 1.0 in Q16.16 */
#define AIRY_Q16_HALF           (1 << 15)  /* 0.5 in Q16.16 */

/*
 * Float conversion helpers are userspace-only: the kernel does not
 * use floating-point (IRON-9 §2.1). Guard with #ifndef __KERNEL__ so
 * kernel TUs never see the float types.
 */
#ifndef __KERNEL__
#define AIRY_Q16_TO_FLOAT(x)    ((float)(x) / (float)(1 << 16))
#define AIRY_Q16_FROM_FLOAT(f)  ((airy_q16_t)((f) * (float)(1 << 16)))
#endif /* __KERNEL__ */

/* ─── CoreLoopThree: Perception → Think → Act ──────────────────────── */
enum airy_cog_phase {
	AIRY_COG_PERCEPT  = 0,   /* Perception: observe environment */
	AIRY_COG_THINK    = 1,   /* Think: reason and plan */
	AIRY_COG_ACT      = 2,   /* Act: execute actions */
	AIRY_COG_PHASE_MAX
};

/* ─── Thinkdual: Fast Mode vs Slow Mode ─────────────────────────────── */
enum airy_think_mode {
	AIRY_THINK_FAST   = 0,   /* Fast: pattern recognition, low latency */
	AIRY_THINK_SLOW   = 1,   /* Slow: deliberate reasoning, high quality */
	AIRY_THINK_MODE_MAX
};

/* ─── Cognition Configuration ────────────────────────────────────────── */
struct airy_cog_config {
	airy_q16_t   confidence_threshold;  /* Minimum confidence to act */
	airy_q16_t   interrupt_priority;    /* Priority for cognitive interrupts */
	__u32        loop_timeout_ms;       /* Max loop cycle duration */
	__u32        max_think_iterations;  /* Max reasoning iterations */
	__u8         think_mode;            /* Default: FAST or SLOW */
	__u8         _pad[7];              /* Alignment */
};

#endif /* _UAPI_AIRYMAX_COGNITION_TYPES_H */

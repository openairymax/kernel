// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_time.c — Airymax core-kernel time services.
 *
 * Provides monotonic nanosecond timestamps and deadline arithmetic
 * built on top of ktime_get_ns().  All arithmetic is integer-only
 * (no floating point) per ALK-6.6 constraints.
 */

#include <linux/printk.h>
#include <linux/ktime.h>
#include <linux/overflow.h>
#include <linux/errno.h>

/* ─── Current monotonic time in nanoseconds ──────────────────────────── */
u64 airy_time_now_ns(void)
{
	return ktime_get_ns();
}

/* ─── Deadline arithmetic ────────────────────────────────────────────── */
u64 airy_time_deadline_ns(u64 base, u64 delta)
{
	u64 deadline;

	/* Guard against 64-bit wraparound. */
	if (check_add_overflow(base, delta, &deadline))
		return U64_MAX;

	return deadline;
}

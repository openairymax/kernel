/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_log_kern.c — A-ULP kernel-side printk bridge.
 *
 * Maps the 8 printk log levels (KERN_EMERG..KERN_DEBUG) to the 5-level
 * A-ULP enumeration (FATAL/ERROR/WARN/INFO/DEBUG) and forwards emitted
 * records to the standard printk ring via vprintk_emit().
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/kern_levels.h>
#include <linux/airymax/log_types.h>

/* ─── printk 8-level → A-ULP 5-level mapping table ────────────────────── */
/*
 * KERN_EMERG(0) / ALERT(1) / CRIT(2) → FATAL
 * KERN_ERR(3)                        → ERROR
 * KERN_WARNING(4)                    → WARN
 * KERN_NOTICE(5) / INFO(6)           → INFO
 * KERN_DEBUG(7)                      → DEBUG
 */
static const int airy_log_level_map[] = {
	[LOGLEVEL_EMERG]   = AIRY_LOG_FATAL,
	[LOGLEVEL_ALERT]   = AIRY_LOG_FATAL,
	[LOGLEVEL_CRIT]    = AIRY_LOG_FATAL,
	[LOGLEVEL_ERR]     = AIRY_LOG_ERROR,
	[LOGLEVEL_WARNING] = AIRY_LOG_WARN,
	[LOGLEVEL_NOTICE]  = AIRY_LOG_INFO,
	[LOGLEVEL_INFO]    = AIRY_LOG_INFO,
	[LOGLEVEL_DEBUG]   = AIRY_LOG_DEBUG,
};

/* ─── Emit a log record via vprintk_emit() ────────────────────────────── */
/*
 * @kern_level: printk level (LOGLEVEL_EMERG..LOGLEVEL_DEBUG, or
 *              LOGLEVEL_DEFAULT for the system default).
 * @fmt:        printf-style format string.
 *
 * The kern_level is forwarded to vprintk_emit() unchanged so that the
 * standard printk filtering and console_loglevel semantics still apply.
 * The A-ULP level mapping is referenced here to keep the table live and
 * to document the A-ULP category this record corresponds to.
 */
void airy_log_emit(int kern_level, const char *fmt, ...)
{
	va_list args;

	if (kern_level < 0 || kern_level > LOGLEVEL_DEBUG)
		kern_level = LOGLEVEL_DEFAULT;

	/* Reference the mapping table: records emitted at this kern_level
	 * correspond to the A-ULP level airy_log_level_map[kern_level]. */
	(void)airy_log_level_map[kern_level];

	va_start(args, fmt);
	vprintk_emit(0 /* LOG_KERN facility */, kern_level, NULL, fmt, args);
	va_end(args);
}

/* ─── Late init: announce kernel-side readiness ───────────────────────── */
static int __init airy_log_kern_init(void)
{
	pr_info("airy log: kernel side ready\n");
	return 0;
}
late_initcall(airy_log_kern_init);

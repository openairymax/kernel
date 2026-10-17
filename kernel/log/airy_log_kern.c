// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_log_kern.c — A-ULP kernel-side printk bridge.
 *
 * Maps the 8 printk log levels (KERN_EMERG..KERN_DEBUG) to the 5-level
 * A-ULP enumeration (FATAL/ERROR/WARN/INFO/DEBUG) and forwards emitted
 * records to the standard printk ring via vprintk_emit().
 *
 * The mapping table and airy_log_kern_to_level() are exported so that
 * other subsystems (e.g. the ring-buffer fastpath) can categorise a
 * record by its A-ULP level without duplicating the table.
 *
 * Design: docs/AirymaxOS/40-dataflows/05-ring-buffer-logging.md §3
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/kern_levels.h>
#include <linux/export.h>
#include <linux/airymax/log_types.h>

/* ─── printk 8-level → A-ULP 5-level mapping table ──────────────────────
 * Indexable by LOGLEVEL_EMERG(0) .. LOGLEVEL_DEBUG(7).
 *
 *   KERN_EMERG(0) / ALERT(1) / CRIT(2) → FATAL
 *   KERN_ERR(3)                        → ERROR
 *   KERN_WARNING(4)                    → WARN
 *   KERN_NOTICE(5) / INFO(6)           → INFO
 *   KERN_DEBUG(7)                      → DEBUG
 *
 * Exported (non-static) so callers that need the A-ULP category for a
 * given printk level can index it directly.
 */
const int airy_log_level_map[] = {
	[LOGLEVEL_EMERG]   = AIRY_LOG_FATAL,
	[LOGLEVEL_ALERT]   = AIRY_LOG_FATAL,
	[LOGLEVEL_CRIT]    = AIRY_LOG_FATAL,
	[LOGLEVEL_ERR]     = AIRY_LOG_ERROR,
	[LOGLEVEL_WARNING] = AIRY_LOG_WARN,
	[LOGLEVEL_NOTICE]  = AIRY_LOG_INFO,
	[LOGLEVEL_INFO]    = AIRY_LOG_INFO,
	[LOGLEVEL_DEBUG]   = AIRY_LOG_DEBUG,
};
EXPORT_SYMBOL_GPL(airy_log_level_map);

/* 表以指定初始化器逐项铺满 LOGLEVEL_EMERG..LOGLEVEL_DEBUG；若 kern_levels.h
 * 挪动起点或终点，未覆盖的槽会静默取 0（AIRY_LOG_DEBUG）。把覆盖范围在
 * 编译期钉死，使映射表与 airy_log_kern_to_level() 的边界判定同源。
 */
static_assert(LOGLEVEL_EMERG == 0, "printk level space must start at 0");
static_assert(ARRAY_SIZE(airy_log_level_map) == LOGLEVEL_DEBUG + 1,
	      "printk level map must cover LOGLEVEL_EMERG..LOGLEVEL_DEBUG");

/* ─── Map a printk level to the A-ULP 5-level enumeration ───────────────
 * @kern_level: printk level (LOGLEVEL_EMERG..LOGLEVEL_DEBUG, or
 *              LOGLEVEL_DEFAULT for the system default).
 *
 * Returns the corresponding airy_log_level enum value.  Out-of-range
 * levels (including LOGLEVEL_DEFAULT) map to AIRY_LOG_INFO.
 */
int airy_log_kern_to_level(int kern_level)
{
	if (kern_level < 0 || kern_level > LOGLEVEL_DEBUG)
		return AIRY_LOG_INFO;
	return airy_log_level_map[kern_level];
}
EXPORT_SYMBOL_GPL(airy_log_kern_to_level);

/* ─── Emit a log record via vprintk_emit() ──────────────────────────────
 * @kern_level: printk level (LOGLEVEL_EMERG..LOGLEVEL_DEBUG, or
 *              LOGLEVEL_DEFAULT for the system default).
 * @fmt:        printf-style format string.
 *
 * The printk level is forwarded to vprintk_emit() UNCHANGED so that the
 * standard printk filtering and console_loglevel semantics still apply.
 * Callers that need the A-ULP category of a record (e.g. for ring-buffer
 * routing) map it through the exported airy_log_kern_to_level().
 */
void airy_log_emit(int kern_level, const char *fmt, ...)
{
	va_list args;

	if (kern_level < 0 || kern_level > LOGLEVEL_DEBUG)
		kern_level = LOGLEVEL_DEFAULT;

	va_start(args, fmt);
	vprintk_emit(0, kern_level, NULL, fmt, args);
	va_end(args);
}
EXPORT_SYMBOL_GPL(airy_log_emit);

/* ─── Late init: announce kernel-side readiness ───────────────────────── */
static int __init airy_log_kern_init(void)
{
	pr_info("airy log: kernel side ready\n");
	return 0;
}
late_initcall(airy_log_kern_init);

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
 * The printk level is forwarded to vprintk_emit() UNCHANGED so that
 * the standard printk filtering and console_loglevel semantics still
 * apply.  The A-ULP level is computed via airy_log_kern_to_level()
 * so the mapping is exercised and available; callers that need the
 * A-ULP category (e.g. for ring-buffer routing with rec->level)
 * should call airy_log_kern_to_level() directly.
 */
void airy_log_emit(int kern_level, const char *fmt, ...)
{
	va_list args;
	int airy_level __maybe_unused;

	if (kern_level < 0 || kern_level > LOGLEVEL_DEBUG)
		kern_level = LOGLEVEL_DEFAULT;

	/* Map the printk 8-level to the A-ULP 5-level.  The result is
	 * not passed to vprintk_emit() because printk filtering relies
	 * on the original 8-level value.  It is, however, available to
	 * any caller via the exported airy_log_kern_to_level().
	 */
	airy_level = airy_log_kern_to_level(kern_level);

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

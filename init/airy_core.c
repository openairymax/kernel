/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_core.c — ALK-6.6 Minimal Boot Entry Point.
 *
 * Prints the Airymax boot banner. The Airy LSM is initialised
 * separately by the LSM framework via DEFINE_LSM(airy).init callback,
 * so this function does NOT call airy_init() directly.
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <airymax/build_types.h>

/* ─── Boot Banner ─────────────────────────────────────────────────────── */

static int __init airy_core_init(void)
{
	pr_info("Airymax ALK-%u.%u.%u — Agent Lifecycle Kernel booting\n",
		AIRY_BUILD_VERSION_MAJOR,
		AIRY_BUILD_VERSION_MINOR,
		AIRY_BUILD_VERSION_PATCH);

	return 0;
}

late_initcall(airy_core_init);

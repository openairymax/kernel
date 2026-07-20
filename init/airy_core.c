/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_core.c — ALK-6.6 Minimal Boot Entry Point.
 *
 * Calls airy_lsm_init() and prints the Airymax boot banner.
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <airymax/build_types.h>

/* ─── LSM Init (declared in security/airy/) ───────────────────────────── */

extern int airy_init(void);

/* ─── Boot Banner ─────────────────────────────────────────────────────── */

static int __init airy_core_init(void)
{
	pr_info("Airymax ALK-%u.%u.%u — Agent Lifecycle Kernel booting\n",
		AIRY_BUILD_VERSION_MAJOR,
		AIRY_BUILD_VERSION_MINOR,
		AIRY_BUILD_VERSION_PATCH);

	/* Delegate LSM initialisation to the security/airy module */
	airy_init();

	return 0;
}

late_initcall(airy_core_init);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_kern_api.c — Airymax core-kernel API entry point.
 *
 * Aggregates initialisation of the corekern subdirectories (api, sched,
 * ipc, taskflow, memory, time, object, locking, irq, bpf) and announces
 * API readiness through a late_initcall.  Compiled into vmlinux when
 * CONFIG_AIRY_COREKERN=y.
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <airymax/build_types.h>

#include "airy_kern_api.h"

/* ─── Subsystem init forward declarations ────────────────────────────── */

extern int airy_locking_init(void);

/* ─── Core API init ──────────────────────────────────────────────────── */
int __init airy_kern_api_init(void)
{
	int rc;

	pr_info("airy corekern: initialising API (ALK-%u.%u.%u)\n",
		AIRY_BUILD_VERSION_MAJOR,
		AIRY_BUILD_VERSION_MINOR,
		AIRY_BUILD_VERSION_PATCH);

	/*
	 * Bring up locking primitives first — every other corekern
	 * subsystem depends on the spinlock wrappers being available.
	 */
	rc = airy_locking_init();
	if (rc) {
		pr_err("airy corekern: locking init failed: %d\n", rc);
		return rc;
	}

	pr_info("airy corekern: api ready\n");
	return 0;
}

/* ─── late_initcall entry ────────────────────────────────────────────── */
late_initcall(airy_kern_api_init);

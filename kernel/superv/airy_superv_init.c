// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_init.c — Micro-Supervisor initialization entry point.
 *
 * Provides late_initcall() to bring up the Micro-Supervisor subsystem:
 *   1. Register Micro-Supervisor supplemental LSM hooks via
 *      airy_superv_register_hooks() (defined in security/airy/).
 *   2. Initialize die_notifier (airy_superv_die_notify_init()).
 *
 * Eventfd context and IPC ring freeze are initialised lazily on demand:
 *   - eventfd context is registered by userspace via airy_sys_clt_notify()
 *   - IPC ring freeze is triggered on first ring creation
 *
 * Design rationale (see docs/AirymaxOS/20-modules/09-kernel-agent-supervisor.md):
 *   - Micro-Supervisor lives in kernel/superv/ as an independent module
 *   - Delegates to security/airy/ for capability-aware enforcement
 *   - late_initcall ensures LSM "airy" is fully initialised first
 */

#include <linux/init.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── Forward declarations (defined in sibling files) ─────────────────── */
void __init airy_superv_die_notify_init(void);

/* ─── Micro-Supervisor late_initcall ──────────────────────────────────── */
static int __init airy_superv_init(void)
{
	int ret;

	pr_info("airy_superv: initialising Micro-Supervisor subsystem\n");

	/* 1. Register supplemental LSM hooks (task_fix_setuid, mmap_addr,
	 *    mprotect, capset, capable) into the existing "airy" LSM. */
	ret = airy_superv_register_hooks();
	if (ret) {
		pr_err("airy_superv: hook registration failed: %d\n", ret);
		return ret;
	}

	/* 2. Initialise die_notifier at INT_MAX priority. */
	airy_superv_die_notify_init();

	/* 3. Eventfd context and IPC ring freeze are initialised lazily:
	 *    - eventfd context is registered by userspace via
	 *      airy_sys_clt_notify() syscall (AIRY_SYS_CLT_NOTIFY, number 551)
	 *    - IPC ring freeze is triggered on first ring creation
	 *      via airy_superv_ipc_freeze_ring() */

	pr_info("airy_superv: Micro-Supervisor initialised\n");
	return 0;
}
late_initcall(airy_superv_init);

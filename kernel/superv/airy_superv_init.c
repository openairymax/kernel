// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_init.c — Micro-Supervisor initialization entry point.
 *
 * Provides late_initcall() to bring up the Micro-Supervisor: registers
 * its supplemental LSM hooks via airy_superv_register_hooks(). The
 * die_notifier is registered by the "airy" LSM itself, so no redundant
 * registration is needed here; late_initcall runs after LSM init.
 *
 * Design rationale: docs/AirymaxOS/20-modules/09-kernel-agent-supervisor.md
 */

#include <linux/init.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

/* ─── Micro-Supervisor late_initcall ──────────────────────────────────── */
static int __init airy_superv_init(void)
{
	int ret;

	pr_info("airy_superv: initialising Micro-Supervisor subsystem\n");

	/* 1. Register supplemental LSM hooks (task_fix_setuid, mmap_addr,
	 *    mprotect, capset, capable) into the existing "airy" LSM.
	 */
	ret = airy_superv_register_hooks();
	if (ret) {
		pr_err("airy_superv: hook registration failed: %d\n", ret);
		return ret;
	}

	/* 2. Open the [IND] protocol gate. Until this point a macro_d
	 *    command would reach rings whose freeze state is still being
	 *    set up, so the gate starts closed and publishes RUNNING only
	 *    after the hooks above are in place.
	 */
	ret = airy_sv_start(airy_sv_ctx());
	if (ret) {
		pr_err("airy_superv: protocol gate failed: %d\n", ret);
		return ret;
	}

	/* 3. The eventfd context is attached lazily: airy_eventfd_register()
	 *    installs it once the Macro-Supervisor binds its fault listener;
	 *    there is no userspace entry point for it yet, so until then the
	 *    context stays NULL and faults are recorded in the airy_fev_* ring.
	 *
	 *    The per-task IPC ring freeze state needs no setup here: the
	 *    "airy" LSM allocates it in airy_task_alloc() at fork time and
	 *    releases it in airy_task_free().
	 *
	 *    die_notifier is registered by the "airy" LSM during
	 *    security_initcall, not here.
	 */

	pr_info("airy_superv: Micro-Supervisor initialised\n");
	return 0;
}
late_initcall(airy_superv_init);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm.c — Airy Pure-C LSM: registration, hooks, and module init.
 *
 * Registers with DEFINE_LSM(airy) at LSM_ORDER_MUTABLE.  Implements seven
 * core LSM hooks: uring_cmd, task_alloc, task_free, task_kill, file_open,
 * inode_alloc_security, inode_free_security.
 * Read-only security data is protected with __ro_after_init.
 *
 * Registration phase (P2-5):
 *   - Boot-only: airy_init() is __init, invoked once during boot from
 *     the LSM framework's security_init() -> orderly_init() path.
 *     There is no runtime register/unregister; the hook list
 *     airy_hooks[] is __ro_after_init and security_add_hooks() is
 *     called exactly once.
 *   - Runtime gating: the airy_enabled module parameter (also
 *     __ro_after_init, set at boot via the airy.enabled=0 kernel
 *     command line) provides a boot-time kill switch. When false,
 *     airy_init() skips security_add_hooks() entirely and the LSM
 *     becomes a no-op. Runtime toggling is NOT supported — changing
 *     /sys/module/airy/parameters/airy_enabled after boot has no
 *     effect on hook registration, only on the per-hook fast-path
 *     check (which is itself __ro_after_init).
 *   - Hook execution vs registration: hooks are registered at boot
 *     (static struct security_hook_list[]), but each hook's body
 *     checks airy_enabled at runtime for the fast-path bypass.
 *     This two-layer design (boot registration + runtime check)
 *     allows CONFIG_SECURITY_AIRY=y builds to ship with the LSM
 *     compiled in and enabled by default (airy_enabled=true); the
 *     airy.enabled=0 command line disables it at boot.
 */

#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/io_uring.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/* ─── Forward declarations ───────────────────────────────────────────── */
void __init airy_die_notify_init(void);

/* ─── Module parameter ─────────────────────────────────────────────────── */
static bool airy_enabled __ro_after_init = true;
module_param(airy_enabled, bool, 0444);
MODULE_PARM_DESC(airy_enabled, "Enable Airy Pure-C LSM (default: true)");

/* ─── LSM blob sizes ──────────────────────────────────────────────────── */
struct lsm_blob_sizes airy_blob_sizes __ro_after_init = {
	.lbs_task  = sizeof(struct airy_task_sec),
	.lbs_inode = sizeof(struct airy_inode_sec),
};

/* ─── Hook: task_alloc — initialise agent security blob ───────────────── */
static int airy_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct airy_task_sec *sec;

	if (!airy_enabled)
		return 0;

	sec = task->security + airy_blob_sizes.lbs_task;
	sec->agent_id       = 0;
	sec->cap_space_root = 0;
	sec->agent_state    = 0;
	sec->fault_count    = 0;
	sec->sched_budget_ns = 0;
	sec->last_heartbeat  = 0;
	sec->frozen_reason   = 0;
	sec->_reserved       = 0;
	sec->ipc_ring        = NULL;

	return 0;
}

/* ─── Hook: task_free — cleanup agent security blob ──────────────────── */
static void airy_task_free(struct task_struct *task)
{
	/* No dynamic allocations to free; capability slots are persistent. */
}

/* ─── Hook: task_kill — enforce capability KILL (P1-4 fix: entry symmetry) */
static int airy_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			  int sig, const struct cred *cred)
{
	struct airy_task_sec *sec;
	__u64 caller_badge;

	if (!airy_enabled)
		return 0;

	sec = current->security + airy_blob_sizes.lbs_task;

	/* Phase 1: agent_state check (retained from original) */
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EPERM;

	/*
	 * Phase 2: Badge check (P1-4 fix — symmetric with io_uring_cmd).
	 * The calling agent must hold AIRY_CAP_PERM_KILL in its badge.
	 * agent_id == 0 means unregistered (init/kernel thread), skip
	 * badge check for backward compatibility.
	 */
	if (sec->agent_id != 0 && sec->agent_id < AIRY_CAP_MAX_AGENTS) {
		caller_badge = READ_ONCE(agent_caps[sec->agent_id].badge);
		if (airy_cap_badge_ok(caller_badge, sec->agent_id,
				      AIRY_CAP_PERM_KILL))
			return -EPERM;
	}

	return 0;
}

/* ─── Hook: file_open — capability-gated file access (P1-4 fix) ────────── */
static int airy_file_open(struct file *file)
{
	struct airy_task_sec *sec;
	__u64 caller_badge;

	if (!airy_enabled)
		return 0;

	sec = current->security + airy_blob_sizes.lbs_task;

	/* Phase 1: agent_state check (retained from original) */
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EACCES;

	/*
	 * Phase 2: Badge check (P1-4 fix — symmetric with io_uring_cmd).
	 * The calling agent must hold AIRY_CAP_PERM_FILE_OPEN in its badge.
	 * agent_id == 0 means unregistered (init/kernel thread), skip
	 * badge check for backward compatibility.
	 */
	if (sec->agent_id != 0 && sec->agent_id < AIRY_CAP_MAX_AGENTS) {
		caller_badge = READ_ONCE(agent_caps[sec->agent_id].badge);
		if (airy_cap_badge_ok(caller_badge, sec->agent_id,
				      AIRY_CAP_PERM_FILE_OPEN))
			return -EACCES;
	}

	return 0;
}

/* ─── Hook: inode_alloc — initialise inode security blob (P1-6 fix) ───── */
static int airy_inode_alloc(struct inode *inode)
{
	struct airy_inode_sec *sec;

	if (!airy_enabled)
		return 0;

	sec = inode->i_security + airy_blob_sizes.lbs_inode;
	sec->cap_required = 0;
	sec->owner_agent  = 0;

	return 0;
}

/* ─── Hook: inode_free — cleanup inode security blob (P1-6 fix) ────────── */
static void airy_inode_free(struct inode *inode)
{
	/* No dynamic allocations to free; blob is inline in inode. */
}

/* ─── Hook: uring_cmd — entry point for capability-based IPC ──────────── */
static int airy_uring_cmd(struct io_uring_cmd *ioucmd)
{
	if (!airy_enabled)
		return 0;

	return airy_uring_cmd_check(ioucmd);
}

/* ─── Hook list ────────────────────────────────────────────────────────── */
static struct security_hook_list airy_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(uring_cmd,       airy_uring_cmd),
	LSM_HOOK_INIT(task_alloc,      airy_task_alloc),
	LSM_HOOK_INIT(task_free,       airy_task_free),
	LSM_HOOK_INIT(task_kill,       airy_task_kill),
	LSM_HOOK_INIT(file_open,       airy_file_open),
	LSM_HOOK_INIT(inode_alloc_security, airy_inode_alloc),
	LSM_HOOK_INIT(inode_free_security,  airy_inode_free),
};

/* ─── Module init ──────────────────────────────────────────────────────── */
static int __init airy_init(void)
{
	if (!airy_enabled) {
		pr_info("airy: disabled via module parameter\n");
		return 0;
	}

	/* Initialise global capability table */
	airy_cap_agent_caps_init();

	security_add_hooks(airy_hooks, ARRAY_SIZE(airy_hooks), "airy");

	/* Register die notifier at INT_MAX priority (airy_die_notify.c) */
	airy_die_notify_init();

	pr_info("airy: Airymax Pure-C LSM initialised\n");
	return 0;
}

/* ─── LSM registration ────────────────────────────────────────────────── */
DEFINE_LSM(airy) = {
	.name   = "airy",
	.order  = LSM_ORDER_MUTABLE,
	.init   = airy_init,
	.blobs  = &airy_blob_sizes,
};

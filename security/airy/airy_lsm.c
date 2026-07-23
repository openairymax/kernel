// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm.c — Airy Pure-C LSM: registration, hooks, and module init.
 *
 * Registers with DEFINE_LSM(airy) at LSM_ORDER_MUTABLE.  Implements five
 * core LSM hooks: uring_cmd, task_alloc, task_free, task_kill, file_open.
 * Read-only security data is protected with __ro_after_init.
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
	.lbs_task = sizeof(struct airy_task_sec),
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

/* ─── Hook: task_kill — enforce capability KILL ───────────────────────── */
static int airy_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			  int sig, const struct cred *cred)
{
	struct airy_task_sec *sec;

	if (!airy_enabled)
		return 0;

	/*
	 * Deny signal delivery if the calling agent is frozen or dead.
	 * A full badge check (airy_cap_badge_ok with AIRY_CAP_PERM_*)
	 * is deferred until per-agent kill permission bits are defined
	 * in the [SC] capability permission space.
	 */
	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EPERM;

	return 0;
}

/* ─── Hook: file_open — capability-gated file access ──────────────────── */
static int airy_file_open(struct file *file)
{
	struct airy_task_sec *sec;

	if (!airy_enabled)
		return 0;

	/*
	 * Deny file access if the calling agent is stopped or dead.
	 * Per-agent file access via capability lookups on the owning
	 * task's capability space is deferred until the inode security
	 * blob (airy_inode_sec) is wired to VFS.
	 */
	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EACCES;

	return 0;
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
	LSM_HOOK_INIT(uring_cmd,  airy_uring_cmd),
	LSM_HOOK_INIT(task_alloc, airy_task_alloc),
	LSM_HOOK_INIT(task_free,  airy_task_free),
	LSM_HOOK_INIT(task_kill,  airy_task_kill),
	LSM_HOOK_INIT(file_open,  airy_file_open),
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

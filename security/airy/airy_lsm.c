// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm.c — Airy Pure-C LSM: registration, hooks, and module init.
 *
 * Registers with DEFINE_LSM(airy) at LSM_ORDER_MUTABLE and implements
 * seven hooks: uring_cmd, task_alloc, task_free, task_kill, file_open,
 * inode_alloc_security, inode_free_security. Boot-only static
 * registration gated by the airy_enabled boot-time kill switch.
 *
 * Design rationale: docs/AirymaxOS/110-security/07-airy-lsm-design.md
 */

#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/io_uring.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/build_bug.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/error.h>

#include <airymax/airy_contract.h>
#include <airymax/airy_policy.h>
#include <airymax/airy_trace.h>

#include "airy_cap.h"
#include "airy_cap_sysctl.h"
#include "airy_probe.h"

/* ─── Module parameter ─────────────────────────────────────────────────── */
/*
 * airy_enabled 必须是 int：OLK 6.6 的 struct lsm_info.enabled 是 int *，
 * ordered_lsm_parse() 直接写 *lsm->enabled，用 bool 会越界写 4 字节。
 * 该变量同时受 CONFIG_LSM 与 lsm= 控制，0444 表示只在启动期可改；
 * 运行期关停需要重新注册钩子，不在支持范围内。
 */
static int airy_enabled __ro_after_init = 1;
module_param(airy_enabled, int, 0444);
MODULE_PARM_DESC(airy_enabled, "Enable Airy Pure-C LSM (default: 1)");

/* ─── LSM blob sizes ──────────────────────────────────────────────────── */
struct lsm_blob_sizes airy_blob_sizes __ro_after_init = {
	.lbs_task  = sizeof(struct airy_task_sec),
	.lbs_inode = sizeof(struct airy_inode_sec),
};

static struct airy_task_sec *airy_tsec(const struct task_struct *task)
{
	return task->security + airy_blob_sizes.lbs_task;
}

/* ─── Hook: task_alloc — initialise agent security blob ───────────────── */
static int airy_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct airy_task_sec *sec;
	struct airy_ipc_ring_freeze_state *ring;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };
	int rc;

	sec = airy_tsec(task);
	sec->agent_id       = 0;
	sec->cap_space_root = 0;
	sec->agent_state    = 0;
	sec->fault_count    = 0;
	sec->sched_budget_ns = 0;
	sec->last_heartbeat  = 0;
	sec->frozen_reason   = 0;
	sec->_reserved       = 0;
	sec->ipc_ring        = NULL;

	/*
	 * Only user tasks can become agents.  Kernel threads carry no
	 * agent identity, so their blob keeps ipc_ring == NULL and every
	 * freeze lookup stays a no-op without a read-side special case.
	 */
	if (!(task->flags & PF_KTHREAD)) {
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);
		if (!ring)
			return -ENOMEM;
		sec->ipc_ring = ring;
	}

	fields[0] = clone_flags;
	fields[1] = (task->flags & PF_KTHREAD) ? 0 : 1;
	fields[2] = sec->agent_id;

	rc = airy_policy_check(AIRY_POLICY_HOOK_TASK_ALLOC, fields, NULL);
	/*
	 * security_task_alloc() runs security_task_free() when a hook
	 * rejects the fork, and that reaches airy_task_free(), which
	 * releases the ring.  Freeing it here too would double-free it.
	 */
	return rc;
}

/* ─── Hook: task_free — cleanup agent security blob ──────────────────── */
static void airy_task_free(struct task_struct *task)
{
	struct airy_task_sec *sec;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };

	sec = airy_tsec(task);
	fields[0] = sec->agent_id;
	fields[1] = sec->agent_state;

	/* Observation hook: the task is already gone, record only. */
	airy_policy_check(AIRY_POLICY_HOOK_TASK_FREE, fields, NULL);

	/*
	 * Release the capability slot before the blob goes away.  Agent 0
	 * is the unbound marker and owns no slot; airy_cap_unreg() also
	 * drops already-released slots, so repeated frees of a shared
	 * agent_id stay harmless.
	 */
	if (sec->agent_id != 0)
		airy_cap_unreg(sec->agent_id);

	/*
	 * The ring is owned by this blob.  The init task never runs the
	 * alloc hook and kernel threads never get a ring, so both reach
	 * here with ipc_ring == NULL and drain through kfree(NULL).
	 */
	kfree(sec->ipc_ring);
	sec->ipc_ring = NULL;
}

/* ─── Hook: task_kill — enforce capability KILL (P1-4 fix: entry symmetry) */
static int airy_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			  int sig, const struct cred *cred)
{
	struct airy_task_sec *sec, *target;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };

	sec = airy_tsec(current);

	/* Phase 1: agent_state check (retained from original) */
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EPERM;

	/*
	 * Phase 2: the calling agent must hold a live capability carrying
	 * AIRY_CAP_PERM_KILL.  agent_id == 0 means unregistered (init or
	 * kernel thread) and skips the capability check.
	 */
	if (sec->agent_id != 0 &&
	    airy_cap_check(sec->agent_id, AIRY_CAP_PERM_KILL))
		return -EPERM;

	target = airy_tsec(p);
	fields[0] = sig;
	fields[1] = target->agent_id;
	fields[2] = target->agent_state;
	fields[3] = sec->agent_id;

	return airy_policy_check(AIRY_POLICY_HOOK_TASK_KILL, fields, NULL);
}

/* ─── Hook: file_open — capability-gated file access (P1-4 fix) ────────── */
static int airy_file_open(struct file *file)
{
	struct airy_task_sec *sec;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };

	sec = airy_tsec(current);

	/* Phase 1: agent_state check (retained from original) */
	if (sec->agent_state == AIRY_AGENT_STOPPED ||
	    sec->agent_state == AIRY_AGENT_DEAD)
		return -EACCES;

	/*
	 * Phase 2: the calling agent must hold a live capability carrying
	 * AIRY_CAP_PERM_FILE_OPEN.  agent_id == 0 means unregistered (init
	 * or kernel thread) and skips the capability check.
	 */
	if (sec->agent_id != 0 &&
	    airy_cap_check(sec->agent_id, AIRY_CAP_PERM_FILE_OPEN))
		return -EACCES;

	fields[0] = file->f_flags;
	fields[1] = file->f_mode & (FMODE_READ | FMODE_WRITE);
	fields[2] = sec->agent_id;

	return airy_policy_check(AIRY_POLICY_HOOK_FILE_OPEN, fields, NULL);
}

/* ─── Hook: inode_alloc — initialise inode security blob (P1-6 fix) ───── */
static int airy_inode_alloc(struct inode *inode)
{
	struct airy_inode_sec *sec;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };

	sec = inode->i_security + airy_blob_sizes.lbs_inode;
	sec->cap_required = 0;
	sec->owner_agent  = 0;

	fields[0] = inode->i_mode & S_IFMT;

	return airy_policy_check(AIRY_POLICY_HOOK_INODE_ALLOC, fields, NULL);
}

/* ─── Hook: inode_free — cleanup inode security blob (P1-6 fix) ────────── */
static void airy_inode_free(struct inode *inode)
{
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };

	fields[0] = inode->i_mode & S_IFMT;

	/* Observation hook: the inode is already gone, record only. */
	airy_policy_check(AIRY_POLICY_HOOK_INODE_FREE, fields, NULL);
}

/* ─── Hook: uring_cmd — entry point for capability-based IPC ──────────── */
static int airy_uring_cmd(struct io_uring_cmd *ioucmd)
{
	struct airy_task_sec *sec;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };
	int rc;

	rc = airy_uring_cmd_check(ioucmd);
	if (rc)
		return rc;

	sec = airy_tsec(current);
	fields[0] = ioucmd->cmd_op;
	fields[1] = ioucmd->flags;
	fields[2] = sec->agent_id;

	return airy_policy_check(AIRY_POLICY_HOOK_URING_CMD, fields, NULL);
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

/* [SC] 契约声明注册 7 个钩子；钩子表为 static，一致性只能在本文件内断言。 */
static_assert(ARRAY_SIZE(airy_hooks) == AIRY_LSM_HOOK_IMPLEMENTED,
	      "airy_hooks[] must register exactly AIRY_LSM_HOOK_IMPLEMENTED hooks");

/* ─── Module init ──────────────────────────────────────────────────────── */
static int __init airy_init(void)
{
	int rc;

	/*
	 * Attest the [SC] contract snapshot before anything is registered: a
	 * drifted layout must never reach the fastpath that indexes
	 * agent_caps[] by hand-computed offsets.
	 */
	rc = airy_contract_check();
	if (rc)
		return rc;

	/* Initialise global capability table */
	airy_cap_agent_caps_init();

	security_add_hooks(airy_hooks, ARRAY_SIZE(airy_hooks), "airy");

	/*
	 * The Micro-Supervisor supplements this module with five more hooks
	 * (airy_superv_lsm.c).  They must be registered here, adjacent to the
	 * call above: security_add_hooks() also records the module name, and
	 * the registry only de-duplicates against the last entry, so a later
	 * late_initcall registration would list "airy" twice.
	 */
	rc = airy_superv_register_hooks();
	if (rc)
		return rc;

	/* Register die notifier at INT_MAX priority (airy_die_notify.c) */
	airy_die_notify_init();

	/*
	 * Agent behaviour tracing is a mandatory observability baseline
	 * (OS-OBS-081), so a failed instance is reported as a failed LSM
	 * init rather than silently dropped.
	 */
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	rc = airy_trace_init();
	if (rc)
		return rc;
#endif

	/*
	 * Publish the capability observation entries.  They replace the
	 * removed airy_sys_capability_inspect() syscall (SSoT
	 * 110-security/03-capability-model.md §5.3) and must exist before
	 * the presence marker advertises readiness.
	 */
	rc = airy_cap_sysctl_init();
	if (rc)
		return rc;

	/*
	 * Publish the agentrt presence marker last: its existence is the
	 * runtime's proof that every previous init step succeeded.
	 */
	rc = airy_probe_init();
	if (rc)
		return rc;

	pr_info("airy: Airymax Pure-C LSM initialised\n");
	return 0;
}

/* ─── LSM registration ────────────────────────────────────────────────── */
DEFINE_LSM(airy) = {
	.name   = "airy",
	.order  = LSM_ORDER_MUTABLE,
	.enabled = &airy_enabled,
	.init   = airy_init,
	.blobs  = &airy_blob_sizes,
};

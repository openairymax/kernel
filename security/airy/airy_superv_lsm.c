// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_lsm.c — Micro-Supervisor LSM hook registration entry.
 *
 * Provides airy_superv_register_hooks() to register Micro-Supervisor
 * specific LSM hooks that supplement the five core hooks defined in
 * airy_lsm.c.  Called by kernel/superv/airy_superv_lsm.c during
 * late_initcall.
 *
 * Design rationale (see docs/AirymaxOS/20-modules/09-kernel-agent-supervisor.md):
 *   - airy_lsm.c  → DEFINE_LSM(airy) main module (5 core hooks)
 *   - airy_superv_lsm.c → Micro-Supervisor supplemental hook registration
 *
 * All hooks here are registered via security_add_hooks() into the
 * existing "airy" LSM blob space (no new LSM module is defined).
 */

#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/security.h>
#include <linux/airymax/error.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/lsm_types.h>

#include "airy_cap.h"

/* ─── Hook: task_fix_setuid — enforce capability boundary on cred switch ─ */
static int airy_superv_task_fix_setuid(struct cred *new,
				       const struct cred *old, int flags)
{
	struct airy_task_sec *sec;

	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_FROZEN)
		return -EPERM;

	return 0;
}

/* ─── Hook: mmap_addr — restrict mmap to capability-approved ranges ────── */
static int airy_superv_mmap_addr(unsigned long addr)
{
	/*
	 * Reject addresses in kernel space to prevent an agent from
	 * mapping kernel memory into its address space.
	 */
	if (addr >= TASK_SIZE)
		return -EACCES;

	return 0;
}

/* ─── Hook: file_mprotect — enforce W^X for capability-gated pages ─────── */
static int airy_superv_file_mprotect(struct vm_area_struct *vma,
				     unsigned long reqprot, unsigned long prot)
{
	/*
	 * Enforce W^X invariant: a page must never be simultaneously
	 * writable and executable, as this enables code injection from
	 * a compromised agent.
	 */
	if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
		return -EACCES;

	return 0;
}

/* ─── Hook: capset — gate CAP_SETPCAP propagation across agents ────────── */
static int airy_superv_capset(struct cred *new, const struct cred *old,
			      const kernel_cap_t *effective,
			      const kernel_cap_t *inheritable,
			      const kernel_cap_t *permitted)
{
	struct airy_task_sec *sec;

	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_FROZEN)
		return -EPERM;

	return 0;
}

/* ─── Hook: capable — per-capability access control ────────────────────── */
static int airy_superv_capable(const struct cred *cred,
			       struct user_namespace *ns,
			       int cap, unsigned int opts)
{
	struct airy_task_sec *sec;

	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_FROZEN)
		return -EPERM;

	return 0;
}

/* ─── Micro-Supervisor supplemental hook list ──────────────────────────── */
static struct security_hook_list airy_superv_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_fix_setuid, airy_superv_task_fix_setuid),
	LSM_HOOK_INIT(mmap_addr,       airy_superv_mmap_addr),
	LSM_HOOK_INIT(file_mprotect,   airy_superv_file_mprotect),
	LSM_HOOK_INIT(capset,          airy_superv_capset),
	LSM_HOOK_INIT(capable,         airy_superv_capable),
};

/**
 * airy_superv_register_hooks - Register Micro-Supervisor supplemental hooks.
 *
 * Called by kernel/superv/airy_superv_lsm.c during late_initcall.
 * Hooks are added to the existing "airy" LSM module (no new DEFINE_LSM).
 *
 * Return: 0 on success, negative error on failure.
 */
int __init airy_superv_register_hooks(void)
{
	security_add_hooks(airy_superv_hooks,
			   ARRAY_SIZE(airy_superv_hooks),
			   "airy");
	pr_info("airy_superv: registered %zu Micro-Supervisor hooks\n",
		ARRAY_SIZE(airy_superv_hooks));
	return 0;
}

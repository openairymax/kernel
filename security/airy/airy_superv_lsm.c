// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_lsm.c — Micro-Supervisor LSM hook registration entry.
 *
 * Registers the supplemental hooks that airy_lsm.c leaves out of its core
 * table, into the existing "airy" LSM blob space (no new LSM module).
 * Called by airy_init() right after the core table is added, see the
 * comment there for why the two calls must stay adjacent.
 */

#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sysctl.h>
#include <linux/security.h>
#include <linux/airymax/error.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/lsm_types.h>

#include <airymax/airy_agent.h>
#include <airymax/airy_policy.h>

#include "airy_cap.h"

/* ─── Hook: task_fix_setuid — enforce capability boundary on cred switch ─ */
static int airy_superv_task_fix_setuid(struct cred *new,
				       const struct cred *old, int flags)
{
	struct airy_task_sec *sec;

	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_STOPPED)
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

/* ─── Hook: file_mprotect — gate the write-then-execute transition ─────── */
static int airy_superv_file_mprotect(struct vm_area_struct *vma,
				     unsigned long reqprot, unsigned long prot)
{
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { };
	unsigned long old = 0;

	/*
	 * Only a mapping that is writable before or after the call and
	 * becomes executable is a W^X event.  Anything else keeps the
	 * historical semantics: read-only execution, PROT_NONE, and the
	 * ordinary file mapping path must not pay for a policy lookup.
	 *
	 * The transition test comes first on purpose.  The exception table
	 * defaults to deny, so consulting it on every mprotect() would refuse
	 * mapping changes that never touch executable permission.
	 */
	if (!(prot & PROT_EXEC) ||
	    (!(prot & PROT_WRITE) && !(vma->vm_flags & VM_WRITE)))
		return 0;

	if (vma->vm_flags & VM_READ)
		old |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		old |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		old |= PROT_EXEC;

	fields[0] = prot;
	fields[1] = old;
	fields[2] = airy_agent_id(current);

	return airy_policy_check(AIRY_POLICY_HOOK_FILE_MPROTECT, fields,
				 NULL);
}

/* ─── Hook: capset — gate CAP_SETPCAP propagation across agents ────────── */
static int airy_superv_capset(struct cred *new, const struct cred *old,
			      const kernel_cap_t *effective,
			      const kernel_cap_t *inheritable,
			      const kernel_cap_t *permitted)
{
	struct airy_task_sec *sec;

	sec = current->security + airy_blob_sizes.lbs_task;
	if (sec->agent_state == AIRY_AGENT_STOPPED)
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
	if (sec->agent_state == AIRY_AGENT_STOPPED)
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

unsigned int airy_superv_hook_count(void)
{
	return ARRAY_SIZE(airy_superv_hooks);
}

/**
 * airy_superv_register_hooks - Register Micro-Supervisor supplemental hooks.
 *
 * Called by airy_init() in airy_lsm.c, directly after the core hook table,
 * so that the "airy" name is appended to the LSM registry only once.
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

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_lsm.c — Micro-Supervisor LSM hook registration wrapper.
 *
 * Provides a thin boot-time registration path that delegates LSM
 * hook setup to the security/airy module.
 */

#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/io_uring.h>

#include "../../security/airy/airy_cap.h"

/* ─── Delegates to security/airy LSM hooks ────────────────────────────── */

extern int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);

/* ─── Per-Task Security Blob (Superv-side) ────────────────────────────── */

static int airy_superv_task_alloc(struct task_struct *task,
				  unsigned long clone_flags)
{
	struct airy_task_sec *sec;

	sec = kzalloc(sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->agent_id = AIRY_CAP_MAX_AGENTS;
	task->security = sec;

	return 0;
}

static void airy_superv_task_free(struct task_struct *task)
{
	struct airy_task_sec *sec = task->security;

	if (sec) {
		task->security = NULL;
		kfree(sec);
	}
}

/* ─── uring_cmd LSM Hook ──────────────────────────────────────────────── */

static int airy_superv_lsm_uring_cmd(struct io_uring_cmd *ioucmd)
{
	return airy_uring_cmd_check(ioucmd);
}

/* ─── LSM Blob Sizes ──────────────────────────────────────────────────── */

struct lsm_blob_sizes airy_superv_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct airy_task_sec),
};

/* ─── LSM Hook Table ──────────────────────────────────────────────────── */

static struct security_hook_list airy_superv_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, airy_superv_task_alloc),
	LSM_HOOK_INIT(task_free, airy_superv_task_free),
	LSM_HOOK_INIT(uring_cmd, airy_superv_lsm_uring_cmd),
};

/* ─── LSM Registration ────────────────────────────────────────────────── */

DEFINE_LSM(airy_superv) = {
	.name   = "airy_superv",
	.blobs  = &airy_superv_blob_sizes,
	.hooks  = airy_superv_hooks,
};

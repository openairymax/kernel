/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_lsm.c — Micro-Supervisor LSM Hook Registration (Airy Pure-C LSM).
 *
 * Registers LSM hooks for Micro-Supervisor enforcement including:
 *   - uring_cmd hook for IPC capability validation
 *   - task_alloc / task_free hooks for per-task security blob management
 */

#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/io_uring.h>

#include "airy_cap.h"

/* ─── Forward declarations ────────────────────────────────────────────── */
int airy_uring_cmd_check(struct io_uring_cmd *ioucmd);

/* ─── Per-Task Security Blob ──────────────────────────────────────────── */

/**
 * airy_superv_task_alloc - Allocate per-task Agent Security Context.
 * @task: The new task being created.
 *
 * Allocates a struct airy_task_sec via kzalloc and attaches it to the
 * task's LSM security blob. Returns 0 on success, -ENOMEM on failure.
 */
static int airy_superv_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct airy_task_sec *sec;

	sec = kzalloc(sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->agent_id = AIRY_CAP_MAX_AGENTS; /* invalid sentinel */

	/* Attach to task's LSM security blob */
	task->security = sec;

	return 0;
}

/**
 * airy_superv_task_free - Free per-task Agent Security Context.
 * @task: The task being released.
 *
 * Frees the struct airy_task_sec previously allocated by
 * airy_superv_task_alloc().
 */
static void airy_superv_task_free(struct task_struct *task)
{
	struct airy_task_sec *sec = task->security;

	if (sec) {
		task->security = NULL;
		kfree(sec);
	}
}

/* ─── uring_cmd LSM Hook ──────────────────────────────────────────────── */

/**
 * airy_superv_lsm_uring_cmd - LSM hook for io_uring command validation.
 * @ioucmd: The io_uring command being issued.
 *
 * Wrapper that delegates to airy_uring_cmd_check() for capability
 * badge validation in the IPC fastpath.
 *
 * Return: 0 if the command is authorized, negative error otherwise.
 */
static int airy_superv_lsm_uring_cmd(struct io_uring_cmd *ioucmd)
{
	return airy_uring_cmd_check(ioucmd);
}

/* ─── LSM Hook Registration ───────────────────────────────────────────── */

/*
 * LSM blob sizes: define how much per-task storage the Airy LSM needs.
 */
struct lsm_blob_sizes air_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct airy_task_sec),
};

/*
 * LSM hook table: maps hook callbacks for the Airy Micro-Supervisor.
 */
static struct security_hook_list airy_superv_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, airy_superv_task_alloc),
	LSM_HOOK_INIT(task_free, airy_superv_task_free),
	LSM_HOOK_INIT(uring_cmd, airy_superv_lsm_uring_cmd),
};

/*
 * LSM ID: registered with the kernel LSM framework.
 */
DEFINE_LSM(airy) = {
	.name = "airy",
	.blobs = &air_blob_sizes,
	.hooks = airy_superv_hooks,
};

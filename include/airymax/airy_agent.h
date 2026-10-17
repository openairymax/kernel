/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_agent.h — Kernel-internal accessor for the per-task agent id.
 *
 * The agent identity is stored in the Airy LSM task blob, so every
 * emit site used to repeat the blob arithmetic on its own. This header
 * is the single reader of that blob for identity purposes; callers that
 * need the whole security blob keep resolving it locally.
 *
 * Without the Airy LSM every task is outside the agent namespace, which
 * the [SC] contract encodes as agent id 0.
 *
 * SSoT: 30-interfaces/10-sc-sched-extension.md §2;
 *       90-observability/08-agent-tracing.md §7.1.
 */

#ifndef _AIRY_AGENT_H
#define _AIRY_AGENT_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>

#include <linux/airymax/lsm_types.h>

#if IS_ENABLED(CONFIG_SECURITY_AIRY)

/* Defined in security/airy/airy_lsm.c. */
extern struct lsm_blob_sizes airy_blob_sizes;

/**
 * airy_agent_id - read the agent id of a task
 * @tsk: task to inspect; NULL is treated as outside the namespace
 *
 * The Airy LSM stores the id in its task blob, whose offset is fixed
 * once airy_blob_sizes is initialised. The id is written by the LSM
 * and read concurrently here, hence the READ_ONCE().
 *
 * Return: the agent id, or 0 when @tsk is NULL or unbound.
 */
static inline __u32 airy_agent_id(const struct task_struct *tsk)
{
	const struct airy_task_sec *sec;

	if (!tsk)
		return 0;

	sec = tsk->security + airy_blob_sizes.lbs_task;
	return READ_ONCE(sec->agent_id);
}

#else /* !CONFIG_SECURITY_AIRY */

static inline __u32 airy_agent_id(const struct task_struct *tsk)
{
	return 0;
}

#endif /* CONFIG_SECURITY_AIRY */

#endif /* _AIRY_AGENT_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_task_desc.c — Airymax task descriptor initialisation.
 *
 * Provides airy_task_desc_init() for struct airy_task_desc (defined in
 * the [SC] <airymax/sched.h> header).  The descriptor carries the
 * AIRY_TASK_MAGIC (0x41475453, 'AGTS') sentinel so that corrupted or
 * uninitialised descriptors can be detected at runtime.
 */

#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/airymax/sched.h>

/* ─── Descriptor initialisation ──────────────────────────────────────── */
int airy_task_desc_init(struct airy_task_desc *desc)
{
	if (!desc)
		return -EINVAL;

	/*
	 * Validate magic: a zero magic means fresh memory, AIRY_TASK_MAGIC
	 * means a benign re-initialisation.  Any other value indicates
	 * memory corruption and is rejected.
	 */
	if (desc->magic != 0 && desc->magic != AIRY_TASK_MAGIC) {
		pr_warn("airy_task_desc_init: corrupt magic 0x%08x\n",
			desc->magic);
		return -EINVAL;
	}

	memset(desc, 0, sizeof(*desc));

	desc->magic        = AIRY_TASK_MAGIC;
	desc->prio         = AIRY_PRIO_MAX / 2;	/* default mid-range priority */
	desc->vtime        = 0;			/* Q16.16, starts at zero    */
	desc->sched_policy = AIRY_SCHED_POLICY_EEVDF;
	desc->weight       = AIRY_WEIGHT_MIN;
	desc->state        = AIRY_AGENT_INIT;

	return 0;
}

/* ─── Descriptor magic validation ────────────────────────────────────── */
bool airy_task_desc_valid(const struct airy_task_desc *desc)
{
	return desc && desc->magic == AIRY_TASK_MAGIC;
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_die_notify.c — Micro-Supervisor die notification delegator.
 *
 * Registers a die notifier at INT_MAX priority that intercepts fatal
 * kernel events and delegates to the LSM's airy_security_fault().
 */

#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/sched.h>
#include <airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── Die Reason → Fault Code Mapping ─────────────────────────────────── */

static __u32 airy_superv_map_fault(unsigned long val)
{
	switch (val) {
	case DIE_OOPS:
		return AIRY_FAULT_VM_FAULT;
	case DIE_PAGE_FAULT:
		return AIRY_FAULT_VM_FAULT;
	case DIE_BUG:
		return AIRY_FAULT_ABNORMAL_CAP;
	case DIE_NMIWATCHDOG:
		return AIRY_FAULT_TIMEOUT;
	default:
		return 0;
	}
}

/* ─── Die Notifier Callback ───────────────────────────────────────────── */

static int airy_superv_die_cb(struct notifier_block *nb, unsigned long val,
			      void *data)
{
	__u32 fault_code;
	__u32 agent_id = 0;
	struct task_struct *task = current;

	fault_code = airy_superv_map_fault(val);
	if (fault_code == 0)
		return NOTIFY_DONE;

	/* Extract agent_id from the current task's LSM security blob */
	if (task->security) {
		struct airy_task_sec *sec = task->security;

		agent_id = sec->agent_id;
		sec->fault_count++;
		sec->frozen_reason = fault_code;
	}

	/* Delegate fatal handling to the LSM module */
	airy_security_fault(agent_id, fault_code);

	return NOTIFY_DONE;
}

/* ─── Notifier Block ──────────────────────────────────────────────────── */

static struct notifier_block airy_superv_die_nb = {
	.notifier_call = airy_superv_die_cb,
	.priority      = INT_MAX,
};

void __init airy_superv_die_notify_init(void)
{
	register_die_notifier(&airy_superv_die_nb);
}

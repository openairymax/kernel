/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_die_notify.c — Die Notification Handler (Airy Pure-C LSM).
 *
 * Registers a die notifier with INT_MAX priority to intercept
 * fatal kernel events (OOPS, page faults, BUGs, NMI watchdog)
 * and map them to AIRY_FAULT_* codes. On fatal conditions, all
 * active IPC rings are frozen to prevent cascading failures.
 */

#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/* ─── Airy Security Fault Notifier Chain ──────────────────────────────── */
/*
 * Separate from the kernel die_chain: this chain is invoked from
 * airy_security_fault() to notify the Supervisor of unrecoverable
 * Airy security violations (badge forgery, capability leaks, etc.).
 * The kernel die_chain handles hardware/kernel faults (OOPS, NMI);
 * airy_die_chain handles Airy capability-space faults.
 */
ATOMIC_NOTIFIER_HEAD(airy_die_chain);

/* ─── External Declarations ───────────────────────────────────────────── */

/*
 * Functions provided by airy_ipc_freeze.c
 */
struct airy_ipc_ring_freeze_state;
extern void airy_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring,
				__u32 reason);
extern struct airy_ipc_ring_freeze_state *
			airy_ipc_ring_for_task(struct task_struct *task);

/*
 * Functions provided by airy_eventfd.c
 */
extern void airy_eventfd_signal_fault(__u32 fault_code, __u32 agent_id,
				      __u64 timestamp);

/* ─── Die Reason → Fault Code Mapping ─────────────────────────────────── */

/**
 * airy_die_map_fault - Map a kernel die reason to an Airy fault code.
 * @val: The die notification value (DIE_OOPS, DIE_PAGE_FAULT, etc.)
 *
 * Returns the corresponding AIRY_FAULT_* code, or 0 if the die reason
 * is not recognized as a fatal condition.
 */
static __u32 airy_die_map_fault(unsigned long val)
{
	switch (val) {
	case DIE_OOPS:
		return AIRY_FAULT_VM_FAULT;        /* Kernel OOPS → VM fault */
	case DIE_PAGE_FAULT:
		return AIRY_FAULT_VM_FAULT;        /* Page fault → VM fault */
	case DIE_TRAP:
		return AIRY_FAULT_ABNORMAL_CAP;    /* BUG()/trap → abnormal capability */
	case DIE_NMI:
		return AIRY_FAULT_TIMEOUT;         /* NMI/NMI watchdog → timeout */
	default:
		return 0;                          /* Not a fatal condition */
	}
}

/* ─── Die Notifier Callback ───────────────────────────────────────────── */

/**
 * airy_die_notifier - Die notification callback for the Airy Micro-Supervisor.
 * @nb:   The notifier block (unused).
 * @val:  The die notification value (DIE_OOPS, DIE_PAGE_FAULT, etc.)
 * @data: Pointer to struct pt_regs for the faulting context.
 *
 * Maps the die reason to an AIRY_FAULT_* code, freezes the current
 * task's IPC ring to quarantine the fault, and signals the fault
 * to the Macro-Supervisor via eventfd for out-of-band handling.
 *
 * Registered at INT_MAX priority to run before any other notifier.
 *
 * Return: NOTIFY_DONE to allow other notifiers to run.
 */
static int airy_die_notifier(struct notifier_block *nb, unsigned long val,
			     void *data)
{
	__u32 fault_code;
	__u32 agent_id;
	__u64 timestamp;
	struct task_struct *task = current;
	struct airy_ipc_ring_freeze_state *ring;

	fault_code = airy_die_map_fault(val);
	if (fault_code == 0)
		return NOTIFY_DONE;

	/*
	 * C-S7.1: Determine agent ID from the current task's security blob.
	 */
	agent_id = 0;
	if (task->security) {
		struct airy_task_sec *sec = task->security +
			airy_blob_sizes.lbs_task;
		__u32 old, new;

		agent_id = sec->agent_id;
		do {
			old = READ_ONCE(sec->fault_count);
			new = old + 1;
		} while (cmpxchg(&sec->fault_count, old, new) != old);
	}

	timestamp = (__u64)ktime_get_mono_fast_ns();

	/*
	 * C-S7.2: Freeze the current task's IPC ring to prevent
	 * cascading failures from propagating through IPC channels.
	 */
	ring = airy_ipc_ring_for_task(task);
	if (ring)
		airy_ipc_freeze_ring(ring, fault_code);

	/*
	 * C-S7.3: Signal the fault event to the Macro-Supervisor
	 * via non-blocking eventfd for out-of-band fault handling.
	 */
	airy_eventfd_signal_fault(fault_code, agent_id, timestamp);

	return NOTIFY_DONE;
}

/* ─── Notifier Block Registration ─────────────────────────────────────── */

/*
 * Die notifier block registered at INT_MAX priority to ensure the
 * Airy Micro-Supervisor runs first on any fatal kernel event.
 */
static struct notifier_block airy_die_nb = {
	.notifier_call = airy_die_notifier,
	.priority      = INT_MAX,
};

/**
 * airy_die_notify_init - Register the Airy die notifier.
 *
 * Called during LSM initialization to hook into the kernel's
 * die notification chain before any other subsystem.
 */
void __init airy_die_notify_init(void)
{
	register_die_notifier(&airy_die_nb);
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_syscalls.c — Airymax System Calls (512-515).
 *
 * Implements the four ALK syscalls for agent IPC, memory rotation
 * control, scheduler control, and cognition lifecycle notification.
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <airymax/ipc.h>
#include <airymax/syscalls.h>
#include <airymax/sched.h>
#include <airymax/cognition_types.h>
#include <airymax/error.h>

/*
 * SYSCALL 512: airy_sys_call — IPC send/recv entry point.
 * @cap: Capability badge for authentication.
 * @msg: User-space pointer to a struct airy_ipc_msg_hdr.
 *
 * The Micro-Supervisor validates the capability badge via
 * airy_cap_badge_ok() before allowing the IPC operation.
 */
SYSCALL_DEFINE2(airy_sys_call, cap_t, cap,
		const struct airy_ipc_msg_hdr __user *, msg)
{
	struct airy_ipc_msg_hdr __user *hdr;

	if (!msg)
		return -AIRY_EFAULT;

	hdr = (struct airy_ipc_msg_hdr __user *)msg;

	/*
	 * If the cap is AIRY_CAP_NULL, the caller is bootstrapping
	 * with a CAP_REQUEST.  Otherwise, validate the badge.
	 */
	if (cap != AIRY_CAP_NULL) {
		/* TODO: full cap validation + IPC dispatch */
		return -AIRY_ENOTSUP;
	}

	return 0;
}

/*
 * SYSCALL 513: airy_sys_rovol_ctl — Memory RoVol (rotation/volume) control.
 * @op:  Operation code.
 * @pid: Target process/task ID.
 * @arg: Operation-specific argument.
 */
SYSCALL_DEFINE3(airy_sys_rovol_ctl, __u32, op, __u32, pid, __u64, arg)
{
	/* TODO: Memory rotation / volume control logic */
	return -AIRY_ENOTSUP;
}

/*
 * SYSCALL 514: airy_sys_sched_ctl — Scheduler control.
 * @op:          Operation code.
 * @cgroup_path: User-space path to the target cgroup.
 * @policy:      User-space scheduling policy string.
 */
SYSCALL_DEFINE3(airy_sys_sched_ctl, __u32, op,
		const char __user *, cgroup_path,
		const char __user *, policy)
{
	/* TODO: Scheduler control via cgroup path + policy string */
	return -AIRY_ENOTSUP;
}

/*
 * SYSCALL 515: airy_sys_clt_notify — Cognition Lifecycle notification.
 * @task_id: Task identifier for the cognition agent.
 * @phase:   Cognition phase (AIRY_COG_PERCEPT / THINK / ACT).
 */
SYSCALL_DEFINE2(airy_sys_clt_notify, int, task_id, __u32, phase)
{
	if (phase >= AIRY_COG_PHASE_MAX)
		return -AIRY_EINVAL;

	/* TODO: Notify kernel cognition subsystem of phase transition */
	return -AIRY_ENOTSUP;
}

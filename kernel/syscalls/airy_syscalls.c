/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_syscalls.c — Airymax System Calls (454-457).
 *
 * Implements the four ALK syscalls for agent IPC, memory rotation
 * control, scheduler control, and cognition lifecycle notification.
 * Syscall numbers are defined in the [SC] <linux/airymax/syscalls.h>
 * header (AIRY_SYS_CALL=454 .. AIRY_SYS_CLT_NOTIFY=457), avoiding the
 * x32 historical range 512-547.
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/syscalls.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/cognition_types.h>
#include <linux/airymax/error.h>

/*
 * SYSCALL 454: airy_sys_call — IPC send/recv entry point.
 * @cap: Capability badge for authentication.
 * @msg: User-space pointer to a struct airy_ipc_msg_hdr.
 *
 * The Micro-Supervisor validates the capability badge via
 * airy_cap_badge_ok() before allowing the IPC operation.
 *
 * M0 stage: returns -ENOSYS pending full capability validation
 * and IPC ring dispatch integration (OS-IRON-004 progressive
 * development).
 */
SYSCALL_DEFINE2(airy_sys_call, cap_t, cap,
		const struct airy_ipc_msg_hdr __user *, msg)
{
	struct airy_ipc_msg_hdr hdr;
	int ret;

	if (!msg)
		return -EFAULT;

	/*
	 * A null capability badge is only valid for CAP_REQUEST
	 * bootstrap, which uses the io_uring_cmd path — not this
	 * syscall.  Reject it here.
	 */
	if (cap == AIRY_CAP_NULL)
		return -EINVAL;

	/* Copy and validate the IPC message header. */
	ret = copy_from_user(&hdr, msg, sizeof(hdr));
	if (ret)
		return -EFAULT;

	if (hdr.magic != AIRY_IPC_MAGIC)
		return -EINVAL;

	/*
	 * Dispatch based on opcode.  M0 returns -ENOSYS for all
	 * opcodes pending io_uring fastpath integration, but the
	 * dispatch path is walked to validate the opcode contract.
	 */
	switch (hdr.opcode) {
	case AIRY_IPC_OP_SEND:
	case AIRY_IPC_OP_SEND_BATCH:
		/* IPC send path — deferred to io_uring fastpath */
		return -ENOSYS;
	case AIRY_IPC_OP_RECV:
		/* IPC receive path — deferred to io_uring fastpath */
		return -ENOSYS;
	case AIRY_IPC_OP_CANCEL:
		/* Cancel pending IPC operation */
		return -ENOSYS;
	case AIRY_IPC_OP_FREEZE:
		/* Freeze IPC ring — supervisor-only */
		return -ENOSYS;
	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* Capability bootstrap — handled via io_uring_cmd */
		return -ENOSYS;
	default:
		return -EINVAL;
	}
}

/*
 * SYSCALL 455: airy_sys_rovol_ctl — Memory RoVol (rotation/volume) control.
 * @op:  Operation code.
 * @pid: Target process/task ID.
 * @arg: Operation-specific argument.
 *
 * M0 stage: returns -ENOSYS pending memory tiering integration
 * (OS-IRON-004 progressive development).
 */
SYSCALL_DEFINE3(airy_sys_rovol_ctl, __u32, op, __u32, pid, __u64, arg)
{
	/* Basic parameter validation — op must be non-zero. */
	if (op == 0)
		return -EINVAL;

	/* M0 stage: memory tiering not yet wired. */
	return -ENOSYS;
}

/*
 * SYSCALL 456: airy_sys_sched_ctl — Scheduler control.
 * @op:          Operation code.
 * @cgroup_path: User-space path to the target cgroup.
 * @policy:      User-space scheduling policy string.
 *
 * M0 stage: returns -ENOSYS pending sched_tac dispatch integration
 * (OS-IRON-004 progressive development).
 */
SYSCALL_DEFINE3(airy_sys_sched_ctl, __u32, op,
		const char __user *, cgroup_path,
		const char __user *, policy)
{
	/* Basic parameter validation. */
	if (op == 0)
		return -EINVAL;
	if (!cgroup_path || !policy)
		return -EINVAL;

	/* M0 stage: sched_tac dispatch not yet wired. */
	return -ENOSYS;
}

/*
 * SYSCALL 457: airy_sys_clt_notify — Cognition Lifecycle notification.
 * @task_id: Task identifier for the cognition agent.
 * @phase:   Cognition phase (AIRY_COG_PERCEPT / THINK / ACT).
 *
 * M0 stage: returns -ENOSYS pending cognition subsystem integration
 * (OS-IRON-004 progressive development). Phase range validation is
 * performed as a lightweight contract check.
 */
SYSCALL_DEFINE2(airy_sys_clt_notify, int, task_id, __u32, phase)
{
	if (phase >= AIRY_COG_PHASE_MAX)
		return -EINVAL;
	if (task_id < 0)
		return -EINVAL;

	/* M0 stage: cognition subsystem not yet integrated. */
	return -ENOSYS;
}

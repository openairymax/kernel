// SPDX-License-Identifier: GPL-2.0-only
/*
 * AirymaxOS ALK syscall entry points: airy_sys_call (548) and the
 * rovol / sched / cognition control syscalls 549-551.
 *
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * The numbers sit above the x32 historical range (512-547); the registry
 * is the SSoT in 140-application-development/07-syscall-registry.md.
 *
 * Milestone M1 scaffolding: every entry performs its argument contract
 * checks and then reports -AIRY_ENOTSUP for operations whose handlers
 * land in M2-M5 (20-modules/01-kernel.md 15.2). -AIRY_ENOTSUP is the
 * [SC] "operation not supported" magnitude from error.h; it replaces the
 * POSIX -ENOSYS, which upstream reserves for an invalid syscall number
 * and which OS-DEV-801's checkpatch gate rejects.
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/syscalls.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/cognition_types.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"
#include "airy_invoke.h"

/*
 * airy_invoke_hdr_check — validate the fixed 128-byte IPC message header.
 * @hdr: Kernel-resident copy of the caller message header.
 *
 * Applies the [SC] Layout C v4 field contract (C-S1 magic, C-S3 payload_len,
 * C-S10 flags, C-S4 reserved) and returns the [SC] AIRY_EIPC_* magnitude that
 * 07-ipc-fastpath.md §3.1 assigns to whichever check fails. The opcode is
 * intentionally left to airy_invoke_op_valid() so the dispatchable set has
 * one definition. See airy_invoke.h for the full contract.
 */
__must_check int airy_invoke_hdr_check(const struct airy_ipc_msg_hdr *hdr)
{
	unsigned int i;

	if (unlikely(!hdr))
		return -EINVAL;

	/* C-S1: the buffer must announce itself as a Layout C v4 header. */
	if (unlikely(hdr->magic != AIRY_IPC_MAGIC))
		return -AIRY_EIPC_MAGIC;

	/*
	 * C-S3: payload_len must fit under the [SC] ceiling. A larger value
	 * can never map onto a legal frame, so it is rejected here rather than
	 * left for the copy-in of the data plane to choke on.
	 */
	if (unlikely(hdr->payload_len > AIRY_IPC_MAX_PAYLOAD))
		return -AIRY_EIPC_PAYLOAD;

	/* C-S10: reserved flag bits (5-15) are contractually zero. */
	if (unlikely(hdr->flags & AIRY_IPC_FLAG_RESERVED))
		return -AIRY_EIPC_FLAGS;

	/*
	 * C-S10: ENCRYPT/COMPRESS are declared in the [SC] header for forward
	 * ABI stability, but no v1.0.1 code path produces or consumes them.
	 * Accepting a message that sets either would let a caller assert a
	 * confidentiality/compression property the kernel never applies, so
	 * they are rejected as unsupported rather than silently ignored.
	 */
	if (unlikely(hdr->flags & (AIRY_IPC_FLAG_ENCRYPT |
				   AIRY_IPC_FLAG_COMPRESS)))
		return -AIRY_EIPC_NOTSUPP;

	/* C-S4: reserved[72] is a closed contract and must be all zero. */
	for (i = 0; i < sizeof(hdr->reserved); i++) {
		if (unlikely(hdr->reserved[i]))
			return -AIRY_EIPC_RESERVED;
	}

	return AIRY_EOK;
}

/*
 * airy_invoke_op_valid — test whether an opcode is dispatchable.
 * @opcode: IPC opcode from the [SC] AIRY_IPC_OP_* space.
 *
 * The dispatchable set is defined solely by airy_op_required_perms():
 * an opcode is valid exactly when the mapping recognises it. Keeping a
 * second opcode list here would let the two drift apart and silently
 * admit an unauthenticated operation (OS-KER-225).
 */
bool airy_invoke_op_valid(u16 opcode)
{
	return airy_op_required_perms(opcode) != AIRY_OP_PERMS_INVALID;
}

/*
 * airy_invoke_dispatch — validate and dispatch a syscall 548 request.
 * @cap: Capability badge presented by the caller.
 * @msg: Kernel-resident copy of the caller message header.
 *
 * First the header field contract is enforced by airy_invoke_hdr_check()
 * (C-S1/C-S3/C-S4/C-S10), then the opcode contract, and only then is @cap
 * authenticated against the caller's own capability slot. The agent_id is
 * derived from current — never from the caller-supplied
 * msg->src_task/dst_task, which are untrusted — so a forged header cannot
 * impersonate another agent. The permission mask demanded of @cap is
 * derived from msg->opcode by airy_op_required_perms(), so an authentic
 * badge that lacks the operation's permission is rejected with
 * -AIRY_ECAP_PERM before any handler runs (OS-KER-225).
 */
__must_check int airy_invoke_dispatch(airy_cap_t cap,
				      const struct airy_ipc_msg_hdr *msg)
{
	struct airy_task_sec *sec;
	__u32 agent_id;
	int ret;

	if (unlikely(!msg))
		return -EINVAL;

	ret = airy_invoke_hdr_check(msg);
	if (unlikely(ret))
		return ret;

	if (unlikely(!airy_invoke_op_valid(msg->opcode)))
		return -AIRY_EIPC_OPCODE;

	sec = current->security + airy_blob_sizes.lbs_task;
	agent_id = READ_ONCE(sec->agent_id);

	ret = airy_cap_badge_ok(cap, agent_id,
				airy_op_required_perms(msg->opcode));
	if (unlikely(ret))
		return ret;

	switch (msg->opcode) {
	case AIRY_IPC_OP_SEND:
	case AIRY_IPC_OP_SEND_BATCH:
		/* IPC send path — M2 handler pending */
		return -AIRY_ENOTSUP;
	case AIRY_IPC_OP_RECV:
		/* IPC receive path — M2 handler pending */
		return -AIRY_ENOTSUP;
	case AIRY_IPC_OP_CANCEL:
		/* Cancel pending IPC operation — M2 handler pending */
		return -AIRY_ENOTSUP;
	case AIRY_IPC_OP_FREEZE:
		/* Freeze IPC ring — supervisor-only, M2 handler pending */
		return -AIRY_ENOTSUP;
	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* Capability bootstrap — handled via io_uring_cmd, M2 pending */
		return -AIRY_ENOTSUP;
	default:
		return -AIRY_EIPC_OPCODE;
	}
}

/*
 * SYSCALL 548: airy_sys_call — control-plane management entry.
 * @cap: Capability badge authenticating the caller (sec_d).
 * @msg: User-space pointer to a struct airy_ipc_msg_hdr.
 *
 * The user header is copied in here; every field of the header contract
 * (C-S1/C-S3/C-S4/C-S10), the opcode contract, and the capability badge are
 * then validated by airy_invoke_dispatch() (OS-KER-225: validation
 * precedes mutation). Keeping that validation in the dispatch choke point
 * — instead of repeating the magic check here — leaves exactly one
 * definition of the header contract.
 *
 * M1 scaffolding: valid opcodes still return -AIRY_ENOTSUP pending M2
 * handler landings. Justified by OS-IRON-004 progressive development;
 * not an IRON-2 violation.
 */
SYSCALL_DEFINE2(airy_sys_call, airy_cap_t, cap,
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

	/* Copy in the IPC message header; airy_invoke_dispatch validates it. */
	ret = copy_from_user(&hdr, msg, sizeof(hdr));
	if (ret)
		return -EFAULT;

	return airy_invoke_dispatch(cap, &hdr);
}

/*
 * SYSCALL 549: airy_sys_rovol_ctl — Memory RoVol (rotation/volume) control.
 * @op:  Operation code.
 * @pid: Target process/task ID.
 * @arg: Operation-specific argument.
 *
 * M1 scaffolding: returns -AIRY_ENOTSUP pending M5 memory tiering
 * (MemoryRovol) integration. Basic parameter validation (op != 0) is
 * performed as a lightweight contract check. Justified by OS-IRON-004
 * progressive development; not an IRON-2 violation.
 */
SYSCALL_DEFINE3(airy_sys_rovol_ctl, __u32, op, __u32, pid, __u64, arg)
{
	/* Basic parameter validation — op must be non-zero. */
	if (op == 0)
		return -EINVAL;

	/* M1 scaffolding: M5 memory tiering dispatch pending. */
	return -AIRY_ENOTSUP;
}

/*
 * SYSCALL 550: airy_sys_sched_ctl — Scheduler control.
 * @op:          Operation code.
 * @cgroup_path: User-space path to the target cgroup.
 * @policy:      User-space scheduling policy string.
 *
 * M1 scaffolding: returns -AIRY_ENOTSUP pending M3 sched_tac dispatch
 * integration. Basic parameter validation (op != 0, pointer nullity)
 * is performed as a lightweight contract check. Justified by
 * OS-IRON-004 progressive development; not an IRON-2 violation.
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

	/* M1 scaffolding: M3 sched_tac dispatch pending. */
	return -AIRY_ENOTSUP;
}

/*
 * SYSCALL 551: airy_sys_clt_notify — Cognition Lifecycle notification.
 * @task_id: Task identifier for the cognition agent.
 * @phase:   Cognition phase (AIRY_COG_PERCEPT / THINK / ACT).
 *
 * M1 scaffolding: returns -AIRY_ENOTSUP pending M5 cognition subsystem
 * (CoreLoopThree kthread) integration. Phase range validation
 * (phase < AIRY_COG_PHASE_MAX) and task_id sign check are performed
 * as lightweight contract checks. Justified by OS-IRON-004 progressive
 * development; not an IRON-2 violation.
 */
SYSCALL_DEFINE2(airy_sys_clt_notify, int, task_id, __u32, phase)
{
	if (phase >= AIRY_COG_PHASE_MAX)
		return -EINVAL;
	if (task_id < 0)
		return -EINVAL;

	/* M1 scaffolding: M5 cognition subsystem dispatch pending. */
	return -AIRY_ENOTSUP;
}

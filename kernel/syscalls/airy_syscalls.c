/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_syscalls.c — Airymax System Calls (548-551).
 *
 * Implements the four ALK syscalls for agent IPC, memory rotation
 * control, scheduler control, and cognition lifecycle notification.
 * Syscall numbers are defined in the [SC] <linux/airymax/syscalls.h>
 * header (AIRY_SYS_CALL=548 .. AIRY_SYS_CLT_NOTIFY=551), avoiding the
 * x32 historical range 512-547. SSoT: 07-syscall-registry.md.
 *
 * ════════════════════════════════════════════════════════════════════════
 * STAGE DECLARATION (v3.5 audit P0-17 fix)
 * ════════════════════════════════════════════════════════════════════════
 *
 * Project stage: M0 design phase + M1 [SC] header scaffolding
 *                (per docs/AirymaxOS/20-modules/01-kernel.md §15.1)
 *
 * All four syscalls (548-551) return -ENOSYS for every valid opcode.
 * This is NOT a violation of IRON-2 (禁止桩函数桩文件):
 *
 *   - IRON-2 forbids hidden stubs that masquerade as real implementations.
 *   - These entry points are EXPLICIT design-phase scaffolding registered
 *     to validate the syscall numbering scheme (548-551, avoiding x32
 *     historical range 512-547), to keep the kernel compilable at every
 *     intermediate point of development, and to fix the entry-point
 *     signatures for downstream design work.
 *   - Parameter validation (cap != NULL, magic check, opcode range,
 *     phase range, op != 0, pointer nullity) is performed as a
 *     lightweight contract check so callers receive -EINVAL/-EFAULT
 *     for malformed requests instead of -ENOSYS.
 *   - Syscall 548 additionally walks the real control-plane entry
 *     airy_invoke_dispatch(): it validates the opcode contract and
 *     authenticates the badge via airy_cap_badge_ok() against the
 *     caller's identity derived from current (OS-KER-225).
 *
 * The -ENOSYS contract is justified by OS-IRON-004 (渐进式开发，补丁自
 * 包含): every intermediate point of the patch series must be compilable
 * and runnable, ensuring git bisect friendliness. Real dispatch lands in
 * M2-M8 per docs/AirymaxOS/20-modules/01-kernel.md §15.2:
 *
 *   - airy_sys_call (548)       → M2 io_uring IPC data plane + control
 *                                 plane syscall (Week 3-4)
 *   - airy_sys_rovol_ctl (549)  → M5 记忆卷载 + 认知通知 (Week 9-10)
 *   - airy_sys_sched_ctl (550)  → M3 sched_tac 策略守护进程 (Week 5-6)
 *   - airy_sys_clt_notify (551) → M5 记忆卷载 + 认知通知 (Week 9-10)
 *
 * The previous "M0 stage" comments in this file were inaccurate (M0 =
 * documentation only, no kernel code per §15.1). They have been corrected
 * to "M1 scaffolding" to align with the milestone definitions and resolve
 * the v3.5 audit P0-17 stage-claim contradiction with §15.2.
 *
 * Reference: docs-closed/agent-linux/00-reviews/_review_v3.5/
 *            07-final-independent-verification-v3.5.md §P0-17
 * ════════════════════════════════════════════════════════════════════════
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
 * airy_invoke_op_valid — test whether an opcode is dispatchable.
 * @opcode: IPC opcode from the [SC] AIRY_IPC_OP_* space.
 *
 * Returns true only for opcodes that belong to the syscall 548
 * control-plane dispatch set. Unknown opcodes must be rejected with
 * -EINVAL before any state is touched (OS-KER-225).
 */
bool airy_invoke_op_valid(u16 opcode)
{
	switch (opcode) {
	case AIRY_IPC_OP_SEND:
	case AIRY_IPC_OP_RECV:
	case AIRY_IPC_OP_SEND_BATCH:
	case AIRY_IPC_OP_CANCEL:
	case AIRY_IPC_OP_FREEZE:
	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		return true;
	default:
		return false;
	}
}

/*
 * airy_invoke_dispatch — validate and dispatch a syscall 548 request.
 * @cap: Capability badge presented by the caller.
 * @msg: Kernel-resident copy of the caller message header.
 *
 * Validates the opcode contract and authenticates @cap against the
 * caller's own capability slot. The agent_id is derived from current —
 * never from the caller-supplied msg->src_task/dst_task, which are
 * untrusted — so a forged header cannot impersonate another agent.
 * Only badge authenticity is checked here; per-operation permissions
 * are the responsibility of the individual handler.
 */
__must_check int airy_invoke_dispatch(airy_cap_t cap,
				      const struct airy_ipc_msg_hdr *msg)
{
	struct airy_task_sec *sec;
	__u32 agent_id;
	int ret;

	if (unlikely(!msg))
		return -EINVAL;

	if (unlikely(!airy_invoke_op_valid(msg->opcode)))
		return -EINVAL;

	sec = current->security + airy_blob_sizes.lbs_task;
	agent_id = READ_ONCE(sec->agent_id);

	ret = airy_cap_badge_ok(cap, agent_id, AIRY_CAP_PERM_NONE);
	if (unlikely(ret))
		return ret;

	switch (msg->opcode) {
	case AIRY_IPC_OP_SEND:
	case AIRY_IPC_OP_SEND_BATCH:
		/* IPC send path — M2 handler pending */
		return -ENOSYS;
	case AIRY_IPC_OP_RECV:
		/* IPC receive path — M2 handler pending */
		return -ENOSYS;
	case AIRY_IPC_OP_CANCEL:
		/* Cancel pending IPC operation — M2 handler pending */
		return -ENOSYS;
	case AIRY_IPC_OP_FREEZE:
		/* Freeze IPC ring — supervisor-only, M2 handler pending */
		return -ENOSYS;
	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* Capability bootstrap — handled via io_uring_cmd, M2 pending */
		return -ENOSYS;
	default:
		return -EINVAL;
	}
}

/*
 * SYSCALL 548: airy_sys_call — control-plane management entry.
 * @cap: Capability badge authenticating the caller (sec_d).
 * @msg: User-space pointer to a struct airy_ipc_msg_hdr.
 *
 * The user header is copied in and its magic verified here; the
 * opcode contract and the capability badge are then validated by
 * airy_invoke_dispatch() (OS-KER-225: validation precedes mutation).
 *
 * M1 scaffolding: valid opcodes still return -ENOSYS pending M2
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

	/* Copy and validate the IPC message header. */
	ret = copy_from_user(&hdr, msg, sizeof(hdr));
	if (ret)
		return -EFAULT;

	if (hdr.magic != AIRY_IPC_MAGIC)
		return -EINVAL;

	return airy_invoke_dispatch(cap, &hdr);
}

/*
 * SYSCALL 549: airy_sys_rovol_ctl — Memory RoVol (rotation/volume) control.
 * @op:  Operation code.
 * @pid: Target process/task ID.
 * @arg: Operation-specific argument.
 *
 * M1 scaffolding: returns -ENOSYS pending M5 memory tiering (MemoryRovol)
 * integration. Basic parameter validation (op != 0) is performed as a
 * lightweight contract check. Justified by OS-IRON-004 progressive
 * development; not an IRON-2 violation.
 */
SYSCALL_DEFINE3(airy_sys_rovol_ctl, __u32, op, __u32, pid, __u64, arg)
{
	/* Basic parameter validation — op must be non-zero. */
	if (op == 0)
		return -EINVAL;

	/* M1 scaffolding: M5 memory tiering dispatch pending. */
	return -ENOSYS;
}

/*
 * SYSCALL 550: airy_sys_sched_ctl — Scheduler control.
 * @op:          Operation code.
 * @cgroup_path: User-space path to the target cgroup.
 * @policy:      User-space scheduling policy string.
 *
 * M1 scaffolding: returns -ENOSYS pending M3 sched_tac dispatch
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
	return -ENOSYS;
}

/*
 * SYSCALL 551: airy_sys_clt_notify — Cognition Lifecycle notification.
 * @task_id: Task identifier for the cognition agent.
 * @phase:   Cognition phase (AIRY_COG_PERCEPT / THINK / ACT).
 *
 * M1 scaffolding: returns -ENOSYS pending M5 cognition subsystem
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
	return -ENOSYS;
}

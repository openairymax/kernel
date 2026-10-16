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
 * airy_sys_call (548) is the sec_d-only capability management entry
 * (30-interfaces/01-syscalls.md §1.4). It dispatches on msg->opcode and
 * serves both halves of the badge lifecycle: install (airy_badge_install)
 * and cascading revocation (airy_badge_revoke). Valid opcodes of the
 * data and bootstrap planes are answered -AIRY_ENOTSUP rather than
 * served here; 549 and 550 answer -AIRY_ENOTSUP as well, while 551
 * records the phase an agent notified through airy_clt_serve().
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/syscalls.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"
#include "airy_invoke.h"
#include "airy_clt.h"

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
 * The dispatchable set is defined solely by airy_op_plane(): an opcode is
 * valid exactly when it belongs to one of the three opcode planes.
 * Keeping a second opcode list here would let the two drift apart and
 * silently admit an unauthenticated operation (OS-KER-225).
 */
bool airy_invoke_op_valid(u16 opcode)
{
	return airy_op_plane(opcode) != AIRY_PLANE_INVALID;
}

/*
 * airy_badge_chk — validate the shape of a sec_d-compiled badge.
 * @badge: 64-bit badge as composed by AIRY_BADGE_COMPILE().
 *
 * Pure value check with no state access, kept separate from the slot
 * write so the shape rules stay trivially auditable and the handler's
 * complexity stays low. Four properties must hold for any badge the
 * kernel is willing to seal into a slot:
 *
 *   - a zero badge is the "no capability" sentinel (AIRY_CAP_NULL), not
 *     a capability (-AIRY_ECAP_BADGE);
 *   - epoch 0 denotes an uninitialised slot, never a live grant, so it
 *     can never authorise anything (-AIRY_ECAP_EPOCH);
 *   - a zero RandomTag would make the badge forgeable by construction
 *     (-AIRY_ECAP_BADGE);
 *   - the reserved permission bits (AIRY_CAP_PERM_RESERVED) are not
 *     interpreted by any check, so a badge carrying them would smuggle
 *     authority the capability model does not define (-AIRY_ECAP_BADGE).
 *
 * -AIRY_ECAP_FORGED is deliberately not used here: that magnitude is
 * reserved for airy_cap_badge_ok(), which compares a presented badge
 * against a live slot.
 */
static __must_check int airy_badge_chk(u64 badge)
{
	if (unlikely(badge == AIRY_CAP_NULL))
		return -AIRY_ECAP_BADGE;

	if (unlikely(AIRY_BADGE_EPOCH(badge) == 0))
		return -AIRY_ECAP_EPOCH;

	if (unlikely(AIRY_BADGE_RANDTAG(badge) == 0))
		return -AIRY_ECAP_BADGE;

	if (unlikely(AIRY_BADGE_PERMS(badge) & AIRY_CAP_PERM_RESERVED))
		return -AIRY_ECAP_BADGE;

	return AIRY_EOK;
}

/*
 * airy_badge_install — install a sec_d-compiled badge into an agent slot.
 * @msg: Kernel-resident copy of the caller message header.
 *
 * Handler for AIRY_IPC_OP_CAP_RESPONSE (COMPILE_BADGE in
 * 07-syscall-registry.md §4.2). Only msg->capability_badge and
 * msg->dst_task are read; the header field contract, the opcode contract
 * and the caller's own badge have already been enforced by
 * airy_invoke_dispatch(), so this function performs exactly three steps:
 *
 *   1. bound-check the target slot index against the slot table;
 *   2. check the badge's shape (airy_badge_chk);
 *   3. require the badge epoch to agree with the target slot's live epoch
 *      before handing the write to airy_cap_register().
 *
 * Step 3 is what makes revocation stick: airy_cap_epoch_bump() raises the
 * slot epoch on revoke, so a badge compiled before the bump no longer
 * matches and cannot resurrect the capability. It equally rejects a badge
 * compiled for an epoch the slot has not reached yet. The same rule
 * guards the CAP_REQUEST bootstrap in airy_cap_check.c, so both
 * capability entry points share one epoch contract.
 *
 * The slot-occupancy decision is left to airy_cap_register(), which tests
 * and writes the slot under the per-bucket lock; re-checking occupancy
 * here would only add a TOCTOU window that the primitive already closes.
 *
 * Return: AIRY_EOK on success; -EINVAL when @msg is NULL; -AIRY_ECAP_OVERFLOW
 *         for an out-of-range target; -AIRY_ECAP_* for a malformed or stale
 *         badge; -AIRY_EEXIST when the target slot is already occupied.
 */
__must_check int airy_badge_install(const struct airy_ipc_msg_hdr *msg)
{
	__u32 agent_id;
	__u64 badge;
	int ret;

	if (unlikely(!msg))
		return -EINVAL;

	if (unlikely(msg->dst_task >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_OVERFLOW;

	agent_id = (__u32)msg->dst_task;
	badge = msg->capability_badge;

	ret = airy_badge_chk(badge);
	if (unlikely(ret))
		return ret;

	if (unlikely(AIRY_BADGE_EPOCH(badge) !=
		     (__u64)READ_ONCE(agent_caps[agent_id].epoch)))
		return -AIRY_ECAP_EPOCH;

	return airy_cap_register(agent_id, badge);
}

/*
 * airy_badge_revoke — revoke an agent's badge and its derived subtree.
 * @msg: Kernel-resident copy of the caller message header.
 *
 * Handler for AIRY_IPC_OP_FREEZE, which is the control-plane carrier for
 * REVOKE_BADGE (30-interfaces/01-syscalls.md §1.4). Only msg->dst_task is
 * read: it names the root of the revocation subtree. The header contract,
 * the opcode contract and the caller's own badge have already been
 * enforced by airy_invoke_dispatch(), so this function adds exactly one
 * thing — a bound check on the target slot index — before handing the
 * cascade to airy_cap_derive().
 *
 * The cascade is deliberate. airy_cap_derive(AIRY_CAP_OP_REVOKE) bumps the
 * target slot's epoch, clears its RandomTag and repeats both for every
 * revocable descendant in the MDB derivation tree (seL4 cteRevoke
 * alignment, 110-security/03-capability-model.md §3.5). Revoking only the
 * target's own epoch would leave capabilities it had already derived —
 * and the authority they carry — alive after the parent is gone.
 *
 * Return: AIRY_EOK on success; -EINVAL when @msg is NULL;
 *         -AIRY_ECAP_OVERFLOW for an out-of-range target; -AIRY_ECAP_MISSING
 *         when the target has no registered badge, so there is nothing to
 *         revoke.
 */
__must_check int airy_badge_revoke(const struct airy_ipc_msg_hdr *msg)
{
	__u32 agent_id;

	if (unlikely(!msg))
		return -EINVAL;

	if (unlikely(msg->dst_task >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_OVERFLOW;

	agent_id = (__u32)msg->dst_task;

	return airy_cap_derive(agent_id, 0, AIRY_CAP_OP_REVOKE, 0);
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
 *
 * Once authenticated the request is routed to the matching handler:
 * AIRY_IPC_OP_CAP_RESPONSE reaches airy_badge_install() and
 * AIRY_IPC_OP_FREEZE reaches airy_badge_revoke(). Every remaining valid
 * opcode belongs to a plane this sec_d-only entry does not serve — the
 * io_uring data plane (SEND/SEND_BATCH/RECV/CANCEL) or the io_uring_cmd
 * bootstrap (CAP_REQUEST) — and is answered -AIRY_ENOTSUP, the [SC]
 * magnitude for "recognised but not offered here". That refusal is a
 * deliberate statement of ownership, not a placeholder: no later stage
 * routes those opcodes through 548.
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
	case AIRY_IPC_OP_FREEZE:
		/*
		 * sec_d REVOKE_BADGE (registry §4.2): the control-plane use
		 * of the FREEZE opcode. Ring freezing itself runs on the
		 * io_uring data plane and does not enter this path.
		 */
		return airy_badge_revoke(msg);
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* sec_d COMPILE_BADGE — install into the target slot */
		return airy_badge_install(msg);
	default:
		/*
		 * SEND/SEND_BATCH/RECV/CANCEL carry the IPC stream on the
		 * io_uring data plane, whose C-S9 inline Badge check
		 * performs their authorisation; CAP_REQUEST is the
		 * unprivileged half of the bootstrap pair, served by the
		 * io_uring_cmd path (airy_cap_check.c
		 * phase2_cap_request). Neither plane routes through this
		 * sec_d-only syscall, so the request is refused
		 * explicitly rather than awaited.
		 */
		return -AIRY_ENOTSUP;
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
 * AIRY_IPC_OP_CAP_RESPONSE (the sec_d COMPILE_BADGE half) and
 * AIRY_IPC_OP_FREEZE (the sec_d REVOKE_BADGE half) are fully served here
 * through airy_badge_install() and airy_badge_revoke(). The remaining
 * valid opcodes belong to the io_uring data plane or the io_uring_cmd
 * bootstrap and are answered -AIRY_ENOTSUP, since 548 is not their entry.
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
 * @phase:   Unified operation code: 0/1/2 are the CoreLoopThree phases
 *           PERCEPT/THINK/ACT, AIRY_COG_PHASE_MAX upwards is reserved for
 *           the kthread-class operations owned by module F.
 *
 * A thin wrapper over airy_clt_serve(), which owns the entry decision:
 * classify the phase space with airy_clt_kind() and then record through
 * airy_clt_notify(). Keeping the decision in one non-static place lets
 * KUnit drive it directly instead of through the syscall ABI.
 */
SYSCALL_DEFINE2(airy_sys_clt_notify, int, task_id, __u32, phase)
{
	return airy_clt_serve(task_id, phase);
}

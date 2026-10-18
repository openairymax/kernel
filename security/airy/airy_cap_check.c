// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_check.c — Slowpath capability check and fault reporting.
 *
 * Implements the five-phase slowpath enforcement for io_uring_cmd IPC
 * messages: frozen ring, CAP_REQUEST bootstrap, degradation, fastpath
 * re-check and LSM enforcement.  airy_op_plane32() classifies cmd_op
 * ahead of the phases: malformed opcodes are refused without a fault
 * report, control-plane opcodes as not-offered-here.  Also hosts
 * airy_security_fault() for unrecoverable violations.
 *
 * SSoT: 110-security/03-capability-model.md §4.3,
 *       110-security/06-io-uring-hardening.md §5.
 */

#include <linux/lsm_hooks.h>
#include <linux/io_uring.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/notifier.h>
#include <asm/unaligned.h>

#include <linux/airymax/error.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/sched.h>

#include <airymax/airy_lockdown.h>

#include "../../kernel/corekern/ipc/airy_ipc_op.h"

#include "airy_cap.h"

/* ─── C-S2 cmd_op Gate ─────────────────────────────────────────────────── */
/*
 * Decide whether this plane serves the command before any state is
 * inspected.  The io_uring_cmd path owns DATA and BOOT only: DATA
 * carries the IPC stream under the C-S9 inline Badge check, BOOT is the
 * CAP_REQUEST bootstrap half.  CTL opcodes are the sec_d management
 * entries served by syscall 548 and are refused here with the same
 * -AIRY_ENOTSUP that 548 returns for the other planes, so each opcode
 * has exactly one serving entry point.
 *
 * A value outside the [SC] opcode space is a malformed request, not a
 * forged badge: it is answered before the phases, without calling
 * airy_security_fault().  Reporting a fault would let any caller freeze
 * its own ring by sending a bad opcode.
 */
static int airy_cmd_gate(u32 cmd_op, enum airy_plane *plane)
{
	enum airy_plane owner = airy_op_plane32(cmd_op);

	*plane = owner;

	switch (owner) {
	case AIRY_PLANE_DATA:
	case AIRY_PLANE_BOOT:
		return 0;
	case AIRY_PLANE_CTL:
		return -AIRY_ENOTSUP;
	default:
		return -AIRY_EIPC_OPCODE;
	}
}

/* ─── Phase 1: C-S0 Ring Frozen Check ──────────────────────────────────── */
/*
 * Check whether the agent's IPC ring is frozen.  A frozen ring means
 * the agent has been administratively suspended; all IPC must be
 * rejected immediately.
 *
 * A task without a ring (kernel thread, init task) is not frozen:
 * there is no agent IPC channel to suspend.
 */
static int phase1_frozen(struct task_struct *task, __u32 agent_id)
{
	int ret;

	ret = airy_ipc_fastpath_check(airy_ipc_ring_for_task(task));
	if (ret)
		pr_debug_ratelimited("airy_cap_check: phase1 agent=%u ring FROZEN\n",
				     agent_id);

	return ret;
}

/* ─── Phase 2: CAP_REQUEST Bootstrap Path ──────────────────────────────── */
/*
 * Handle the special CAP_REQUEST opcode that allows an agent to
 * request its initial capability set during bootstrap.  This is
 * the only path that can create capabilities without prior authority.
 */
static int phase2_cap_request(__u32 agent_id, __u64 badge)
{
	/*
	 * CAP_REQUEST is only valid when the agent has no existing
	 * capabilities (freshly spawned, empty slot).
	 */
	if (READ_ONCE(agent_caps[agent_id].badge) != AIRY_CAP_NULL) {
		pr_debug_ratelimited("airy_cap_check: phase2 agent=%u CAP_REQUEST rejected - slot occupied\n",
			agent_id);
		return -AIRY_ECAP_OVERFLOW;
	}

	/* Validate the bootstrap badge against the per-agent epoch */
	if (AIRY_BADGE_EPOCH(badge) !=
	    (__u64)READ_ONCE(agent_caps[agent_id].epoch)) {
		pr_debug_ratelimited("airy_cap_check: phase2 agent=%u CAP_REQUEST rejected - epoch mismatch badge_epoch=%llu slot_epoch=%u\n",
			agent_id,
			(unsigned long long)AIRY_BADGE_EPOCH(badge),
			READ_ONCE(agent_caps[agent_id].epoch));
		return -AIRY_ECAP_EPOCH;
	}

	pr_debug_ratelimited("airy_cap_check: phase2 agent=%u CAP_REQUEST bootstrap badge=0x%016llx\n",
		agent_id, (unsigned long long)badge);

	/* Register the initial capability */
	return airy_cap_register(agent_id, badge);
}

/* ─── Phase 3: [DSL]/agentrt Degradation ───────────────────────────────── */
/*
 * Reached when sec->agent_state == AIRY_AGENT_STOPPED.  A STOPPED agent
 * has been administratively suspended (TASK_STOPPED, pending adjudication)
 * and MUST NOT be allowed to perform IPC.
 *
 * The previous implementation returned 0 (allow) here, which was a
 * fail-open security hole: any agent entering the STOPPED state could
 * bypass ALL badge/epoch/permission checks and issue arbitrary IPC with
 * forged badges.  This is especially dangerous because STOPPED is the
 * state an agent enters when it is being quarantined for a policy
 * violation — exactly the moment enforcement must hold.
 *
 * The [DSL] compile-time fallback (AIRY_SC_FALLBACK) is a separate
 * concern handled by the [SC] header contracts; it does not license a
 * runtime fail-open path.  Fail closed: deny the operation as if the
 * ring were frozen, and let the caller's fault path report it.
 */
static int phase3_dsl_degradation(__u32 agent_id)
{
	pr_warn_ratelimited("airy: agent %u IPC rejected in STOPPED state (fail-closed)\n",
			    agent_id);
	return -AIRY_EIPC_FROZEN;
}

/* ─── Phase 4: Fastpath C-S9 Re-check ──────────────────────────────────── */
/*
 * Re-run the fastpath badge validation to resolve races between
 * concurrent operations (e.g., a revoke happening during slowpath).
 */
static int phase4_fastpath_recheck(__u64 badge, __u32 agent_id,
				   __u16 required_perms)
{
	int ret = airy_cap_badge_ok(badge, agent_id, required_perms);

	pr_debug_ratelimited("airy_cap_check: phase4 agent=%u fastpath recheck ret=%d badge=0x%016llx perms=0x%04x\n",
		agent_id, ret, (unsigned long long)badge, required_perms);
	return ret;
}

/* ─── Phase 5: Slowpath Enforcement ────────────────────────────────────── */
/*
 * Perform LSM-hook-based enforcement for the operation.
 * At this point all fastpath checks have been exhausted; the slowpath
 * performs additional policy checks that cannot be done in the
 * fastpath context.
 */
static int phase5_slowpath_enforce(__u32 agent_id, __u64 badge,
				   __u16 required_perms)
{
	struct airy_cap_slot *slot;
	__u64 slot_badge;
	__u16 slot_perms;

	pr_debug_ratelimited("airy_cap_check: phase5 ENTER agent=%u badge=0x%016llx required_perms=0x%04x\n",
		agent_id, (unsigned long long)badge, required_perms);

	slot = airy_cap_lookup(agent_id);
	if (!slot) {
		pr_debug_ratelimited("airy_cap_check: phase5 agent=%u FAIL - slot not found (CAP_MISSING)\n",
			agent_id);
		return -AIRY_ECAP_MISSING;
	}

	/*
	 * Full badge comparison (not just fastpath fields).
	 * READ_ONCE prevents torn reads on weakly-ordered architectures
	 * (ARM64) when airy_cap_derive() concurrently writes slot->badge
	 * under airy_cap_derive_lock (e.g. ROTATE/MUTATE/MOVE/DELETE).
	 * This mirrors Linux 6.6 io_uring's defensive READ_ONCE pattern
	 * for shared-memory reads (see io_uring.c io_get_sqe).
	 */
	slot_badge = READ_ONCE(slot->badge);
	if (slot_badge != badge) {
		pr_debug_ratelimited("airy_cap_check: phase5 agent=%u FAIL - badge FORGED slot_badge=0x%016llx != req_badge=0x%016llx\n",
			agent_id,
			(unsigned long long)slot_badge,
			(unsigned long long)badge);
		return -AIRY_ECAP_FORGED;
	}

	/* Full permission check (same READ_ONCE rationale as badge) */
	slot_perms = READ_ONCE(slot->perms);
	if ((slot_perms & required_perms) != required_perms) {
		pr_debug_ratelimited("airy_cap_check: phase5 agent=%u FAIL - perm denied slot_perms=0x%04x required=0x%04x missing=0x%04x\n",
			agent_id, slot_perms, required_perms,
			(__u16)(required_perms & ~slot_perms));
		return -AIRY_ECAP_PERM;
	}

	pr_debug_ratelimited("airy_cap_check: phase5 agent=%u PASS - badge=0x%016llx perms=0x%04x epoch=%u\n",
		agent_id, (unsigned long long)slot_badge, slot_perms,
		READ_ONCE(slot->epoch));
	return 0;
}

/* ─── Slowpath Slot Check ──────────────────────────────────────────────── */
/*
 * Verify that the capability slot of agent_id is live and carries every
 * permission bit in required_perms.  This is the slowpath entry used by
 * the LSM hooks, which have no caller-supplied badge to compare against.
 *
 * A slot is live only while its four fields are mutually consistent:
 * epoch, randtag and perms must match the copies embedded in badge.
 * airy_cap_revoke_subtree() bumps epoch and clears randtag but leaves
 * badge and perms untouched, so a live slot that was revoked fails the
 * epoch check even though its permission bits still look valid.  A pure
 * permission test would wrongly honour revoked capabilities.
 *
 * The whole snapshot is taken under the bucket lock: ROTATE publishes
 * randtag before badge, and taking the lock guarantees the four fields
 * come from the same generation instead of a torn intermediate state.
 * The order of the checks matches airy_cap_badge_ok() so both paths
 * report the same reason for the same slot state.
 */
int airy_cap_check(__u32 agent_id, __u16 required_perms)
{
	struct airy_cap_slot *slot;
	spinlock_t *lock;
	unsigned long flags;
	__u64 badge;
	__u16 perms, epoch;
	__u32 tag;

	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return -AIRY_ECAP_MISSING;

	slot = &agent_caps[agent_id];
	lock = &airy_cap_bucket_locks[airy_cap_bucket(agent_id)];

	spin_lock_irqsave(lock, flags);
	badge = slot->badge;
	epoch = slot->epoch;
	tag = slot->randtag;
	perms = slot->perms;
	spin_unlock_irqrestore(lock, flags);

	if (badge == AIRY_CAP_NULL)
		return -AIRY_ECAP_MISSING;

	if (epoch != AIRY_BADGE_EPOCH(badge))
		return -AIRY_ECAP_EPOCH;

	if (tag != AIRY_BADGE_RANDTAG(badge) ||
	    perms != AIRY_BADGE_PERMS(badge))
		return -AIRY_ECAP_FORGED;

	if ((perms & required_perms) != required_perms)
		return -AIRY_ECAP_PERM;

	return 0;
}

/* ─── Enforcement Failure to Fault Code ────────────────────────────────── */
/*
 * Map an enforcement failure to the fault code the Supervisor records.
 * Only a forged badge is a CAP_FORGED violation; an epoch, permission
 * or missing-slot rejection is ABNORMAL_CAP.  A frozen ring never
 * reaches the fault path, so -AIRY_EIPC_FROZEN has no mapping here.
 */
static __u32 airy_fault_code(int err)
{
	if (err == -AIRY_ECAP_FORGED)
		return AIRY_FAULT_CAP_FORGED;

	return AIRY_FAULT_ABNORMAL_CAP;
}

/* ─── airy_uring_cmd_check ─────────────────────────────────────────────── */
/*
 * Slowpath capability check for io_uring_cmd IPC messages.
 *
 * First the cmd_op is gated (C-S2): a malformed value is refused with
 * -AIRY_EIPC_OPCODE and a control-plane value with -AIRY_ENOTSUP, both
 * before any phase runs and without touching per-agent state.  The
 * remaining commands execute the five-phase protocol:
 *   1. Check if the agent ring is frozen (C-S0)
 *   2. Handle CAP_REQUEST bootstrap
 *   3. Try [DSL] degradation if compatible
 *   4. Re-check fastpath C-S9 (race resolution)
 *   5. Full slowpath enforcement
 *
 * The permission mask a DATA command must carry is derived from the
 * opcode by airy_op_required_perms(), the same single source of truth
 * syscall 548 uses.  It is deliberately not read from the caller-owned
 * pdu: a caller that supplied its own required_perms could ask for zero
 * and bypass the permission bits entirely.
 *
 * The pdu layout is thus:
 *   bytes [0..7]   — capability badge (u64, little-endian)
 *   bytes [8..31]  — reserved, ignored
 */
int airy_uring_cmd_check(struct io_uring_cmd *ioucmd)
{
	struct task_struct *task = current;
	struct airy_task_sec *sec;
	enum airy_plane plane;
	__u32 agent_id;
	__u64 badge;
	__u16 required_perms;
	int ret;

	/* Retrieve agent security context from current task */
	sec = task->security + airy_blob_sizes.lbs_task;
	agent_id = READ_ONCE(sec->agent_id);

	pr_debug_ratelimited("airy_cap_check: ENTER agent=%u cmd_op=%u state=%d\n",
		agent_id, ioucmd->cmd_op, sec->agent_state);

	/*
	 * C-S2: reject malformed and control-plane opcodes before any
	 * per-agent state is read or mutated.
	 */
	ret = airy_cmd_gate(ioucmd->cmd_op, &plane);
	if (ret)
		return ret;

	/*
	 * Phase 1: C-S0 — ring frozen check.  A frozen ring blocks every
	 * command, bootstrap included: suspension must not be escapable
	 * by re-requesting capabilities.  This is a plain error, not a
	 * fault: the ring is already frozen, so it must not count as a
	 * new violation or re-enter the die_notifier chain.
	 */
	ret = phase1_frozen(task, agent_id);
	if (ret)
		return ret;

	badge = get_unaligned_le64(&ioucmd->pdu[0]);

	/*
	 * Phase 2: CAP_REQUEST bootstrap path.  CAP_REQUEST is the only
	 * BOOT-plane opcode, so the plane verdict doubles as the opcode
	 * verdict here.
	 */
	if (plane == AIRY_PLANE_BOOT) {
		ret = airy_lock_gate(AIRY_LOCK_IF_CAP_GRANT);
		if (ret)
			return ret;
		return phase2_cap_request(agent_id, badge);
	}

	required_perms = airy_op_required_perms((__u16)ioucmd->cmd_op);

	/*
	 * Phase 3: [DSL]/agentrt degradation
	 */
	if (sec->agent_state == AIRY_AGENT_STOPPED)
		return phase3_dsl_degradation(agent_id);

	/*
	 * Phase 4: fastpath C-S9 re-check
	 */
	ret = phase4_fastpath_recheck(badge, agent_id, required_perms);
	if (ret == 0)
		return 0;  /* fastpath passed, allow */

	/*
	 * Phase 5: slowpath enforcement with LSM hooks
	 */
	ret = phase5_slowpath_enforce(agent_id, badge, required_perms);
	if (ret < 0)
		goto fault;

	pr_debug_ratelimited("airy_cap_check: agent=%u ALL PHASES PASSED\n", agent_id);
	return 0;

fault:
	pr_warn("airy_cap_check: agent=%u SECURITY FAULT ret=%d — triggering die_notifier\n",
		agent_id, ret);
	airy_security_fault(agent_id, airy_fault_code(ret));
	return ret;
}

/* ─── airy_security_fault ──────────────────────────────────────────────── */
/*
 * Report an unrecoverable security fault for an agent.
 *
 * Increments the per-agent fault counter, freezes the agent's IPC ring
 * so the frozen state is what phase 1 reads on the next command, and
 * notifies the die_notifier chain for out-of-band Supervisor action.
 *
 * agent_id vs current (P2 fix): the fault is reported for @agent_id,
 * but the per-task fault_count/frozen_reason fields live in the
 * security blob of the task that OWNS that agent_id.  Modifying
 * current->security unconditionally was a bug: when airy_security_fault
 * is invoked from a supervisor/workqueue context, current is the
 * supervisor (not the offender), and the supervisor's fault counter and
 * frozen_reason would be corrupted.  Only touch current's blob when
 * current actually carries the offending agent_id; otherwise leave the
 * per-task state alone — the die_notifier chain carries the agent_id
 * so the Supervisor can act on the correct agent out-of-band.
 */
void airy_security_fault(__u32 agent_id, __u32 fault_code)
{
	struct airy_task_sec *sec;
	struct task_struct *task = current;

	pr_err("airy: security fault agent=%u code=0x%x\n",
	       agent_id, fault_code);

	if (agent_id < AIRY_CAP_MAX_AGENTS && task && task->security) {
		sec = task->security + airy_blob_sizes.lbs_task;

		/* Only mutate current's blob if current IS the offender */
		if (READ_ONCE(sec->agent_id) == agent_id) {
			__u32 old, new;

			do {
				old = READ_ONCE(sec->fault_count);
				new = old + 1;
			} while (cmpxchg(&sec->fault_count, old, new) != old);

			/*
			 * Freeze the ring, the enforcement source of truth
			 * read by phase 1.  frozen_reason mirrors the code
			 * for the Supervisor.  Both stores are relaxed
			 * single-word writes, so this is safe from the IPC
			 * and die contexts that call this function.
			 */
			airy_ipc_freeze_ring(airy_ipc_ring_for_task(task),
					     fault_code);
			WRITE_ONCE(sec->frozen_reason, fault_code);
		}
	}

	/*
	 * Notify the Airy security fault chain so the Supervisor can
	 * take out-of-band action (e.g., terminate or quarantine the
	 * offending agent).  This is separate from the kernel die_chain
	 * which handles hardware/kernel faults.
	 */
	atomic_notifier_call_chain(&airy_die_chain, fault_code, task);
}

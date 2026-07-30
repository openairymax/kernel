// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_check.c — Slowpath capability check and fault reporting.
 *
 * Implements the five-phase slowpath capability enforcement for
 * io_uring_cmd IPC messages that fail the fastpath C-S9 validation.
 *
 * Phase 1: C-S0  Ring frozen check
 * Phase 2: CAP_REQUEST bootstrap path
 * Phase 3: [DSL]/agentrt degradation path
 * Phase 4: Fastpath C-S9 re-check (race-resolution)
 * Phase 5: Slowpath enforcement with LSM hooks
 *
 * Also provides airy_security_fault() for reporting unrecoverable
 * security violations to the die_notifier chain.
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

#include "airy_cap.h"

/* Airy security fault notifier chain (defined in airy_die_notify.c) */
extern struct atomic_notifier_head airy_die_chain;

/* ─── Phase 1: C-S0 Ring Frozen Check ──────────────────────────────────── */
/*
 * Check whether the agent's IPC ring is frozen.  A frozen ring means
 * the agent has been administratively suspended; all IPC must be
 * rejected immediately.
 */
static int phase1_ring_frozen(struct airy_task_sec *sec)
{
	/* Ring is frozen if frozen_reason != 0 */
	if (READ_ONCE(sec->frozen_reason) != 0) {
		pr_debug_ratelimited("airy_cap_check: phase1 agent=%u ring FROZEN reason=0x%x\n",
			sec->agent_id, READ_ONCE(sec->frozen_reason));
		return -AIRY_EIPC_FROZEN;
	}

	return 0;
}

/* ─── Phase 2: CAP_REQUEST Bootstrap Path ──────────────────────────────── */
/*
 * Handle the special CAP_REQUEST opcode that allows an agent to
 * request its initial capability set during bootstrap.  This is
 * the only path that can create capabilities without prior authority.
 */
static int phase2_cap_request(struct io_uring_cmd *ioucmd,
			     __u32 agent_id, __u64 badge)
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

	/* Full badge comparison (not just fastpath fields).
	 * READ_ONCE prevents torn reads on weakly-ordered architectures
	 * (ARM64) when airy_cap_derive() concurrently writes slot->badge
	 * under airy_cap_derive_lock (e.g. ROTATE/MUTATE/MOVE/DELETE).
	 * This mirrors Linux 6.6 io_uring's defensive READ_ONCE pattern
	 * for shared-memory reads (see io_uring.c io_get_sqe). */
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

/* ─── airy_uring_cmd_check ─────────────────────────────────────────────── */
/*
 * Slowpath capability check for io_uring_cmd IPC messages.
 *
 * Executes the five-phase protocol:
 *   1. Check if the agent ring is frozen (C-S0)
 *   2. Handle CAP_REQUEST bootstrap
 *   3. Try [DSL] degradation if compatible
 *   4. Re-check fastpath C-S9 (race resolution)
 *   5. Full slowpath enforcement
 */
int airy_uring_cmd_check(struct io_uring_cmd *ioucmd)
{
	struct task_struct *task = current;
	struct airy_task_sec *sec;
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
	 * Phase 1: C-S0 — ring frozen check
	 */
	ret = phase1_ring_frozen(sec);
	if (ret < 0)
		goto fault;

	/*
	 * Phase 2: CAP_REQUEST bootstrap path
	 *
	 * Extract badge (64-bit) and required_perms (16-bit) from the
	 * io_uring_cmd inline pdu buffer.  The pdu layout is:
	 *   bytes [0..7]   — capability badge (u64, little-endian)
	 *   bytes [8..9]   — required permission bits (u16, little-endian)
	 *   bytes [10..31] — reserved for future extension
	 */
	badge = get_unaligned_le64(&ioucmd->pdu[0]);
	required_perms = get_unaligned_le16(&ioucmd->pdu[8]);

	if (required_perms == 0) {
		/* CAP_REQUEST bootstrap: no perms required */
		return phase2_cap_request(ioucmd, agent_id, badge);
	}

	/*
	 * Phase 3: [DSL]/agentrt degradation
	 */
	if (sec->agent_state == AIRY_AGENT_STOPPED) {
		return phase3_dsl_degradation(agent_id);
	}

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
	airy_security_fault(agent_id, AIRY_FAULT_CAP_FORGED);
	return ret;
}

/* ─── airy_security_fault ──────────────────────────────────────────────── */
/*
 * Report an unrecoverable security fault for an agent.
 *
 * Increments the per-agent fault counter and logs the event.
 * In a full implementation, this triggers the die_notifier chain
 * to freeze or terminate the offending agent.
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

			/* Freeze the agent ring */
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

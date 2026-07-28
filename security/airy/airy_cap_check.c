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
	if (READ_ONCE(sec->frozen_reason) != 0)
		return -AIRY_EIPC_FROZEN;

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
	if (READ_ONCE(agent_caps[agent_id].badge) != AIRY_CAP_NULL)
		return -AIRY_ECAP_OVERFLOW;

	/* Validate the bootstrap badge against the per-agent epoch */
	if (AIRY_BADGE_EPOCH(badge) !=
	    (__u64)READ_ONCE(agent_caps[agent_id].epoch))
		return -AIRY_ECAP_EPOCH;

	/* Register the initial capability */
	return airy_cap_register(agent_id, badge);
}

/* ─── Phase 3: [DSL]/agentrt Degradation ───────────────────────────────── */
/*
 * When the [SC] shared contract fastpath is unavailable (e.g., during
 * kernel rescue mode or degraded operation), fall back to DSL POSIX
 * mapping and allow basic operations.
 */
static int phase3_dsl_degradation(__u32 agent_id)
{
	/*
	 * In degraded mode, allow all operations with reduced security.
	 * The five core POSIX codes (EINVAL, ENOMEM, EBUSY, ECANCELED,
	 * EAGAIN) map 38 POSIX codes for fallback compatibility.
	 */
	pr_warn_ratelimited("airy: agent %u operating in [DSL] degraded mode\n",
			    agent_id);
	return 0;
}

/* ─── Phase 4: Fastpath C-S9 Re-check ──────────────────────────────────── */
/*
 * Re-run the fastpath badge validation to resolve races between
 * concurrent operations (e.g., a revoke happening during slowpath).
 */
static int phase4_fastpath_recheck(__u64 badge, __u32 agent_id,
				   __u16 required_perms)
{
	return airy_cap_badge_ok(badge, agent_id, required_perms);
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

	slot = airy_cap_lookup(agent_id);
	if (!slot)
		return -AIRY_ECAP_MISSING;

	/* Full badge comparison (not just fastpath fields) */
	if (slot->badge != badge)
		return -AIRY_ECAP_FORGED;

	/* Full permission check */
	if ((slot->perms & required_perms) != required_perms)
		return -AIRY_ECAP_PERM;

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

	return 0;

fault:
	/*
	 * All phases exhausted — report security fault.
	 * The die_notifier chain will freeze/terminate the agent.
	 */
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
 */
void airy_security_fault(__u32 agent_id, __u32 fault_code)
{
	struct airy_task_sec *sec;

	pr_err("airy: security fault agent=%u code=0x%x\n",
	       agent_id, fault_code);

	if (agent_id < AIRY_CAP_MAX_AGENTS) {
		__u32 old, new;

		sec = current->security + airy_blob_sizes.lbs_task;
		/* Increment per-task fault counter if agent matches */
		do {
			old = READ_ONCE(sec->fault_count);
			new = old + 1;
		} while (cmpxchg(&sec->fault_count, old, new) != old);

		/* Freeze the agent ring */
		WRITE_ONCE(sec->frozen_reason, fault_code);
	}

	/*
	 * Notify the Airy security fault chain so the Supervisor can
	 * take out-of-band action (e.g., terminate or quarantine the
	 * offending agent).  This is separate from the kernel die_chain
	 * which handles hardware/kernel faults.
	 */
	atomic_notifier_call_chain(&airy_die_chain, fault_code, current);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_array.c — Capability slot lookup and registration.
 *
 * Provides O(1) indexed access into the static agent_caps[] array.
 * Bound-checks agent_id against AIRY_CAP_MAX_AGENTS and validates
 * slot state before returning a pointer or error.
 */

#include <linux/spinlock.h>
#include <linux/printk.h>

#include "airy_cap.h"

/*
 * Per-bucket hashed spinlock array (P2 lock-hierarchy fix).
 *
 * Defined here — the module that owns agent_caps[] also owns its locks —
 * and shared with airy_cap_derive.c via airy_cap.h.  Both register and
 * derive paths acquire the bucket lock(s) covering the slots they touch,
 * closing the TOCTOU window that existed when these two paths used
 * non-intersecting locks (register: global spinlock; derive: this bucket
 * array) and could double-write the same dst slot concurrently.
 */
spinlock_t airy_cap_bucket_locks[AIRY_CAP_BUCKET_NR] = {
	[0 ... AIRY_CAP_BUCKET_NR - 1] =
		__SPIN_LOCK_UNLOCKED(airy_cap_bucket_locks)
};

/* ─── airy_cap_lookup ──────────────────────────────────────────────────── */
/*
 * Look up a capability slot by agent ID.
 *
 * Returns a pointer to the slot on success, or NULL if agent_id is
 * out of range or the slot is empty (badge == 0).
 */
struct airy_cap_slot *airy_cap_lookup(__u32 agent_id)
{
	if (agent_id >= AIRY_CAP_MAX_AGENTS) {
		pr_debug_ratelimited("airy_cap_lookup: agent=%u out of range (MAX=%u)\n",
			agent_id, AIRY_CAP_MAX_AGENTS);
		return NULL;
	}

	if (READ_ONCE(agent_caps[agent_id].badge) == AIRY_CAP_NULL) {
		pr_debug_ratelimited("airy_cap_lookup: agent=%u slot empty (badge=NULL)\n",
			agent_id);
		return NULL;
	}

	return &agent_caps[agent_id];
}

/* ─── airy_cap_register ────────────────────────────────────────────────── */
/*
 * Register a new capability badge for an agent.
 *
 * agent_id must be in [0, AIRY_CAP_MAX_AGENTS) and the slot must be
 * currently empty (badge == 0).
 *
 * Returns 0 on success, -AIRY_ECAP_OVERFLOW if out of range,
 * -AIRY_EEXIST if the slot is already occupied.
 *
 * Locking (P2 fix): acquires the per-bucket spinlock for agent_id — the
 * SAME lock array used by airy_cap_derive().  The former global
 * airy_cap_array_lock did not intersect with derive's bucket locks, so
 * concurrent register+derive(COPY/MINT/MOVE) on the same dst slot raced
 * on the "badge == NULL then write" TOCTOU and could double-write the
 * slot.  Sharing the bucket array closes that window: both writers now
 * hold the same lock before checking+writing the slot.
 */
int airy_cap_register(__u32 agent_id, __u64 badge)
{
	unsigned long flags;
	spinlock_t *lock;

	if (agent_id >= AIRY_CAP_MAX_AGENTS) {
		pr_debug_ratelimited("airy_cap_register: agent=%u out of range (MAX=%u)\n",
			agent_id, AIRY_CAP_MAX_AGENTS);
		return -AIRY_ECAP_OVERFLOW;
	}

	lock = &airy_cap_bucket_locks[airy_cap_bucket(agent_id)];
	spin_lock_irqsave(lock, flags);

	if (agent_caps[agent_id].badge != AIRY_CAP_NULL) {
		pr_debug_ratelimited("airy_cap_register: agent=%u FAIL - slot occupied badge=0x%016llx\n",
			agent_id, (unsigned long long)agent_caps[agent_id].badge);
		spin_unlock_irqrestore(lock, flags);
		return -AIRY_EEXIST;
	}

	agent_caps[agent_id].badge    = badge;
	agent_caps[agent_id].agent_id = agent_id;
	agent_caps[agent_id].perms    = (__u16)AIRY_BADGE_PERMS(badge);
	agent_caps[agent_id].randtag  = (__u32)AIRY_BADGE_RANDTAG(badge);
	agent_caps[agent_id].epoch    = (__u16)AIRY_BADGE_EPOCH(badge);

	pr_debug_ratelimited("airy_cap_register: agent=%u OK badge=0x%016llx epoch=%u perms=0x%04x randtag=0x%08x\n",
		agent_id, (unsigned long long)badge,
		agent_caps[agent_id].epoch,
		agent_caps[agent_id].perms,
		agent_caps[agent_id].randtag);

	spin_unlock_irqrestore(lock, flags);

	return 0;
}

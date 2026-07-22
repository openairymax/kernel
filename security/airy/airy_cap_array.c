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

#include "airy_cap.h"

static DEFINE_SPINLOCK(airy_cap_array_lock);

/* ─── airy_cap_lookup ──────────────────────────────────────────────────── */
/*
 * Look up a capability slot by agent ID.
 *
 * Returns a pointer to the slot on success, or NULL if agent_id is
 * out of range or the slot is empty (badge == 0).
 */
struct airy_cap_slot *airy_cap_lookup(__u32 agent_id)
{
	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return NULL;

	if (READ_ONCE(agent_caps[agent_id].badge) == AIRY_CAP_NULL)
		return NULL;

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
 */
int airy_cap_register(__u32 agent_id, __u64 badge)
{
	unsigned long flags;

	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return -AIRY_ECAP_OVERFLOW;

	spin_lock_irqsave(&airy_cap_array_lock, flags);

	if (agent_caps[agent_id].badge != AIRY_CAP_NULL) {
		spin_unlock_irqrestore(&airy_cap_array_lock, flags);
		return -AIRY_EEXIST;
	}

	agent_caps[agent_id].badge    = badge;
	agent_caps[agent_id].agent_id = agent_id;
	agent_caps[agent_id].perms    = (__u16)AIRY_BADGE_PERMS(badge);
	agent_caps[agent_id].randtag  = (__u32)AIRY_BADGE_RANDTAG(badge);

	spin_unlock_irqrestore(&airy_cap_array_lock, flags);

	return 0;
}

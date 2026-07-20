/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_revoke.c — O(1) Capability Revocation (Airy Pure-C LSM).
 *
 * Revokes ALL agent badges globally in a single atomic increment of the
 * global epoch counter, followed by zeroing the target slot's random tag.
 * This is an O(1) operation regardless of the number of active agents.
 */

#include <linux/atomic.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/**
 * airy_cap_badge_revoke - Revoke all badges for a target agent globally.
 * @target_agent_id: The agent whose capabilities should be revoked.
 *
 * Performs O(1) global revocation:
 *   1. Atomically increments airy_cap_global_epoch, which immediately
 *      invalidates every badge that carries the old epoch value when
 *      validated by airy_cap_badge_ok().
 *   2. Zeros the target agent's capability slot random tag to prevent
 *      forgery of the new epoch badge.
 *
 * Caller must hold appropriate locking for the capability table.
 */
void airy_cap_badge_revoke(__u32 target_agent_id)
{
	if (target_agent_id >= AIRY_CAP_MAX_AGENTS)
		return;

	/*
	 * C-S4.1: Increment global epoch — O(1) atomic operation.
	 * All existing badges carrying the old epoch value become
	 * immediately invalid on the next airy_cap_badge_ok() check.
	 */
	atomic_inc(&airy_cap_global_epoch);

	/*
	 * C-S4.2: Zero the slot's random tag to prevent an attacker
	 * from reusing the old badge with the new epoch.
	 */
	WRITE_ONCE(agent_caps[target_agent_id].randtag, 0u);
}

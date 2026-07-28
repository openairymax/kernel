/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_rotate.c — Per-Agent Capability Badge Rotation (Airy Pure-C LSM).
 *
 * Per-agent epoch rotation generates a new cryptographically random
 * tag and recompiles the badge with the updated random tag, making
 * any previously issued badges invalid while preserving the epoch
 * and permission bits.
 */

#include <linux/random.h>
#include <linux/airymax/ipc.h>

#include "airy_cap.h"

/**
 * airy_cap_rotate - Rotate the capability badge for a specific agent.
 * @agent_id: The agent whose badge should be rotated.
 *
 * Reads the current capability slot, extracts the epoch and permissions,
 * generates a new random tag via get_random_u32(), recompiles the badge
 * using AIRY_BADGE_COMPILE, and writes the updated badge and random tag
 * back to the capability slot.
 *
 * This operation invalidates all previously-distributed badges for this
 * agent without affecting other agents or requiring a global epoch bump.
 *
 * Return: 0 on success, negative error code on failure.
 */
int airy_cap_rotate(__u32 agent_id)
{
	__u64 old_badge;
	__u64 epoch;
	__u16 perms;
	__u32 new_randtag;
	__u64 new_badge;

	if (agent_id >= AIRY_CAP_MAX_AGENTS)
		return -AIRY_ECAP_MISSING;

	/*
	 * C-S5.1: Read current badge from the capability slot.
	 */
	old_badge = READ_ONCE(agent_caps[agent_id].badge);

	/*
	 * C-S5.2: Extract current epoch and permissions from the old badge.
	 */
	epoch = AIRY_BADGE_EPOCH(old_badge);
	perms = (__u16)AIRY_BADGE_PERMS(old_badge);

	/*
	 * C-S5.3: Generate a new cryptographically random tag.
	 * get_random_u32() provides sufficient entropy for forgery prevention.
	 */
	new_randtag = get_random_u32();

	/*
	 * C-S5.4: Recompile the badge with the new random tag,
	 * preserving epoch and permissions.
	 */
	new_badge = AIRY_BADGE_COMPILE(epoch, new_randtag, perms);

	/*
	 * C-S5.5: Write back the new random tag first, then the new badge.
	 *
	 * Ordering rationale: the fastpath (airy_cap_badge_ok) reads
	 * slot->randtag but NOT slot->badge — it extracts randtag from
	 * the caller-supplied badge argument. Therefore:
	 *   - If we write badge first: old badge's randtag matches old
	 *     slot->randtag → old badge PASSES fastpath (BUG).
	 *   - If we write randtag first: old badge's randtag != new
	 *     slot->randtag → old badge FAILS fastpath (CORRECT).
	 *
	 * smp_store_release() ensures the randtag store is visible before
	 * the badge store on weakly-ordered architectures (ARM64, etc.),
	 * preventing the CPU from reordering the two stores.
	 */
	smp_store_release(&agent_caps[agent_id].randtag, new_randtag);
	smp_store_release(&agent_caps[agent_id].badge, new_badge);

	return 0;
}

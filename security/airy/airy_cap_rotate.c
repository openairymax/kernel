/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_rotate.c — Per-Agent Capability Badge Rotation (Airy Pure-C LSM).
 *
 * Thin wrapper around airy_cap_derive(AIRY_CAP_OP_ROTATE) to provide
 * a self-documenting public API for badge rotation.  All actual work
 * (random tag generation, smp_store_release ordering, epoch/perms
 * preservation) is performed under airy_cap_derive_lock inside
 * airy_cap_derive.c, ensuring atomicity relative to concurrent
 * derivation operations on the same slot.
 */

#include <linux/airymax/security_types.h>
#include <linux/airymax/error.h>
#include <linux/printk.h>

#include "airy_cap.h"

/**
 * airy_cap_rotate - Rotate the capability badge for a specific agent.
 * @agent_id: The agent whose badge should be rotated.
 *
 * Delegates to airy_cap_derive(agent_id, agent_id, AIRY_CAP_OP_ROTATE, 0)
 * which acquires airy_cap_derive_lock and performs the rotation atomically.
 *
 * This operation invalidates all previously-distributed badges for this
 * agent without affecting other agents or requiring a global epoch bump.
 *
 * Return: 0 on success, negative error code on failure.
 */
int airy_cap_rotate(__u32 agent_id)
{
	pr_debug_ratelimited("airy_cap_rotate: agent=%u delegating to airy_cap_derive(ROTATE)\n",
		agent_id);
	return airy_cap_derive(agent_id, agent_id, AIRY_CAP_OP_ROTATE, 0);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_init.c — Capability global state definition and zeroisation.
 *
 * Defines the 1024-entry agent_caps[] array (cacheline-aligned,
 * __ro_after_init pointer target) and the global epoch counter.
 * airy_cap_agent_caps_init() zeroes all slots and resets epoch to 1
 * so that badge epoch 0 is always invalid.
 */

#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/errno.h>

#include "airy_cap.h"

/* ─── Global Capability Array ──────────────────────────────────────────── */
/*
 * agent_caps — 1024 capability slots, each 64-byte cacheline-aligned.
 * The pointer itself is __ro_after_init; the pointed-to array may be
 * modified (slots are updated at runtime).
 */
static struct airy_cap_slot __airymax_cap_table[AIRY_CAP_MAX_AGENTS]
	__aligned(64);

struct airy_cap_slot *agent_caps __ro_after_init = __airymax_cap_table;

/* ─── Global Epoch ─────────────────────────────────────────────────────── */
atomic_t airy_cap_global_epoch;

/* ─── airy_cap_agent_caps_init ─────────────────────────────────────────── */
/*
 * Zero all 1024 capability slots and set the global epoch to 1.
 * Epoch 0 is reserved to represent "invalid/never-valid" badges.
 */
void airy_cap_agent_caps_init(void)
{
	int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		agent_caps[i].badge    = 0;
		agent_caps[i].agent_id = 0;
		agent_caps[i].flags    = 0;
		agent_caps[i].randtag  = 0;
		agent_caps[i].perms    = 0;
		agent_caps[i]._pad     = 0;
	}

	atomic_set(&airy_cap_global_epoch, 1);
}

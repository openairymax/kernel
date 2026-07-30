// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_capability.c — Capability Folding global state and slowpath.
 *
 * This file is always compiled (obj-y) and provides the authoritative
 * definition of agent_caps[] and airy_cap_global_epoch.  When
 * CONFIG_SECURITY_AIRY=y, security/airy/ provides the full LSM hooks
 * and capability derivation operations on top of this state.
 */

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"

/* ─── Global Capability Array (authoritative definition) ─────────────── */
/*
 * agent_caps — 1024 capability slots, each 128-byte cacheline-aligned.
 * The pointer itself is __ro_after_init; the pointed-to array may be
 * modified at runtime by sec_d (the sole writer).
 */
static struct airy_cap_slot __airymax_cap_table[AIRY_CAP_MAX_AGENTS]
	AIRY_ALIGNED(64);

struct airy_cap_slot *agent_caps __ro_after_init = __airymax_cap_table;

/* ─── Global Epoch (authoritative definition) ────────────────────────── */
atomic_t airy_cap_global_epoch;

/* ─── Capability Initialization ──────────────────────────────────────── */
void airy_cap_agent_caps_init(void)
{
	int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		agent_caps[i].badge    = 0;
		agent_caps[i].agent_id = 0;
		agent_caps[i].flags    = 0;
		agent_caps[i].randtag  = 0;
		agent_caps[i].perms    = 0;
		agent_caps[i].epoch    = 1;
	}

	atomic_set(&airy_cap_global_epoch, 1);
}

/* ─── Slowpath badge verification (wrapper around airy_cap_badge_ok) ─── */
int airy_cap_badge_verify(u64 badge, u32 agent_id, __u16 expected_perms)
{
	return airy_cap_badge_ok(badge, agent_id, expected_perms);
}

/* ─── O(1) targeted revocation: bump per-agent epoch ────────────────── */
u64 airy_cap_epoch_bump(u32 agent_id)
{
	__u16 new_epoch;

	if (unlikely(agent_id >= AIRY_CAP_MAX_AGENTS))
		return 0;

	new_epoch = READ_ONCE(agent_caps[agent_id].epoch) + 1;
	WRITE_ONCE(agent_caps[agent_id].epoch, new_epoch);
	return (__u64)new_epoch;
}

/* ─── O(N) global revocation: bump all per-agent epochs (UNFREEZE) ──── */
void airy_cap_epoch_bump_all(void)
{
	int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		__u16 e = READ_ONCE(agent_caps[i].epoch) + 1;
		WRITE_ONCE(agent_caps[i].epoch, e);
	}

	atomic_inc(&airy_cap_global_epoch);
}

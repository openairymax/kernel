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
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "airy_ipc_capability.h"

/* ─── Global Capability Array (authoritative definition) ─────────────── */
/*
 * agent_caps — 1024 capability slots, each 64-byte cacheline-aligned
 * (AIRY_ALIGNED(64); sizeof(struct airy_cap_slot) == 128 bytes due to
 * content 80 + alignment padding to next multiple of 64).
 * The pointer itself is __ro_after_init; the pointed-to array may be
 * modified at runtime by sec_d (the sole writer).
 */
static struct airy_cap_slot __airymax_cap_table[AIRY_CAP_MAX_AGENTS]
	AIRY_ALIGNED(64);

struct airy_cap_slot *agent_caps __ro_after_init = __airymax_cap_table;

/* ─── Global Epoch (authoritative definition) ────────────────────────── */
atomic_t airy_cap_global_epoch;

/* ─── Paranoid Mode (SSoT 110-security/07 §12.2.3) ───────────────────── */
/*
 * airy_security_paranoid — serialize fastpath badge checks with a
 * speculation fence.  Defined next to agent_caps[] because that array
 * (and the badge check reading it) belongs to this translation unit;
 * CONFIG_SECURITY_AIRY selects AIRY_IPC, so the LSM shares this one
 * definition instead of carrying a duplicate.  __read_mostly (not
 * __ro_after_init) so KUnit can exercise both branches; the sysfs
 * attribute is 0444, i.e. boot-time only in production.
 */
bool airy_security_paranoid __read_mostly;
module_param_named(security_paranoid, airy_security_paranoid, bool, 0444);
MODULE_PARM_DESC(security_paranoid,
		 "Serialize fastpath badge checks with a speculation fence (default: false)");

/* ─── Capability Initialization ──────────────────────────────────────── */
/*
 * Reset the whole table to the pristine boot state.  The slot is
 * zeroed in full rather than field by field so that the MDB link
 * fields (parent_agent / first_child / next_sibling / generation /
 * revocable) cannot survive a re-initialisation and graft stale tree
 * edges onto freshly registered agents.  epoch starts at 1 because a
 * zero badge field and epoch 0 would make a forged badge with epoch 0
 * indistinguishable from an empty slot.
 */
void airy_cap_agent_caps_init(void)
{
	int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		memset(&agent_caps[i], 0, sizeof(agent_caps[i]));
		agent_caps[i].epoch = 1;
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

	new_epoch = airy_epoch_next(READ_ONCE(agent_caps[agent_id].epoch));
	WRITE_ONCE(agent_caps[agent_id].epoch, new_epoch);
	return (__u64)new_epoch;
}

/* ─── O(N) global revocation: bump all per-agent epochs (UNFREEZE) ──── */
void airy_cap_epoch_bump_all(void)
{
	int i;

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++)
		WRITE_ONCE(agent_caps[i].epoch,
			   airy_epoch_next(READ_ONCE(agent_caps[i].epoch)));

	atomic_inc(&airy_cap_global_epoch);
}

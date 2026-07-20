/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_capability.h — IPC entry-side Capability Folding fastpath.
 *
 * Declares airy_cap_badge_verify() / airy_cap_epoch_bump() and provides
 * airy_cap_badge_ok_fast() as a static inline fastpath.  This is the
 * IPC entry-side counterpart of security/airy/airy_cap.h's
 * airy_cap_badge_ok(): semantically consistent but maintaining its own
 * per-agent slot table so the IPC fastpath can be specialised without
 * coupling to the LSM blob layout.
 */

#ifndef _AIRY_IPC_CAPABILITY_H
#define _AIRY_IPC_CAPABILITY_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/airymax/ipc.h>

/* ─── IPC-side capability slot table ──────────────────────────────────── */
#define AIRY_IPC_CAP_MAX_AGENTS		1024

struct airy_ipc_cap_slot {
	__u16	epoch;		/* 16-bit epoch matching badge layout */
	__u16	perms;		/* permission bitmask (AIRY_CAP_PERM_*) */
	__u32	randtag;	/* 32-bit random tag for forgery prevention */
} __aligned(SMP_CACHE_BYTES);

extern struct airy_ipc_cap_slot
	airy_ipc_cap_slots[AIRY_IPC_CAP_MAX_AGENTS] __cacheline_aligned;

/* ─── Slowpath (defined in airy_ipc_capability.c) ─────────────────────── */
bool airy_cap_badge_verify(u64 badge, u32 agent_id, u64 expected_perms);
u64  airy_cap_epoch_bump(void);

/* ─── Fastpath inline: 3 READ_ONCE + bit operations (~10ns) ──────────── */
/*
 * airy_cap_badge_ok_fast — fastpath badge validation for the IPC entry.
 *
 * Performs 3 READ_ONCE from the cacheline-aligned slot (epoch, randtag,
 * perms) and bitwise permission checks.  Does NOT consult the global
 * revocation epoch — callers that need O(1) revocation must additionally
 * invoke airy_cap_badge_verify() on the slow path.
 *
 * Returns true if the badge is well-formed and matches the slot.
 */
static inline bool airy_cap_badge_ok_fast(u64 badge, u32 agent_id,
					  u64 expected_perms)
{
	__u16 slot_epoch;
	__u16 slot_perms;
	__u32 slot_randtag;

	if (unlikely(agent_id >= AIRY_IPC_CAP_MAX_AGENTS))
		return false;

	/* 3 READ_ONCE from the cacheline-aligned slot */
	slot_epoch   = READ_ONCE(airy_ipc_cap_slots[agent_id].epoch);
	slot_randtag = READ_ONCE(airy_ipc_cap_slots[agent_id].randtag);
	slot_perms   = READ_ONCE(airy_ipc_cap_slots[agent_id].perms);

	/* Epoch check (per-slot) */
	if (AIRY_BADGE_EPOCH(badge) != (__u64)slot_epoch)
		return false;

	/* RandomTag check (forgery prevention) */
	if (AIRY_BADGE_RANDTAG(badge) != (__u64)slot_randtag)
		return false;

	/* Permission check: both badge and slot must grant the perms */
	if ((AIRY_BADGE_PERMS(badge) & expected_perms) != expected_perms)
		return false;
	if (((__u64)slot_perms & expected_perms) != expected_perms)
		return false;

	return true;
}

#endif /* _AIRY_IPC_CAPABILITY_H */

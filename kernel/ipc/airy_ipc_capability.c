/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_capability.c — IPC entry-side Capability Folding backend.
 *
 * Provides the slowpath badge verifier (airy_cap_badge_verify) which
 * adds the global revocation epoch check on top of the fastpath slot
 * lookup, and airy_cap_epoch_bump() which O(1)-revokes every badge
 * minted under the previous epoch by incrementing a single atomic64.
 */

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "airy_ipc_capability.h"

/* ─── Per-agent slot table (cacheline-aligned, zero-initialised BSS) ──── */
struct airy_ipc_cap_slot
	airy_ipc_cap_slots[AIRY_IPC_CAP_MAX_AGENTS] __cacheline_aligned;

/* ─── Global revocation epoch ─────────────────────────────────────────── */
/*
 * Single atomic64 counter; minting copies the low 16 bits into the
 * badge's Epoch field.  Bumping this counter invalidates every badge
 * minted under any previous epoch in O(1) time.
 */
static atomic64_t airy_cap_global_epoch = ATOMIC64_INIT(1);

/* ─── Slowpath badge verification ─────────────────────────────────────── */
/*
 * @badge:           64-bit Capability Folding badge.
 * @agent_id:        target agent slot index.
 * @expected_perms:  bitmask of AIRY_CAP_PERM_* the caller requires.
 *
 * Returns true iff:
 *   1. agent_id is in range,
 *   2. the badge's epoch matches both the per-slot epoch and the
 *      current global revocation epoch,
 *   3. the badge's random tag matches the slot's stored tag,
 *   4. both the badge and the slot grant every requested permission.
 */
bool airy_cap_badge_verify(u64 badge, u32 agent_id, u64 expected_perms)
{
	__u16 slot_epoch;
	__u16 slot_perms;
	__u32 slot_randtag;
	__u64 global_epoch;
	__u64 badge_epoch;
	__u64 badge_randtag;
	__u64 badge_perms;

	if (agent_id >= AIRY_IPC_CAP_MAX_AGENTS)
		return false;

	/* 3 READ_ONCE from the cacheline-aligned slot */
	slot_epoch   = READ_ONCE(airy_ipc_cap_slots[agent_id].epoch);
	slot_randtag = READ_ONCE(airy_ipc_cap_slots[agent_id].randtag);
	slot_perms   = READ_ONCE(airy_ipc_cap_slots[agent_id].perms);

	/* Atomic read of the global revocation epoch */
	global_epoch = (__u64)atomic64_read(&airy_cap_global_epoch);

	badge_epoch   = AIRY_BADGE_EPOCH(badge);
	badge_randtag = AIRY_BADGE_RANDTAG(badge);
	badge_perms   = AIRY_BADGE_PERMS(badge);

	/* Epoch check: badge epoch must match both the slot and the
	 * current global epoch (catches O(1) revocation). */
	if (badge_epoch != (__u64)slot_epoch)
		return false;
	if (badge_epoch != (global_epoch & 0xFFFFULL))
		return false;

	/* RandomTag check (forgery prevention) */
	if (badge_randtag != (__u64)slot_randtag)
		return false;

	/* Permission check: both badge and slot must grant the perms */
	if ((badge_perms & expected_perms) != expected_perms)
		return false;
	if (((__u64)slot_perms & expected_perms) != expected_perms)
		return false;

	return true;
}

/* ─── O(1) revocation: bump the global epoch ──────────────────────────── */
u64 airy_cap_epoch_bump(void)
{
	return (__u64)atomic64_inc_return(&airy_cap_global_epoch);
}

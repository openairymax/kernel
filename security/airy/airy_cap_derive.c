// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_derive.c — seL4-style CNode 7 derivation operations.
 *
 * Implements airy_cap_derive() which dispatches to one of seven
 * capability derivation operations: copy, mint, move, mutate,
 * revoke, delete, rotate.
 *
 * All operations are performed under the assumption that the caller
 * holds the appropriate authority (validated by the fastpath or
 * slowpath before reaching this point).
 */

#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/compiler.h>

#include <airymax/security_types.h>
#include <airymax/error.h>

#include "airy_cap.h"

/* ─── airy_cap_derive ──────────────────────────────────────────────────── */
/*
 * Dispatch capability derivation operation.
 *
 * src_agent  — source agent ID (slot index)
 * dst_agent  — destination agent ID (slot index)
 * op         — one of enum airy_cap_op
 * new_perms  — new permission mask (used by copy, mint, mutate)
 *
 * Returns 0 on success, negative airy_err_t on failure.
 */
int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
		    enum airy_cap_op op, __u16 new_perms)
{
	struct airy_cap_slot *src, *dst;
	__u64 epoch, randtag;
	__u16 perms;

	/* Validate source for all operations except revoke (global) */
	if (op != AIRY_CAP_OP_REVOKE) {
		src = airy_cap_lookup(src_agent);
		if (!src)
			return -AIRY_ECAP_MISSING;
	}

	switch (op) {
	/* ─── COPY ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_COPY:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS)
			return -AIRY_ECAP_OVERFLOW;
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL)
			return -AIRY_EEXIST;

		/* Copy badge unchanged (no demotion) */
		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;
		break;

	/* ─── MINT ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MINT:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS)
			return -AIRY_ECAP_OVERFLOW;
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL)
			return -AIRY_EEXIST;

		/* Mint new badge with potentially reduced permissions */
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;
		perms   = new_perms & src->perms;  /* may demote */

		dst->badge    = AIRY_BADGE_MAKE(epoch, randtag, perms);
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = perms;
		break;

	/* ─── MOVE ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MOVE:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS)
			return -AIRY_ECAP_OVERFLOW;
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL)
			return -AIRY_EEXIST;

		/* Transfer badge, invalidate source */
		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;

		/* Invalidate source slot */
		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		break;

	/* ─── MUTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MUTATE:
		/* Modify permissions of existing badge in-place */
		epoch = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;

		WRITE_ONCE(src->badge, AIRY_BADGE_MAKE(epoch, randtag,
						       new_perms));
		WRITE_ONCE(src->perms, new_perms);
		break;

	/* ─── REVOKE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_REVOKE:
		/*
		 * Global epoch invalidation: incrementing the epoch
		 * instantly invalidates all existing badges.
		 * The fastpath C-S9.1 will reject any badge whose
		 * epoch != global_epoch.
		 */
		atomic_inc(&airy_cap_global_epoch);
		break;

	/* ─── DELETE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_DELETE:
		/* Clear the source slot */
		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		break;

	/* ─── ROTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_ROTATE: {
		__u32 new_tag;

		/* Generate cryptographically random tag */
		new_tag = get_random_u32();
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		perms   = src->perms;

		WRITE_ONCE(src->badge, AIRY_BADGE_MAKE(epoch, new_tag,
						       perms));
		WRITE_ONCE(src->randtag, new_tag);
		break;
	}

	default:
		return -AIRY_EINVAL;
	}

	return 0;
}

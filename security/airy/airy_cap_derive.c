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
#include <linux/spinlock.h>
#include <linux/printk.h>

#include <linux/airymax/security_types.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

static DEFINE_SPINLOCK(airy_cap_derive_lock);

/* Operation names for logging */
static const char *const cap_op_names[] = {
	"COPY", "MINT", "MOVE", "MUTATE", "REVOKE", "DELETE", "ROTATE"
};

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
 *
 * The entire operation runs under airy_cap_derive_lock to close the
 * TOCTOU window between slot-state checks (empty/valid) and the
 * subsequent writes. get_random_u32() and atomic_inc() are
 * non-sleeping and safe under the spinlock.
 */
int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
		    enum airy_cap_op op, __u16 new_perms)
{
	struct airy_cap_slot *src, *dst;
	__u64 epoch, randtag;
	__u16 perms;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&airy_cap_derive_lock, flags);

	pr_info("airy_cap_derive: ENTER op=%s(%u) src=%u dst=%u new_perms=0x%04x\n",
		op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, src_agent, dst_agent, new_perms);

	/* Validate source slot for all operations.  REVOKE needs the
	 * slot to increment its per-agent epoch (K9-1 changed REVOKE
	 * from global epoch to per-agent epoch, making src mandatory). */
	src = airy_cap_lookup(src_agent);
	if (!src) {
		pr_info("airy_cap_derive: op=%s FAIL - src agent %u not found\n",
			op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
			src_agent);
		ret = -AIRY_ECAP_MISSING;
		goto out;
	}

	switch (op) {
	/* ─── COPY ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_COPY:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_info("airy_cap_derive: COPY FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_info("airy_cap_derive: COPY FAIL - dst %u occupied badge=0x%016llx\n",
				dst_agent, (unsigned long long)dst->badge);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/* Copy badge unchanged (no demotion) */
		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;
		dst->epoch    = src->epoch;
		pr_info("airy_cap_derive: COPY src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x\n",
			src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch, dst->perms);
		break;

	/* ─── MINT ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MINT:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_info("airy_cap_derive: MINT FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_info("airy_cap_derive: MINT FAIL - dst %u occupied\n",
				dst_agent);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/* Mint new badge with potentially reduced permissions */
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;
		perms   = new_perms & src->perms;  /* may demote */

		dst->badge    = AIRY_BADGE_COMPILE(epoch, randtag, perms);
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = perms;
		dst->epoch    = src->epoch;
		pr_info("airy_cap_derive: MINT src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x (demoted from 0x%04x)\n",
			src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch,
			dst->perms, src->perms);
		break;

	/* ─── MOVE ──────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MOVE:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_info("airy_cap_derive: MOVE FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_info("airy_cap_derive: MOVE FAIL - dst %u occupied\n",
				dst_agent);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/* Transfer badge, invalidate source */
		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;
		dst->epoch    = src->epoch;

		/* Invalidate source slot */
		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		WRITE_ONCE(src->epoch, 0);
		pr_info("airy_cap_derive: MOVE src=%u→dst=%u badge=0x%016llx epoch=%u (src invalidated)\n",
			src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch);
		break;

	/* ─── MUTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MUTATE:
		/* Modify permissions of existing badge in-place */
		epoch = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;

		WRITE_ONCE(src->badge, AIRY_BADGE_COMPILE(epoch, randtag,
						       new_perms));
		WRITE_ONCE(src->perms, new_perms);
		pr_info("airy_cap_derive: MUTATE agent=%u perms 0x%04x→0x%04x badge=0x%016llx\n",
			src_agent, src->perms, new_perms,
			(unsigned long long)AIRY_BADGE_COMPILE(epoch, randtag, new_perms));
		break;

	/* ─── REVOKE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_REVOKE:
		/*
		 * Per-agent epoch invalidation: incrementing only the
		 * target slot's epoch instantly invalidates that agent's
		 * existing badges without affecting other agents.
		 * The fastpath C-S9.1 will reject any badge whose
		 * epoch != slot epoch.
		 */
		{
			__u16 old_epoch = READ_ONCE(src->epoch);
			__u16 new_epoch_val = old_epoch + 1;
			WRITE_ONCE(src->epoch, new_epoch_val);
			WRITE_ONCE(src->randtag, 0);
			pr_info("airy_cap_derive: REVOKE agent=%u epoch %u→%u (all badges invalidated)\n",
				src_agent, old_epoch, new_epoch_val);
		}
		break;

	/* ─── DELETE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_DELETE:
		/* Clear the source slot entirely, including epoch */
		pr_info("airy_cap_derive: DELETE agent=%u badge=0x%016llx epoch=%u (clearing slot)\n",
			src_agent, (unsigned long long)src->badge,
			READ_ONCE(src->epoch));
		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		WRITE_ONCE(src->epoch, 0);
		break;

	/* ─── ROTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_ROTATE: {
		__u32 new_tag;

		/* Generate cryptographically random tag */
		new_tag = get_random_u32();
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		perms   = src->perms;

		pr_info("airy_cap_derive: ROTATE agent=%u old_tag=0x%08x→new_tag=0x%08x epoch=%u perms=0x%04x\n",
			src_agent, src->randtag, new_tag,
			(__u16)epoch, perms);

		/* Write randtag first, then badge — see airy_cap_rotate.c
		 * C-S5.5 for ordering rationale. smp_store_release prevents
		 * store-store reordering on weakly-ordered architectures. */
		smp_store_release(&src->randtag, new_tag);
		smp_store_release(&src->badge,
				  AIRY_BADGE_COMPILE(epoch, new_tag, perms));
		break;
	}

	default:
		pr_warn("airy_cap_derive: UNKNOWN op=%u src=%u dst=%u\n",
			op, src_agent, dst_agent);
		ret = -AIRY_EINVAL;
		break;
	}

out:
	pr_info("airy_cap_derive: EXIT op=%s(%u) ret=%d\n",
		op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, ret);
	spin_unlock_irqrestore(&airy_cap_derive_lock, flags);
	return ret;
}

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
 * MDB derivation tree (K9-1 fix): COPY/MINT/MOVE maintain a
 * left-child right-sibling tree via parent_agent/first_child/
 * next_sibling fields.  REVOKE cascades along this tree, providing
 * seL4-aligned recursive revocation semantics.  COPY supports
 * optional permission demotion when new_perms != 0 (P1-10 fix).
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

/* ─── MDB tree maintenance helpers ──────────────────────────────────── */

/*
 * Link dst as a child of src in the MDB derivation tree.
 * Uses left-child right-sibling representation:
 *   - If src has no first_child, dst becomes first_child.
 *   - Otherwise, dst is prepended to the sibling chain.
 */
static void airy_cap_mdb_link_child(struct airy_cap_slot *src,
				    struct airy_cap_slot *dst,
				    __u32 src_agent, __u32 dst_agent)
{
	__u32 old_first_child = READ_ONCE(src->first_child);

	dst->parent_agent  = src_agent;
	dst->generation    = READ_ONCE(src->generation) + 1;
	dst->revocable     = 1;  /* Default: parent REVOKE cascades */
	dst->next_sibling  = old_first_child;
	WRITE_ONCE(src->first_child, dst_agent);
}

/*
 * Unlink agent_id from its parent's child chain (for DELETE/MOVE).
 * Walks the sibling list starting from parent's first_child.
 */
static void airy_cap_mdb_unlink_child(__u32 agent_id)
{
	struct airy_cap_slot *slot = &agent_caps[agent_id];
	__u32 parent_id = READ_ONCE(slot->parent_agent);
	struct airy_cap_slot *parent;
	__u32 cur, *prev_ptr;

	if (parent_id == 0)
		return;  /* Root node, no parent to unlink from */

	parent = &agent_caps[parent_id];
	prev_ptr = &parent->first_child;
	cur = READ_ONCE(*prev_ptr);

	while (cur != 0 && cur != agent_id) {
		struct airy_cap_slot *cur_slot = &agent_caps[cur];
		prev_ptr = &cur_slot->next_sibling;
		cur = READ_ONCE(*prev_ptr);
	}

	if (cur == agent_id)
		WRITE_ONCE(*prev_ptr, READ_ONCE(slot->next_sibling));

	WRITE_ONCE(slot->parent_agent, 0);
	WRITE_ONCE(slot->next_sibling, 0);
}

/*
 * Recursive cascading revocation (K9-1 fix, seL4 CNode alignment).
 * Walks the MDB derivation tree from the given agent, incrementing
 * epoch and clearing randtag for every revocable descendant.
 *
 * Complexity: O(N) where N = subtree size.  Typical depth ≤ 3.
 */
static void airy_cap_revoke_subtree(__u32 agent_id, __u16 new_epoch)
{
	struct airy_cap_slot *slot = &agent_caps[agent_id];
	__u32 child = READ_ONCE(slot->first_child);

	/* Invalidate this slot */
	WRITE_ONCE(slot->epoch, new_epoch);
	WRITE_ONCE(slot->randtag, 0);

	/* Recursively revoke all revocable children */
	while (child != 0) {
		struct airy_cap_slot *child_slot = &agent_caps[child];

		if (READ_ONCE(child_slot->revocable))
			airy_cap_revoke_subtree(child, new_epoch);

		child = READ_ONCE(child_slot->next_sibling);
	}
}

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
 * non-blocking and safe under the spinlock.
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

	pr_debug_ratelimited("airy_cap_derive: ENTER op=%s(%u) src=%u dst=%u new_perms=0x%04x\n",
		op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, src_agent, dst_agent, new_perms);

	/* Validate source slot for all operations.  REVOKE needs the
	 * slot to increment its epoch (K9-1 changed REVOKE to cascading
	 * via MDB tree, src is the root of the revocation subtree). */
	src = airy_cap_lookup(src_agent);
	if (!src) {
		pr_debug_ratelimited("airy_cap_derive: op=%s FAIL - src agent %u not found\n",
			op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
			src_agent);
		ret = -AIRY_ECAP_MISSING;
		goto out;
	}

	switch (op) {
	/* ─── COPY (optional demotion, P1-10 fix) ─────────────────── */
	case AIRY_CAP_OP_COPY:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("airy_cap_derive: COPY FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("airy_cap_derive: COPY FAIL - dst %u occupied badge=0x%016llx\n",
				dst_agent, (unsigned long long)dst->badge);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/*
		 * Copy badge with optional permission demotion (P1-10 fix).
		 * new_perms == 0: clone unchanged (backward compatible)
		 * new_perms != 0: intersect with source perms (seL4 maskCapRights)
		 */
		if (new_perms != 0)
			perms = new_perms & src->perms;
		else
			perms = src->perms;

		epoch   = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;
		dst->badge    = AIRY_BADGE_COMPILE(epoch, randtag, perms);
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = perms;
		dst->epoch    = src->epoch;

		/* MDB tree: link dst as child of src */
		airy_cap_mdb_link_child(src, dst, src_agent, dst_agent);

		pr_debug_ratelimited("airy_cap_derive: COPY src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x (parent=%u gen=%u)\n",
			src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch, dst->perms,
			dst->parent_agent, dst->generation);
		break;

	/* ─── MINT (always demotes, maintains MDB tree) ────────────── */
	case AIRY_CAP_OP_MINT:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("airy_cap_derive: MINT FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("airy_cap_derive: MINT FAIL - dst %u occupied\n",
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

		/* MDB tree: link dst as child of src */
		airy_cap_mdb_link_child(src, dst, src_agent, dst_agent);

		pr_debug_ratelimited("airy_cap_derive: MINT src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x (demoted from 0x%04x parent=%u gen=%u)\n",
			src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch,
			dst->perms, src->perms, dst->parent_agent, dst->generation);
		break;

	/* ─── MOVE (transfer + unlink from parent) ─────────────────── */
	case AIRY_CAP_OP_MOVE:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("airy_cap_derive: MOVE FAIL - dst %u >= MAX %u\n",
				dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("airy_cap_derive: MOVE FAIL - dst %u occupied\n",
				dst_agent);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/* Transfer badge */
		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;
		dst->epoch    = src->epoch;

		/* MDB tree: unlink src, link dst as child of src's parent */
		airy_cap_mdb_unlink_child(src_agent);
		if (src->parent_agent != 0) {
			struct airy_cap_slot *parent = &agent_caps[src->parent_agent];
			airy_cap_mdb_link_child(parent, dst,
						src->parent_agent, dst_agent);
		}

		/* Invalidate source slot */
		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		WRITE_ONCE(src->epoch, 0);
		WRITE_ONCE(src->parent_agent, 0);
		WRITE_ONCE(src->first_child, 0);
		WRITE_ONCE(src->next_sibling, 0);
		WRITE_ONCE(src->generation, 0);
		WRITE_ONCE(src->revocable, 0);

		pr_debug_ratelimited("airy_cap_derive: MOVE src=%u→dst=%u badge=0x%016llx epoch=%u (src invalidated, MDB re-linked)\n",
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
		pr_debug_ratelimited("airy_cap_derive: MUTATE agent=%u perms 0x%04x→0x%04x badge=0x%016llx\n",
			src_agent, src->perms, new_perms,
			(unsigned long long)AIRY_BADGE_COMPILE(epoch, randtag, new_perms));
		break;

	/* ─── REVOKE (cascading via MDB tree, K9-1 fix) ────────────── */
	case AIRY_CAP_OP_REVOKE:
		/*
		 * Cascading revocation (seL4 CNode cteRevoke alignment):
		 * Increment epoch and clear randtag for the target slot
		 * AND all revocable descendants in the MDB derivation tree.
		 * This ensures that when a parent capability is revoked,
		 * all derived capabilities are also invalidated.
		 *
		 * The fastpath C-S9.1 will reject any badge whose
		 * epoch != slot epoch, so all descendants' badges become
		 * invalid immediately.
		 */
		{
			__u16 old_epoch = READ_ONCE(src->epoch);
			__u16 new_epoch_val = old_epoch + 1;

			airy_cap_revoke_subtree(src_agent, new_epoch_val);

			pr_debug_ratelimited("airy_cap_derive: REVOKE agent=%u epoch %u→%u (cascading, all descendants invalidated)\n",
				src_agent, old_epoch, new_epoch_val);
		}
		break;

	/* ─── DELETE (unlink from MDB tree, clear slot) ────────────── */
	case AIRY_CAP_OP_DELETE:
		pr_debug_ratelimited("airy_cap_derive: DELETE agent=%u badge=0x%016llx epoch=%u (clearing slot)\n",
			src_agent, (unsigned long long)src->badge,
			READ_ONCE(src->epoch));

		/* MDB tree: unlink from parent's child chain */
		airy_cap_mdb_unlink_child(src_agent);

		WRITE_ONCE(src->badge, AIRY_CAP_NULL);
		WRITE_ONCE(src->agent_id, 0);
		WRITE_ONCE(src->flags, 0);
		WRITE_ONCE(src->randtag, 0);
		WRITE_ONCE(src->perms, 0);
		WRITE_ONCE(src->epoch, 0);
		WRITE_ONCE(src->parent_agent, 0);
		WRITE_ONCE(src->first_child, 0);
		WRITE_ONCE(src->next_sibling, 0);
		WRITE_ONCE(src->generation, 0);
		WRITE_ONCE(src->revocable, 0);
		break;

	/* ─── ROTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_ROTATE: {
		__u32 new_tag;

		/* Generate cryptographically random tag */
		new_tag = get_random_u32();
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		perms   = src->perms;

		pr_debug_ratelimited("airy_cap_derive: ROTATE agent=%u old_tag=0x%08x→new_tag=0x%08x epoch=%u perms=0x%04x\n",
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
	pr_debug_ratelimited("airy_cap_derive: EXIT op=%s(%u) ret=%d\n",
		op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, ret);
	spin_unlock_irqrestore(&airy_cap_derive_lock, flags);
	return ret;
}

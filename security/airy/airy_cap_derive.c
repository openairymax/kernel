// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_derive.c — seL4-style CNode capability derivation.
 *
 * Dispatches airy_cap_derive() to seven operations: copy, mint, move,
 * mutate, revoke, delete, rotate. COPY/MINT/MOVE/DELETE maintain a
 * left-child right-sibling MDB tree; REVOKE cascades along it. MOVE
 * carries the derived subtree, DELETE promotes the children to roots. A
 * 64-bucket hashed spinlock array replaces the former global lock.
 *
 * Design rationale: docs/AirymaxOS/110-security/03-capability-model.md
 */

#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/printk.h>

#include <linux/airymax/security_types.h>
#include <linux/airymax/error.h>

#include "airy_cap.h"

/*
 * Fine-grained per-bucket lock array (P1-11 fix, P2 shared with register).
 *
 * The lock array airy_cap_bucket_locks[] and airy_cap_bucket() are defined
 * in airy_cap_array.c and shared via airy_cap.h so that BOTH
 * airy_cap_register() and airy_cap_derive() acquire the same per-bucket
 * locks.  This closes the TOCTOU window across the register/derive
 * boundary (P2 fix): previously register used a separate global spinlock
 * that did not intersect with these bucket locks.
 *
 * Agent IDs are mapped to buckets via a bitmask, so operations on
 * disjoint agent sets proceed concurrently.  COPY/MINT acquire the src
 * and dst buckets in canonical ascending order to avoid deadlock.
 * REVOKE, MOVE and DELETE acquire all 64 locks because the subtree and
 * the parent/child chain may span arbitrary buckets.
 */

/*
 * Lock context for multi-bucket acquisition.  Acquires up to 2 bucket
 * locks in canonical (ascending pointer) order.  The first (outermost)
 * lock saves+disables IRQs via spin_lock_irqsave; inner locks use
 * plain spin_lock since IRQs are already disabled.  Duplicate buckets
 * (two agents hashing to the same bucket) are acquired only once.
 */
struct cap_derive_lock_ctx {
	spinlock_t	*locks[2];
	unsigned long	flags;
	int		n;
};

static void cap_derive_lock_begin(struct cap_derive_lock_ctx *ctx)
{
	ctx->n = 0;
}

static void cap_derive_lock_add(struct cap_derive_lock_ctx *ctx,
				__u32 agent_id)
{
	spinlock_t *lock = &airy_cap_bucket_locks[airy_cap_bucket(agent_id)];
	int i, pos;

	/* Skip if this bucket is already held */
	for (i = 0; i < ctx->n; i++)
		if (ctx->locks[i] == lock)
			return;

	/* Find sorted insertion position (ascending lock address) */
	pos = ctx->n;
	for (i = 0; i < ctx->n; i++) {
		if (ctx->locks[i] > lock) {
			pos = i;
			break;
		}
	}

	/* Shift entries right to make room */
	for (i = ctx->n; i > pos; i--)
		ctx->locks[i] = ctx->locks[i - 1];

	if (ctx->n == 0)
		spin_lock_irqsave(lock, ctx->flags);
	else
		spin_lock(lock);	/* IRQs already disabled */

	ctx->locks[pos] = lock;
	ctx->n++;
}

static void cap_derive_lock_end(struct cap_derive_lock_ctx *ctx)
{
	int i;

	/* Release in reverse acquisition order */
	for (i = ctx->n - 1; i > 0; i--)
		spin_unlock(ctx->locks[i]);
	if (ctx->n > 0)
		spin_unlock_irqrestore(ctx->locks[0], ctx->flags);
}

/*
 * Acquire ALL bucket locks in ascending order for REVOKE/MOVE/DELETE.
 * These operations walk the MDB derivation subtree and rewrite the
 * parent/child chain, which may touch slots in arbitrary buckets.
 * Since they are rare control-plane operations, acquiring all 64 locks
 * is acceptable.
 */
static unsigned long cap_derive_lock_all(void)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&airy_cap_bucket_locks[0], flags);
	for (i = 1; i < AIRY_CAP_BUCKET_NR; i++)
		spin_lock(&airy_cap_bucket_locks[i]);
	return flags;
}

static void cap_derive_unlock_all(unsigned long flags)
{
	int i;

	for (i = AIRY_CAP_BUCKET_NR - 1; i > 0; i--)
		spin_unlock(&airy_cap_bucket_locks[i]);
	spin_unlock_irqrestore(&airy_cap_bucket_locks[0], flags);
}

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
 * Reparent every child of @agent_id under @new_parent.  A non-zero
 * @new_parent keeps the derivation depth, so MOVE carries the subtree
 * along with the capability.  @new_parent == 0 promotes the children to
 * roots and resets their depth, which is how DELETE avoids leaving
 * parent_agent pointing at a recycled slot.
 */
static void cap_mdb_reparent(__u32 agent_id, __u32 new_parent)
{
	__u32 child = READ_ONCE(agent_caps[agent_id].first_child);

	while (child != 0) {
		struct airy_cap_slot *slot = &agent_caps[child];
		__u32 next = READ_ONCE(slot->next_sibling);

		WRITE_ONCE(slot->parent_agent, new_parent);
		if (new_parent == 0) {
			WRITE_ONCE(slot->next_sibling, 0);
			WRITE_ONCE(slot->generation, 0);
		}
		child = next;
	}
}

/* Clear every field of a slot, leaving it ready for re-registration. */
static void cap_slot_reset(struct airy_cap_slot *slot)
{
	WRITE_ONCE(slot->badge, AIRY_CAP_NULL);
	WRITE_ONCE(slot->agent_id, 0);
	WRITE_ONCE(slot->flags, 0);
	WRITE_ONCE(slot->randtag, 0);
	WRITE_ONCE(slot->perms, 0);
	WRITE_ONCE(slot->epoch, 0);
	WRITE_ONCE(slot->parent_agent, 0);
	WRITE_ONCE(slot->first_child, 0);
	WRITE_ONCE(slot->next_sibling, 0);
	WRITE_ONCE(slot->generation, 0);
	WRITE_ONCE(slot->revocable, 0);
}

/*
 * Scratch stack for the MDB revoke walk.  REVOKE and airy_cap_unreg()
 * both hold all 64 bucket locks, so a single instance is serialised
 * across CPUs.  The MDB is a tree whose nodes are slots, hence at most
 * AIRY_CAP_MAX_AGENTS nodes and one push per node: the stack cannot
 * overflow.  An explicit stack replaces the former recursion, whose
 * worst case of 1024 frames would exhaust the 16 KiB kernel stack
 * while every bucket lock is held with IRQs disabled.
 */
static __u32 cap_revoke_stack[AIRY_CAP_MAX_AGENTS];

/*
 * Cascading revocation (K9-1 fix, seL4 CNode alignment).  Walks the
 * MDB derivation tree from the given agent, incrementing epoch and
 * clearing randtag for every revocable descendant.
 *
 * Complexity: O(N) where N = subtree size.
 */
static void airy_cap_revoke_subtree(__u32 agent_id, __u16 new_epoch)
{
	unsigned int nr = 0;

	cap_revoke_stack[nr++] = agent_id;

	while (nr != 0) {
		struct airy_cap_slot *slot;
		__u32 child;

		slot = &agent_caps[cap_revoke_stack[--nr]];
		WRITE_ONCE(slot->epoch, new_epoch);
		WRITE_ONCE(slot->randtag, 0);

		child = READ_ONCE(slot->first_child);
		while (child != 0) {
			struct airy_cap_slot *child_slot = &agent_caps[child];

			if (READ_ONCE(child_slot->revocable))
				cap_revoke_stack[nr++] = child;
			child = READ_ONCE(child_slot->next_sibling);
		}
	}
}

/* ─── airy_cap_unreg ───────────────────────────────────────────────────── */
/*
 * Release an agent's capability slot when the agent terminates.
 *
 * SSoT 110-security/03-capability-model.md §13.3: revoke the agent's
 * derivation subtree first, then delete the slot itself.  Both steps
 * run under a single acquisition of all bucket locks: splitting them
 * into two airy_cap_derive() calls would open a window in which a
 * concurrent COPY/MINT from the dying agent could attach a fresh child
 * after the revoke and survive it.
 *
 * Revoked children keep their slots but lose their authority: the
 * revoke bumps their epoch and clears the random tag, so every badge
 * minted before the revoke fails validation.  The children are then
 * promoted to MDB roots so no parent_agent points at the slot about to
 * be recycled.  agent_id 0 is the unbound marker and never owns a slot,
 * so it is ignored along with out-of-range IDs.
 */
void airy_cap_unreg(__u32 agent_id)
{
	struct airy_cap_slot *slot;
	unsigned long flags;

	if (agent_id == 0 || agent_id >= AIRY_CAP_MAX_AGENTS)
		return;

	flags = cap_derive_lock_all();

	slot = &agent_caps[agent_id];
	if (READ_ONCE(slot->badge) != AIRY_CAP_NULL) {
		__u16 epoch = READ_ONCE(slot->epoch) + 1;

		airy_cap_revoke_subtree(agent_id, epoch);
		cap_mdb_reparent(agent_id, 0);
		airy_cap_mdb_unlink_child(agent_id);
		cap_slot_reset(slot);

		pr_debug_ratelimited("%s: agent=%u epoch %u\n",
				     __func__, agent_id, epoch);
	}

	cap_derive_unlock_all(flags);
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
 * Locking (P1-11 fix): the former global spinlock is replaced by a
 * 64-bucket hashed lock array.  COPY/MINT acquire the buckets covering
 * src and dst, MUTATE/ROTATE only the source bucket.  REVOKE, MOVE and
 * DELETE acquire all 64 buckets: the revocation subtree, the parent's
 * child chain and the children's parent links may all span arbitrary
 * buckets.  This closes the TOCTOU window between slot-state checks and
 * subsequent writes while allowing concurrent derivation on disjoint
 * agent sets.  get_random_u32() and atomic_inc() are non-blocking and
 * safe under the spinlock.
 */
int airy_cap_derive(__u32 src_agent, __u32 dst_agent,
		    enum airy_cap_op op, __u16 new_perms)
{
	struct airy_cap_slot *src, *dst;
	struct cap_derive_lock_ctx ctx;
	__u64 epoch, randtag;
	__u16 perms;
	unsigned long all_flags = 0;
	bool all_locked = false;
	int ret = 0;

	pr_debug_ratelimited("%s: ENTER op=%s(%u) src=%u dst=%u new_perms=0x%04x\n",
		__func__, op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, src_agent, dst_agent, new_perms);

	/*
	 * Acquire locks before slot lookup to close the TOCTOU window.
	 * REVOKE cascades through the entire MDB subtree, while MOVE and
	 * DELETE rewrite the parent's child chain and (for MOVE) the
	 * children's parent links, so all three may touch slots in
	 * arbitrary buckets and acquire all 64 locks.  COPY/MINT/MUTATE/
	 * ROTATE touch only the slots they name.
	 */
	if (op == AIRY_CAP_OP_REVOKE || op == AIRY_CAP_OP_MOVE ||
	    op == AIRY_CAP_OP_DELETE) {
		all_flags = cap_derive_lock_all();
		all_locked = true;
	} else {
		cap_derive_lock_begin(&ctx);
		cap_derive_lock_add(&ctx, src_agent);
		if (op == AIRY_CAP_OP_COPY || op == AIRY_CAP_OP_MINT)
			cap_derive_lock_add(&ctx, dst_agent);
	}

	/*
	 * Validate source slot for all operations.  REVOKE needs the slot
	 * to increment its epoch (K9-1 changed REVOKE to cascading via the
	 * MDB tree, src is the root of the revocation subtree).
	 */
	src = airy_cap_lookup(src_agent);
	if (!src) {
		pr_debug_ratelimited("%s: op=%s FAIL - src agent %u not found\n",
			__func__, op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
			src_agent);
		ret = -AIRY_ECAP_MISSING;
		goto out;
	}

	switch (op) {
	/* ─── COPY (optional demotion, P1-10 fix) ─────────────────── */
	case AIRY_CAP_OP_COPY:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("%s: COPY FAIL - dst %u >= MAX %u\n",
				__func__, dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("%s: COPY FAIL - dst %u occupied badge=0x%016llx\n",
				__func__, dst_agent, (unsigned long long)dst->badge);
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

		pr_debug_ratelimited("%s: COPY src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x (parent=%u gen=%u)\n",
			__func__, src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch, dst->perms,
			dst->parent_agent, dst->generation);
		break;

	/* ─── MINT (always demotes, maintains MDB tree) ────────────── */
	case AIRY_CAP_OP_MINT:
		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("%s: MINT FAIL - dst %u >= MAX %u\n",
				__func__, dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("%s: MINT FAIL - dst %u occupied\n",
				__func__, dst_agent);
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

		pr_debug_ratelimited("%s: MINT src=%u→dst=%u badge=0x%016llx epoch=%u perms=0x%04x (demoted from 0x%04x parent=%u gen=%u)\n",
			__func__, src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch,
			dst->perms, src->perms, dst->parent_agent, dst->generation);
		break;

	/* ─── MOVE (transfer + unlink from parent) ─────────────────── */
	case AIRY_CAP_OP_MOVE: {
		struct airy_cap_slot *parent;
		__u32 parent_id, child;
		__u16 generation, revocable;

		if (dst_agent >= AIRY_CAP_MAX_AGENTS) {
			pr_debug_ratelimited("%s: MOVE FAIL - dst %u >= MAX %u\n",
				__func__, dst_agent, AIRY_CAP_MAX_AGENTS);
			ret = -AIRY_ECAP_OVERFLOW;
			goto out;
		}
		dst = &agent_caps[dst_agent];
		if (dst->badge != AIRY_CAP_NULL) {
			pr_debug_ratelimited("%s: MOVE FAIL - dst %u occupied\n",
				__func__, dst_agent);
			ret = -AIRY_EEXIST;
			goto out;
		}

		/*
		 * The capability moves as a whole: the destination takes
		 * over the badge and the MDB position, and the derived
		 * children follow it.  Snapshot the links before the
		 * source slot is unlinked and cleared.
		 */
		parent_id  = READ_ONCE(src->parent_agent);
		child      = READ_ONCE(src->first_child);
		generation = READ_ONCE(src->generation);
		revocable  = READ_ONCE(src->revocable);

		dst->badge    = src->badge;
		dst->agent_id = dst_agent;
		dst->flags    = src->flags;
		dst->randtag  = src->randtag;
		dst->perms    = src->perms;
		dst->epoch    = src->epoch;

		if (parent_id != 0) {
			parent = &agent_caps[parent_id];
			airy_cap_mdb_unlink_child(src_agent);
			airy_cap_mdb_link_child(parent, dst, parent_id,
						dst_agent);
			WRITE_ONCE(dst->generation, generation);
			WRITE_ONCE(dst->revocable, revocable);
		} else {
			WRITE_ONCE(dst->parent_agent, 0);
			WRITE_ONCE(dst->next_sibling, 0);
			WRITE_ONCE(dst->generation, generation);
			WRITE_ONCE(dst->revocable, revocable);
		}
		WRITE_ONCE(dst->first_child, child);
		cap_mdb_reparent(src_agent, dst_agent);

		cap_slot_reset(src);

		pr_debug_ratelimited("%s: MOVE src=%u→dst=%u badge=0x%016llx epoch=%u parent=%u gen=%u children=%u\n",
			__func__, src_agent, dst_agent,
			(unsigned long long)dst->badge, dst->epoch,
			dst->parent_agent, dst->generation, child);
		break;
	}

	/* ─── MUTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_MUTATE:
		/* Modify permissions of existing badge in-place */
		epoch = AIRY_BADGE_EPOCH(src->badge);
		randtag = (__u64)src->randtag;

		WRITE_ONCE(src->badge, AIRY_BADGE_COMPILE(epoch, randtag,
						       new_perms));
		WRITE_ONCE(src->perms, new_perms);
		pr_debug_ratelimited("%s: MUTATE agent=%u perms 0x%04x→0x%04x badge=0x%016llx\n",
			__func__, src_agent, src->perms, new_perms,
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

			pr_debug_ratelimited("%s: REVOKE agent=%u epoch %u→%u (cascading, all descendants invalidated)\n",
				__func__, src_agent, old_epoch, new_epoch_val);
		}
		break;

	/* ─── DELETE (unlink from MDB tree, clear slot) ────────────── */
	case AIRY_CAP_OP_DELETE:
		pr_debug_ratelimited("%s: DELETE agent=%u badge=0x%016llx epoch=%u (clearing slot)\n",
			__func__, src_agent, (unsigned long long)src->badge,
			READ_ONCE(src->epoch));

		/*
		 * DELETE never cascades (SSoT §3.4): the derived children
		 * stay valid and are promoted to roots.  Leaving their
		 * parent_agent pointing at the cleared slot would let a
		 * later registration of the same index inherit the old
		 * subtree and revoke it.
		 */
		cap_mdb_reparent(src_agent, 0);
		airy_cap_mdb_unlink_child(src_agent);
		cap_slot_reset(src);
		break;

	/* ─── ROTATE ────────────────────────────────────────────────── */
	case AIRY_CAP_OP_ROTATE: {
		__u32 new_tag;

		/* Generate cryptographically random tag */
		new_tag = get_random_u32();
		epoch   = AIRY_BADGE_EPOCH(src->badge);
		perms   = src->perms;

		pr_debug_ratelimited("%s: ROTATE agent=%u old_tag=0x%08x→new_tag=0x%08x epoch=%u perms=0x%04x\n",
			__func__, src_agent, src->randtag, new_tag,
			(__u16)epoch, perms);

		/*
		 * Write randtag first, then badge — see airy_cap_rotate.c
		 * C-S5.5 for ordering rationale.  smp_store_release prevents
		 * store-store reordering on weakly-ordered architectures.
		 */
		smp_store_release(&src->randtag, new_tag);
		/* Publish badge only after the tag store above. */
		smp_store_release(&src->badge,
				  AIRY_BADGE_COMPILE(epoch, new_tag, perms));
		break;
	}

	default:
		pr_warn("%s: UNKNOWN op=%u src=%u dst=%u\n",
			__func__, op, src_agent, dst_agent);
		ret = -AIRY_EINVAL;
		break;
	}

out:
	pr_debug_ratelimited("%s: EXIT op=%s(%u) ret=%d\n",
		__func__, op < ARRAY_SIZE(cap_op_names) ? cap_op_names[op] : "UNKNOWN",
		op, ret);
	if (all_locked)
		cap_derive_unlock_all(all_flags);
	else
		cap_derive_lock_end(&ctx);
	return ret;
}

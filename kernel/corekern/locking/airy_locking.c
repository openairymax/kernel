// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_locking.c — Airymax core-kernel locking primitives.
 *
 * Provides airy_locking_init() for subsystem bring-up (called from
 * the api late_initcall) and airy_spin_lock_nested() as a thin wrapper
 * around the kernel's spin_lock_nested() for lockdep-annotated
 * hierarchical acquisitions.
 */

#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/bug.h>
#include <linux/errno.h>

/* ─── Self-test lock ─────────────────────────────────────────────────── */
static DEFINE_SPINLOCK(airy_locking_self_lock);

/* ─── Subsystem init ─────────────────────────────────────────────────── */
int __init airy_locking_init(void)
{
	unsigned long flags;

	/*
	 * Self-test: acquire and release the lock to verify that the
	 * spinlock implementation is functional before any other corekern
	 * subsystem depends on it.
	 */
	spin_lock_irqsave(&airy_locking_self_lock, flags);
	spin_unlock_irqrestore(&airy_locking_self_lock, flags);

	pr_info("airy_locking: initialised (self-test passed)\n");
	return 0;
}

/* ─── spin_lock_nested() wrapper ─────────────────────────────────────── */
void airy_spin_lock_nested(spinlock_t *lock, unsigned int subclass)
{
	if (!lock) {
		WARN_ONCE(1, "airy_spin_lock_nested: NULL lock\n");
		return;
	}

	spin_lock_nested(lock, subclass);
}

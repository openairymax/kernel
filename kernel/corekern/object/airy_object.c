// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_object.c — Airymax kernel object registry.
 *
 * Maintains a global linked list of airy_object entries protected by a
 * spinlock.  Supports register / unregister / lookup by 32-bit object
 * id.  The registry is used by other corekern subsystems to publish
 * named handles (e.g. IPC rings, scheduling policy instances).
 */

#include <linux/printk.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/types.h>

/* ─── Object descriptor ──────────────────────────────────────────────── */
struct airy_object {
	struct list_head	list;
	u32			id;
	const char		*name;
	void			*priv;
};

/* ─── Global registry ────────────────────────────────────────────────── */
static DEFINE_SPINLOCK(airy_object_lock);
static LIST_HEAD(airy_object_list);

/* ─── Register an object ─────────────────────────────────────────────── */
int airy_object_register(struct airy_object *obj)
{
	unsigned long flags;
	struct airy_object *iter;

	if (!obj || !obj->name)
		return -EINVAL;

	spin_lock_irqsave(&airy_object_lock, flags);

	/* Check for duplicate ID before inserting. */
	list_for_each_entry(iter, &airy_object_list, list) {
		if (iter->id == obj->id) {
			spin_unlock_irqrestore(&airy_object_lock, flags);
			pr_warn_ratelimited("airy_object: duplicate id=%u\n", obj->id);
			return -EEXIST;
		}
	}

	list_add_tail(&obj->list, &airy_object_list);
	spin_unlock_irqrestore(&airy_object_lock, flags);

	pr_info("airy_object: registered id=%u name=%s\n", obj->id, obj->name);
	return 0;
}

/* ─── Unregister an object ───────────────────────────────────────────── */
void airy_object_unregister(struct airy_object *obj)
{
	unsigned long flags;

	if (!obj)
		return;

	spin_lock_irqsave(&airy_object_lock, flags);
	list_del_init(&obj->list);
	spin_unlock_irqrestore(&airy_object_lock, flags);

	pr_info("airy_object: unregistered id=%u name=%s\n", obj->id, obj->name);
}

/* ─── Look up an object by id ────────────────────────────────────────── */
struct airy_object *airy_object_lookup(u32 id)
{
	struct airy_object *obj;
	unsigned long flags;

	spin_lock_irqsave(&airy_object_lock, flags);
	list_for_each_entry(obj, &airy_object_list, list) {
		if (obj->id == id) {
			spin_unlock_irqrestore(&airy_object_lock, flags);
			return obj;
		}
	}
	spin_unlock_irqrestore(&airy_object_lock, flags);

	return NULL;
}

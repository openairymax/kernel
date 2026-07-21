// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_irq.c — Airymax core-kernel interrupt management.
 *
 * Wraps request_irq() / free_irq() so that corekern subsystems can
 * register interrupt handlers without duplicating the dev_id and
 * flag plumbing.  All handlers are registered with a fixed "airy_irq"
 * name and NULL dev_id for simplicity.
 */

#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/errno.h>

/* ─── Register an interrupt handler ──────────────────────────────────── */
int airy_irq_register_handler(int irq, irq_handler_t fn)
{
	int ret;

	if (irq < 0 || !fn)
		return -EINVAL;

	ret = request_irq((unsigned int)irq, fn, 0, "airy_irq", NULL);
	if (ret) {
		pr_err("airy_irq: request_irq(%d) failed: %d\n", irq, ret);
		return ret;
	}

	pr_info("airy_irq: registered handler for irq %d\n", irq);
	return 0;
}

/* ─── Unregister an interrupt handler ────────────────────────────────── */
void airy_irq_unregister_handler(int irq)
{
	if (irq < 0)
		return;

	free_irq((unsigned int)irq, NULL);
	pr_info("airy_irq: unregistered handler for irq %d\n", irq);
}

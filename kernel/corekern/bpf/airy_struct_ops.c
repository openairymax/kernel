// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_struct_ops.c — Airymax eBPF struct_ops registration.
 *
 * Defines the Airymax-specific struct_ops value type and its state
 * machine.  Only compiled when CONFIG_BPF=y (see top-level Kbuild).
 * The actual bpf_struct_ops registration with the BPF subsystem is
 * deferred to the integration layer; here we provide the state
 * management that the integration layer builds upon.
 */

#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

/* ─── struct_ops state machine ───────────────────────────────────────── */
enum airy_struct_ops_state {
	AIRY_STRUCT_OPS_STATE_INACTIVE		= 0,
	AIRY_STRUCT_OPS_STATE_REGISTERED	= 1,
	AIRY_STRUCT_OPS_STATE_ACTIVE		= 2,
	AIRY_STRUCT_OPS_STATE_MAX
};

/* ─── struct_ops value ───────────────────────────────────────────────── */
struct airy_struct_ops_value {
	enum airy_struct_ops_state	state;
	u32				refcount;
	const char			*name;
	void				*data;
};

/* ─── State name lookup ──────────────────────────────────────────────── */
static const char * const airy_struct_ops_state_names[] = {
	[AIRY_STRUCT_OPS_STATE_INACTIVE]	= "inactive",
	[AIRY_STRUCT_OPS_STATE_REGISTERED]	= "registered",
	[AIRY_STRUCT_OPS_STATE_ACTIVE]		= "active",
};

static const char *
airy_struct_ops_state_name(enum airy_struct_ops_state state)
{
	if ((unsigned int)state >= AIRY_STRUCT_OPS_STATE_MAX)
		return "unknown";
	return airy_struct_ops_state_names[(unsigned int)state];
}

/* ─── Register a struct_ops value ────────────────────────────────────── */
int airy_struct_ops_register(struct airy_struct_ops_value *val)
{
	if (!val)
		return -EINVAL;

	if (val->state != AIRY_STRUCT_OPS_STATE_INACTIVE) {
		pr_warn("airy_struct_ops: cannot register from state '%s'\n",
			airy_struct_ops_state_name(val->state));
		return -EBUSY;
	}

	val->state    = AIRY_STRUCT_OPS_STATE_REGISTERED;
	val->refcount = 0;

	pr_info("airy_struct_ops: registered value (name=%s)\n",
		val->name ? val->name : "(null)");
	return 0;
}

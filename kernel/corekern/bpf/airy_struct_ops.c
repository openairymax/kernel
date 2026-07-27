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
 *
 * SSoT: the struct_ops state machine and common_value layout are
 * defined in <linux/airymax/bpf_struct_ops.h> (supplementary shared
 * contract header). This file MUST NOT redefine those types.
 */

#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/airymax/bpf_struct_ops.h>

/* ─── State name lookup ────────────────────────────────────────────────
 * Maps SSoT enum airy_struct_ops_state values (INIT/REGISTERED/ACTIVE/
 * DRAINING) to human-readable strings for diagnostics.
 */
static const char * const airy_struct_ops_state_names[] = {
	[AIRY_STRUCT_OPS_INIT]       = "init",
	[AIRY_STRUCT_OPS_REGISTERED] = "registered",
	[AIRY_STRUCT_OPS_ACTIVE]     = "active",
	[AIRY_STRUCT_OPS_DRAINING]   = "draining",
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

	if (val->common.state != AIRY_STRUCT_OPS_INIT) {
		pr_warn("airy_struct_ops: cannot register from state '%s'\n",
			airy_struct_ops_state_name(val->common.state));
		return -EBUSY;
	}

	val->common.state       = AIRY_STRUCT_OPS_REGISTERED;
	val->common.refcount    = 0;

	pr_info("airy_struct_ops: registered value (name=%s)\n",
		val->name[0] ? (const char *)val->name : "(null)");
	return 0;
}

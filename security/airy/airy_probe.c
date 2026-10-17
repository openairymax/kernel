// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_probe.c — agentrt presence probe (/proc/sys/agentrt/present).
 *
 * agentrt opens this file to decide between the kernel-accelerated syscall
 * path and its user-space fallback, so the marker is a readiness contract:
 * it is registered from airy_init() only after the capability table, hooks,
 * die notifier and tracing are live, and it exports AIRY_PROBE_READY while
 * visible.  A failed registration leaves the file absent, keeping agentrt
 * on the fallback path instead of calling into a half-initialised kernel.
 *
 * Design rationale: docs/AirymaxOS/30-interfaces/05-syscall-semantic-mapping.md
 * §7.2 (OS-IFACE-007).
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sysctl.h>

#include "airy_probe.h"

#define AIRY_PROBE_DIR	"agentrt"

static int airy_probe_state = AIRY_PROBE_ABSENT;

#ifdef CONFIG_SYSCTL

static struct ctl_table airy_probe_table[] = {
	{
		.procname	= "present",
		.data		= &airy_probe_state,
		.maxlen		= sizeof(airy_probe_state),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table_header *airy_probe_hdr;

/**
 * airy_probe_init - Publish /proc/sys/agentrt/present.
 *
 * Return: 0 on success or when already published; -ENOMEM when the
 * sysctl tree cannot be registered.
 */
int airy_probe_init(void)
{
	if (airy_probe_hdr)
		return 0;

	WRITE_ONCE(airy_probe_state, AIRY_PROBE_READY);
	airy_probe_hdr = register_sysctl(AIRY_PROBE_DIR, airy_probe_table);
	if (!airy_probe_hdr) {
		WRITE_ONCE(airy_probe_state, AIRY_PROBE_ABSENT);
		pr_err("airy: cannot register /proc/sys/%s/present\n",
		       AIRY_PROBE_DIR);
		return -ENOMEM;
	}

	pr_info("airy: /proc/sys/%s/present published\n", AIRY_PROBE_DIR);
	return 0;
}

/**
 * airy_probe_exit - Withdraw the presence marker.
 *
 * Used by the KUnit suite; production kernels keep the marker for their
 * entire lifetime.
 */
void airy_probe_exit(void)
{
	if (!airy_probe_hdr)
		return;

	unregister_sysctl_table(airy_probe_hdr);
	airy_probe_hdr = NULL;
	WRITE_ONCE(airy_probe_state, AIRY_PROBE_ABSENT);
}

#else /* !CONFIG_SYSCTL */

int airy_probe_init(void)
{
	return 0;
}

void airy_probe_exit(void)
{
}

#endif /* CONFIG_SYSCTL */

/**
 * airy_probe_val - Current marker value.
 *
 * Return: AIRY_PROBE_READY while the file is published, otherwise
 * AIRY_PROBE_ABSENT.
 */
int airy_probe_val(void)
{
	return READ_ONCE(airy_probe_state);
}

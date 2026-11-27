// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_policy_tables.c — publish the reference policy compiled from .adl.
 *
 * The tables live in security_policy_tables.h, rendered from
 * tools/dsl/examples/security_policy.adl by tools/dsl/dsl_compile.py.  The
 * header is committed next to this file so the kernel builds without the
 * parent repository; the codegen gate re-renders it and compares.
 *
 * The three tables are the boot baseline: uring_guard refuses the reserved
 * command opcode, task_guard and file_open_guard record creation and open
 * activity.  They supplement the capability checks and the W^X exception
 * table rather than replacing them, so a registration failure is reported
 * once and does not stop enforcement or boot.
 *
 * SSoT: 110-security/10-policy-compiler.md §9.
 */

#include <linux/errno.h>
#include <linux/kernel.h>

#include <airymax/airy_policy.h>

#include "security_policy_tables.h"

static const struct airy_policy_table *const airy_policy_tables[] = {
	&airy_policy_uring_guard_table,
	&airy_policy_task_guard_table,
	&airy_policy_file_open_guard_table,
};

int airy_policy_tables_register(void)
{
	int rc;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(airy_policy_tables); i++) {
		rc = airy_policy_register(airy_policy_tables[i]);
		if (rc)
			return rc;
	}

	return 0;
}

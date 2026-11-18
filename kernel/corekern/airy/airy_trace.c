// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_trace.c — Agent trace instance lifecycle.
 *
 * Owns the single CREATE_TRACE_POINTS translation unit for
 * include/trace/events/airy.h and creates the agent_trace ftrace
 * instance.  The instance must exist before tracer_init_tracefs()
 * materialises instances/: trace_array_get_by_name() binds every
 * registered event while trace_instance_dir is still NULL, and
 * trace_array_create_dir() later projects that binding into events/airy.
 *
 * The reference is never dropped: removing the instance through tracefs
 * would make the observability baseline a moving target.
 *
 * SSoT: 90-observability/08-agent-tracing.md §1.1 (OS-KER-171);
 *       01-ftrace-framework.md §7.3 (OS-KER-055).
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/trace.h>
#include <linux/types.h>

#include <airymax/airy_trace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/airy.h>

static bool airy_trace_live;

int airy_trace_init(void)
{
	struct trace_array *tr;

	if (airy_trace_live)
		return 0;

	tr = trace_array_get_by_name(AIRY_TRACE_INST_NAME, "airy");
	if (!tr) {
		pr_err("airy: %s trace instance unavailable, events/airy will not exist\n",
		       AIRY_TRACE_INST_NAME);
		return -ENOMEM;
	}

	airy_trace_live = true;
	pr_info("airy: %s trace instance ready (events/airy)\n",
		AIRY_TRACE_INST_NAME);
	return 0;
}

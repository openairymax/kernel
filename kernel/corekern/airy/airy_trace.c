// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_trace.c — Agent trace instance lifecycle.
 *
 * Owns the single CREATE_TRACE_POINTS translation unit for
 * include/trace/events/airy.h, so every trace_airy_*() emit helper
 * resolves to the tracepoint objects defined here, and creates the
 * independent agent_trace ftrace instance that holds the agent stream
 * apart from the global buffer.
 *
 * The instance must exist before the fs_initcall tracer_init_tracefs()
 * materialises instances/: while trace_instance_dir is still NULL,
 * trace_array_get_by_name() (the public creator — it calls the static
 * trace_array_create_systems(), and returns an array that is already on
 * ftrace_trace_arrays) binds every registered airy event through
 * __trace_early_add_events().  That binding is what
 * trace_array_create_dir() later projects into events/airy, because
 * __add_event_to_tracers() only walks arrays that exist when an event is
 * registered.  Creating the instance after tracing_init_dentry() instead
 * would leave an instance without an events directory.
 *
 * The reference taken here is never dropped: it pins the instance for the
 * lifetime of the kernel so a removal through tracefs cannot turn the
 * observability baseline into a moving target.
 *
 * Design rationale: docs/AirymaxOS/90-observability/08-agent-tracing.md
 * §1.1 (OS-KER-171); 01-ftrace-framework.md §7.3 (OS-KER-055).
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

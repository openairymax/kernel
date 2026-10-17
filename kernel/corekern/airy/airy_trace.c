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
 * apart from the global buffer; airy_init() calls it before the
 * fs_initcall tracer_init_tracefs() materialises instances/.
 *
 * Design rationale: docs/AirymaxOS/90-observability/08-agent-tracing.md
 * §1.1 (OS-KER-171); 01-ftrace-framework.md §7.3 (OS-KER-055).
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/trace.h>

#include <airymax/airy_trace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/airy.h>

static struct trace_array *airy_tr;

int airy_trace_init(void)
{
	struct trace_array *tr;

	if (airy_tr)
		return 0;

	tr = trace_array_get_by_name(AIRY_TRACE_INST_NAME, "airy");
	if (!tr) {
		pr_warn("airy: cannot create the %s trace instance\n",
			AIRY_TRACE_INST_NAME);
		return -ENOMEM;
	}

	airy_tr = tr;
	pr_info("airy: %s trace instance ready (events/airy)\n",
		AIRY_TRACE_INST_NAME);
	return 0;
}

void airy_trace_exit(void)
{
	if (!airy_tr)
		return;

	trace_array_put(airy_tr);
	trace_array_destroy(airy_tr);
	airy_tr = NULL;
}

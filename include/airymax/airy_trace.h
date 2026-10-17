/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Kernel-internal surface of the airy tracing facility: the transition
 * reason vocabulary shared by every emit site, the identity of the
 * independent trace instance that carries the agent stream, and the
 * init/exit entry points. The ftrace events themselves are declared in
 * include/trace/events/airy.h; a caller includes this header for the
 * vocabulary and <trace/events/airy.h> for the trace_airy_*() emit
 * functions, so the whole facility is reachable from one place.
 *
 * SSoT: 90-observability/05-debugfs-tracefs.md §7 (OS-KER-143);
 *       90-observability/08-agent-tracing.md §2.2, §7.2;
 *       90-observability/01-ftrace-framework.md §7.3 (OS-KER-055).
 */

#ifndef _AIRY_TRACE_H
#define _AIRY_TRACE_H

#include <linux/types.h>

#include <linux/airymax/sched.h>

/* Independent ftrace instance that holds the agent trace stream. */
#define AIRY_TRACE_INST_NAME	"agent_trace"
#define AIRY_TRACE_BUF_KB	16384

/* State transition reason codes, 08-agent-tracing.md §7.2. */
enum airy_trace_reason {
	AIRY_TRACE_REASON_INIT,
	AIRY_TRACE_REASON_DAG_UPDATE,
	AIRY_TRACE_REASON_PLAN_READY,
	AIRY_TRACE_REASON_DISPATCH,
	AIRY_TRACE_REASON_IPC_WAIT,
	AIRY_TRACE_REASON_IPC_RECV,
	AIRY_TRACE_REASON_SUPERVISE_SUSPEND,
	AIRY_TRACE_REASON_SUPERVISE_RESUME,
	AIRY_TRACE_REASON_SUPERVISE_TERMINATE,
	AIRY_TRACE_REASON_BUDGET_EXCEEDED,
	AIRY_TRACE_REASON_MAX
};

/*
 * The traced lifecycle is the [SC] one, not a private copy: event
 * fields carry the numeric values of enum airy_agent_state, so the
 * two representations must stay in lockstep (05-debugfs-tracefs.md
 * §7, "字段应对齐 [SC] sched.h enum airy_agent_state 8 态").
 */
_Static_assert(AIRY_AGENT_STATE_MAX == 8,
	       "airy trace tracks the 8 [SC] agent lifecycle states");

/* Instance lifecycle (defined in kernel/corekern/airy/airy_trace.c). */
/**
 * airy_trace_init - create the independent agent_trace ftrace instance
 *
 * Registers the independent instance so agent events are recorded
 * apart from the global stream (01-ftrace-framework.md §7.3); the
 * directory is materialised under instances/ once the tracing
 * filesystem comes up, and its buffer size is then set from
 * userspace (08-agent-tracing.md §3.3). Non-static so both the LSM
 * init path and KUnit drive the same instance.
 *
 * Return: 0 on success; -Exxx when the instance cannot be created.
 */
__must_check int airy_trace_init(void);

/**
 * airy_trace_exit - release the agent_trace ftrace instance
 *
 * Undoes airy_trace_init(). Safe to call when no instance exists.
 */
void airy_trace_exit(void);

#endif /* _AIRY_TRACE_H */

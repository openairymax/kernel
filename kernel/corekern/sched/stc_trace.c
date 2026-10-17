// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_trace.c — Emit sched_tac class switches to the airy ftrace stream.
 *
 * One emission point, two events: airy_sched_switch records the class
 * the task leaves and enters plus the sched_tac tier, while
 * airy_sched_latency carries the same measurement so a consumer can
 * aggregate latency without parsing switch records.
 *
 * The latency is measured around sched_setattr(): it is the cost of
 * applying the class, the quantity OS-STD-023 bounds. Wakeup-to-run
 * latency (OS-OBS-035) belongs to the native sched tracers and is
 * never inferred from dispatch.
 *
 * SSoT: 90-observability/05-debugfs-tracefs.md §7 (OS-KER-143);
 *       90-observability/08-agent-tracing.md §2.2 / 03-perf-analysis §5.4.
 */

#include <linux/types.h>

#include "stc_policy.h"

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

bool stc_trace_on(void)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	return trace_airy_sched_switch_enabled() ||
	       trace_airy_sched_latency_enabled();
#else
	return false;
#endif
}

void stc_emit_sched(u32 agent_id, u32 prev_state, u32 next_state,
		    u32 sched_class, u64 latency_ns)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_sched_switch(agent_id, prev_state, next_state,
				sched_class, latency_ns);
	trace_airy_sched_latency(agent_id, sched_class, latency_ns);
#endif
}

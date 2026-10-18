/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Airy subsystem ftrace events emitted by the in-kernel core. The
 * field order and width of every TRACE_EVENT below are a tracing ABI:
 * consumers parse them by offset, so they must not change between
 * releases. The events carry the [SC] numeric vocabulary (agent state,
 * reason, sched class) rather than a second copy of it, keeping the
 * traced value and the contract identical. The prev_state/next_state
 * pair of airy_sched_switch is the documented exception: it holds the
 * native SCHED_* class the task leaves and enters, the class the
 * dispatcher actually applies.
 *
 * SSoT: 90-observability/05-debugfs-tracefs.md §7 (OS-KER-143);
 *       90-observability/08-agent-tracing.md §2.2, §7.2.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM airy

#if !defined(_TRACE_AIRY_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_AIRY_H
#include <linux/tracepoint.h>

TRACE_EVENT(airy_agent_state_change,

	TP_PROTO(u32 agent_id, u32 prev_state, u32 next_state, u32 reason),

	TP_ARGS(agent_id, prev_state, next_state, reason),

	TP_STRUCT__entry(
		__field(	u32,	agent_id	)
		__field(	u32,	prev_state	)
		__field(	u32,	next_state	)
		__field(	u32,	reason		)
	),

	TP_fast_assign(
		__entry->agent_id = agent_id;
		__entry->prev_state = prev_state;
		__entry->next_state = next_state;
		__entry->reason = reason;
	),

	TP_printk("agent=%u prev=%u next=%u reason=%u",
		__entry->agent_id, __entry->prev_state,
		__entry->next_state, __entry->reason)
);

TRACE_EVENT(airy_sched_switch,

	TP_PROTO(u32 agent_id, u32 prev_state, u32 next_state,
		 u32 sched_class, u64 latency_ns),

	TP_ARGS(agent_id, prev_state, next_state, sched_class, latency_ns),

	TP_STRUCT__entry(
		__field(	u32,	agent_id	)
		__field(	u32,	prev_state	)
		__field(	u32,	next_state	)
		__field(	u32,	sched_class	)
		__field(	u64,	latency_ns	)
	),

	TP_fast_assign(
		__entry->agent_id = agent_id;
		__entry->prev_state = prev_state;
		__entry->next_state = next_state;
		__entry->sched_class = sched_class;
		__entry->latency_ns = latency_ns;
	),

	TP_printk("agent=%u prev=%u next=%u class=%u latency=%lluns",
		__entry->agent_id, __entry->prev_state, __entry->next_state,
		__entry->sched_class, __entry->latency_ns)
);

TRACE_EVENT(airy_sched_latency,

	TP_PROTO(u32 agent_id, u32 sched_class, u64 latency_ns),

	TP_ARGS(agent_id, sched_class, latency_ns),

	TP_STRUCT__entry(
		__field(	u32,	agent_id	)
		__field(	u32,	sched_class	)
		__field(	u64,	latency_ns	)
	),

	TP_fast_assign(
		__entry->agent_id = agent_id;
		__entry->sched_class = sched_class;
		__entry->latency_ns = latency_ns;
	),

	TP_printk("agent=%u class=%u latency=%lluns",
		__entry->agent_id, __entry->sched_class, __entry->latency_ns)
);

TRACE_EVENT(airy_ipc_send,

	TP_PROTO(u32 src_agent, u32 dst_agent, u32 op, u8 fastpath,
		 u64 latency_ns),

	TP_ARGS(src_agent, dst_agent, op, fastpath, latency_ns),

	TP_STRUCT__entry(
		__field(	u32,	src_agent	)
		__field(	u32,	dst_agent	)
		__field(	u32,	op		)
		__field(	u8,	fastpath	)
		__field(	u64,	latency_ns	)
	),

	TP_fast_assign(
		__entry->src_agent = src_agent;
		__entry->dst_agent = dst_agent;
		__entry->op = op;
		__entry->fastpath = fastpath;
		__entry->latency_ns = latency_ns;
	),

	TP_printk("src=%u dst=%u op=%u fastpath=%u latency=%lluns",
		__entry->src_agent, __entry->dst_agent, __entry->op,
		__entry->fastpath, __entry->latency_ns)
);

TRACE_EVENT(airy_ipc_recv,

	TP_PROTO(u32 src_agent, u32 dst_agent, u32 op, u64 latency_ns),

	TP_ARGS(src_agent, dst_agent, op, latency_ns),

	TP_STRUCT__entry(
		__field(	u32,	src_agent	)
		__field(	u32,	dst_agent	)
		__field(	u32,	op		)
		__field(	u64,	latency_ns	)
	),

	TP_fast_assign(
		__entry->src_agent = src_agent;
		__entry->dst_agent = dst_agent;
		__entry->op = op;
		__entry->latency_ns = latency_ns;
	),

	TP_printk("src=%u dst=%u op=%u latency=%lluns",
		__entry->src_agent, __entry->dst_agent, __entry->op,
		__entry->latency_ns)
);

TRACE_EVENT(airy_superv_enforce,

	TP_PROTO(u32 agent_id, u32 action, u32 reason),

	TP_ARGS(agent_id, action, reason),

	TP_STRUCT__entry(
		__field(	u32,	agent_id	)
		__field(	u32,	action		)
		__field(	u32,	reason		)
	),

	TP_fast_assign(
		__entry->agent_id = agent_id;
		__entry->action = action;
		__entry->reason = reason;
	),

	TP_printk("agent=%u action=%u reason=%u",
		__entry->agent_id, __entry->action, __entry->reason)
);

TRACE_EVENT(airy_ring_buffer_write,

	TP_PROTO(u32 level, u32 size, u32 overrun),

	TP_ARGS(level, size, overrun),

	TP_STRUCT__entry(
		__field(	u32,	level	)
		__field(	u32,	size	)
		__field(	u32,	overrun	)
	),

	TP_fast_assign(
		__entry->level = level;
		__entry->size = size;
		__entry->overrun = overrun;
	),

	TP_printk("level=%u size=%u overrun=%u",
		__entry->level, __entry->size, __entry->overrun)
);

TRACE_EVENT(airy_lockdown_change,

	TP_PROTO(u32 prev, u32 level, u32 trigger),

	TP_ARGS(prev, level, trigger),

	TP_STRUCT__entry(
		__field(	u32,	prev	)
		__field(	u32,	level	)
		__field(	u32,	trigger	)
	),

	TP_fast_assign(
		__entry->prev = prev;
		__entry->level = level;
		__entry->trigger = trigger;
	),

	TP_printk("prev=%u level=%u trigger=%u",
		__entry->prev, __entry->level, __entry->trigger)
);

/*
 * domain: 0 = agent-facing interface gate, 1 = security_locked_down()
 * reason. id names the enum airy_lock_iface or enum lockdown_reason
 * entry that was refused; required/active are ladder levels.
 */
TRACE_EVENT(airy_lockdown_reject,

	TP_PROTO(u32 domain, u32 id, u32 required, u32 active),

	TP_ARGS(domain, id, required, active),

	TP_STRUCT__entry(
		__field(	u32,	domain		)
		__field(	u32,	id		)
		__field(	u32,	required	)
		__field(	u32,	active		)
	),

	TP_fast_assign(
		__entry->domain = domain;
		__entry->id = id;
		__entry->required = required;
		__entry->active = active;
	),

	TP_printk("domain=%u id=%u required=%u active=%u",
		__entry->domain, __entry->id, __entry->required,
		__entry->active)
);

#endif /* _TRACE_AIRY_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

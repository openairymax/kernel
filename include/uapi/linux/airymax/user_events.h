/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airymax/user_events.h — daemon trace event contract ([SC] layer).
 *
 * user_events is the only channel through which user-space daemons report
 * trace events (OS-OBS-061). This header fixes the part that every producer
 * and consumer must agree on: registration names, registration format
 * strings and payload layouts. It declares no runtime handle — a handle owns
 * a file descriptor and an mmap'd enable word, so it belongs to the
 * user-space library, which is an [IND] implementation (OS-OBS-065).
 *
 * A producer registers AIRY_UEVENT_<event> with the matching
 * AIRY_UEVENT_FMT_<event> string; tracefs then exposes the event at
 * /sys/kernel/tracing/events/user_events/airy_user_<event>. The kernel side
 * only publishes the same table read-only at /sys/airy/events, so a
 * producer can check its registration before touching tracefs.
 *
 * SSoT: 90-observability/06-user-events.md
 */

#ifndef _UAPI_LINUX_AIRYMAX_USER_EVENTS_H
#define _UAPI_LINUX_AIRYMAX_USER_EVENTS_H

#include <linux/airymax/uapi_compat.h>

/* Layout version of the table below; bumped when names or fields change. */
#define AIRY_UEVENT_ABI		1

/* Registration names live in one tracefs namespace. */
#define AIRY_UEVENT_PREFIX	"airy_user_"

#define AIRY_UEVENT_COGN_START		AIRY_UEVENT_PREFIX "cognition_start"
#define AIRY_UEVENT_COGN_END		AIRY_UEVENT_PREFIX "cognition_end"
#define AIRY_UEVENT_MEM_ACCESS		AIRY_UEVENT_PREFIX "memory_access"
#define AIRY_UEVENT_TOOL_CALL		AIRY_UEVENT_PREFIX "tool_call"
#define AIRY_UEVENT_SUPERV_ENFORCE	AIRY_UEVENT_PREFIX "superv_enforce"

/*
 * Registration format strings. Field order, type and spacing are the wire
 * layout: user_events stores the payload verbatim and the tracepoint format
 * file reports these offsets, so a mismatch silently misplaces every field
 * after it. The UAPI structures below must keep the same order.
 */
#define AIRY_UEVENT_FMT_COGN_START \
	"u32 agent_id u32 input_tokens u64 timestamp_ns"
#define AIRY_UEVENT_FMT_COGN_END \
	"u32 agent_id u32 output_tokens u64 latency_ns"
#define AIRY_UEVENT_FMT_MEM_ACCESS \
	"u32 agent_id u8 level u8 hit u64 latency_ns u64 addr"
#define AIRY_UEVENT_FMT_TOOL_CALL \
	"u32 agent_id u32 tool_id u64 latency_ns " \
	"u8 result u32 output_tokens"
#define AIRY_UEVENT_FMT_SUPERV_ENFORCE \
	"u32 agent_id u32 action u32 reason"

/* ─── Payloads ──────────────────────────────────────────────────────── */

/**
 * struct airy_user_cognition_start - a reasoning request began
 * @agent_id: agent slot that accepted the request
 * @input_tokens: prompt size in tokens
 * @timestamp_ns: CLOCK_MONOTONIC timestamp taken in user space
 */
struct airy_user_cognition_start {
	__u32 agent_id;
	__u32 input_tokens;
	__u64 timestamp_ns;
};

/**
 * struct airy_user_cognition_end - a reasoning request finished
 * @agent_id: agent slot that produced the answer
 * @output_tokens: answer size in tokens
 * @latency_ns: wall time spent inside the engine
 */
struct airy_user_cognition_end {
	__u32 agent_id;
	__u32 output_tokens;
	__u64 latency_ns;
};

/**
 * struct airy_user_memory_access - one tiered memory lookup
 * @agent_id: agent slot that issued the lookup
 * @level: memory tier, 1 (L1) through 4 (cold store)
 * @hit: non-zero when the lookup was served by that tier
 * @latency_ns: lookup latency
 * @addr: address that was resolved, for correlating misses
 */
struct airy_user_memory_access {
	__u32 agent_id;
	__u8 level;
	__u8 hit;
	__u64 latency_ns;
	__u64 addr;
};

/**
 * struct airy_user_tool_call - one tool invocation
 * @agent_id: agent slot that invoked the tool
 * @tool_id: registered tool identifier
 * @latency_ns: invocation latency
 * @result: result class; zero means success
 * @output_tokens: tokens added to the context by the result
 */
struct airy_user_tool_call {
	__u32 agent_id;
	__u32 tool_id;
	__u64 latency_ns;
	__u8 result;
	__u32 output_tokens;
};

/**
 * struct airy_user_superv_enforce - a supervision verdict was applied
 * @agent_id: agent slot the verdict targeted
 * @action: &enum airy_adjud value that was applied
 * @reason: AIRY_FAULT_* code that drove the verdict, or zero
 *
 * OS-OBS-063 requires this event to be written both here and to the A-ULP
 * ring buffer, so a lost trace buffer cannot hide an enforcement.
 */
struct airy_user_superv_enforce {
	__u32 agent_id;
	__u32 action;
	__u32 reason;
};

#define AIRY_UEVENT_COGN_START_SIZE	16
#define AIRY_UEVENT_COGN_END_SIZE	16
#define AIRY_UEVENT_MEM_ACCESS_SIZE	24
#define AIRY_UEVENT_TOOL_CALL_SIZE	24
#define AIRY_UEVENT_SUPERV_SIZE		12

_Static_assert(sizeof(struct airy_user_cognition_start) ==
	       AIRY_UEVENT_COGN_START_SIZE,
	       "airy_user_cognition_start layout drifted");
_Static_assert(sizeof(struct airy_user_cognition_end) ==
	       AIRY_UEVENT_COGN_END_SIZE,
	       "airy_user_cognition_end layout drifted");
_Static_assert(sizeof(struct airy_user_memory_access) ==
	       AIRY_UEVENT_MEM_ACCESS_SIZE,
	       "airy_user_memory_access layout drifted");
_Static_assert(sizeof(struct airy_user_tool_call) ==
	       AIRY_UEVENT_TOOL_CALL_SIZE,
	       "airy_user_tool_call layout drifted");
_Static_assert(sizeof(struct airy_user_superv_enforce) ==
	       AIRY_UEVENT_SUPERV_SIZE,
	       "airy_user_superv_enforce layout drifted");

#endif /* _UAPI_LINUX_AIRYMAX_USER_EVENTS_H */

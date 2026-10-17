// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_trace.c — Emit IPC handoffs to the airy ftrace stream.
 *
 * Two events, one per direction: airy_ipc_send is emitted after the
 * ring accepted a header, airy_ipc_recv once a consumer dequeued one.
 * Both carry the header opcode, so a consumer can pair a send with the
 * matching receive.
 *
 * Identities are asymmetric by necessity. The sender is the task
 * executing the call; the source reported on receive is the header's
 * src_task, the only identity a dequeued header carries. Send thus
 * reports the confirmed identity, receive the claimed one.
 *
 * SSoT: 90-observability/05-debugfs-tracefs.md §7.2;
 *       90-observability/08-agent-tracing.md §2.2.
 */

#include <linux/types.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>

#include "airy_ipc_internal.h"

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>

/*
 * Agent ids live in [0, AIRY_CAP_MAX_AGENTS). A header field beyond
 * that range names nobody, which the trace vocabulary encodes as 0,
 * the same value airy_agent_id() returns outside the namespace.
 */
static u32 ipc_agent_of(u64 task)
{
	if (task >= AIRY_CAP_MAX_AGENTS)
		return 0;

	return (u32)task;
}
#endif

bool airy_send_on(void)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	return trace_airy_ipc_send_enabled();
#else
	return false;
#endif
}

bool airy_recv_on(void)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	return trace_airy_ipc_recv_enabled();
#else
	return false;
#endif
}

void airy_send_emit(const struct airy_ipc_msg_hdr *hdr, u32 src_agent,
		    u8 fastpath, u64 latency_ns)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_ipc_send(src_agent, ipc_agent_of(hdr->dst_task),
			    hdr->opcode, fastpath, latency_ns);
#endif
}

void airy_recv_emit(const struct airy_ipc_msg_hdr *hdr, u32 dst_agent,
		    u64 latency_ns)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_ipc_recv(ipc_agent_of(hdr->src_task), dst_agent,
			    hdr->opcode, latency_ns);
#endif
}

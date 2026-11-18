/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_trace.h — IPC tracepoint emit surface.
 *
 * Two planes hand a 128-byte header to a consumer: the io_uring data
 * plane and the 548 control-plane dispatch. Both report through the same
 * emitter pair, so the declarations live here instead of in the ipc
 * internal header: the syscall layer may report a handoff without
 * reaching into another subsystem's private header, while the
 * implementation stays single (corekern/ipc/airy_ipc_trace.c).
 *
 * SSoT: 90-observability/08-agent-tracing.md §2.2.
 */

#ifndef _AIRY_IPC_TRACE_H
#define _AIRY_IPC_TRACE_H

#include <linux/types.h>

#include <linux/airymax/ipc.h>

bool airy_send_on(void);
bool airy_recv_on(void);
void airy_send_emit(const struct airy_ipc_msg_hdr *hdr, u32 src_agent,
		    u8 fastpath, u64 latency_ns);
void airy_recv_emit(const struct airy_ipc_msg_hdr *hdr, u32 dst_agent,
		    u64 latency_ns);

#endif /* _AIRY_IPC_TRACE_H */

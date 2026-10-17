// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Hot-path send: the C-S0 frozen check and the C-S12 header digest,
 * then delegation to airy_ipc_ring_post(). Not an IPC entry point:
 * the only legal entry is the io_uring IORING_OP_URING_CMD path, after
 * the LSM five-phase check has validated the Badge (C-S9).
 *
 * Design rationale: docs/AirymaxOS/30-interfaces/07-ipc-fastpath.md
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include <airymax/airy_agent.h>

#include "airy_ipc_internal.h"

/* ─── Fast-path send ─────────────────────────────────────────────────── */
/*
 * Post a message to the IPC ring after the caller has validated the
 * agent's Badge via C-S9 (airy_cap_badge_ok).  See the file-level
 * comment above for the full Badge decision path.
 *
 * ring:  destination ring (must be initialised via airy_ipc_ring_init)
 * hdr:   message header to post (caller ensures valid magic/payload)
 *
 * Returns 0 on success, -EINVAL for null arguments, -AIRY_EIPC_FROZEN
 * if the ring is administratively frozen, or -AIRY_EIPC_CRC32 when the
 * C-S12 header digest does not match.  ring_post() may additionally
 * surface its own SC codes (C-S1 -AIRY_EIPC_MAGIC, C-S6
 * -AIRY_EIPC_KFIFO).
 */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr)
{
	u64 start = 0;
	bool trace;
	int ret;

	if (!ring || !hdr)
		return -EINVAL;

	/* C-S0: bail out immediately if the ring is quiesced.  Return
	 * -AIRY_EIPC_FROZEN (not generic -EAGAIN) so userland can tell
	 * "ring administratively frozen" from "transient retry".  This
	 * catches the race where the Micro-Supervisor suspends the agent
	 * between C-S9 and ring_post.
	 */
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	/* C-S12: verify the header digest before the slot write.  The
	 * fastpath carries no payload (any payload-bearing message
	 * degrades to slowpath), so the digest covers header[0:52) alone.
	 * A mismatch means the header was corrupted in flight; drop the
	 * message rather than deliver it.
	 */
	ret = airy_crc32_ok(hdr, NULL);
	if (unlikely(ret))
		return ret;

	/* Delegate to ring_post() which performs the actual slot write.
	 * ring_post() re-checks frozen (defence in depth) and validates
	 * magic before writing.
	 *
	 * The send event reports the task that actually executed the
	 * call, not the header's src_task, and only once the ring has
	 * accepted the header. Its latency is the post cost, measured
	 * from the same timestamp the trace predicate guards.
	 */
	trace = airy_send_on();
	if (trace)
		start = ktime_get_ns();

	ret = airy_ipc_ring_post(ring, hdr);
	if (!ret && trace)
		airy_send_emit(hdr, airy_agent_id(current), 1,
			       ktime_get_ns() - start);

	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Hot-path send: the C-S0 frozen check, the header and Badge chain in
 * airy_ipc_validate() (C-S1..C-S4, C-S8..C-S10), the C-S12 digest and
 * finally delegation to airy_ipc_ring_post(). A digest mismatch is
 * reported as AIRY_FAULT_RING_CORRUPT so the supervisor can isolate the
 * sender; the message is dropped. The ring-bound checks (C-S5..C-S7,
 * C-S11) belong to the ring, which is the only layer that owns a per-cpu
 * slot; everything decidable from the header is settled here before a
 * slot is written.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/ktime.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include <airymax/airy_agent.h>

#include "../../../security/airy/airy_cap.h"

#include "airy_ipc_check.h"
#include "airy_ipc_internal.h"

/* ─── Fast-path send ─────────────────────────────────────────────────── */
/*
 * Post a message to the IPC ring after the header and Badge have been
 * accepted. Every check that depends on the header alone runs before the
 * slot write, so a rejected message never occupies ring capacity and the
 * consumer never observes it.
 *
 * ring:  destination ring (must be initialised via airy_ipc_ring_init)
 * hdr:   message header to post
 *
 * Returns 0 on success, -EINVAL for null arguments, the negated [SC]
 * code of the first failing chain check (C-S1..C-S4, C-S8..C-S10, C-S12),
 * -AIRY_EIPC_FROZEN (C-S0), or a ring_post() code (C-S1
 * -AIRY_EIPC_MAGIC, C-S6 -AIRY_EIPC_KFIFO). A C-S12 mismatch also raises
 * AIRY_FAULT_RING_CORRUPT before the error is returned.
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

	/* C-S1..C-S4, C-S8..C-S10: settle the header and the Badge.  C-S8
	 * keeps the rest of the chain in task context, which the ring
	 * assumes: preemption stays enabled until ring_post() takes its
	 * own per-cpu slot, and no wakeup may be issued from here.
	 */
	ret = airy_ipc_validate(hdr);
	if (unlikely(ret))
		return ret;

	/* C-S12: verify the header digest before the slot write.  The
	 * fastpath carries no payload (any payload-bearing message
	 * degrades to slowpath), so the digest covers header[0:52) alone.
	 * A mismatch means the header was corrupted in flight; report the
	 * ring fault and drop the message rather than deliver it.
	 */
	ret = airy_crc32_ok(hdr, NULL);
	if (unlikely(ret)) {
#if IS_ENABLED(CONFIG_SECURITY_AIRY)
		if (ret == -AIRY_EIPC_CRC32)
			airy_security_fault((__u32)hdr->src_task,
					    AIRY_FAULT_RING_CORRUPT);
#endif
		return ret;
	}

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

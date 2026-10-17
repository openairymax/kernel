// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Two data-plane entry points share one header chain: the C-S1..C-S4
 * and C-S8..C-S10 checks in airy_ipc_validate(), the C-S12 digest, and
 * the AIRY_FAULT_RING_CORRUPT report a mismatch owes the supervisor.
 * The ring entry then delegates to airy_ipc_ring_post(); the mailbox
 * entry delegates to airy_ipc_kfifo_send() and carries no per-agent
 * freeze bit, because a mailbox is shared by every agent on its CPU.
 * C-S5..C-S7 and C-S11 belong to those delivery primitives, the only
 * layers that own a per-cpu slot. A delivery handed back for retry
 * (-EAGAIN) or rejected as full (-AIRY_EIPC_KFIFO) is counted in
 * slow_send_hit so that degradation stays observable.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include <airymax/airy_agent.h>

#include "../../../security/airy/airy_cap.h"

#include "airy_ipc_check.h"
#include "airy_ipc_internal.h"

/* ─── Shared header chain ──────── */
/*
 * Settle every check that depends on the header alone. Both entries run
 * this before they touch a slot, so a rejected header never occupies
 * capacity and the consumer never observes it.
 *
 * Returns 0 when the header may be delivered, or the negated [SC] code
 * of the first failing check. A digest mismatch raises
 * AIRY_FAULT_RING_CORRUPT before the error is returned.
 */
static int fp_check(const struct airy_ipc_msg_hdr *hdr)
{
	int ret;

	ret = airy_ipc_validate(hdr);
	if (unlikely(ret))
		return ret;

	ret = airy_crc32_ok(hdr, NULL);
#if IS_ENABLED(CONFIG_SECURITY_AIRY)
	if (unlikely(ret == -AIRY_EIPC_CRC32))
		airy_security_fault((__u32)hdr->src_task,
				    AIRY_FAULT_RING_CORRUPT);
#endif
	return ret;
}

/* Report a send that the delivery primitive handed to the slowpath. */
static void fp_degrade(int ret)
{
	if (ret == -EAGAIN || ret == -AIRY_EIPC_KFIFO)
		this_cpu_inc(airy_ipc_stats_cpu.slow_send_hit);
}

/*
 * Emit the send event for an accepted header. It reports the task that
 * executed the call, not the header's src_task, and its latency is the
 * delivery cost measured from the timestamp the predicate guards.
 */
static void fp_emit(const struct airy_ipc_msg_hdr *hdr, bool trace, u64 start)
{
	if (trace)
		airy_send_emit(hdr, airy_agent_id(current), 1,
			       ktime_get_ns() - start);
}

/* ─── Ring entry ──────── */
/*
 * Post a message to the IPC ring after the header and Badge have been
 * accepted.
 *
 * ring:  destination ring (must be initialised via airy_ipc_ring_init)
 * hdr:   message header to post
 *
 * Returns 0 on success, -EINVAL for null arguments, -AIRY_EIPC_FROZEN
 * (C-S0), the negated [SC] code of the first failing chain check, or a
 * ring_post() code (C-S5 -EAGAIN, C-S6 -AIRY_EIPC_KFIFO).
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

	ret = fp_check(hdr);
	if (unlikely(ret))
		return ret;

	trace = airy_send_on();
	if (trace)
		start = ktime_get_ns();

	ret = airy_ipc_ring_post(ring, hdr);
	if (!ret)
		fp_emit(hdr, trace, start);
	else
		fp_degrade(ret);

	return ret;
}

/* ─── Mailbox entry ──────── */
/*
 * Deliver a header into a CPU mailbox after the shared chain accepted
 * it. C-S5, C-S6 and C-S11 are settled by airy_ipc_kfifo_send(), which
 * is the layer owning the mailbox slot.
 *
 * Returns 0 on success, -EINVAL for null arguments, the negated [SC]
 * code of the first failing chain check, -EAGAIN when C-S5 or the HI
 * backpressure latch degrades the caller, or -AIRY_EIPC_KFIFO when
 * C-S6 finds no free slot.
 */
int airy_ipc_fast_send_kfifo(struct airy_ipc_kfifo *kf,
			     const struct airy_ipc_msg_hdr *hdr)
{
	u64 start = 0;
	bool trace;
	int ret;

	if (!kf || !hdr)
		return -EINVAL;

	ret = fp_check(hdr);
	if (unlikely(ret))
		return ret;

	trace = airy_send_on();
	if (trace)
		start = ktime_get_ns();

	ret = airy_ipc_kfifo_send(kf, hdr);
	if (!ret)
		fp_emit(hdr, trace, start);
	else
		fp_degrade(ret);

	return ret;
}

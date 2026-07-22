// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_uring_cmd.c — IORING_OP_URING_CMD handler for Airymax IPC.
 *
 * Entry point for io_uring command requests targeting the Airymax IPC
 * fabric.  Parses ioucmd->cmd_op, performs C-S9 fastpath badge validation
 * against the caller's capability slot, and dispatches to the appropriate
 * ring / fastpath / freeze / zero-copy function.
 *
 * The inline pdu[32] carries the 64-bit capability badge (bytes 0–7) and,
 * for FREEZE, the 32-bit reason code (bytes 8–11).  The ring instance and
 * full 128-byte message header extraction from shared memory is performed
 * by the integration layer (OS-IRON-004, M1).
 */

#include <linux/printk.h>
#include <linux/io_uring.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/lsm_hooks.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"
#include "../../../security/airy/airy_cap.h"

/* ─── Freeze operations (declared in security/airy/airy_ipc_freeze.c) ── */
extern struct airy_ipc_ring_freeze_state *
		airy_ipc_ring_for_task(struct task_struct *task);
extern void airy_ipc_freeze_ring(struct airy_ipc_ring_freeze_state *ring,
				__u32 reason);

/* ─── uring command dispatch ─────────────────────────────────────────── */
int airy_uring_cmd_handle(struct io_uring_cmd *ioucmd)
{
	struct task_struct *task = current;
	struct airy_task_sec *sec;
	struct airy_ipc_ring_freeze_state *ring;
	__u32 agent_id;
	__u64 badge;
	__u32 reason;
	u32 cmd_op;
	int ret;

	if (!ioucmd)
		return -EINVAL;

	cmd_op = ioucmd->cmd_op;

	/* C-S7.1: extract agent_id from the current task's security blob. */
	if (!task->security)
		return -EPERM;
	sec = task->security + airy_blob_sizes.lbs_task;
	agent_id = READ_ONCE(sec->agent_id);

	/*
	 * C-S9 fastpath: extract the badge from the inline pdu (bytes 0–7)
	 * and validate epoch + random-tag + permissions before dispatching.
	 */
	memcpy(&badge, ioucmd->pdu, sizeof(badge));

	switch (cmd_op) {
	case AIRY_IPC_OP_SEND:
		/* Hot-path unicast send — route to fastpath. */
		ret = airy_cap_badge_ok(badge, agent_id, AIRY_CAP_PERM_SEND);
		if (ret)
			return ret;
		/*
		 * M0: ring instance extraction from the ioucmd payload is
		 * not yet wired (OS-IRON-004).  airy_ipc_fastpath_send()
		 * requires both a ring pointer and a 128-byte message
		 * header; until the per-agent ring pool is implemented,
		 * return -ENOSYS so callers know the operation is pending.
		 */
		return -ENOSYS;

	case AIRY_IPC_OP_RECV:
		/* Receive path — managed by the ring consumer. */
		ret = airy_cap_badge_ok(badge, agent_id, AIRY_CAP_PERM_RECV);
		if (ret)
			return ret;
		/* M0: recv dispatch not yet implemented */
		return -ENOSYS;

	case AIRY_IPC_OP_SEND_BATCH:
		/* Batch send — ring path with AIRY_IPC_FLAG_BATCH_TAIL. */
		ret = airy_cap_badge_ok(badge, agent_id, AIRY_CAP_PERM_BATCH);
		if (ret)
			return ret;
		/* M0: batch send dispatch not yet implemented */
		return -ENOSYS;

	case AIRY_IPC_OP_CANCEL:
		/* Cancel pending operation. */
		ret = airy_cap_badge_ok(badge, agent_id, 0);
		if (ret)
			return ret;
		/* M0: cancel dispatch not yet implemented */
		return -ENOSYS;

	case AIRY_IPC_OP_FREEZE:
		/* Quiesce the ring — sets the frozen flag. */
		ret = airy_cap_badge_ok(badge, agent_id, AIRY_CAP_PERM_FREEZE);
		if (ret)
			return ret;
		ring = airy_ipc_ring_for_task(task);
		if (!ring)
			return -ENODEV;
		memcpy(&reason, ioucmd->pdu + sizeof(badge), sizeof(reason));
		airy_ipc_freeze_ring(ring, reason);
		return 0;

	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* Capability bootstrap — route to sec_d via zero-copy path. */
		/* M0: sec_d routing not yet implemented */
		return -ENOSYS;

	default:
		pr_warn_ratelimited("airy_uring_cmd: unknown cmd_op=%u\n",
				    cmd_op);
		return -EOPNOTSUPP;
	}
}

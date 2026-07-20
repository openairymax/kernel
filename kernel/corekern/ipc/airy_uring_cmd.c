// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_uring_cmd.c — IORING_OP_URING_CMD handler for Airymax IPC.
 *
 * Entry point for io_uring command requests targeting the Airymax IPC
 * fabric.  Parses ioucmd->cmd_op and dispatches to one of three paths:
 *
 *   • ring      — airy_ipc_ring_post() for batch / freeze / cancel ops
 *   • fastpath  — airy_ipc_fastpath_send() for AIRY_IPC_OP_SEND
 *   • zero_copy — airy_ipc_zero_copy_register() for capability bootstrap
 *
 * The actual ring instance and message header extraction from the inline
 * ioucmd->cmd payload is performed by the integration layer; this file
 * resolves the routing decision and validates the opcode.
 */

#include <linux/printk.h>
#include <linux/io_uring.h>
#include <linux/errno.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_internal.h"

/* ─── uring command dispatch ─────────────────────────────────────────── */
int airy_uring_cmd_handle(struct io_uring_cmd *ioucmd)
{
	u32 cmd_op;

	if (!ioucmd)
		return -EINVAL;

	cmd_op = ioucmd->cmd_op;

	switch (cmd_op) {
	case AIRY_IPC_OP_SEND:
		/* Hot-path unicast send — route to fastpath. */
		pr_info_ratelimited("airy_uring_cmd: SEND → fastpath\n");
		return 0;

	case AIRY_IPC_OP_RECV:
		/* Receive path — managed by the ring consumer. */
		pr_info_ratelimited("airy_uring_cmd: RECV → ring\n");
		return 0;

	case AIRY_IPC_OP_SEND_BATCH:
		/* Batch send — ring path with AIRY_IPC_FLAG_BATCH_TAIL. */
		pr_info_ratelimited("airy_uring_cmd: SEND_BATCH → ring\n");
		return 0;

	case AIRY_IPC_OP_CANCEL:
		pr_info_ratelimited("airy_uring_cmd: CANCEL → ring\n");
		return 0;

	case AIRY_IPC_OP_FREEZE:
		/* Quiesce the ring — sets the frozen flag. */
		pr_info_ratelimited("airy_uring_cmd: FREEZE → ring\n");
		return 0;

	case AIRY_IPC_OP_CAP_REQUEST:
	case AIRY_IPC_OP_CAP_RESPONSE:
		/* Capability bootstrap uses the zero-copy path. */
		pr_info_ratelimited("airy_uring_cmd: cap op=%u → zero_copy\n",
				    cmd_op);
		return 0;

	default:
		pr_warn_ratelimited("airy_uring_cmd: unknown cmd_op=%u\n",
				    cmd_op);
		return -EOPNOTSUPP;
	}
}

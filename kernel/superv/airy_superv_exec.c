// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_exec.c — execution entry for [IND] supervisor commands.
 *
 * macro_d reaches the kernel through the io_uring data plane, but the
 * supervisor opcodes are not part of the agent-facing IPC fabric:
 * they sit outside the [SC] AIRY_IPC_OP_* namespace, where the plane
 * and permission classifiers deliberately report them as invalid. This
 * file is the one place that turns such a command into a ring or task
 * state change, so the [IND] contract has a single authority check and
 * a single dispatch table instead of one per transport.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/sched.h>

#include <linux/airymax/error.h>
#include <linux/airymax/security_types.h>

#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

/*
 * airy_sv_exec - execute one [IND] supervisor command.
 * @cap: badge presented by the caller.
 * @ctx: protocol context.
 * @cmd: shape-checked command.
 *
 * Return: 0 on success, else the negated error of the first failed
 *         check or of the dispatched command.
 */
int airy_sv_exec(airy_cap_t cap, struct airy_sv_ctx *ctx,
		 const struct airy_superv_cmd *cmd)
{
	int ret;

	ret = airy_sv_cmd_chk(cmd);
	if (unlikely(ret))
		return ret;

	if (unlikely(!airy_sv_ready(ctx)))
		return -EAGAIN;

	ret = airy_cap_badge_ok(cap, airy_agent_id(current),
				AIRY_CAP_PERM_SUPERVISE);
	if (unlikely(ret))
		return ret;

	switch (cmd->opcode) {
	case AIRY_IPC_OP_ADJUDICATE:
		return airy_sv_adjud(ctx, cmd->agent_id, cmd->adjud,
				     cmd->reason);
	case AIRY_IPC_OP_UNFREEZE:
		return airy_sv_thaw(ctx, cmd->agent_id);
	case AIRY_IPC_OP_HEARTBEAT:
		airy_wdog_beat();
		return 0;
	default:
		return -AIRY_EIPC_OPCODE;
	}
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_proto.c — Micro-Supervisor protocol state and command check.
 *
 * Owns the lifecycle state of the supervision protocol and the shape
 * check every macro_d command passes before any ring or task state is
 * touched. Execution of the commands themselves belongs to the later
 * freeze/thaw/adjudication slices, so this file stays free of policy.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md
 */

#include <asm/barrier.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/lsm_types.h>

#include "airy_superv.h"

static struct airy_sv_ctx airy_sv_global;

/*
 * airy_sv_ctx - global protocol context.
 *
 * Return: the singleton owned by this module; never NULL, so callers may
 *         pass the result to airy_sv_ready() without a second check.
 */
struct airy_sv_ctx *airy_sv_ctx(void)
{
	return &airy_sv_global;
}

/*
 * airy_sv_start - bring a protocol context to RUNNING.
 * @ctx: context to initialise.
 *
 * Return: 0 on success; -EINVAL when @ctx is NULL.
 */
int airy_sv_start(struct airy_sv_ctx *ctx)
{
	if (unlikely(!ctx))
		return -EINVAL;

	smp_store_release(&ctx->state, AIRY_SV_RUNNING);

	return 0;
}

/*
 * airy_sv_ready - is the protocol layer accepting commands?
 * @ctx: context to test; may be NULL.
 *
 * Return: true only when @ctx is in AIRY_SV_RUNNING.
 */
bool airy_sv_ready(const struct airy_sv_ctx *ctx)
{
	return ctx && smp_load_acquire(&ctx->state) == AIRY_SV_RUNNING;
}

/*
 * airy_sv_cmd_chk - validate the shape of a macro_d command.
 * @cmd: command copied from user space.
 *
 * Pure shape check; readiness and the caller's SUPERVISE badge are
 * enforced by the dispatch entry. The agent bound is checked before the
 * opcode so an out-of-range target is reported as such even when the
 * opcode is also bad: the target is the field that would be indexed.
 *
 * Return: 0 when @cmd is well formed, else the negated error magnitude.
 */
int airy_sv_cmd_chk(const struct airy_superv_cmd *cmd)
{
	if (unlikely(!cmd))
		return -EINVAL;

	if (unlikely(cmd->agent_id >= AIRY_CAP_MAX_AGENTS))
		return -AIRY_ECAP_OVERFLOW;

	switch (cmd->opcode) {
	case AIRY_IPC_OP_ADJUDICATE:
		if (unlikely(cmd->adjud >= AIRY_ADJUD_NR))
			return -EINVAL;
		return 0;
	case AIRY_IPC_OP_UNFREEZE:
		if (unlikely(cmd->adjud))
			return -EINVAL;
		return 0;
	default:
		return -AIRY_EIPC_OPCODE;
	}
}

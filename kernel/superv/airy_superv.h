/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv.h — Micro-Supervisor internal protocol contract.
 *
 * Declares the supervision protocol runtime state and the shape check
 * every macro_d command passes before it may touch a ring or a task.
 * The wire format itself is [IND] layer and lives in the UAPI header
 * <linux/airymax/superv.h>.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md
 */

#ifndef _AIRY_SUPERV_H
#define _AIRY_SUPERV_H

#include <linux/types.h>

#include <linux/airymax/superv.h>

/**
 * enum airy_sv_state - lifecycle state of the protocol layer
 * @AIRY_SV_IDLE: commands are refused; hooks are not yet in place
 * @AIRY_SV_RUNNING: the layer accepts macro_d commands
 */
enum airy_sv_state {
	AIRY_SV_IDLE	 = 0,
	AIRY_SV_RUNNING	 = 1,
};

/**
 * struct airy_sv_ctx - protocol layer runtime state
 * @state: one of &enum airy_sv_state
 *
 * A command that arrives before the late_initcall has brought the layer
 * up must be refused rather than dispatched into a half-built ring, so
 * the state is published with release semantics and read with acquire
 * semantics (OS-KER-225: validation before mutation).
 */
struct airy_sv_ctx {
	u32 state;
};

/**
 * airy_sv_start() - bring a protocol context to RUNNING
 * @ctx: context to initialise; may be the global context or a local one
 *
 * Return: 0 on success; -EINVAL when @ctx is NULL.
 */
int airy_sv_start(struct airy_sv_ctx *ctx);

/**
 * airy_sv_ctx() - global protocol context
 *
 * Return: the singleton context owned by kernel/kernel/superv/.
 */
struct airy_sv_ctx *airy_sv_ctx(void);

/**
 * airy_sv_ready() - is the protocol layer accepting commands?
 * @ctx: context to test; may be NULL
 *
 * Return: true when @ctx is in &AIRY_SV_RUNNING; false otherwise,
 *         including a NULL context.
 */
bool airy_sv_ready(const struct airy_sv_ctx *ctx);

/**
 * airy_sv_cmd_chk() - validate the shape of a macro_d command
 * @cmd: command copied from user space
 *
 * Shape only: the caller's SUPERVISE badge and the protocol readiness
 * gate are enforced by the dispatch entry. Keeping the two concerns
 * apart leaves this check pure, so it is callable from KUnit without a
 * live supervisor. Checks run in a fixed order, making the first
 * failure the reported error:
 *
 *   - a NULL command is a caller bug (-EINVAL)
 *   - an agent id at or above AIRY_CAP_MAX_AGENTS would index outside
 *     the capability array (-AIRY_ECAP_OVERFLOW)
 *   - an opcode outside the [IND] supervisor pair is not a supervision
 *     command (-AIRY_EIPC_OPCODE)
 *   - ADJUDICATE must carry a valid &enum airy_adjud (-EINVAL)
 *   - UNFREEZE carries no verdict, so its adjud field must be zero
 *     (-EINVAL)
 *
 * @reason is deliberately unvalidated: it is diagnostic context copied
 * into logs and fault records, never used to select a code path.
 *
 * Return: 0 when @cmd is well formed; otherwise the negated magnitude
 *         listed above.
 */
int airy_sv_cmd_chk(const struct airy_superv_cmd *cmd);

#endif /* _AIRY_SUPERV_H */

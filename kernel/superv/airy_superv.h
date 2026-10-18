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

#include <linux/airymax/security_types.h>
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

struct task_struct;

/**
 * typedef airy_sv_task_fn - callback applied to one matching task
 * @task: task pinned for the duration of the callback
 * @arg: caller context passed through airy_sv_walk()
 *
 * The callback runs under the RCU read lock with the task pinned, so
 * it must not sleep: ring state changes, signal delivery and priority
 * changes are safe; anything taking a mutex is not.
 */
typedef void (*airy_sv_task_fn)(struct task_struct *task, void *arg);

/**
 * airy_sv_id_chk() - reject agent ids outside the supervised range
 * @agent_id: id copied from a command
 *
 * Zero is the unbound sentinel: a task that never joined an agent
 * carries it, so a command naming zero can never match.  The upper
 * bound keeps every use of the id inside agent_caps[].
 *
 * Return: 0 when @agent_id names a possible agent; -EINVAL when it is
 *         zero; -AIRY_ECAP_OVERFLOW when it is outside the agent range.
 */
int airy_sv_id_chk(__u32 agent_id);

/**
 * airy_sv_walk() - apply a callback to every task of an agent
 * @agent_id: agent whose tasks are visited; must already be validated
 * @fn: callback invoked once per matching task; must not sleep
 * @arg: opaque pointer handed to @fn
 *
 * The walk holds the RCU read lock and pins each matching task, so the
 * callback may read and write the task blob and its ring without
 * racing against task exit.
 *
 * Return: the number of tasks that matched @agent_id.
 */
unsigned int airy_sv_walk(__u32 agent_id, airy_sv_task_fn fn, void *arg);

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

/**
 * airy_sv_freeze() - freeze every IPC ring owned by an agent
 * @ctx: protocol context; commands are refused unless it is RUNNING
 * @agent_id: target agent; zero is the unbound sentinel and is refused
 * @reason: AIRY_FAULT_* code recorded in each ring and in the event
 *
 * A command names an agent, not a task.  An agent may spread over
 * several tasks and every task owns its own ring, so all of them are
 * frozen before the call reports success.  Freezing an already frozen
 * ring is a no-op that still counts, which makes a retried command
 * succeed without special-casing the retry.
 *
 * There is no agent id to task index in the kernel and the capability
 * slot carries no task pointer, so the rings are located by walking
 * the process list under RCU and matching the agent id in each task's
 * security blob.  Freezing is a cold, supervisor-initiated path; the
 * walk costs nothing on the IPC fastpath and adds no per-task index
 * that would need to be kept in step with fork and exit.
 *
 * One eventfd notification is posted per command, not per ring: the
 * counter carries a single (agent id, fault code) pair, so a second
 * post for the same command would only duplicate the wakeup.
 *
 * Return: 0 when at least one ring was frozen; -EINVAL when @agent_id
 *         is zero; -AIRY_ECAP_OVERFLOW when it is outside the agent
 *         range; -EAGAIN when @ctx is not RUNNING; -AIRY_EIPC_CONTEXT
 *         when no task carries @agent_id or none of them owns a ring.
 */
int airy_sv_freeze(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 reason);

/**
 * airy_sv_frz() - freeze every IPC ring of an agent without notifying
 * @agent_id: target agent; zero is refused
 * @reason: AIRY_FAULT_* code recorded in each ring
 *
 * Kernel half of airy_sv_freeze(), split out so the adjudication path
 * can contain an agent without echoing a second fault notification for
 * a verdict it is already reporting.
 *
 * Return: 0 when at least one ring was frozen; -EINVAL when @agent_id
 *         is zero; -AIRY_ECAP_OVERFLOW when it is outside the agent
 *         range; -AIRY_EIPC_CONTEXT when no task carries @agent_id or
 *         none of them owns a ring.
 */
int airy_sv_frz(__u32 agent_id, __u32 reason);

/**
 * airy_sv_thaw() - thaw every IPC ring owned by an agent
 * @ctx: protocol context; commands are refused unless it is RUNNING
 * @agent_id: target agent; zero is the unbound sentinel and is refused
 *
 * Thawing is not the isolated inverse of a freeze: the design requires
 * every outstanding badge to be retired before traffic resumes, so the
 * global epoch is bumped once the ring set is known to exist and before
 * any ring is reopened.  A thaw for an agent that owns no ring must not
 * revoke the badges of the whole system, hence the probe pass that
 * counts rings without touching them.
 *
 * Freeze and thaw share one mutex.  It is the kernel half of the sec_d
 * serialisation the design asks for: without it a thaw could land
 * between a freeze and the eventfd notification for that freeze and
 * silently undo a freeze already reported as successful.
 *
 * Return: 0 when at least one ring was thawed; -EINVAL when @agent_id
 *         is zero; -AIRY_ECAP_OVERFLOW when it is outside the agent
 *         range; -EAGAIN when @ctx is not RUNNING; -AIRY_EIPC_CONTEXT
 *         when no task carries @agent_id or none of them owns a ring.
 */
int airy_sv_thaw(struct airy_sv_ctx *ctx, __u32 agent_id);

/**
 * airy_sv_adjud() - apply a supervisor verdict to every task of an agent
 * @ctx: protocol context; commands are refused unless it is RUNNING
 * @agent_id: target agent; zero is refused
 * @adjud: one of &enum airy_adjud; AIRY_ADJUD_NR is refused
 * @reason: diagnostic context recorded in logs and the trace event
 *
 * WARN only records the verdict.  DEGRADE lowers the scheduling weight
 * so a misbehaving task yields sooner.  PAUSE stops the task and marks
 * the blob STOPPED.  TERMINATE retires the badge and freezes the rings
 * before killing, so a task never runs with a badge that has already
 * been revoked.  RESUME restores a paused task to READY and undoes the
 * degraded weight.
 *
 * Return: 0 when at least one task carried @agent_id; -EINVAL for a
 *         zero id or an out-of-range verdict; -AIRY_ECAP_OVERFLOW for
 *         an id outside the agent range; -EAGAIN when @ctx is not
 *         RUNNING; -AIRY_EIPC_CONTEXT when no task carries @agent_id.
 */
int airy_sv_adjud(struct airy_sv_ctx *ctx, __u32 agent_id, __u32 adjud,
		  __u32 reason);

/**
 * airy_sv_exec() - execute one [IND] supervisor command
 * @cap: badge presented by the caller (macro_d)
 * @ctx: protocol context; commands are refused unless it is RUNNING
 * @cmd: command copied from user space; shape-checked before dispatch
 *
 * The single execution entry for the [IND] supervisor opcode pair.
 * Those opcodes live outside the [SC] AIRY_IPC_OP_* namespace on
 * purpose, so airy_op_plane() and airy_op_required_perms() classify
 * them as invalid and the syscall 548 dispatcher never sees them.
 * This entry therefore performs its own authorisation instead of
 * reusing the [SC] classifier.
 *
 * Checks run in a fixed order, making the first failure the reported
 * error: command shape, protocol readiness (-EAGAIN), then the
 * caller's SUPERVISE authority.  The caller identity is read from
 * current, never from @cmd, so a well-formed command cannot name its
 * own authority: @cmd->agent_id is only ever the target.
 *
 * Return: 0 when the command was executed; otherwise the negated
 *         magnitude of the first failed check, or the target error
 *         (-AIRY_EIPC_CONTEXT when no task carries @cmd->agent_id).
 */
int airy_sv_exec(airy_cap_t cap, struct airy_sv_ctx *ctx,
		 const struct airy_superv_cmd *cmd);

#endif /* _AIRY_SUPERV_H */

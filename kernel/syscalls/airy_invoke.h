/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * kernel/kernel/syscalls/airy_invoke.h
 *
 * Control-plane invocation dispatch contract for syscall 548
 * (airy_sys_call). The dispatch key is the single dimension
 * msg->opcode, whose authoritative values are the [SC]
 * AIRY_IPC_OP_* macros in <linux/airymax/ipc.h>; this header
 * declares the dispatch skeleton but never redefines them.
 * High-rate IPC data moves through io_uring (IORING_OP_URING_CMD)
 * and does not enter this path.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.2.
 */

#ifndef _AIRY_INVOKE_H
#define _AIRY_INVOKE_H

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/security_types.h>

/* ─── Invocation context ─────────────────────────────────────────────── */
/**
 * struct airy_invoke_ctx - per-request context for syscall 548 dispatch
 * @cap:    Capability badge presented by the caller (airy_cap_t).
 * @opcode: Dispatch key, copied from the validated msg->opcode.
 * @msg:    Caller message header, already copied into kernel memory.
 *
 * Bundles the immutable inputs of a single airy_sys_call() request so
 * that dispatch handlers share one argument. It is filled only after
 * the message header has passed validation (OS-KER-225).
 */
struct airy_invoke_ctx {
	airy_cap_t cap;
	u16 opcode;
	const struct airy_ipc_msg_hdr *msg;
};

/* ─── Dispatch entry points (defined in airy_syscalls.c) ─────────────── */
/**
 * airy_invoke_op_valid() - test whether an opcode is dispatchable
 * @opcode: IPC opcode taken from the [SC] ipc.h AIRY_IPC_OP_* space.
 *
 * Tells the caller whether @opcode belongs to the control-plane
 * dispatch set. Unknown opcodes must be rejected with -EINVAL before
 * any state is touched.
 *
 * Return: true if @opcode is dispatchable, false otherwise.
 */
bool airy_invoke_op_valid(u16 opcode);

/**
 * airy_invoke_dispatch() - validate and dispatch a syscall 548 request
 * @cap: Capability badge presented by the caller.
 * @msg: Kernel-resident copy of the caller message header.
 *
 * Validates the opcode contract and the capability badge, then routes
 * the request to the matching control-plane handler. Validation always
 * precedes mutation (OS-KER-225). The badge is checked with
 * airy_cap_badge_ok() against the caller's own capability slot, whose
 * agent_id is derived from current — never from the caller-supplied
 * msg->src_task/dst_task, which are untrusted.
 *
 * Return: 0 on success; -EINVAL on a malformed or unknown opcode;
 *         -AIRY_ECAP_* when badge validation fails; -ENOSYS while the
 *         handler for a valid opcode has not yet landed.
 */
__must_check int airy_invoke_dispatch(airy_cap_t cap,
				      const struct airy_ipc_msg_hdr *msg);

#endif /* _AIRY_INVOKE_H */

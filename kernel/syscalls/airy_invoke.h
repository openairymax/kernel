/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
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

/* Opcode permission mapping */
/*
 * Sentinel returned by airy_op_required_perms() for an opcode that is
 * not part of the dispatch contract. It lies outside the AIRY_CAP_PERM_*
 * space (the widest real mask is AIRY_CAP_PERM_ALL == 0x007F) so it can
 * never be mistaken for a grantable permission mask.
 */
#define AIRY_OP_PERMS_INVALID	0xFFFFu

/**
 * airy_op_required_perms() - map an IPC opcode to its required permissions
 * @opcode: Dispatch key from the [SC] AIRY_IPC_OP_* space.
 *
 * Side-effect-free translation of a control-plane opcode into the
 * capability permission mask the caller must hold. The result is fed to
 * airy_cap_badge_ok() so that authorization, not merely badge
 * authenticity, is enforced before any handler runs. It is also the
 * single source of truth for which opcodes are dispatchable at all:
 * airy_invoke_op_valid() accepts exactly the opcodes that do not map to
 * AIRY_OP_PERMS_INVALID.
 *
 * SEND, SEND_BATCH and CANCEL operate on the IPC stream and require
 * AIRY_CAP_PERM_SEND; RECV requires AIRY_CAP_PERM_RECV; FREEZE is a
 * supervisory action requiring AIRY_CAP_PERM_SUPERVISE. The capability
 * bootstrap pair CAP_REQUEST/CAP_RESPONSE carries no permission of its
 * own and maps to AIRY_CAP_PERM_NONE. Every other opcode yields
 * AIRY_OP_PERMS_INVALID.
 *
 * SSoT: 110-security/03-capability-model.md §2.6.1.
 *
 * Return: the required permission mask, or AIRY_OP_PERMS_INVALID when
 *         @opcode is outside the dispatch contract.
 */
static inline u16 airy_op_required_perms(u16 opcode)
{
	/* Indexed by (opcode - AIRY_IPC_OP_SEND); holes are rejected. */
	static const u16 op_perms[] = {
		AIRY_CAP_PERM_SEND,	 /* AIRY_IPC_OP_SEND       0x0001 */
		AIRY_CAP_PERM_RECV,	 /* AIRY_IPC_OP_RECV       0x0002 */
		AIRY_CAP_PERM_SEND,	 /* AIRY_IPC_OP_SEND_BATCH 0x0003 */
		AIRY_CAP_PERM_SEND,	 /* AIRY_IPC_OP_CANCEL     0x0004 */
		AIRY_CAP_PERM_SUPERVISE, /* AIRY_IPC_OP_FREEZE     0x0005 */
	};

	if (opcode >= AIRY_IPC_OP_SEND && opcode <= AIRY_IPC_OP_FREEZE)
		return op_perms[opcode - AIRY_IPC_OP_SEND];

	if (opcode == AIRY_IPC_OP_CAP_REQUEST ||
	    opcode == AIRY_IPC_OP_CAP_RESPONSE)
		return AIRY_CAP_PERM_NONE;

	return AIRY_OP_PERMS_INVALID;
}

/* Message header contract validation */
/**
 * airy_invoke_hdr_check() - validate the fixed 128-byte IPC message header
 * @hdr: Kernel-resident copy of the caller message header.
 *
 * Enforces the [SC] Layout C v4 field contract that the syscall 548 entry
 * rests on, and is the single choke point every header must pass before any
 * state is touched (OS-KER-225). Four checks are applied, cheapest first:
 *
 *   - C-S1:  magic must equal AIRY_IPC_MAGIC, otherwise the buffer is not a
 *            Layout C v4 header at all (-AIRY_EIPC_MAGIC).
 *   - C-S3:  payload_len must not exceed AIRY_IPC_MAX_PAYLOAD
 *            (-AIRY_EIPC_PAYLOAD). The data plane would otherwise be asked
 *            to frame a payload that no legal message can carry.
 *   - C-S10: the reserved flag bits (AIRY_IPC_FLAG_RESERVED, bits 5-15)
 *            must be zero (-AIRY_EIPC_FLAGS), and the declared-but-unimpl-
 *            emented ENCRYPT/COMPRESS features must not be requested
 *            (-AIRY_EIPC_NOTSUPP). Either one would let a caller assert a
 *            guarantee the kernel does not honour.
 *   - C-S4:  reserved[72] must be all zero (-AIRY_EIPC_RESERVED), keeping
 *            the header a closed contract and denying a covert channel
 *            through fields the kernel never interprets.
 *
 * The opcode is deliberately not checked here: its validity is owned by
 * airy_op_required_perms()/airy_invoke_op_valid() so that the dispatchable
 * set has exactly one definition (see airy_invoke_dispatch()).
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1 (C-S1/C-S3/C-S4/C-S10);
 *       30-interfaces/08-sc-error-contract.md §2.3 (error magnitudes).
 *
 * Return: AIRY_EOK (0) when @hdr satisfies the contract; -EINVAL when @hdr
 *         is NULL; otherwise the negated [SC] AIRY_EIPC_* magnitude.
 */
__must_check int airy_invoke_hdr_check(const struct airy_ipc_msg_hdr *hdr);

/* Invocation context */
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

/* Dispatch entry points (defined in airy_syscalls.c) */
/**
 * airy_invoke_op_valid() - test whether an opcode is dispatchable
 * @opcode: IPC opcode taken from the [SC] ipc.h AIRY_IPC_OP_* space.
 *
 * Tells the caller whether @opcode belongs to the control-plane
 * dispatch set. Unknown opcodes must be rejected with -AIRY_EIPC_OPCODE
 * before any state is touched.
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
 * msg->src_task/dst_task, which are untrusted. The permission mask the
 * badge must carry is derived from the opcode by
 * airy_op_required_perms(), so a badge that is authentic but lacks the
 * operation's permission is rejected with -AIRY_ECAP_PERM.
 *
 * Return: 0 on success; -AIRY_EIPC_OPCODE on a malformed or unknown
 *         opcode; -AIRY_ECAP_* when badge validation fails;
 *         -AIRY_ENOTSUP while the handler for a valid opcode has not
 *         yet landed.
 */
__must_check int airy_invoke_dispatch(airy_cap_t cap,
				      const struct airy_ipc_msg_hdr *msg);

#endif /* _AIRY_INVOKE_H */

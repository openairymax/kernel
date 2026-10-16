/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Control-plane invocation dispatch contract for syscall 548
 * (airy_sys_call). The dispatch key is the single dimension
 * msg->opcode, whose authoritative values are the [SC]
 * AIRY_IPC_OP_* macros in <linux/airymax/ipc.h>; this header
 * never redefines them. Those values span three planes — CTL
 * (served here), DATA (io_uring IORING_OP_URING_CMD) and BOOT
 * (the io_uring_cmd capability bootstrap) — so 548 answers only
 * its own plane instead of standing in for the others.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.1-§4.2.
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
 * authenticity, is enforced before any handler runs. Which opcodes are
 * dispatchable at all is owned by airy_op_plane(); this mapping only
 * answers what an already-recognised opcode demands.
 *
 * SEND, SEND_BATCH and CANCEL operate on the IPC stream and require
 * AIRY_CAP_PERM_SEND; RECV requires AIRY_CAP_PERM_RECV; FREEZE is a
 * supervisory action requiring AIRY_CAP_PERM_SUPERVISE.
 *
 * CAP_RESPONSE installs a compiled badge into another agent's slot, so it
 * is a supervisory action too and also requires AIRY_CAP_PERM_SUPERVISE.
 * Syscall 548 is the sec_d-only capability management entry
 * (30-interfaces/01-syscalls.md §1.4); mapping CAP_RESPONSE to
 * AIRY_CAP_PERM_NONE would let any registered agent mint a badge for any
 * peer and would turn the entry into a privilege-escalation primitive.
 * CAP_REQUEST is the unprivileged half of that pair — the requester holds
 * no capability yet — and maps to AIRY_CAP_PERM_NONE. Every other opcode
 * yields AIRY_OP_PERMS_INVALID.
 *
 * SSoT: 110-security/03-capability-model.md §2.6.1 (badge composition);
 *       30-interfaces/01-syscalls.md §1.4 (sec_d-only management entry).
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

	switch (opcode) {
	case AIRY_IPC_OP_CAP_REQUEST:
		return AIRY_CAP_PERM_NONE;
	case AIRY_IPC_OP_CAP_RESPONSE:
		return AIRY_CAP_PERM_SUPERVISE;
	default:
		return AIRY_OP_PERMS_INVALID;
	}
}

/* Opcode plane classification */
/*
 * The [SC] AIRY_IPC_OP_* values are not all served by syscall 548; they
 * split by ownership into three planes, and a fourth state for values
 * outside the contract. Keeping the split explicit stops 548 from being
 * read as the owner of every opcode, and stops a future edit from
 * believing a data- or bootstrap-plane opcode is merely "not yet
 * implemented here".
 *
 *   CTL  — capability management served by 548 itself;
 *   DATA — IPC stream transfer owned by the io_uring data plane, whose
 *          C-S9 inline Badge check authorises independently of 548;
 *   BOOT — capability bootstrap served by the io_uring_cmd path
 *          (airy_cap_check.c phase2_cap_request), never by 548;
 *   INVALID — outside the [SC] AIRY_IPC_OP_* dispatch contract.
 */
enum airy_plane {
	AIRY_PLANE_CTL,
	AIRY_PLANE_DATA,
	AIRY_PLANE_BOOT,
	AIRY_PLANE_INVALID,
};

/**
 * airy_op_plane() - classify an opcode by the plane that serves it
 * @opcode: Dispatch key from the [SC] AIRY_IPC_OP_* space.
 *
 * Pure classifier with no state and no dependency on current, so KUnit
 * drives it directly and airy_invoke_op_valid() can delegate to it. It
 * is the single source of truth for opcode validity: an opcode is
 * dispatchable exactly when its plane is not AIRY_PLANE_INVALID.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.1-§4.2
 *       (op-dispatch principle and data-plane cmd_op ownership).
 *
 * Return: the plane that owns @opcode, or AIRY_PLANE_INVALID when it is
 *         not part of the dispatch contract.
 */
static inline enum airy_plane airy_op_plane(u16 opcode)
{
	switch (opcode) {
	case AIRY_IPC_OP_FREEZE:
	case AIRY_IPC_OP_CAP_RESPONSE:
		return AIRY_PLANE_CTL;
	case AIRY_IPC_OP_SEND:
	case AIRY_IPC_OP_RECV:
	case AIRY_IPC_OP_SEND_BATCH:
	case AIRY_IPC_OP_CANCEL:
		return AIRY_PLANE_DATA;
	case AIRY_IPC_OP_CAP_REQUEST:
		return AIRY_PLANE_BOOT;
	default:
		return AIRY_PLANE_INVALID;
	}
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
 * airy_op_plane()/airy_invoke_op_valid() so that the dispatchable set has
 * exactly one definition (see airy_invoke_dispatch()).
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1 (C-S1/C-S3/C-S4/C-S10);
 *       30-interfaces/08-sc-error-contract.md §2.3 (error magnitudes).
 *
 * Return: AIRY_EOK (0) when @hdr satisfies the contract; -EINVAL when @hdr
 *         is NULL; otherwise the negated [SC] AIRY_EIPC_* magnitude.
 */
__must_check int airy_invoke_hdr_check(const struct airy_ipc_msg_hdr *hdr);

/* Dispatch entry points (defined in airy_syscalls.c) */
/**
 * airy_invoke_op_valid() - test whether an opcode is dispatchable
 * @opcode: IPC opcode taken from the [SC] ipc.h AIRY_IPC_OP_* space.
 *
 * Tells the caller whether @opcode belongs to the control-plane
 * dispatch set. Unknown opcodes must be rejected with -AIRY_EIPC_OPCODE
 * before any state is touched. Delegates to airy_op_plane() so the
 * dispatchable set has one definition.
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
 * Only the CTL plane is served here. A valid opcode owned by the data or
 * bootstrap plane is answered -AIRY_ENOTSUP: those planes carry their own
 * authorisation (the io_uring fastpath C-S9 inline Badge check and the
 * io_uring_cmd bootstrap respectively) and never route through 548, so
 * there is no handler to wait for.
 *
 * Return: 0 on success; -AIRY_EIPC_OPCODE for an opcode outside the
 *         [SC] AIRY_IPC_OP_* space; -AIRY_ECAP_* when badge validation
 *         fails; -AIRY_ENOTSUP for a valid opcode belonging to a plane
 *         this control-plane entry does not serve.
 */
__must_check int airy_invoke_dispatch(airy_cap_t cap,
				      const struct airy_ipc_msg_hdr *msg);

/* Control-plane handlers (defined in airy_syscalls.c) */
/**
 * airy_badge_install() - install a sec_d-compiled badge into an agent slot
 * @msg: Kernel-resident copy of the caller message header. Only
 *       @capability_badge and @dst_task are read; the rest of the header
 *       contract is enforced by airy_invoke_dispatch() before the call.
 *
 * Handler for AIRY_IPC_OP_CAP_RESPONSE, the sec_d half of the capability
 * bootstrap pair (COMPILE_BADGE in
 * 140-application-development/07-syscall-registry.md §4.2). It validates
 * the shape of the compiled badge, requires its epoch to agree with the
 * target slot's live epoch — which is what denies epoch regression and
 * the resurrection of a revoked capability — and then hands the slot
 * write to airy_cap_register().
 *
 * Exposed to KUnit so the badge install contract has a direct test hook;
 * it is not a second dispatch entry point.
 *
 * Return: AIRY_EOK on success; -EINVAL when @msg is NULL; -AIRY_ECAP_*
 *         for an out-of-range target or a malformed/stale badge;
 *         -AIRY_EEXIST when the target slot is already occupied.
 */
__must_check int airy_badge_install(const struct airy_ipc_msg_hdr *msg);

/**
 * airy_badge_revoke() - revoke an agent's badge and its derived subtree
 * @msg: Kernel-resident copy of the caller message header. Only @dst_task
 *       is read; the rest of the header contract is enforced by
 *       airy_invoke_dispatch() before the call.
 *
 * Handler for AIRY_IPC_OP_FREEZE, the control-plane carrier for
 * REVOKE_BADGE in 140-application-development/07-syscall-registry.md §4.2.
 * @dst_task names the root of the revocation subtree; the cascade itself —
 * bump the root's epoch, clear its RandomTag and repeat for every
 * revocable descendant — is delegated to airy_cap_derive() so the
 * derivation tree has a single revocation authority
 * (110-security/03-capability-model.md §3.5).
 *
 * Exposed to KUnit so the revocation contract has a direct test hook; it
 * is not a second dispatch entry point.
 *
 * Return: AIRY_EOK on success; -EINVAL when @msg is NULL;
 *         -AIRY_ECAP_OVERFLOW for an out-of-range target; -AIRY_ECAP_MISSING
 *         when the target has no registered badge.
 */
__must_check int airy_badge_revoke(const struct airy_ipc_msg_hdr *msg);

#endif /* _AIRY_INVOKE_H */

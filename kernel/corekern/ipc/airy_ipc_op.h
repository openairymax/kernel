/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_op.h — opcode contract shared by the control and data planes.
 *
 * Syscall 548 and the io_uring data plane both key their dispatch on the
 * [SC] AIRY_IPC_OP_* space, so the plane classifier and the permission
 * mapping live here, below both, and are included rather than copied.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.1-§4.2;
 *       110-security/03-capability-model.md §2.6.1.
 */

#ifndef _AIRY_IPC_OP_H
#define _AIRY_IPC_OP_H

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

#endif /* _AIRY_IPC_OP_H */

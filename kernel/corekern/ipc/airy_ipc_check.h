/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check.h — Layout C v4 header contract shared by both planes.
 *
 * The io_uring data plane and syscall 548 consume the same 128-byte
 * header, so the field contract has exactly one implementation here.
 * airy_ipc_hdr_ok() covers the checks that depend only on the header;
 * airy_ipc_validate() adds the context gate the data plane needs.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1.
 */

#ifndef _AIRY_IPC_CHECK_H
#define _AIRY_IPC_CHECK_H

#include <linux/compiler.h>
#include <linux/types.h>

#include <linux/airymax/ipc.h>

/**
 * airy_ipc_hdr_ok() - apply the plane-independent header field contract
 * @hdr: Kernel-resident copy of the message header.
 *
 * Runs the stateless field checks in the SSoT order: C-S1 magic, C-S2
 * opcode, C-S3 payload ceiling and C-S4 reserved tail. The magic test
 * comes first because a mismatched magic invalidates every later field;
 * the opcode test follows because the plane that raised the header
 * decides what the rest of the fields mean. C-S4's hdr_size half is
 * enforced at compile time by the 128-byte assertion in ipc.h, so only
 * the reserved tail needs a runtime scan.
 *
 * The caller-specific checks stay with each entry: context and Badge
 * (C-S8/C-S9) only make sense on the data plane, while the syscall
 * entry authenticates its badge from a syscall argument rather than
 * from the header.
 *
 * Return: AIRY_EOK (0) on success; -EINVAL when @hdr is NULL; otherwise
 *         the negated [SC] AIRY_EIPC_* magnitude of the failing check.
 */
__must_check int airy_ipc_hdr_ok(const struct airy_ipc_msg_hdr *hdr);

/**
 * airy_flags_ok() - apply the C-S10 flag contract
 * @hdr: Header already accepted by airy_ipc_hdr_ok().
 *
 * Kept separate from the field checks because C-S10 runs after the
 * Badge checkpoint C-S9 on the data plane, while the syscall entry
 * applies it directly after the field checks.
 *
 * Return: AIRY_EOK (0) on success; -AIRY_EIPC_FLAGS for a reserved flag
 *         bit; -AIRY_EIPC_NOTSUPP for ENCRYPT/COMPRESS.
 */
__must_check int airy_flags_ok(const struct airy_ipc_msg_hdr *hdr);

/**
 * airy_ipc_validate() - run the fastpath checks the header can decide
 * @hdr: Kernel-resident copy of the message header.
 *
 * Executes C-S1..C-S4, C-S8 and C-S10 in the order 07-ipc-fastpath.md
 * §3.1 fixes, so the first failing check is also the reported error.
 * The ring-bound checks (C-S0, C-S5..C-S7, C-S11, C-S12) stay with the
 * data-plane entry, which is the only caller that owns a ring.
 *
 * Return: AIRY_EOK (0) on success; -EINVAL when @hdr is NULL; otherwise
 *         the negated [SC] AIRY_EIPC_* magnitude of the failing check.
 */
__must_check int airy_ipc_validate(const struct airy_ipc_msg_hdr *hdr);

#endif /* _AIRY_IPC_CHECK_H */

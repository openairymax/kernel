/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check.h — Layout C v4 header contract shared by both planes.
 *
 * The io_uring data plane and syscall 548 consume the same 128-byte
 * header, so the field contract has exactly one implementation here and
 * both entries call it instead of carrying their own copy.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1.
 */

#ifndef _AIRY_IPC_CHECK_H
#define _AIRY_IPC_CHECK_H

#include <linux/compiler.h>
#include <linux/types.h>

#include <linux/airymax/ipc.h>

/**
 * airy_ipc_hdr_ok() - apply the Layout C v4 field contract
 * @hdr: Kernel-resident copy of the message header.
 *
 * Runs the stateless part of the fastpath chain, cheapest first: C-S1
 * magic, C-S3 payload ceiling, C-S10 flag contract and C-S4 reserved
 * tail. The opcode plane (C-S2) and the call-site dependent checks
 * (context, Badge, digest) stay with each entry, because only it knows
 * which plane and which kernel context the header arrived from.
 *
 * Return: AIRY_EOK (0) on success; -EINVAL when @hdr is NULL; otherwise
 *         the negated [SC] AIRY_EIPC_* magnitude of the failing check.
 */
__must_check int airy_ipc_hdr_ok(const struct airy_ipc_msg_hdr *hdr);

#endif /* _AIRY_IPC_CHECK_H */

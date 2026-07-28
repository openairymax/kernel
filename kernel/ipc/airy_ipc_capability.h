/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_capability.h — IPC capability slowpath declarations.
 *
 * The authoritative capability types, global state, and fastpath
 * inline validation live in security/airy/airy_cap.h.  This file
 * declares only the slowpath wrappers that are specific to the
 * IPC control plane.
 */

#ifndef _AIRY_IPC_CAPABILITY_H
#define _AIRY_IPC_CAPABILITY_H

#include <linux/types.h>
#include <linux/compiler.h>

/* Pull in authoritative types + fastpath inline from security/airy/ */
#include "../../security/airy/airy_cap.h"

/* ─── Slowpath wrappers (defined in airy_ipc_capability.c) ───────────── */
int  airy_cap_badge_verify(u64 badge, u32 agent_id, __u16 expected_perms);
u64  airy_cap_epoch_bump(u32 agent_id);
void airy_cap_epoch_bump_all(void);

#endif /* _AIRY_IPC_CAPABILITY_H */

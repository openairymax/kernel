// SPDX-License-Identifier: GPL-2.0-only
/*
 * AirymaxOS ALK MemoryRoVol control entry behind syscall 549.
 *
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 549 carries one `op` argument that is the [SC] airy_rovol_op code of
 * memory_types.h. The snapshot/restore/migrate/staging engines that
 * would serve those operations belong to milestone M5, so this release
 * owns only the entry contract: refuse an undefined op, and answer a
 * recognised op with -AIRY_ENOTSUP rather than standing in for a backend
 * that is not built. See airy_rovol.h for the contract SSoT and
 * 20-modules/04-memory.md §4.8 for the milestone boundary.
 */

#include <linux/compiler.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/syscalls.h>

#include "airy_rovol.h"
#include "airy_sysabi.h"

/* ─── Syscall 549 entry policy ────────────────────────────────────────── */

/**
 * airy_rovol_serve - Serve the op half of syscall 549.
 * @op: MemoryRoVol operation code.
 *
 * Validates @op before anything else, so a value outside the [SC]
 * airy_rovol_op space is refused with -AIRY_EINVAL and never mistaken
 * for a recognised-but-unbuilt operation. A defined op reaches the
 * second answer: -AIRY_ENOTSUP, because the backend it names is a
 * milestone M5 deliverable (04-memory.md §4.8). Keeping the two
 * outcomes distinct lets a caller tell a malformed request from an
 * unavailable feature rather than guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_rovol_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_rovol_serve(__u32 op)
{
	if (unlikely(airy_op_check(AIRY_SYS_ROVOL_CTL, op)))
		return -AIRY_EINVAL;

	return -AIRY_ENOTSUP;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * AirymaxOS ALK sched_tac control entry behind syscall 550.
 *
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 550 carries one `op` argument that is the [SC] airy_sched_op code of
 * sched.h. The policy, budget, latency, priority, vtime and yield
 * backends that would serve those operations belong to milestone M3, so
 * this release owns only the entry contract: refuse an undefined op, and
 * answer a recognised op with -AIRY_ENOTSUP rather than standing in for
 * a backend that is not built. See airy_sched.h for the contract SSoT
 * and 20-modules/01-kernel.md §9.1 for the milestone boundary.
 */

#include <linux/compiler.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include "airy_sched.h"

/* ─── Syscall 550 entry policy ────────────────────────────────────────── */

/**
 * airy_sched_serve - Serve the op half of syscall 550.
 * @op: sched_tac operation code.
 *
 * Classifies @op before anything else, so a value outside the [SC]
 * airy_sched_op space is refused with -AIRY_EINVAL and never mistaken
 * for a recognised-but-unbuilt operation. A defined op reaches the
 * second answer: -AIRY_ENOTSUP, because the backend it names is a
 * milestone M3 deliverable (01-kernel.md §9.1). Keeping the two
 * outcomes distinct lets a caller tell a malformed request from an
 * unavailable feature rather than guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_sched_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_sched_serve(__u32 op)
{
	if (unlikely(airy_sched_kind(op) == AIRY_SCHED_CLASS_INVALID))
		return -AIRY_EINVAL;

	return -AIRY_ENOTSUP;
}

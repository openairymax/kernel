/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * sched_tac control contract for syscall 550 (airy_sys_sched_ctl). The
 * argument that carries meaning is `op`, the [SC] airy_sched_op code of
 * sched.h; 0 is invalid and every value below AIRY_SCHED_SET_POLICY or
 * at or above AIRY_SCHED_OP_MAX is refused. The policy, budget, latency,
 * priority, vtime and yield backends that would serve the recognised
 * operations belong to milestone M3, so this release answers them with
 * -AIRY_ENOTSUP instead of standing in for them.
 *
 * SSoT: 20-modules/01-kernel.md §9.1;
 *       140-application-development/07-syscall-registry.md §4.4;
 *       30-interfaces/10-sc-sched-extension.md.
 */

#ifndef _AIRY_SCHED_H
#define _AIRY_SCHED_H

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/airymax/sched.h>

/* Op-code classification */
/*
 * The `op` argument of syscall 550 is exactly the [SC] airy_sched_op
 * space. Making the boundary explicit stops a future edit from reading a
 * rejected operation as merely "not yet implemented here": an undefined
 * op is a caller contract violation, while a recognised op is a
 * capability this release has not built yet. The two must not be
 * collapsed.
 */
enum airy_sched_class {
	AIRY_SCHED_CLASS_OP,
	AIRY_SCHED_CLASS_INVALID,
};

/**
 * airy_sched_kind - classify the syscall 550 op argument
 * @op: Value taken from the 550 `op` argument.
 *
 * Pure classifier with no state and no dependency on current, so KUnit
 * drives it directly and the 550 entry uses it as its boundary check. It
 * is the single definition of which op values 550 accepts.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.4 (op table).
 *
 * Return: AIRY_SCHED_CLASS_OP when @op is a defined airy_sched_op,
 *         AIRY_SCHED_CLASS_INVALID otherwise.
 */
static inline enum airy_sched_class airy_sched_kind(__u32 op)
{
	if (op >= (__u32)AIRY_SCHED_SET_POLICY && op < (__u32)AIRY_SCHED_OP_MAX)
		return AIRY_SCHED_CLASS_OP;

	return AIRY_SCHED_CLASS_INVALID;
}

/* Entry point (defined in airy_sched.c) */
/**
 * airy_sched_serve - serve the op half of syscall 550
 * @op: sched_tac operation code.
 *
 * The single definition of the 550 entry decision, kept non-static so
 * KUnit drives it directly instead of through the syscall ABI. It
 * classifies @op with airy_sched_kind() first — validation precedes
 * mutation — so an undefined op is refused with -AIRY_EINVAL, the [SC]
 * magnitude for an invalid argument. A recognised op reaches the second
 * answer: -AIRY_ENOTSUP, because the policy/budget/latency/priority/
 * vtime/yield backend it names is a milestone M3 deliverable
 * (20-modules/01-kernel.md §9.1). Keeping the two outcomes distinct lets
 * a caller tell a malformed request from an unavailable feature instead
 * of guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_sched_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_sched_serve(__u32 op);

#endif /* _AIRY_SCHED_H */

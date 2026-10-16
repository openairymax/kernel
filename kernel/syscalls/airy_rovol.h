/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * MemoryRoVol (rotation/volume) control contract for syscall 549
 * (airy_sys_rovol_ctl). The argument that carries meaning is `op`, the
 * [SC] airy_rovol_op code of memory_types.h; 0 is invalid and every
 * value below AIRY_ROVOL_SNAPSHOT or at or above AIRY_ROVOL_OP_MAX is
 * refused. The snapshot/restore/migrate/staging backends that would
 * serve the recognised operations belong to milestone M5, so this
 * release answers them with -AIRY_ENOTSUP instead of standing in for
 * them.
 *
 * SSoT: 20-modules/04-memory.md §4.8;
 *       140-application-development/05-memory-rovol-api.md;
 *       140-application-development/07-syscall-registry.md §4.3.
 */

#ifndef _AIRY_ROVOL_H
#define _AIRY_ROVOL_H

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/airymax/memory_types.h>

/* Op-code classification */
/*
 * The `op` argument of syscall 549 is exactly the [SC] airy_rovol_op
 * space. Making the boundary explicit stops a future edit from reading
 * a rejected operation as merely "not yet implemented here": an
 * undefined op is a caller contract violation, while a recognised op is
 * a capability this release has not built yet. The two must not be
 * collapsed.
 */
enum airy_rovol_class {
	AIRY_ROVOL_CLASS_OP,
	AIRY_ROVOL_CLASS_INVALID,
};

/**
 * airy_rovol_kind - classify the syscall 549 op argument
 * @op: Value taken from the 549 `op` argument.
 *
 * Pure classifier with no state and no dependency on current, so KUnit
 * drives it directly and the 549 entry uses it as its boundary check. It
 * is the single definition of which op values 549 accepts.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §4.3 (op table).
 *
 * Return: AIRY_ROVOL_CLASS_OP when @op is a defined airy_rovol_op,
 *         AIRY_ROVOL_CLASS_INVALID otherwise.
 */
static inline enum airy_rovol_class airy_rovol_kind(__u32 op)
{
	if (op >= (__u32)AIRY_ROVOL_SNAPSHOT && op < (__u32)AIRY_ROVOL_OP_MAX)
		return AIRY_ROVOL_CLASS_OP;

	return AIRY_ROVOL_CLASS_INVALID;
}

/* Entry point (defined in airy_rovol.c) */
/**
 * airy_rovol_serve - serve the op half of syscall 549
 * @op: MemoryRoVol operation code.
 *
 * The single definition of the 549 entry decision, kept non-static so
 * KUnit drives it directly instead of through the syscall ABI. It
 * classifies @op with airy_rovol_kind() first — validation precedes
 * mutation — so an undefined op is refused with -AIRY_EINVAL, the [SC]
 * magnitude for an invalid argument. A recognised op reaches the second
 * answer: -AIRY_ENOTSUP, because the backend it names is a milestone M5
 * deliverable (20-modules/04-memory.md §4.8). Keeping the two outcomes
 * distinct lets a caller tell a malformed request from an unavailable
 * feature instead of guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_rovol_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_rovol_serve(__u32 op);

#endif /* _AIRY_ROVOL_H */

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

/* Entry point (defined in airy_rovol.c) */
/**
 * airy_rovol_serve - serve the op half of syscall 549
 * @op: MemoryRoVol operation code.
 *
 * The single definition of the 549 entry decision, kept non-static so
 * KUnit drives it directly instead of through the syscall ABI. It
 * validates @op against the syscall registry (airy_op_check()), so an
 * undefined op is refused with -AIRY_EINVAL, the [SC] magnitude for an
 * invalid argument, and is never mistaken for a recognised-but-unbuilt
 * operation. A recognised op reaches the second answer: -AIRY_ENOTSUP,
 * because the backend it names is a milestone M5 deliverable
 * (20-modules/04-memory.md §4.8). Keeping the two outcomes distinct
 * lets a caller tell a malformed request from an unavailable feature
 * instead of guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_rovol_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_rovol_serve(__u32 op);

#endif /* _AIRY_ROVOL_H */

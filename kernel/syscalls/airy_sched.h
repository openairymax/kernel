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

/* Entry point (defined in airy_sched.c) */
/**
 * airy_sched_serve - serve the op half of syscall 550
 * @op: sched_tac operation code.
 *
 * The single definition of the 550 entry decision, kept non-static so
 * KUnit drives it directly instead of through the syscall ABI. It
 * validates @op against the syscall registry (airy_op_check()), so an
 * undefined op is refused with -AIRY_EINVAL, the [SC] magnitude for an
 * invalid argument, and is never mistaken for a recognised-but-unbuilt
 * operation. A recognised op reaches the second answer: -AIRY_ENOTSUP,
 * because the backend it names is a milestone M3 deliverable
 * (20-modules/01-kernel.md §9.1). Keeping the two outcomes distinct
 * lets a caller tell a malformed request from an unavailable feature
 * instead of guessing.
 *
 * Return: -AIRY_EINVAL when @op is not a defined airy_sched_op;
 *         -AIRY_ENOTSUP for a recognised op whose backend is not built
 *         in this release.
 */
__must_check int airy_sched_serve(__u32 op);

#endif /* _AIRY_SCHED_H */

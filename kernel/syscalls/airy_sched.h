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

/*
 * 550 的两个文本参数（cgroup 路径与策略标识）在进入内核前必须有界
 * 复制并逐序列校验。4096 是 PATH_MAX，覆盖最长 cgroup 路径；更大的
 * 输入按 -AIRY_EINVAL 拒绝，而不是静默截断。
 */
#define AIRY_SCHED_ARG_MAX	4096

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

/**
 * airy_sched_chk - validate one NUL-terminated kernel string
 * @s: string already copied into kernel space.
 *
 * The policy shared by both 550 text arguments, kept separate from the
 * copy so that its entire decision can be exercised without a user
 * pointer. A NULL string is refused with -AIRY_EINVAL instead of being
 * dereferenced; a non-NULL string is scanned once as strict UTF-8.
 *
 * Return: AIRY_EOK when @s is valid UTF-8, -AIRY_EINVAL for a NULL
 *         string, otherwise the -AIRY_EENC_* code of the first
 *         malformed sequence.
 */
__must_check int airy_sched_chk(const char *s);

/**
 * airy_sched_arg - validate one text argument of syscall 550
 * @arg: user-space string argument.
 *
 * Copies at most AIRY_SCHED_ARG_MAX bytes from @arg and validates the
 * result as one strict UTF-8 string. Copy faults, oversize input and
 * illegal encodings are reported as -AIRY_EFAULT, -AIRY_EINVAL and
 * -AIRY_EENC_* respectively; AIRY_EOK means the string may be consumed
 * by the sched_tac backend that milestone M3 will add.
 *
 * Return: AIRY_EOK when @arg is a valid UTF-8 string; a negative
 *         AIRY_E* code otherwise.
 */
__must_check int airy_sched_arg(const char __user *arg);

/**
 * airy_sched_ctl - serve syscall 550
 * @op: sched_tac operation code.
 * @cgroup_path: user-space path to the target cgroup.
 * @policy: user-space scheduling policy string.
 *
 * The complete entry decision. @op is classified first through
 * airy_sched_serve(), so an undefined op is refused before either
 * pointer is dereferenced. A recognised op then requires both strings
 * to pass airy_sched_arg(); only a well-formed request reaches the
 * -AIRY_ENOTSUP degradation that marks the unbuilt M3 backend.
 *
 * Return: -AIRY_EINVAL for an undefined @op, the AIRY_E* code of the
 *         first malformed string, or -AIRY_ENOTSUP for a well-formed
 *         request whose backend is not built in this release.
 */
__must_check int airy_sched_ctl(__u32 op, const char __user *cgroup_path,
				const char __user *policy);

#endif /* _AIRY_SCHED_H */

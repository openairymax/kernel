// SPDX-License-Identifier: GPL-2.0-only
/*
 * AirymaxOS ALK sched_tac control entry behind syscall 550.
 *
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 550 carries one `op` argument that is the [SC] airy_sched_op code of
 * sched.h, plus a cgroup path and a policy string. The policy, budget,
 * latency, priority, vtime and yield backends that would serve those
 * operations belong to milestone M3, so this release owns the entry
 * contract: refuse an undefined op, copy and UTF-8-validate both text
 * arguments, and answer only a well-formed request with -AIRY_ENOTSUP
 * rather than standing in for a backend that is not built. See
 * airy_sched.h for the contract SSoT and 20-modules/01-kernel.md §9.1
 * for the milestone boundary.
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/syscalls.h>

#include <airymax/airy_utf8.h>

#include "airy_sched.h"
#include "airy_sysabi.h"

/* ─── Syscall 550 entry policy ────────────────────────────────────────── */

/**
 * airy_sched_serve - Serve the op half of syscall 550.
 * @op: sched_tac operation code.
 *
 * Validates @op before anything else, so a value outside the [SC]
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
	if (unlikely(airy_op_check(AIRY_SYS_SCHED_CTL, op)))
		return -AIRY_EINVAL;

	return -AIRY_ENOTSUP;
}

/* ─── Text argument validation ────────────────────────────────────────── */

/* strndup_user() reports POSIX codes; map them into the [SC] space. */
static int airy_sched_err(int err)
{
	switch (err) {
	case -ENOMEM:
		return -AIRY_ENOMEM;
	case -EFAULT:
		return -AIRY_EFAULT;
	default:
		return -AIRY_EINVAL;
	}
}

/**
 * airy_sched_chk - Validate one NUL-terminated kernel string.
 * @s: string already copied into kernel space.
 *
 * The policy applied to both 550 text arguments, split out from the
 * copy so that its whole decision is reachable without a user pointer.
 * A NULL string is refused rather than dereferenced, so a caller that
 * loses an argument still gets a defined answer.
 *
 * Return: AIRY_EOK when @s is valid UTF-8, -AIRY_EINVAL for a NULL
 *         string, otherwise the -AIRY_EENC_* code of the first
 *         malformed sequence.
 */
__must_check int airy_sched_chk(const char *s)
{
	int ret;

	if (!s)
		return -AIRY_EINVAL;

	ret = airy_u8_scan(s, strlen(s));
	if (ret < 0)
		return ret;

	return AIRY_EOK;
}

/**
 * airy_sched_arg - Validate one text argument of syscall 550.
 * @arg: user-space string argument.
 *
 * Return: AIRY_EOK when @arg is a valid UTF-8 string; a negative
 *         AIRY_E* code otherwise.
 */
__must_check int airy_sched_arg(const char __user *arg)
{
	char *buf;
	int ret;

	buf = strndup_user(arg, AIRY_SCHED_ARG_MAX);
	if (IS_ERR(buf))
		return airy_sched_err(PTR_ERR(buf));

	ret = airy_sched_chk(buf);
	kfree(buf);

	return ret;
}

/**
 * airy_sched_ctl - Serve syscall 550.
 * @op: sched_tac operation code.
 * @cgroup_path: user-space path to the target cgroup.
 * @policy: user-space scheduling policy string.
 *
 * Return: -AIRY_EINVAL for an undefined @op, the AIRY_E* code of the
 *         first malformed string, or -AIRY_ENOTSUP for a well-formed
 *         request whose backend is not built in this release.
 */
__must_check int airy_sched_ctl(__u32 op, const char __user *cgroup_path,
				const char __user *policy)
{
	int ret;

	ret = airy_sched_serve(op);
	if (ret != -AIRY_ENOTSUP)
		return ret;

	ret = airy_sched_arg(cgroup_path);
	if (ret)
		return ret;

	ret = airy_sched_arg(policy);
	if (ret)
		return ret;

	return -AIRY_ENOTSUP;
}

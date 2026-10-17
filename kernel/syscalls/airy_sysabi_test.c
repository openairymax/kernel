// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_sysabi_test.c — KUnit coverage for the core syscall registry
 * and the version negotiation rule in airy_sysabi.c.
 *
 * The registry is pure data plus two total functions, so the suite
 * inspects it the way a caller does: walk every descriptor, check that
 * the numbers form the published 548-551 block in ascending order, that
 * the operation space each entry claims is the one its [SC] enum
 * defines, and that airy_op_check() answers the boundaries and the
 * magnitudes the SSoT promises. SSoT: 07-syscall-registry.md §13.1.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/cognition_types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/memory_types.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/syscalls.h>

#include "airy_sysabi.h"

/* The three entries whose operation space this registry owns. */
static const u16 airy_sysabi_ranged[] = {
	AIRY_SYS_ROVOL_CTL,
	AIRY_SYS_SCHED_CTL,
	AIRY_SYS_CLT_NOTIFY,
};

static void airy_sysabi_num_test(struct kunit *test)
{
	/* Number immutability: the four core slots never move (ABI 铁律). */
	KUNIT_EXPECT_EQ(test, 548, AIRY_SYS_CALL);
	KUNIT_EXPECT_EQ(test, 549, AIRY_SYS_ROVOL_CTL);
	KUNIT_EXPECT_EQ(test, 550, AIRY_SYS_SCHED_CTL);
	KUNIT_EXPECT_EQ(test, 551, AIRY_SYS_CLT_NOTIFY);

	KUNIT_EXPECT_EQ(test, 552, AIRY_SYS_RESERVED_BASE);
	KUNIT_EXPECT_EQ(test, 571, AIRY_SYS_RESERVED_END);
	KUNIT_EXPECT_EQ(test, 24, AIRY_SYS_SLOTS_MAX);
}

static void airy_sysabi_order_test(struct kunit *test)
{
	int i;

	/* One descriptor per core slot, ascending by exactly one. */
	KUNIT_ASSERT_EQ(test, AIRY_DESC_COUNT,
			(int)(AIRY_SYS_CLT_NOTIFY - AIRY_SYS_CALL + 1));

	for (i = 0; i < AIRY_DESC_COUNT; i++)
		KUNIT_EXPECT_EQ_MSG(test, AIRY_SYS_CALL + i,
				    airy_sys_desc_tbl[i].nr,
				    "descriptor %d out of order", i);
}

static void airy_sysabi_find_test(struct kunit *test)
{
	int i;

	for (i = 0; i < AIRY_DESC_COUNT; i++) {
		const struct airy_sys_desc *d = &airy_sys_desc_tbl[i];

		KUNIT_ASSERT_PTR_EQ(test, d, airy_desc_find(d->nr));

		/* Lookup matches the whole number, not a truncated prefix. */
		KUNIT_EXPECT_NULL(test, airy_desc_find(d->nr + 0x100));
	}

	/* Anything outside the four slots has no descriptor. */
	KUNIT_EXPECT_NULL(test, airy_desc_find(0));
	KUNIT_EXPECT_NULL(test, airy_desc_find(AIRY_SYS_CALL - 1));
	KUNIT_EXPECT_NULL(test, airy_desc_find(AIRY_SYS_CLT_NOTIFY + 1));
	KUNIT_EXPECT_NULL(test, airy_desc_find(AIRY_SYS_RESERVED_END));
	KUNIT_EXPECT_NULL(test, airy_desc_find(0xffff));
}

static void airy_sysabi_args_test(struct kunit *test)
{
	const struct airy_sys_desc *call = airy_desc_find(AIRY_SYS_CALL);

	KUNIT_ASSERT_NOT_NULL(test, call);

	/* 548 takes (fd, msg); the operation lives inside msg->opcode. */
	KUNIT_EXPECT_EQ(test, 2, call->nargs);
	KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_SRC_MSG, call->op_src);
	KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_DOM_NONE, call->op_dom);
	KUNIT_EXPECT_EQ(test, 0, call->op_first);
	KUNIT_EXPECT_EQ(test, 0, call->op_last);

	/* 549 and 550 take (op, arg, flags) with the op in arg 0. */
	KUNIT_EXPECT_EQ(test, 3, airy_desc_find(AIRY_SYS_ROVOL_CTL)->nargs);
	KUNIT_EXPECT_EQ(test, 3, airy_desc_find(AIRY_SYS_SCHED_CTL)->nargs);
	KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_SRC_ARG0,
			airy_desc_find(AIRY_SYS_ROVOL_CTL)->op_src);
	KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_SRC_ARG0,
			airy_desc_find(AIRY_SYS_SCHED_CTL)->op_src);

	/* 551 takes (task_id, phase) with the phase in arg 1. */
	KUNIT_EXPECT_EQ(test, 2,
			airy_desc_find(AIRY_SYS_CLT_NOTIFY)->nargs);
	KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_SRC_ARG1,
			airy_desc_find(AIRY_SYS_CLT_NOTIFY)->op_src);
}

static void airy_sysabi_range_test(struct kunit *test)
{
	unsigned int i;

	/*
	 * Each ranged entry owns exactly the half-open interval its [SC]
	 * enum defines: the first code is accepted, the last code is not.
	 */
	for (i = 0; i < ARRAY_SIZE(airy_sysabi_ranged); i++) {
		u16 nr = airy_sysabi_ranged[i];
		const struct airy_sys_desc *d = airy_desc_find(nr);

		KUNIT_ASSERT_NOT_NULL(test, d);
		KUNIT_EXPECT_EQ(test, AIRY_SYS_OP_DOM_RANGE, d->op_dom);
		KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_op_check(nr, d->op_first));
		KUNIT_EXPECT_EQ(test, AIRY_EOK,
				airy_op_check(nr, d->op_last - 1));
		KUNIT_EXPECT_EQ(test, -d->op_err,
				airy_op_check(nr, d->op_last));
		KUNIT_EXPECT_EQ(test, -d->op_err,
				airy_op_check(nr, 0xffffffffu));

		/* A space that starts above zero must reject the gap. */
		if (d->op_first)
			KUNIT_EXPECT_EQ(test, -d->op_err,
					airy_op_check(nr, d->op_first - 1));
	}
}

static void airy_sysabi_err_test(struct kunit *test)
{
	/* 549 and 550 answer a malformed op with the invalid-argument code. */
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_ROVOL_CTL, AIRY_ROVOL_OP_MAX));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_SCHED_CTL, AIRY_SCHED_OP_MAX));

	/* 551 answers its reserved space with the cognition-phase code. */
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_op_check(AIRY_SYS_CLT_NOTIFY,
				      AIRY_COG_PHASE_MAX));

	/* 548 belongs to the IPC plane: this registry cannot judge it. */
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_CALL, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_CALL, 0x01));

	/* Nor can it judge a number it does not describe. */
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_RESERVED_BASE, 1));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_op_check(0, 1));
}

static void airy_sysabi_wide_test(struct kunit *test)
{
	/*
	 * The op argument is 32 bits wide. A value whose low half is a
	 * valid code must still be refused, so the check cannot operate on
	 * a narrowed copy of the argument.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_ROVOL_CTL, 0x10000u + 1));
	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL,
			airy_op_check(AIRY_SYS_SCHED_CTL, 0x10000u + 1));
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_op_check(AIRY_SYS_CLT_NOTIFY, 0x10000u));
	KUNIT_EXPECT_EQ(test, -AIRY_ECOG_PHASE,
			airy_op_check(AIRY_SYS_CLT_NOTIFY, 0x10000u + 2));
}

static void airy_sysabi_name_test(struct kunit *test)
{
	int i, j;

	for (i = 0; i < AIRY_DESC_COUNT; i++) {
		const char *name = airy_sys_desc_tbl[i].name;

		KUNIT_ASSERT_NOT_NULL(test, name);
		KUNIT_EXPECT_EQ(test, 0, strncmp(name, "airy_sys_",
						 strlen("airy_sys_")));

		/* One name per entry, so diagnostics stay unambiguous. */
		for (j = i + 1; j < AIRY_DESC_COUNT; j++)
			KUNIT_EXPECT_NE(test, 0,
					strcmp(name,
					       airy_sys_desc_tbl[j].name));
	}
}

static void airy_abi_accept_test(struct kunit *test)
{
	struct airy_abi_hdr hdr = {
		.size = sizeof(hdr),
		.version = AIRY_ABI_VERSION,
		.reserved = 0,
	};

	KUNIT_EXPECT_EQ(test, 0x0100, AIRY_ABI_VERSION);
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_abi_verdict(&hdr, sizeof(hdr)));
}

static void airy_abi_forward_test(struct kunit *test)
{
	struct airy_abi_hdr hdr = {
		.size = sizeof(hdr) + 64,
		.version = AIRY_ABI_VERSION,
		.reserved = 0,
	};

	/* A newer, larger struct is readable: the kernel reads known bytes. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK,
			airy_abi_verdict(&hdr, sizeof(hdr)));

	/* The same holds when the caller passes a larger known size. */
	hdr.size = sizeof(hdr) + 128;
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_abi_verdict(&hdr, sizeof(hdr) + 64));
}

static void airy_abi_malformed_test(struct kunit *test)
{
	struct airy_abi_hdr hdr = {
		.size = sizeof(hdr),
		.version = AIRY_ABI_VERSION,
		.reserved = 0,
	};

	/* A size that cannot hold the prefix, or that is short of known. */
	hdr.size = sizeof(hdr) - 1;
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_abi_verdict(&hdr, sizeof(hdr)));

	hdr.size = sizeof(hdr);
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_abi_verdict(&hdr, sizeof(hdr) + 1));

	/* The reserved field is a promise, not a hint. */
	hdr.size = sizeof(hdr);
	hdr.reserved = 1;
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_abi_verdict(&hdr, sizeof(hdr)));

	hdr.reserved = 0;
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_abi_verdict(NULL, sizeof(hdr)));
}

static void airy_abi_version_test(struct kunit *test)
{
	struct airy_abi_hdr hdr = {
		.size = sizeof(hdr),
		.version = AIRY_ABI_VERSION,
		.reserved = 0,
	};

	/*
	 * A well-formed header of another version is a request for a
	 * contract this kernel does not implement, not a malformed one.
	 */
	hdr.version = AIRY_ABI_VERSION + 1;
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP,
			airy_abi_verdict(&hdr, sizeof(hdr)));

	hdr.version = AIRY_ABI_VERSION << 1;
	KUNIT_EXPECT_EQ(test, -AIRY_ENOTSUP,
			airy_abi_verdict(&hdr, sizeof(hdr)));
}

static void airy_sysabi_uapi_test(struct kunit *test)
{
#ifdef __NR_airy_sys_call
	/* The UAPI numbering and the registry share one truth. */
	KUNIT_EXPECT_EQ(test, __NR_airy_sys_call, AIRY_SYS_CALL);
	KUNIT_EXPECT_EQ(test, __NR_airy_sys_rovol_ctl, AIRY_SYS_ROVOL_CTL);
	KUNIT_EXPECT_EQ(test, __NR_airy_sys_sched_ctl, AIRY_SYS_SCHED_CTL);
	KUNIT_EXPECT_EQ(test, __NR_airy_sys_clt_notify, AIRY_SYS_CLT_NOTIFY);
#else
	kunit_skip(test, "architecture does not wire the 548-551 block yet");
#endif
}

static struct kunit_case airy_sysabi_cases[] = {
	KUNIT_CASE(airy_sysabi_num_test),
	KUNIT_CASE(airy_sysabi_order_test),
	KUNIT_CASE(airy_sysabi_find_test),
	KUNIT_CASE(airy_sysabi_args_test),
	KUNIT_CASE(airy_sysabi_range_test),
	KUNIT_CASE(airy_sysabi_err_test),
	KUNIT_CASE(airy_sysabi_wide_test),
	KUNIT_CASE(airy_sysabi_name_test),
	KUNIT_CASE(airy_sysabi_uapi_test),
	KUNIT_CASE(airy_abi_accept_test),
	KUNIT_CASE(airy_abi_forward_test),
	KUNIT_CASE(airy_abi_malformed_test),
	KUNIT_CASE(airy_abi_version_test),
	{}
};

static struct kunit_suite airy_sysabi_suite = {
	.name = "airy_sysabi_registry",
	.test_cases = airy_sysabi_cases,
};

kunit_test_suites(&airy_sysabi_suite);

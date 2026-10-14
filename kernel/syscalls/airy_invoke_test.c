// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_invoke_test.c — KUnit coverage for the syscall 548 message-header
 * contract validation (airy_invoke_hdr_check, C-S1/C-S3/C-S4/C-S10).
 *
 * A well-formed Layout C v4 header must be accepted, and each contract
 * field must be rejected independently with the [SC] error magnitude that
 * 07-ipc-fastpath.md §3.1 assigns to its C-S check.  This keeps the syscall
 * entry from admitting a header the data-plane fastpath would have refused,
 * which is what would happen if the two validators drifted apart.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "airy_invoke.h"

static void airy_invoke_hdr_accept_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
		.flags = 0,
	};

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_magic_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = 0xdeadbeefu };

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC, airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_payload_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = AIRY_IPC_MAGIC };

	/* A zero-length payload needs no data plane at all. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_invoke_hdr_check(&hdr));

	/* The ceiling is inclusive: a payload of exactly that size is legal. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD;
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_invoke_hdr_check(&hdr));

	/* One byte past the ceiling must be refused. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD + 1u;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_PAYLOAD, airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_flags_reserved_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_RESERVED,
	};

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FLAGS, airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_flags_unsupported_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_ENCRYPT,
	};

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_invoke_hdr_check(&hdr));

	hdr = (struct airy_ipc_msg_hdr){
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_COMPRESS,
	};
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_reserved_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = AIRY_IPC_MAGIC };
	size_t last = sizeof(hdr.reserved) - 1;

	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED,
			airy_invoke_hdr_check(&hdr));

	/*
	 * The final reserved byte must be covered too: the scan must not
	 * stop one element early.
	 */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = AIRY_IPC_MAGIC;
	hdr.reserved[last] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED,
			airy_invoke_hdr_check(&hdr));
}

static void airy_invoke_hdr_null_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_invoke_hdr_check(NULL));
}

static struct kunit_case airy_invoke_cases[] = {
	KUNIT_CASE(airy_invoke_hdr_accept_test),
	KUNIT_CASE(airy_invoke_hdr_magic_test),
	KUNIT_CASE(airy_invoke_hdr_payload_test),
	KUNIT_CASE(airy_invoke_hdr_flags_reserved_test),
	KUNIT_CASE(airy_invoke_hdr_flags_unsupported_test),
	KUNIT_CASE(airy_invoke_hdr_reserved_test),
	KUNIT_CASE(airy_invoke_hdr_null_test),
	{}
};

static struct kunit_suite airy_invoke_suite = {
	.name = "airy_invoke_syscall_548",
	.test_cases = airy_invoke_cases,
};

kunit_test_suites(&airy_invoke_suite);

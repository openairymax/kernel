// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check_test.c — KUnit coverage for the Layout C v4 header
 * contract shared by the io_uring data plane and syscall 548.
 *
 * Each case pins one check of airy_ipc_hdr_ok() and the [SC] magnitude
 * 07-ipc-fastpath.md §3.1 assigns to it, so a reordering or a relaxed
 * field test is caught here before either entry can accept a malformed
 * header.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_check.h"

static void hdr_accept_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
		.flags = 0,
	};

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_hdr_ok(&hdr));
}

static void hdr_magic_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = 0xdeadbeefu };

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC, airy_ipc_hdr_ok(&hdr));
}

static void hdr_payload_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = AIRY_IPC_MAGIC };

	/* A zero-length payload needs no data plane at all. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_hdr_ok(&hdr));

	/* The ceiling is inclusive: a payload of exactly that size is legal. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD;
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_hdr_ok(&hdr));

	/* One byte past the ceiling must be refused. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD + 1u;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_PAYLOAD, airy_ipc_hdr_ok(&hdr));
}

static void hdr_flags_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_RESERVED,
	};

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FLAGS, airy_ipc_hdr_ok(&hdr));
}

static void hdr_unsupp_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_ENCRYPT,
	};

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_ipc_hdr_ok(&hdr));

	hdr = (struct airy_ipc_msg_hdr){
		.magic = AIRY_IPC_MAGIC,
		.flags = AIRY_IPC_FLAG_COMPRESS,
	};
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_ipc_hdr_ok(&hdr));
}

static void hdr_reserved_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = AIRY_IPC_MAGIC };
	size_t last = sizeof(hdr.reserved) - 1;

	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_hdr_ok(&hdr));

	/*
	 * The final reserved byte must be covered too: the scan must not
	 * stop one element early.
	 */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = AIRY_IPC_MAGIC;
	hdr.reserved[last] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_hdr_ok(&hdr));
}

static void hdr_null_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_hdr_ok(NULL));
}

static struct kunit_case airy_ipc_check_cases[] = {
	KUNIT_CASE(hdr_accept_test),
	KUNIT_CASE(hdr_magic_test),
	KUNIT_CASE(hdr_payload_test),
	KUNIT_CASE(hdr_flags_test),
	KUNIT_CASE(hdr_unsupp_test),
	KUNIT_CASE(hdr_reserved_test),
	KUNIT_CASE(hdr_null_test),
	{}
};

static struct kunit_suite airy_ipc_check_suite = {
	.name = "airy_ipc_check",
	.test_cases = airy_ipc_check_cases,
};

kunit_test_suite(airy_ipc_check_suite);

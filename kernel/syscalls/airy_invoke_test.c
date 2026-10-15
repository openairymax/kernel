// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_invoke_test.c — KUnit coverage for the syscall 548 control-plane
 * entry defined in airy_syscalls.c.
 *
 * Two layers are exercised: the Layout C v4 header contract
 * (airy_invoke_hdr_check, C-S1/C-S3/C-S4/C-S10) and the opcode plus
 * ordering rules of the dispatch skeleton (airy_invoke_dispatch).
 *
 * The badge path is deliberately left out — it dereferences
 * current->security and reads the global capability slots, neither of
 * which is hermetic under KUnit; the capability suites own it.
 */

#include <kunit/test.h>
#include <linux/array_size.h>
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

static void airy_invoke_op_valid_accept_test(struct kunit *test)
{
	static const u16 dispatchable[] = {
		AIRY_IPC_OP_SEND, AIRY_IPC_OP_RECV, AIRY_IPC_OP_SEND_BATCH,
		AIRY_IPC_OP_CANCEL, AIRY_IPC_OP_FREEZE,
		AIRY_IPC_OP_CAP_REQUEST, AIRY_IPC_OP_CAP_RESPONSE,
	};
	unsigned int i;
	u16 op;

	for (i = 0; i < ARRAY_SIZE(dispatchable); i++) {
		op = dispatchable[i];

		KUNIT_EXPECT_TRUE_MSG(test, airy_invoke_op_valid(op),
				      "0x%04x not dispatchable", op);
	}
}

static void airy_invoke_op_valid_reject_test(struct kunit *test)
{
	static const u16 holes[] = {
		0x0000,	/* below the contiguous SEND..FREEZE block */
		0x0006,	/* first hole above FREEZE */
		0x000f,	/* last hole below CAP_REQUEST */
		0x0012,	/* first hole above CAP_RESPONSE */
		0xffff,	/* the AIRY_OP_PERMS_INVALID sentinel */
	};
	unsigned int i;
	u16 op;

	for (i = 0; i < ARRAY_SIZE(holes); i++) {
		op = holes[i];

		KUNIT_EXPECT_FALSE_MSG(test, airy_invoke_op_valid(op),
				       "0x%04x must be refused", op);
	}
}

static void airy_invoke_dispatch_entry_test(struct kunit *test)
{
	const struct airy_ipc_msg_hdr bad_magic = {
		.magic = 0xdeadbeefu,
		.opcode = AIRY_IPC_OP_SEND,
	};
	const struct airy_ipc_msg_hdr bad_payload = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
		.payload_len = AIRY_IPC_MAX_PAYLOAD + 1u,
	};

	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_invoke_dispatch(AIRY_CAP_NULL, NULL));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC,
			airy_invoke_dispatch(AIRY_CAP_NULL, &bad_magic));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_PAYLOAD,
			airy_invoke_dispatch(AIRY_CAP_NULL, &bad_payload));
}

static void airy_invoke_dispatch_order_test(struct kunit *test)
{
	const struct airy_ipc_msg_hdr unknown = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = 0x0006,
	};

	/*
	 * The opcode contract precedes badge authorisation: an unknown opcode
	 * in an otherwise valid header is refused with -AIRY_EIPC_OPCODE even
	 * though the badge is null.
	 */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE,
			airy_invoke_dispatch(AIRY_CAP_NULL, &unknown));
}

static struct kunit_case airy_invoke_cases[] = {
	KUNIT_CASE(airy_invoke_hdr_accept_test),
	KUNIT_CASE(airy_invoke_hdr_magic_test),
	KUNIT_CASE(airy_invoke_hdr_payload_test),
	KUNIT_CASE(airy_invoke_hdr_flags_reserved_test),
	KUNIT_CASE(airy_invoke_hdr_flags_unsupported_test),
	KUNIT_CASE(airy_invoke_hdr_reserved_test),
	KUNIT_CASE(airy_invoke_hdr_null_test),
	KUNIT_CASE(airy_invoke_op_valid_accept_test),
	KUNIT_CASE(airy_invoke_op_valid_reject_test),
	KUNIT_CASE(airy_invoke_dispatch_entry_test),
	KUNIT_CASE(airy_invoke_dispatch_order_test),
	{}
};

static struct kunit_suite airy_invoke_suite = {
	.name = "airy_invoke_syscall_548",
	.test_cases = airy_invoke_cases,
};

kunit_test_suites(&airy_invoke_suite);

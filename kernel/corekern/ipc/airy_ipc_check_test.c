// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check_test.c — KUnit coverage for the Layout C v4 header
 * contract shared by the io_uring data plane and syscall 548.
 *
 * Each case pins one check of airy_ipc_hdr_ok(), airy_flags_ok() or
 * airy_ipc_validate() and the [SC] magnitude 07-ipc-fastpath.md §3.1
 * assigns to it, so a reordering or a relaxed field test is caught here
 * before either entry can accept a malformed header. The C-S9 cases
 * borrow one capability slot and restore it on exit, because the fold
 * reads agent_caps[] rather than a parameter.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "../../../security/airy/airy_cap.h"

#include "airy_ipc_check.h"

#define TEST_AGENT	1001u	/* capability slot borrowed per case */
#define TEST_EPOCH	9u
#define TEST_RANDTAG	0xA5A5F00Du

struct check_fixture {
	struct airy_cap_slot saved;
};

static int check_init(struct kunit *test)
{
	struct check_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	f->saved = agent_caps[TEST_AGENT];
	agent_caps[TEST_AGENT].epoch = TEST_EPOCH;
	agent_caps[TEST_AGENT].randtag = TEST_RANDTAG;
	agent_caps[TEST_AGENT].perms = AIRY_CAP_PERM_SEND;
	test->priv = f;

	return 0;
}

static void check_exit(struct kunit *test)
{
	struct check_fixture *f = test->priv;

	if (f)
		agent_caps[TEST_AGENT] = f->saved;
}

static struct airy_ipc_msg_hdr valid_hdr(void)
{
	return (struct airy_ipc_msg_hdr){
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
		.src_task = TEST_AGENT,
	};
}

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
	struct airy_ipc_msg_hdr hdr = {
		.magic = 0xdeadbeefu,
		.opcode = AIRY_IPC_OP_SEND,
	};

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC, airy_ipc_hdr_ok(&hdr));
}

static void hdr_opcode_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = 0,
	};

	/* Opcode 0 is outside every plane and must be refused. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_ipc_hdr_ok(&hdr));

	hdr.opcode = 0x0006;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_ipc_hdr_ok(&hdr));
}

static void hdr_order_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = 0xdeadbeefu,
		.opcode = 0,
		.payload_len = AIRY_IPC_MAX_PAYLOAD + 1u,
	};

	/* C-S1 must win over every later failure. */
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_MAGIC, airy_ipc_hdr_ok(&hdr));

	/* C-S2 must win over C-S3 and C-S4. */
	hdr.magic = AIRY_IPC_MAGIC;
	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_ipc_hdr_ok(&hdr));

	/* C-S3 must win over C-S4. */
	hdr.opcode = AIRY_IPC_OP_SEND;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_PAYLOAD, airy_ipc_hdr_ok(&hdr));
}

static void hdr_payload_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
	};

	/* A zero-length payload needs no data plane at all. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_hdr_ok(&hdr));

	/* The ceiling is inclusive: a payload of exactly that size is legal. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD;
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_hdr_ok(&hdr));

	/* One byte past the ceiling must be refused. */
	hdr.payload_len = AIRY_IPC_MAX_PAYLOAD + 1u;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_PAYLOAD, airy_ipc_hdr_ok(&hdr));
}

static void hdr_reserved_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_SEND,
	};
	size_t last = sizeof(hdr.reserved) - 1;

	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_hdr_ok(&hdr));

	/*
	 * The final reserved byte must be covered too: the scan must not
	 * stop one element early.
	 */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = AIRY_IPC_MAGIC;
	hdr.opcode = AIRY_IPC_OP_SEND;
	hdr.reserved[last] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_hdr_ok(&hdr));
}

static void hdr_null_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_ipc_hdr_ok(NULL));
}

static void flags_accept_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .flags = 0 };

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_flags_ok(&hdr));
}

static void flags_reserved_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .flags = AIRY_IPC_FLAG_RESERVED };

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FLAGS, airy_flags_ok(&hdr));
}

static void flags_unsupp_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .flags = AIRY_IPC_FLAG_ENCRYPT };

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_flags_ok(&hdr));

	hdr.flags = AIRY_IPC_FLAG_COMPRESS;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_flags_ok(&hdr));
}

static void validate_accept_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = {
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_RECV,
		.flags = 0,
	};

	/* KUnit runs in task context, which is the only legal caller. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_validate(&hdr));
}

static void validate_order_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = { .magic = AIRY_IPC_MAGIC };

	/* The context gate never hides a field failure. */
	hdr.opcode = 0;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_OPCODE, airy_ipc_validate(&hdr));

	/*
	 * C-S4 precedes C-S10: a header that fails both must report the
	 * field failure, not the flag failure.
	 */
	hdr.opcode = AIRY_IPC_OP_SEND;
	hdr.flags = AIRY_IPC_FLAG_RESERVED;
	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_validate(&hdr));

	/* With the reserved tail clean, C-S10 is the remaining failure. */
	hdr.reserved[0] = 0;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FLAGS, airy_ipc_validate(&hdr));
}

static void cap_req_pass_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.opcode = AIRY_IPC_OP_CAP_REQUEST;
	hdr.dst_task = AIRY_SEC_D_TASK_ID;

	/* Bootstrap carries no Badge and is legal only towards sec_d. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_validate(&hdr));
}

static void cap_req_bad_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.opcode = AIRY_IPC_OP_CAP_REQUEST;
	hdr.dst_task = 1;

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_BADGE, airy_ipc_validate(&hdr));
}

static void cap_carry_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	/* A zero Badge may not claim to carry a capability. */
	hdr.flags = AIRY_IPC_FLAG_CAP_CARRY;
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_BADGE, airy_ipc_validate(&hdr));
}

static void cap_absent_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	/* H3/H6: no Badge is the agentrt and [DSL] shape, and it passes. */
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_validate(&hdr));
}

static void cap_epoch_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH - 1, TEST_RANDTAG,
						  AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH, airy_ipc_validate(&hdr));
}

static void cap_forged_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH,
						  TEST_RANDTAG ^ 1u,
						  AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED, airy_ipc_validate(&hdr));
}

static void cap_perm_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	/* The Badge is authentic but does not cover the opcode. */
	hdr.opcode = AIRY_IPC_OP_RECV;
	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
						  AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_PERM, airy_ipc_validate(&hdr));
}

static void cap_perm_ok_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
						  AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_ipc_validate(&hdr));
}

static void cap_range_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	/* An id outside the table names no slot, so no Badge can match it. */
	hdr.src_task = AIRY_CAP_MAX_AGENTS;
	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH, TEST_RANDTAG,
						  AIRY_CAP_PERM_SEND);

	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING, airy_ipc_validate(&hdr));
}

static void cap_order_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr = valid_hdr();

	hdr.capability_badge = AIRY_BADGE_COMPILE(TEST_EPOCH,
						  TEST_RANDTAG ^ 1u,
						  AIRY_CAP_PERM_SEND);
	hdr.flags = AIRY_IPC_FLAG_RESERVED;

	/* C-S9 precedes C-S10. */
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED, airy_ipc_validate(&hdr));

	/* C-S4 precedes C-S9, so a dirty reserved tail wins. */
	hdr.reserved[0] = 1;
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_RESERVED, airy_ipc_validate(&hdr));
}

static struct kunit_case airy_ipc_check_cases[] = {
	KUNIT_CASE(hdr_accept_test),
	KUNIT_CASE(hdr_magic_test),
	KUNIT_CASE(hdr_opcode_test),
	KUNIT_CASE(hdr_order_test),
	KUNIT_CASE(hdr_payload_test),
	KUNIT_CASE(hdr_reserved_test),
	KUNIT_CASE(hdr_null_test),
	KUNIT_CASE(flags_accept_test),
	KUNIT_CASE(flags_reserved_test),
	KUNIT_CASE(flags_unsupp_test),
	KUNIT_CASE(validate_accept_test),
	KUNIT_CASE(validate_order_test),
	KUNIT_CASE(cap_req_pass_test),
	KUNIT_CASE(cap_req_bad_test),
	KUNIT_CASE(cap_carry_test),
	KUNIT_CASE(cap_absent_test),
	KUNIT_CASE(cap_epoch_test),
	KUNIT_CASE(cap_forged_test),
	KUNIT_CASE(cap_perm_test),
	KUNIT_CASE(cap_perm_ok_test),
	KUNIT_CASE(cap_range_test),
	KUNIT_CASE(cap_order_test),
	{}
};

static struct kunit_suite airy_ipc_check_suite = {
	.name = "airy_ipc_check",
	.init = check_init,
	.exit = check_exit,
	.test_cases = airy_ipc_check_cases,
};

kunit_test_suite(airy_ipc_check_suite);

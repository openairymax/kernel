// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_invoke_test.c — KUnit coverage for the syscall 548 control-plane
 * entry defined in airy_syscalls.c.
 *
 * Four layers are exercised: the Layout C v4 header contract
 * (airy_invoke_hdr_check, C-S1/C-S3/C-S4/C-S10), the opcode plus ordering
 * rules of the dispatch skeleton (airy_invoke_dispatch), and the two halves
 * of the badge lifecycle — install (airy_badge_install, the sec_d
 * COMPILE_BADGE half) and revocation (airy_badge_revoke, the sec_d
 * REVOKE_BADGE half).
 *
 * Both handlers read only the message header and the global capability
 * slot table — never current->security — so they are hermetic under KUnit:
 * the suite parks the run in one reserved slot, saves the live contents in
 * the test context and restores them on exit.
 */

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "../../security/airy/airy_cap.h"
#include "airy_invoke.h"

/*
 * airy_badge_install() touches only the global capability slot table, so
 * every case runs against one reserved slot whose live contents are
 * restored on exit. AIRY_TEST_AGENT (1023) is the last slot and is not
 * claimed by the derivation (1020/1021) or LSM (1022) suites.
 */
#define AIRY_TEST_AGENT	1023u
#define AIRY_TEST_EPOCH	1u

struct badge_install_ctx {
	struct airy_cap_slot saved_slot;
};

static int badge_install_test_init(struct kunit *test)
{
	struct badge_install_ctx *ctx;
	struct airy_cap_slot *slot = &agent_caps[AIRY_TEST_AGENT];

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;

	/* Park an empty slot at the epoch boot initialisation leaves in place. */
	ctx->saved_slot = *slot;
	memset(slot, 0, sizeof(*slot));
	WRITE_ONCE(slot->epoch, AIRY_TEST_EPOCH);

	return 0;
}

static void badge_install_test_exit(struct kunit *test)
{
	struct badge_install_ctx *ctx = test->priv;

	if (!ctx)
		return;

	agent_caps[AIRY_TEST_AGENT] = ctx->saved_slot;
}

/* Build a CAP_RESPONSE header carrying @badge for target agent @dst. */
static struct airy_ipc_msg_hdr badge_msg(__u64 dst, __u64 badge)
{
	return (struct airy_ipc_msg_hdr){
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_CAP_RESPONSE,
		.dst_task = dst,
		.capability_badge = badge,
	};
}

/* Build a FREEZE (REVOKE_BADGE) header naming target agent @dst. */
static struct airy_ipc_msg_hdr freeze_msg(__u64 dst)
{
	return (struct airy_ipc_msg_hdr){
		.magic = AIRY_IPC_MAGIC,
		.opcode = AIRY_IPC_OP_FREEZE,
		.dst_task = dst,
	};
}

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

static void airy_badge_install_reject_test(struct kunit *test)
{
	const u64 good = AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0x1234ABCDu,
					    AIRY_CAP_PERM_SEND);
	struct airy_cap_slot *slot = &agent_caps[AIRY_TEST_AGENT];
	struct airy_ipc_msg_hdr hdr = badge_msg(AIRY_TEST_AGENT, good);

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_badge_install(NULL));

	/* Out-of-range target is refused before the badge is inspected. */
	hdr.dst_task = AIRY_CAP_MAX_AGENTS;
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW, airy_badge_install(&hdr));

	/* A zero badge is the "no capability" sentinel. */
	hdr = badge_msg(AIRY_TEST_AGENT, AIRY_CAP_NULL);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_BADGE, airy_badge_install(&hdr));

	/* Epoch 0 marks an uninitialised slot, never a live grant. */
	hdr = badge_msg(AIRY_TEST_AGENT,
			AIRY_BADGE_COMPILE(0, 0x1234ABCDu, AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH, airy_badge_install(&hdr));

	/* A zero RandomTag would make the badge forgeable by construction. */
	hdr = badge_msg(AIRY_TEST_AGENT,
			AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0,
					   AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_BADGE, airy_badge_install(&hdr));

	/* Reserved permission bits name authority no check interprets. */
	hdr = badge_msg(AIRY_TEST_AGENT,
			AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0x1234ABCDu,
					   AIRY_CAP_PERM_RESERVED));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_BADGE, airy_badge_install(&hdr));

	/* A badge minted for a future epoch must not seal here. */
	hdr = badge_msg(AIRY_TEST_AGENT,
			AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH + 1u, 0x1234ABCDu,
					   AIRY_CAP_PERM_SEND));
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH, airy_badge_install(&hdr));

	/* Every rejection must leave the parked slot untouched. */
	KUNIT_EXPECT_EQ(test, AIRY_CAP_NULL, slot->badge);
	KUNIT_EXPECT_EQ(test, AIRY_TEST_EPOCH, slot->epoch);
}

static void airy_badge_install_ok_test(struct kunit *test)
{
	const u64 badge = AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0x1234ABCDu,
					     AIRY_CAP_PERM_SEND |
					     AIRY_CAP_PERM_RECV);
	struct airy_cap_slot *slot = &agent_caps[AIRY_TEST_AGENT];
	struct airy_ipc_msg_hdr hdr = badge_msg(AIRY_TEST_AGENT, badge);

	KUNIT_ASSERT_EQ(test, AIRY_EOK, airy_badge_install(&hdr));

	KUNIT_EXPECT_EQ(test, badge, slot->badge);
	KUNIT_EXPECT_EQ(test, AIRY_TEST_AGENT, slot->agent_id);
	KUNIT_EXPECT_EQ(test, AIRY_TEST_EPOCH, slot->epoch);
	KUNIT_EXPECT_EQ(test, 0x1234ABCDu, slot->randtag);
	KUNIT_EXPECT_EQ(test, AIRY_CAP_PERM_SEND | AIRY_CAP_PERM_RECV,
			slot->perms);

	/* Single-shot slot: a second grant is refused, not overwritten. */
	hdr = badge_msg(AIRY_TEST_AGENT,
			AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0x5A5A5A5Au,
					   AIRY_CAP_PERM_RECV));
	KUNIT_EXPECT_EQ(test, -AIRY_EEXIST, airy_badge_install(&hdr));
	KUNIT_EXPECT_EQ(test, badge, slot->badge);
}

static void airy_badge_revoke_reject_test(struct kunit *test)
{
	struct airy_cap_slot *slot = &agent_caps[AIRY_TEST_AGENT];
	struct airy_ipc_msg_hdr hdr = freeze_msg(AIRY_TEST_AGENT);

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_badge_revoke(NULL));

	/* Out-of-range target is refused before the slot is inspected. */
	hdr.dst_task = AIRY_CAP_MAX_AGENTS;
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_OVERFLOW, airy_badge_revoke(&hdr));

	/*
	 * An empty slot holds no badge, so airy_cap_lookup() yields NULL and
	 * the cascade is refused with -AIRY_ECAP_MISSING.
	 */
	hdr = freeze_msg(AIRY_TEST_AGENT);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_MISSING, airy_badge_revoke(&hdr));

	/* Every rejection must leave the parked slot untouched. */
	KUNIT_EXPECT_EQ(test, AIRY_CAP_NULL, slot->badge);
	KUNIT_EXPECT_EQ(test, AIRY_TEST_EPOCH, slot->epoch);
}

static void airy_badge_revoke_ok_test(struct kunit *test)
{
	const u64 badge = AIRY_BADGE_COMPILE(AIRY_TEST_EPOCH, 0x1234ABCDu,
					     AIRY_CAP_PERM_SEND);
	struct airy_cap_slot *slot = &agent_caps[AIRY_TEST_AGENT];
	struct airy_ipc_msg_hdr hdr = badge_msg(AIRY_TEST_AGENT, badge);

	KUNIT_ASSERT_EQ(test, AIRY_EOK, airy_badge_install(&hdr));

	/* The freshly installed badge authenticates on the fastpath. */
	KUNIT_ASSERT_EQ(test, AIRY_EOK,
			airy_cap_badge_ok(badge, AIRY_TEST_AGENT,
					  AIRY_CAP_PERM_SEND));

	hdr = freeze_msg(AIRY_TEST_AGENT);
	KUNIT_ASSERT_EQ(test, AIRY_EOK, airy_badge_revoke(&hdr));

	/* Revocation bumps the epoch and clears the RandomTag. */
	KUNIT_EXPECT_EQ(test, AIRY_TEST_EPOCH + 1u, slot->epoch);
	KUNIT_EXPECT_EQ(test, 0, slot->randtag);

	/* The pre-revocation badge is now stale against the slot epoch. */
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_EPOCH,
			airy_cap_badge_ok(badge, AIRY_TEST_AGENT,
					  AIRY_CAP_PERM_SEND));
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
	KUNIT_CASE(airy_badge_install_reject_test),
	KUNIT_CASE(airy_badge_install_ok_test),
	KUNIT_CASE(airy_badge_revoke_reject_test),
	KUNIT_CASE(airy_badge_revoke_ok_test),
	{}
};

static struct kunit_suite airy_invoke_suite = {
	.name = "airy_invoke_syscall_548",
	.init = badge_install_test_init,
	.exit = badge_install_test_exit,
	.test_cases = airy_invoke_cases,
};

kunit_test_suites(&airy_invoke_suite);

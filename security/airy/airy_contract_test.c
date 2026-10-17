// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_contract_test.c — KUnit coverage for the [SC] contract snapshot
 * attestation (airy_contract_check, A-11).
 *
 * The compile-time asserts in airy_contract.h pin the invariants against
 * sources, but what the fastpath actually runs against is the layout the
 * toolchain produced for this target. This suite drives the same
 * attestation airy_init() runs at boot, so a regression that makes it
 * reject a matching build (and thereby disable the Airy LSM) is caught
 * here instead of at boot.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/log_types.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/memory_types.h>

#include <airymax/airy_contract.h>

static void airy_contract_accept_test(struct kunit *test)
{
	/*
	 * A matching build must attest cleanly: any drift would make
	 * airy_init() keep the whole LSM disabled.
	 */
	KUNIT_EXPECT_EQ(test, 0, airy_contract_check());
}

static void airy_contract_abi_version_test(struct kunit *test)
{
	/*
	 * The snapshot describes Layout C v4; a bump must update both the
	 * contract header and this expectation together.
	 */
	KUNIT_EXPECT_EQ(test, 4, AIRY_CONTRACT_ABI_VERSION);
}

static void airy_contract_ipc_cmd_budget_test(struct kunit *test)
{
	/*
	 * The SQE128 cmd payload is a hard 80-byte budget, and the fastpath
	 * only reads the inline pdu[32] prefix.
	 */
	KUNIT_EXPECT_TRUE(test, (u64)sizeof(struct airy_ipc_cmd) <=
				(u64)AIRY_IPC_CMD_MAX);
	KUNIT_EXPECT_TRUE(test, (u64)offsetof(struct airy_ipc_cmd, ring_id) <= 32u);
}

static void airy_contract_badge_tiling_test(struct kunit *test)
{
	/*
	 * Epoch, random tag and permission masks must tile all 64 bits with
	 * no gap and no overlap, or a forged badge can pass the C-S9 check.
	 */
	KUNIT_EXPECT_EQ(test, ~(u64)0,
			AIRY_BADGE_EPOCH_MASK | AIRY_BADGE_RANDTAG_MASK |
			AIRY_BADGE_PERMS_MASK);
	KUNIT_EXPECT_EQ(test, 0,
			(AIRY_BADGE_EPOCH_MASK & AIRY_BADGE_RANDTAG_MASK) |
			(AIRY_BADGE_EPOCH_MASK & AIRY_BADGE_PERMS_MASK) |
			(AIRY_BADGE_RANDTAG_MASK & AIRY_BADGE_PERMS_MASK));
}

static void airy_contract_blob_capacity_test(struct kunit *test)
{
	/*
	 * airy_lsm.c sizes its LSM blobs from sizeof(struct airy_inode_sec)
	 * and indexes inode security by fixed offsets; the capability table
	 * is a compile-time array bounded by AIRY_CAP_MAX_AGENTS. Both are
	 * layout the hooks read and write directly.
	 */
	KUNIT_EXPECT_EQ(test, 8, (int)sizeof(struct airy_inode_sec));
	KUNIT_EXPECT_EQ(test, 0,
			(int)offsetof(struct airy_inode_sec, cap_required));
	KUNIT_EXPECT_EQ(test, 4,
			(int)offsetof(struct airy_inode_sec, owner_agent));
	KUNIT_EXPECT_EQ(test, 1024, AIRY_CAP_MAX_AGENTS);
}

static void airy_log_layout(struct kunit *test)
{
	/*
	 * airy_log_ring.c strides the ring by AIRY_LOG_RECORD_SIZE and hands
	 * out the record pointer for producers to fill by offset. The slot
	 * size, payload extent and alignment must stay exactly as contracted.
	 */
	KUNIT_EXPECT_EQ(test, (int)AIRY_LOG_RECORD_SIZE,
			(int)sizeof(struct airy_log_record));
	KUNIT_EXPECT_EQ(test, 4, (int)offsetof(struct airy_log_record, level));
	KUNIT_EXPECT_EQ(test, 24, (int)offsetof(struct airy_log_record, payload));
	KUNIT_EXPECT_EQ(test, 96,
			(int)sizeof(((struct airy_log_record *)0)->payload));
	KUNIT_EXPECT_EQ(test, 64, (int)_Alignof(struct airy_log_record));
	KUNIT_EXPECT_EQ(test, 5, (int)AIRY_LOG_LEVEL_MAX);
}

static void airy_task_chk(struct kunit *test)
{
	/*
	 * taskflow and the sched_tac backend address the descriptor by
	 * offset, not by field name. Size, alignment and every offset that
	 * carries identity or lifecycle state must match the [SC] contract.
	 */
	KUNIT_EXPECT_EQ(test, 64, (int)sizeof(struct airy_task_desc));
	KUNIT_EXPECT_EQ(test, 64, (int)_Alignof(struct airy_task_desc));
	KUNIT_EXPECT_EQ(test, 0, (int)offsetof(struct airy_task_desc, magic));
	KUNIT_EXPECT_EQ(test, 4, (int)offsetof(struct airy_task_desc, prio));
	KUNIT_EXPECT_EQ(test, 32, (int)offsetof(struct airy_task_desc, vtime));
	KUNIT_EXPECT_EQ(test, 48, (int)offsetof(struct airy_task_desc, state));
	KUNIT_EXPECT_EQ(test, 0x41475453, (int)AIRY_TASK_MAGIC);
	KUNIT_EXPECT_EQ(test, 139, AIRY_PRIO_MAX);
	KUNIT_EXPECT_EQ(test, 8, (int)AIRY_AGENT_STATE_MAX);
	KUNIT_EXPECT_EQ(test, 0x08, (int)AIRY_SCHED_OP_MAX);
}

static void airy_mem_chk(struct kunit *test)
{
	/*
	 * airy_mem_tier_of() classifies a gfp hint by the low nibble, and
	 * the rovol dispatcher rejects opcodes at AIRY_ROVOL_OP_MAX. Both
	 * number spaces are user-visible ABI and must stay as contracted.
	 */
	KUNIT_EXPECT_EQ(test, 0, (int)AIRY_MEM_HOT);
	KUNIT_EXPECT_EQ(test, 3, (int)AIRY_MEM_PMEM);
	KUNIT_EXPECT_EQ(test, 4, (int)AIRY_MEM_LEVEL_MAX);
	KUNIT_EXPECT_EQ(test, 0x01, (int)AIRY_GFP_HOT);
	KUNIT_EXPECT_EQ(test, 0x08, (int)AIRY_GFP_PMEM);
	KUNIT_EXPECT_EQ(test, 0x0f,
			(int)(AIRY_GFP_HOT | AIRY_GFP_WARM | AIRY_GFP_COLD |
			      AIRY_GFP_PMEM));
	KUNIT_EXPECT_EQ(test, 0x0f,
			(int)(AIRY_PAGE_CLASS_ANON | AIRY_PAGE_CLASS_FILE |
			      AIRY_PAGE_CLASS_SHMEM | AIRY_PAGE_CLASS_AGENT));
	KUNIT_EXPECT_EQ(test, 0x01, (int)AIRY_ROVOL_SNAPSHOT);
	KUNIT_EXPECT_EQ(test, 0x0A, (int)AIRY_ROVOL_TIER_GET);
	KUNIT_EXPECT_EQ(test, 0x0B, (int)AIRY_ROVOL_OP_MAX);
}

static struct kunit_case airy_contract_cases[] = {
	KUNIT_CASE(airy_contract_accept_test),
	KUNIT_CASE(airy_contract_abi_version_test),
	KUNIT_CASE(airy_contract_ipc_cmd_budget_test),
	KUNIT_CASE(airy_contract_badge_tiling_test),
	KUNIT_CASE(airy_contract_blob_capacity_test),
	KUNIT_CASE(airy_log_layout),
	KUNIT_CASE(airy_task_chk),
	KUNIT_CASE(airy_mem_chk),
	{}
};

static struct kunit_suite airy_contract_suite = {
	.name = "airy_contract_snapshot",
	.test_cases = airy_contract_cases,
};

kunit_test_suites(&airy_contract_suite);

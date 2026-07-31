// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_capability_test.c — KUnit regression for the P1-5 alignment fix.
 *
 * P1-5 replaced the open-coded __aligned(64) on the global capability
 * table with the AIRY_ALIGNED(64) macro from <linux/airymax/uapi_compat.h>,
 * the single OS-IRON-016-sanctioned exception for struct-level alignment
 * in UAPI headers.  These tests pin the resulting cacheline alignment of
 * both struct airy_cap_slot and the authoritative agent_caps[] array
 * defined in airy_ipc_capability.c, so a future revert cannot silently
 * drop the alignment that the C-S9 fastpath relies on for cache locality.
 *
 * The test reaches agent_caps via airy_ipc_capability.h (non-static extern
 * pointer), so airy_ipc_capability.o stays in the link unchanged.
 */

#include <kunit/test.h>
#include <linux/stddef.h>
#include <linux/types.h>

#include "airy_ipc_capability.h"

/* Local type used only to verify AIRY_ALIGNED() still raises alignment. */
struct airy_aligned_probe {
	char c;
} AIRY_ALIGNED(128);

static void cap_slot_alignment_test(struct kunit *test)
{
	/* AIRY_ALIGNED(64) on the struct declaration raises the fundamental
	 * alignment to at least 64 bytes (one cacheline on x86/arm64). */
	KUNIT_EXPECT_GE(test, (unsigned long)__alignof__(struct airy_cap_slot),
			64UL);

	/* Size must be a multiple of the alignment: 80 bytes of content
	 * round up to 128, preserving cacheline alignment of every slot. */
	KUNIT_EXPECT_EQ(test, (size_t)0,
			sizeof(struct airy_cap_slot) % 64);
}

static void agent_caps_array_alignment_test(struct kunit *test)
{
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, agent_caps);

	/* __airymax_cap_table is declared AIRY_ALIGNED(64); agent_caps
	 * aliases it, so the array base must be 64-byte aligned. */
	KUNIT_EXPECT_EQ(test, (uintptr_t)0,
			(uintptr_t)agent_caps % 64);

	/* Because sizeof(slot) is a multiple of 64, every element is also
	 * 64-byte aligned.  Spot-check the first, a few middle indices, and
	 * the last slot to catch any future padding regression. */
	KUNIT_EXPECT_EQ(test, (uintptr_t)0,
			(uintptr_t)&agent_caps[0] % 64);
	for (i = AIRY_CAP_MAX_AGENTS / 4;
	     i < AIRY_CAP_MAX_AGENTS;
	     i += AIRY_CAP_MAX_AGENTS / 4) {
		KUNIT_EXPECT_EQ(test, (uintptr_t)0,
				(uintptr_t)&agent_caps[i] % 64);
	}
	KUNIT_EXPECT_EQ(test, (uintptr_t)0,
			(uintptr_t)&agent_caps[AIRY_CAP_MAX_AGENTS - 1] % 64);
}

static void airy_aligned_macro_test(struct kunit *test)
{
	/* The macro that P1-5 standardised on must still raise alignment
	 * when applied to an arbitrary type (here 128 bytes). */
	KUNIT_EXPECT_GE(test,
			(unsigned long)__alignof__(struct airy_aligned_probe),
			128UL);
}

static struct kunit_case airy_ipc_capability_cases[] = {
	KUNIT_CASE(cap_slot_alignment_test),
	KUNIT_CASE(agent_caps_array_alignment_test),
	KUNIT_CASE(airy_aligned_macro_test),
	{}
};

static struct kunit_suite airy_ipc_capability_suite = {
	.name = "airy_ipc_capability_p1_5",
	.test_cases = airy_ipc_capability_cases,
};

kunit_test_suites(&airy_ipc_capability_suite);

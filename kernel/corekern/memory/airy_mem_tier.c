// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_mem_tier.c — Airymax L1-L4 memory tier classification.
 *
 * Maps an Airymax GFP hint (AIRY_GFP_HOT/WARM/COLD/PMEM, encoded in the
 * low nibble of the gfp_t) to one of four memory tiers (L1 HBM/DDR hot,
 * L2 DDR warm, L3 CXL/NVMe cold, L4 PMEM persistent).  The per-tier
 * shift values in airy_mem_tier_shift[] are used by the allocator to
 * bias allocation sizes for each tier.
 */

#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/bug.h>
#include <linux/airymax/memory_types.h>

/* ─── Memory tier enumeration ────────────────────────────────────────── */
enum airy_mem_tier {
	AIRY_MEM_TIER_L1 = 0,	/* Hot  — HBM/DDR       */
	AIRY_MEM_TIER_L2 = 1,	/* Warm — DDR           */
	AIRY_MEM_TIER_L3 = 2,	/* Cold — CXL/NVMe      */
	AIRY_MEM_TIER_L4 = 3,	/* PMEM — persistent    */
	AIRY_MEM_TIER_MAX
};

/* ─── Per-tier size shift (log2 of preferred allocation granularity) ─── */
static const int airy_mem_tier_shift[] = {
	[AIRY_MEM_TIER_L1] = 0,		/* L1: PAGE_SIZE granularity  */
	[AIRY_MEM_TIER_L2] = 3,		/* L2: 8× PAGE batches        */
	[AIRY_MEM_TIER_L3] = 6,		/* L3: 64× PAGE batches       */
	[AIRY_MEM_TIER_L4] = 9,		/* L4: 512× PAGE batches      */
};

/* ─── GFP → tier classification ──────────────────────────────────────── */
enum airy_mem_tier airy_mem_tier_of(gfp_t gfp)
{
	unsigned int tier_bits = (unsigned int)gfp & 0x0f;

	if (tier_bits & AIRY_GFP_HOT)
		return AIRY_MEM_TIER_L1;
	if (tier_bits & AIRY_GFP_WARM)
		return AIRY_MEM_TIER_L2;
	if (tier_bits & AIRY_GFP_COLD)
		return AIRY_MEM_TIER_L3;
	if (tier_bits & AIRY_GFP_PMEM)
		return AIRY_MEM_TIER_L4;

	/* Plain GFP_KERNEL defaults to the warm tier. */
	return AIRY_MEM_TIER_L2;
}

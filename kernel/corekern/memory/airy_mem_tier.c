// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_mem_tier.c — Airymax L1-L4 memory tier classification.
 *
 * Maps an Airymax GFP hint (AIRY_GFP_HOT/WARM/COLD/PMEM, encoded in the
 * low nibble of the gfp_t) onto the [SC] enum airy_mem_level from
 * <linux/airymax/memory_types.h>, which owns the L1-L4 number space.
 * The per-tier shift table holds the log2 of the preferred allocation
 * granularity for each tier.
 */

#include <linux/gfp.h>
#include <linux/build_bug.h>
#include <linux/array_size.h>

#include <linux/airymax/memory_types.h>

/*
 * Tier numbers come from the [SC] enum; a level added to the contract
 * without a granularity here would leave that tier unclassified.
 */
static const int airy_mem_tier_shift[] = {
	[AIRY_MEM_HOT]  = 0,	/* L1: PAGE_SIZE granularity  */
	[AIRY_MEM_WARM] = 3,	/* L2: 8x PAGE batches        */
	[AIRY_MEM_COLD] = 6,	/* L3: 64x PAGE batches       */
	[AIRY_MEM_PMEM] = 9,	/* L4: 512x PAGE batches      */
};

static_assert(ARRAY_SIZE(airy_mem_tier_shift) == AIRY_MEM_LEVEL_MAX,
	      "tier shift table must cover every [SC] memory level");

/* ─── GFP → tier classification ──────────────────────────────────────── */
enum airy_mem_level airy_mem_tier_of(gfp_t gfp)
{
	unsigned int tier_bits = (unsigned int)gfp & 0x0f;

	if (tier_bits & AIRY_GFP_HOT)
		return AIRY_MEM_HOT;
	if (tier_bits & AIRY_GFP_WARM)
		return AIRY_MEM_WARM;
	if (tier_bits & AIRY_GFP_COLD)
		return AIRY_MEM_COLD;
	if (tier_bits & AIRY_GFP_PMEM)
		return AIRY_MEM_PMEM;

	/* Plain GFP_KERNEL defaults to the warm tier. */
	return AIRY_MEM_WARM;
}

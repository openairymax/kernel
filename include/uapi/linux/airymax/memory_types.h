/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * MemoryRoVol types — [SC] shared contract header.
 *
 * L1-L4 memory tiering definitions and GFP mask semantics.
 */

#ifndef _UAPI_AIRYMAX_MEMORY_TYPES_H
#define _UAPI_AIRYMAX_MEMORY_TYPES_H

#include <linux/airymax/uapi_compat.h>

/* ─── Memory Tier Levels ─────────────────────────────────────────────── */
enum airy_mem_level {
	AIRY_MEM_HOT    = 0,   /* L1: HBM/DDR hot tier */
	AIRY_MEM_WARM   = 1,   /* L2: DDR warm tier */
	AIRY_MEM_COLD   = 2,   /* L3: CXL/NVMe cold tier */
	AIRY_MEM_PMEM   = 3,   /* L4: PMEM persistent tier */
	AIRY_MEM_LEVEL_MAX
};

/* ─── GFP Mask Semantics for MemoryRoVol ──────────────────────────────── */
#define AIRY_GFP_HOT    0x01   /* Allocate from hot tier */
#define AIRY_GFP_WARM   0x02   /* Allocate from warm tier */
#define AIRY_GFP_COLD   0x04   /* Allocate from cold tier */
#define AIRY_GFP_PMEM   0x08   /* Allocate from PMEM tier */

/* ─── Memory Page Classification ──────────────────────────────────────── */
#define AIRY_PAGE_CLASS_ANON     0x01  /* Anonymous page */
#define AIRY_PAGE_CLASS_FILE     0x02  /* File-backed page */
#define AIRY_PAGE_CLASS_SHMEM    0x04  /* Shared memory page */
#define AIRY_PAGE_CLASS_AGENT    0x08  /* Agent-private page */

/* ─── MemoryRoVol Control Opcodes (airy_sys_rovol_ctl, syscall 549) ────
 * op numbering authority: 140-application-development/07-syscall-registry.md
 * §4.3/§6.2 (0x01-0x0A). 0 is invalid and rejected before dispatch.
 */
enum airy_rovol_op {
	AIRY_ROVOL_SNAPSHOT     = 0x01,  /* Capture process memory snapshot */
	AIRY_ROVOL_RESTORE      = 0x02,  /* Restore memory from snapshot */
	AIRY_ROVOL_MIGRATE      = 0x03,  /* Cross-node / cross-tier migration */
	AIRY_ROVOL_TIER_SET     = 0x04,  /* Set page tier (CXL policy) */
	AIRY_ROVOL_MGLRU_CONFIG = 0x05,  /* Configure Multi-Gen LRU */
	AIRY_ROVOL_LIST         = 0x06,  /* List snapshots */
	AIRY_ROVOL_DELETE       = 0x07,  /* Delete snapshot */
	AIRY_ROVOL_DEMOTE       = 0x08,  /* Demote page (hot -> cold tier) */
	AIRY_ROVOL_PROMOTE      = 0x09,  /* Promote page (cold -> hot tier) */
	AIRY_ROVOL_TIER_GET     = 0x0A,  /* Query page tier */
	AIRY_ROVOL_OP_MAX                /* Exclusive upper bound (= 0x0B) */
};

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, MemoryRoVol L2-L4 tiering is
 * unavailable; only L1 (hot tier, anonymous pages) is accessible. All
 * GFP flags collapse to AIRY_GFP_HOT and all page classes collapse to
 * AIRY_PAGE_CLASS_ANON. alloc_pages + mmap remain functional.
 * See [DSL] §2.2 and §4.1.
 */
#ifdef AIRY_SC_FALLBACK
	/* All tiers collapse to L1 hot. */
	#define AIRY_DSL_MEM_LEVEL   AIRY_MEM_HOT
	#define AIRY_DSL_MEM_TIERS   1  /* Only L1 retained */

	/* All GFP flags collapse to HOT. */
	#define AIRY_DSL_GFP_HOT     AIRY_GFP_HOT
	#define AIRY_DSL_GFP_WARM    AIRY_GFP_HOT
	#define AIRY_DSL_GFP_COLD    AIRY_GFP_HOT
	#define AIRY_DSL_GFP_PMEM    AIRY_GFP_HOT

	/* All page classes collapse to ANON. */
	#define AIRY_DSL_PAGE_CLASS_ANON   AIRY_PAGE_CLASS_ANON
	#define AIRY_DSL_PAGE_CLASS_FILE   AIRY_PAGE_CLASS_ANON
	#define AIRY_DSL_PAGE_CLASS_SHMEM  AIRY_PAGE_CLASS_ANON
	#define AIRY_DSL_PAGE_CLASS_AGENT  AIRY_PAGE_CLASS_ANON

	/* MemoryRoVol control unavailable: no rovol op is served. */
	#define AIRY_DSL_ROVOL_OPS         0

	#warning "AIRY_SC_FALLBACK active: memory_types.h degraded to L1 hot tier only, MemoryRoVol L2-L4 unavailable"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_MEMORY_TYPES_H */

/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
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

#endif /* _UAPI_AIRYMAX_MEMORY_TYPES_H */

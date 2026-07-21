/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * kconfig_types.h — [IND] Kconfig-derived internal types.
 *
 * Types and constants that depend on kernel configuration options.
 * NOT part of the [SC] shared contract layer.
 */

#ifndef _AIRYMAX_KCONFIG_TYPES_H
#define _AIRYMAX_KCONFIG_TYPES_H

#include <linux/types.h>
#include <linux/kconfig.h>

/* Platform detection helpers */
#ifdef CONFIG_X86_64
	#define AIRY_ARCH_X86_64        1
#else
	#define AIRY_ARCH_X86_64        0
#endif

#ifdef CONFIG_ARM64
	#define AIRY_ARCH_ARM64         1
#else
	#define AIRY_ARCH_ARM64         0
#endif

/* Scheduling feature flags */
#define AIRY_HAS_SCHED_DEADLINE     IS_ENABLED(CONFIG_SCHED_DEADLINE)
#define AIRY_HAS_IO_URING           IS_ENABLED(CONFIG_IO_URING)
#define AIRY_HAS_LRU_GEN            IS_ENABLED(CONFIG_LRU_GEN)

/* Capability table sizing (Kconfig-tunable) */
#define AIRY_CONFIG_CAP_TABLE_SIZE  CONFIG_AIRY_CAP_TABLE_SIZE

#endif /* _AIRYMAX_KCONFIG_TYPES_H */

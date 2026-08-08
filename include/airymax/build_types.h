/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * build_types.h — [IND] Build-derived internal types.
 *
 * These types are generated or derived during the kernel build process
 * and are NOT part of the [SC] shared contract layer.
 */

#ifndef _AIRYMAX_BUILD_TYPES_H
#define _AIRYMAX_BUILD_TYPES_H

#include <linux/types.h>

/* Build-time constants derived from Kconfig */
#ifdef CONFIG_AIRY_SYSCALL
	#define AIRY_SYSCALL_ENABLED    1
#else
	#define AIRY_SYSCALL_ENABLED    0
#endif

#ifdef CONFIG_SECURITY_AIRY
	#define AIRY_LSM_ENABLED        1
#else
	#define AIRY_LSM_ENABLED        0
#endif

/* Build-derived version strings.
 *
 * 0.1.1 是奠基开发代号（项目工程基线，非产品版本号）；产品对外版本
 * 统一为 v1.0.1（IRON-7：禁止 v1.0/v1.1/v1.1.1/v1.2/v2.0 中间过渡
 * 版本）。0.1.1 作为唯一奠基版本直接过渡到 1.0.1，本宏在发布构建
 * 中切换为 1/0/1。
 */
#define AIRY_BUILD_VERSION_MAJOR     0
#define AIRY_BUILD_VERSION_MINOR     1
#define AIRY_BUILD_VERSION_PATCH     1

#endif /* _AIRYMAX_BUILD_TYPES_H */

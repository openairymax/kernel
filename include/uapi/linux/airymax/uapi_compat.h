/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-UAPI Compat: three-way type bridge for [SC] shared contract headers.
 *
 * This header provides portable fixed-width integer types for UAPI headers
 * that must compile identically in kernel-space, Linux user-space, and
 * non-Linux platforms (macOS, Windows agentrt).
 *
 *   #ifdef __KERNEL__      -> #include <linux/types.h>   (provides __u32 etc.)
 *   #elif defined(__linux__) -> typedef from <stdint.h>  (glibc/musl)
 *   #else                  -> typedef from <stdint.h>    (macOS/Windows)
 */

#ifndef _UAPI_AIRYMAX_UAPI_COMPAT_H
#define _UAPI_AIRYMAX_UAPI_COMPAT_H

#ifdef __KERNEL__
	/* Kernel-space: use Linux kernel UAPI types */
	#include <linux/types.h>
#elif defined(__linux__)
	/* Linux user-space: map stdint to kernel UAPI names */
	#include <stdint.h>
	typedef int32_t   __s32;
	typedef uint32_t  __u32;
	typedef int64_t   __s64;
	typedef uint64_t  __u64;
	typedef int16_t   __s16;
	typedef uint16_t  __u16;
	typedef int8_t    __s8;
	typedef uint8_t   __u8;
#else
	/* Non-Linux user-space (macOS, Windows): same mapping */
	#include <stdint.h>
	typedef int32_t   __s32;
	typedef uint32_t  __u32;
	typedef int64_t   __s64;
	typedef uint64_t  __u64;
	typedef int16_t   __s16;
	typedef uint16_t  __u16;
	typedef int8_t    __s8;
	typedef uint8_t   __u8;
#endif

#endif /* _UAPI_AIRYMAX_UAPI_COMPAT_H */

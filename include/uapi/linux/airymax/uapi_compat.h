/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
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
 *   #elif defined(__linux__) -> #include <linux/types.h>  (same UAPI types)
 *   #else                  -> typedef from <stdint.h>    (macOS/Windows)
 */

#ifndef _UAPI_AIRYMAX_UAPI_COMPAT_H
#define _UAPI_AIRYMAX_UAPI_COMPAT_H

#ifdef __KERNEL__
	/* Kernel-space: use Linux kernel UAPI types */
	#include <linux/types.h>
	#define _AIRY_UAPI_COMPAT_TYPES_SET 1
#elif defined(__linux__)
	/* Linux user-space: <linux/types.h> is the authoritative source of
	 * __u32/__u64/... types. Include it directly rather than redefining
	 * with <stdint.h> types, which may differ in type identity (e.g. on
	 * 64-bit, uint64_t = unsigned long vs __u64 = unsigned long long). */
	#include <linux/types.h>
	#include <stddef.h>   /* offsetof, used by layout _Static_asserts in [SC] headers */
	#define _AIRY_UAPI_COMPAT_TYPES_SET 1
#else
	/* Non-Linux user-space (macOS, Windows): same mapping */
	#include <stdint.h>
	#include <stddef.h>   /* offsetof, used by layout _Static_asserts in [SC] headers */
	typedef int32_t   __s32;
	typedef uint32_t  __u32;
	typedef int64_t   __s64;
	typedef uint64_t  __u64;
	typedef int16_t   __s16;
	typedef uint16_t  __u16;
	typedef int8_t    __s8;
	typedef uint8_t   __u8;
	#define _AIRY_UAPI_COMPAT_TYPES_SET 1
#endif

/* ─── Struct Alignment Abstraction (OS-IRON-016 sanctioned exception) ──
 *
 * AIRY_ALIGNED(N) provides a compiler-agnostic way to specify struct
 * alignment in UAPI headers without directly using __attribute__.
 *
 * C11's _Alignas cannot be placed after a struct type definition (it
 * only applies to variable declarations), so compiler extensions are
 * unavoidable for struct-level alignment. This macro is the single
 * sanctioned exception to OS-IRON-016's prohibition on __attribute__
 * in UAPI headers — all other __attribute__ uses remain prohibited.
 *
 * Usage (placement after closing brace, same as __attribute__):
 *
 *   struct foo {
 *       ...
 *   } AIRY_ALIGNED(64);
 *
 * Supported compilers:
 *   GCC / Clang: __attribute__((aligned(N)))   [Linux kernel + user-space]
 *   MSVC:        __declspec(align(N))           [Windows user-space, placed
 *                                               before struct keyword via
 *                                               AIRY_ALIGNED_PREFIX]
 *   C11 fallback: _Alignas(N)                   [may not work for struct
 *                                               type definitions]
 *
 * Rationale: Linux 6.6 UAPI headers use __aligned(N) (from
 * include/uapi/linux/types.h) which expands to __attribute__((aligned(N))).
 * AirymaxOS cannot reuse __aligned(N) directly in [SC] headers because
 * macOS/Windows user-space builds do not include <linux/types.h>.
 *
 * 注意：与 commons/utils/compat/include/compat.h 的 AIRY_ALIGNED 同名，
 * 用 #ifndef 保护避免跨头重复定义（2026-08-14 构建修复）。
 */
#ifndef AIRY_ALIGNED
#if defined(__GNUC__) || defined(__clang__)
	#define AIRY_ALIGNED(n) __attribute__((aligned(n)))
#elif defined(_MSC_VER)
	/* MSVC: __declspec(align(N)) must be placed BEFORE the struct keyword.
	 * Use AIRY_ALIGNED_PREFIX(N) struct foo { ... }; for MSVC builds.
	 * For portable code, use AIRY_ALIGNED(N) after the closing brace —
	 * MSVC will silently ignore it (no alignment), which is acceptable
	 * because Windows agentrt uses Clang, not MSVC, for [SC] headers. */
	#define AIRY_ALIGNED(n)
	#define AIRY_ALIGNED_PREFIX(n) __declspec(align(n))
#else
	/* C11 fallback: _Alignas may not enforce struct-level alignment
	 * after a type definition. This is a best-effort fallback. */
	#define AIRY_ALIGNED(n) _Alignas(n)
#endif
#endif /* AIRY_ALIGNED */

/* ─── Compile-time Assertion (E1, seL4 assert.h 对齐) ────────────────────
 *
 * AIRY_COMPILE_ASSERT(cond, msg) — 双模式编译期契约断言，用于 [SC]
 * 头文件中"内核-用户态常量一致性"的编译期钉死（v3.6 评审 E1，参考
 * seL4 include/assert.h L45-69 的 static_assert 用法）。
 *
 * 模式选择：
 *   C++            → static_assert（原生）
 *   C11 及以上     → _Static_assert（GCC/Clang/MSVC 均支持）
 *   其他（旧编译器）→ typedef 数组技巧（负数组长度触发编译错误）
 *
 * 与 Linux 内核 BUILD_BUG_ON 的差异：本宏用于 UAPI 共享头文件，
 * 必须同时在内核态、Linux 用户态、macOS/Windows 用户态编译通过。
 */
#if defined(__cplusplus)
	#define AIRY_COMPILE_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
	#define AIRY_COMPILE_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
	#define AIRY_COMPILE_ASSERT(cond, msg) \
		typedef char airy_ca_[(cond) ? 1 : -1]
#endif

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, the three-way type bridge collapses
 * to a two-way bridge: __KERNEL__ vs non-__KERNEL__. The non-Linux
 * branch (macOS/Windows) reuses the Linux user-space typedefs because
 * both rely on <stdint.h> with identical fixed-width mappings. This
 * guarantees that agentrt cross-platform builds still compile when the
 * full [SC] contract is degraded. See [DSL] §2.2.
 */
#ifdef AIRY_SC_FALLBACK
	#ifdef __KERNEL__
		/* Kernel branch unchanged — <linux/types.h> is authoritative. */
	#else
		/* User-space branches: if the main bridge already provided the
		 * fixed-width types (_AIRY_UAPI_COMPAT_TYPES_SET), keep them —
		 * re-typedefing from <stdint.h> would change type identity on
		 * 64-bit Linux (long vs long long) and conflict (the old per-type
		 * `#ifndef __u64` guards cannot detect typedefs, only macros).
		 * The stdint mapping below is the fallback when types are absent. */
		#ifndef _AIRY_UAPI_COMPAT_TYPES_SET
			#define _AIRY_DSL_UAPI_COMPAT_DONE
			#include <stdint.h>
			#include <stddef.h>
			typedef int32_t   __s32;
			typedef uint32_t  __u32;
			typedef int64_t   __s64;
			typedef uint64_t  __u64;
			typedef int16_t   __s16;
			typedef uint16_t  __u16;
			typedef int8_t    __s8;
			typedef uint8_t   __u8;
		#endif
	#endif
	#define AIRY_DSL_UAPI_BRANCHES  2  /* __KERNEL__ vs user-space */

	#warning "AIRY_SC_FALLBACK active: uapi_compat.h degraded to two-way bridge (__KERNEL__ vs user-space)"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_UAPI_COMPAT_H */

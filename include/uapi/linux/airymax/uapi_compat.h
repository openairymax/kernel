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
 *   #ifdef __KERNEL__      -> #include <linux/types.h>   (fixed-width types)
 *   #elif defined(__linux__) -> #include <linux/types.h>  (same UAPI types)
 *   #else                  -> typedef from <stdint.h>    (macOS/Windows)
 */

#ifndef _UAPI_AIRYMAX_UAPI_COMPAT_H
#define _UAPI_AIRYMAX_UAPI_COMPAT_H

#ifdef __KERNEL__
	/* Kernel-space: <linux/types.h> supplies the fixed-width types and
	 * <linux/stddef.h> supplies offsetof() for the layout assertions that
	 * the [SC] contract headers carry. Kbuild searches include/ before
	 * include/uapi/, so <linux/stddef.h> resolves to the kernel-internal
	 * definition (not the UAPI stub), which is the only offsetof provider
	 * available under -nostdinc. */
	#include <linux/types.h>
	#include <linux/stddef.h>   /* offsetof, used by layout _Static_asserts in [SC] headers */
	#define _AIRY_UAPI_COMPAT_TYPES_SET 1
#elif defined(__linux__)
	/* Linux user-space: <linux/types.h> is the authoritative source of
	 * the fixed-width UAPI types. Include it directly rather than
	 * redefining with <stdint.h> types, which may differ in type identity
	 * (e.g. on 64-bit, uint64_t = unsigned long vs __u64 = unsigned long
	 * long). */
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
 * unavoidable for struct-level alignment. AIRY_ALIGNED (defined here) and
 * AIRY_API (defined below) are the sanctioned compiler-portability
 * exceptions to OS-IRON-016's prohibition on __attribute__ in UAPI
 * headers — all other __attribute__ uses remain prohibited.
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

/* ─── Symbol Export Macro (OS-IRON-016 sanctioned exception) ────────────
 *
 * AIRY_API marks a function as part of the exported [SC] ABI. It expands
 * to the default symbol-visibility attribute on GCC>=4 / Clang so that
 * exports survive a -fvisibility=hidden library build, and to nothing on
 * compilers without visibility support — keeping the UAPI header
 * compiler-agnostic. Form follows 30-interfaces/01-syscalls.md §3.1.
 *
 * Guarded with #ifndef so a library build may override it (e.g.
 * -DAIRY_API=...) without a redefinition warning.
 */
#ifndef AIRY_API
#if defined(__GNUC__) && __GNUC__ >= 4
	#define AIRY_API __attribute__((visibility("default")))
#else
	#define AIRY_API
#endif
#endif /* AIRY_API */

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
	/* C90 兜底：负长度数组触发编译错误。typedef 名必须逐次唯一，否则同一
	 * 头里两处断言会在同一个编译单元里重定义同名 typedef，clang 的
	 * -Wtypedef-redefinition 会把 UAPI 头自检（-std=c90 -Wall）判红。
	 * __COUNTER__ 保证跨头唯一，缺失时退回 __LINE__。 */
	#define AIRY_JOIN_(a, b) a##b
	#define AIRY_JOIN(a, b) AIRY_JOIN_(a, b)
	#ifdef __COUNTER__
		#define AIRY_ASSERT_ID __COUNTER__
	#else
		#define AIRY_ASSERT_ID __LINE__
	#endif
	#define AIRY_COMPILE_ASSERT(cond, msg) \
		typedef char AIRY_JOIN(airy_ca_, AIRY_ASSERT_ID)[(cond) ? 1 : -1]
#endif

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined the bridge is contracted down to the
 * two paths [DSL] §2.2 guarantees: __KERNEL__ and __linux__. Non-Linux
 * hosts keep the <stdint.h> mapping above so agentrt cross-platform
 * builds still compile, but they are outside the degraded guarantee and
 * are not part of AIRY_DSL_UAPI_BRANCHES.
 *
 * The block is declarative only: the main bridge above already selected
 * the authoritative type source for every branch. Re-typedefing here was
 * unreachable (every branch sets _AIRY_UAPI_COMPAT_TYPES_SET) and would
 * change type identity on 64-bit Linux (long vs long long), so the
 * invariant is asserted rather than re-established.
 */
#ifdef AIRY_SC_FALLBACK
	#ifndef _AIRY_UAPI_COMPAT_TYPES_SET
		#error "AIRY_SC_FALLBACK: type bridge did not establish fixed-width types"
	#endif

	#define AIRY_DSL_UAPI_BRANCHES  2  /* __KERNEL__ vs __linux__ */

	#warning "AIRY_SC_FALLBACK active: uapi_compat.h degraded to two-way bridge (__KERNEL__ / __linux__)"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_UAPI_COMPAT_H */

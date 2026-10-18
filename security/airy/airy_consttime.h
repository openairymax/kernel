/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_consttime.h — 常量时间比较原语（Airy Pure-C LSM）。
 *
 * SSoT: docs-linux/110-security/07-airy-lsm-design.md §12.2.1/§12.2.2/
 * §12.2.3。fastpath C-S9 Badge 校验的三段比较必须全部执行，比较结果
 * 不得引入数据相关的分支；失败路径补齐 dummy 延迟以抹平响应时间差；
 * paranoid 模式下在读取槽位前插入投机执行屏障。
 */

#ifndef _SECURITY_AIRY_CONSTTIME_H
#define _SECURITY_AIRY_CONSTTIME_H

#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/types.h>

#define AIRY_CT_DELAY_NS	10U

/*
 * airy_ct_nz32 - 非零判定，返回 1 当且仅当 @v 非零。
 *
 * @v | -@v 的符号位在 @v 非零时必为 1，全程无分支、无数据相关访存。
 */
static __always_inline u32 airy_ct_nz32(u32 v)
{
	return (v | (0U - v)) >> 31;
}

/* airy_ct_eq32 - 常量时间相等判定，返回 1 当且仅当 @a == @b。 */
static __always_inline u32 airy_ct_eq32(u32 a, u32 b)
{
	u32 eq = airy_ct_nz32(a ^ b) ^ 1U;

	barrier();
	return eq;
}

/* airy_ct_perm - 权限包含判定，返回 1 当且仅当 @have 含 @need 全部位。 */
static __always_inline u32 airy_ct_perm(u32 have, u32 need)
{
	return airy_ct_eq32(have & need, need);
}

/*
 * airy_ct_delay - 失败路径 dummy 延迟（SSoT §12.2.1）。
 *
 * 仅在 Badge 校验失败时调用，使失败响应时间贴近成功路径。延迟量级
 * 由 ndelay() 保证，不追求单纳秒精度；barrier() 阻止编译器把延迟
 * 移出失败路径或与其他存储合并。
 */
static __always_inline void airy_ct_delay(void)
{
	ndelay(AIRY_CT_DELAY_NS);
	barrier();
}

/*
 * airy_ct_fence - 投机执行序列化屏障（SSoT §12.2.3）。
 *
 * 仅在 paranoid 模式调用，紧邻槽位读取之前，阻止推测执行把读取结果
 * 带过校验点。x86_64 用 lfence，arm64 用 isb；其余架构没有对应的
 * 单指令屏障，依赖 OLK 默认缓解策略，此处只保留编译器屏障。
 */
static __always_inline void airy_ct_fence(void)
{
#if defined(CONFIG_X86_64)
	asm volatile("lfence" ::: "memory");
#elif defined(CONFIG_ARM64)
	asm volatile("isb" ::: "memory");
#else
	barrier();
#endif
}

#endif /* _SECURITY_AIRY_CONSTTIME_H */

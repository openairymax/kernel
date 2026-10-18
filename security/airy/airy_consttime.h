/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_consttime.h — 常量时间比较原语（Airy Pure-C LSM）。
 *
 * SSoT: docs-linux/110-security/07-airy-lsm-design.md §12.2.1。
 * fastpath C-S9 Badge 校验的三段比较必须全部执行，比较结果不得
 * 引入数据相关的分支；失败路径补齐 dummy 延迟以抹平响应时间差。
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

#endif /* _SECURITY_AIRY_CONSTTIME_H */

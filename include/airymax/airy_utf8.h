/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 文件头（中文）：AirymaxOS 内核侧严格 UTF-8 校验原语（P-01）。
 *
 * 任何跨越内核边界的文本（syscall 参数、配置路径、策略标识）都必须在
 * 进入内核数据结构之前按 RFC 3629 逐序列判定。宽松的「字节非零即可」
 * 判定会让过长编码、UTF-16 代理对、Unicode 非字符与 BOM 混入后续比较
 * 与日志，产生同形不同码的字符串碰撞。
 *
 * 本头只暴露一组最小原语：序列长度判定（内联，无符号）、单序列解码与
 * 整串扫描。三者共用同一张判定表，错误码出自
 * <linux/airymax/error.h> 的 Encoding 子空间（241-246）。
 *
 * SSoT: docs/docs-linux/180-i18n/02-encoding-spec.md §2.2、§2.3、§7
 */

#ifndef _AIRY_UTF8_H
#define _AIRY_UTF8_H

#include <linux/compiler.h>
#include <linux/types.h>

/* UTF-8 单序列最多 4 字节，码点上界为 U+10FFFF。 */
#define AIRY_U8_MAX	4
#define AIRY_U8_MAXCP	0x10ffffU

/** typedef airy_ucp_t - 解码后的 Unicode 码点。 */
typedef u32 airy_ucp_t;

/**
 * airy_u8_len - 由首字节判定 UTF-8 序列长度。
 * @lead: 序列首字节。
 *
 * 只做结构判定，不校验续字节。0x80-0xBF 是续字节、0xC0-0xC1 与
 * 0xF5-0xFF 永远不能作为合法首字节，三者一律返回 0。
 *
 * Return: 1、2、3 或 4；@lead 不是合法首字节时返回 0。
 */
static inline unsigned int airy_u8_len(u8 lead)
{
	if (lead < 0x80)
		return 1;
	if (lead < 0xc2)
		return 0;
	if (lead < 0xe0)
		return 2;
	if (lead < 0xf0)
		return 3;
	if (lead < 0xf5)
		return 4;

	return 0;
}

/**
 * airy_u8_dec - 解码一个 UTF-8 序列并校验其合法性。
 * @s: 序列起点。
 * @len: @s 起可读字节数。
 * @cp: 输出码点，仅在返回正数时写入。
 *
 * 依次拒绝：截断序列、非法续字节、过长编码、UTF-16 代理对
 * （U+D800-U+DFFF）、超出 U+10FFFF、Unicode 非字符（U+FDD0-U+FDEF 与
 * 每平面末尾的 U+nFFFE/U+nFFFF）以及 BOM（U+FEFF，任意位置）。
 *
 * Return: 消耗的字节数（1-4）；非法时返回负的 AIRY_EENC_* 错误码。
 */
__must_check int airy_u8_dec(const u8 *s, size_t len, airy_ucp_t *cp);

/**
 * airy_u8_scan - 校验并以码点计数整个字节串。
 * @s: 待校验字节串。
 * @len: @s 的字节长度。
 *
 * 空串是合法输入，返回 0 个码点。@s 为 NULL 且 @len 非零时按非法
 * 序列处理，而不是解引用空指针。
 *
 * 返回值是 int 计数，调用方须保证码点数不超过 INT_MAX；本函数服务的
 * 内核边界单次最多接收 AIRY_SCHED_ARG_MAX 字节，远低于该上界。
 *
 * Return: 码点数；任一序列非法时返回该序列的负 AIRY_EENC_* 错误码。
 */
__must_check int airy_u8_scan(const u8 *s, size_t len);

#endif /* _AIRY_UTF8_H */

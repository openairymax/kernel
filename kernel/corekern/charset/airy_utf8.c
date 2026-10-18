// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_utf8.c — Airymax strict UTF-8 validation primitives.
 *
 * Single implementation of the RFC 3629 decision table shared by every
 * kernel entry that accepts text from userspace. The decoder rejects
 * structure faults (truncation, bad continuation, overlong forms) and
 * policy faults (surrogates, noncharacters, BOM, out-of-range code
 * points) with distinct AIRY_EENC_* codes so a caller can report the
 * first offending sequence without rescanning the input.
 *
 * SSoT: docs/docs-linux/180-i18n/02-encoding-spec.md §2.2、§2.3、§7
 */

#include <linux/compiler.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include <airymax/airy_utf8.h>

/* ─── 单序列解码 ──────────────────────────────────────────────────────── */

/**
 * airy_u8_dec - Decode and validate one UTF-8 sequence.
 * @s: sequence start.
 * @len: readable bytes from @s.
 * @cp: decoded code point, written only on success.
 *
 * Return: bytes consumed (1-4), or a negative AIRY_EENC_* code.
 */
__must_check int airy_u8_dec(const u8 *s, size_t len, airy_ucp_t *cp)
{
	airy_ucp_t u;
	size_t i;
	unsigned int n;

	if (!s || !cp || !len)
		return -AIRY_EENC_INVALID;

	n = airy_u8_len(s[0]);
	if (!n || n > len)
		return -AIRY_EENC_INVALID;

	for (i = 1; i < n; i++)
		if ((s[i] & 0xc0) != 0x80)
			return -AIRY_EENC_INVALID;

	switch (n) {
	case 1:
		u = s[0];
		break;
	case 2:
		u = ((airy_ucp_t)(s[0] & 0x1f) << 6) | (s[1] & 0x3f);
		break;
	case 3:
		u = ((airy_ucp_t)(s[0] & 0x0f) << 12) |
		    ((airy_ucp_t)(s[1] & 0x3f) << 6) | (s[2] & 0x3f);
		if (u < 0x800)
			return -AIRY_EENC_OVERLONG;
		if (u >= 0xd800 && u <= 0xdfff)
			return -AIRY_EENC_SURROGATE;
		break;
	default:
		u = ((airy_ucp_t)(s[0] & 0x07) << 18) |
		    ((airy_ucp_t)(s[1] & 0x3f) << 12) |
		    ((airy_ucp_t)(s[2] & 0x3f) << 6) | (s[3] & 0x3f);
		if (u < 0x10000)
			return -AIRY_EENC_OVERLONG;
		if (u > AIRY_U8_MAXCP)
			return -AIRY_EENC_RANGE;
		break;
	}

	if (u == 0xfeff)
		return -AIRY_EENC_BOM;

	if ((u >= 0xfdd0 && u <= 0xfdef) || (u & 0xfffe) == 0xfffe)
		return -AIRY_EENC_NONCHAR;

	*cp = u;

	return n;
}

/* ─── 整串扫描 ────────────────────────────────────────────────────────── */

/**
 * airy_u8_scan - Validate a byte string and count its code points.
 * @s: byte string.
 * @len: byte length of @s.
 *
 * Return: code point count, or the negative AIRY_EENC_* code of the
 *         first illegal sequence.
 */
__must_check int airy_u8_scan(const u8 *s, size_t len)
{
	airy_ucp_t cp;
	size_t i = 0;
	int n = 0;

	if (unlikely(!s && len))
		return -AIRY_EENC_INVALID;

	while (i < len) {
		int seq;

		seq = airy_u8_dec(s + i, len - i, &cp);
		if (seq < 0)
			return seq;
		i += seq;
		n++;
	}

	return n;
}

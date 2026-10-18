// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_utf8_test.c — KUnit coverage for the strict UTF-8 primitives.
 *
 * The suite drives airy_u8_len(), airy_u8_dec() and airy_u8_scan() over
 * the full RFC 3629 boundary matrix: every legal sequence width, every
 * structural fault (truncation, bad continuation, overlong form) and
 * every policy fault (surrogate, noncharacter, BOM, out-of-range code
 * point). Each rejection also proves the output code point is left
 * untouched, so a caller can never observe a half-decoded value.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>

#include <airymax/airy_utf8.h>

static void u8_ok(struct kunit *test, const u8 *seq, size_t len,
		  airy_ucp_t want, const char *what)
{
	airy_ucp_t cp = 0;

	KUNIT_EXPECT_EQ_MSG(test, (int)len, airy_u8_dec(seq, len, &cp),
			    "%s: sequence length", what);
	KUNIT_EXPECT_EQ_MSG(test, want, cp, "%s: code point", what);
}

static void u8_bad(struct kunit *test, const u8 *seq, size_t len,
		   int err, const char *what)
{
	airy_ucp_t cp = 0xffffffffu;

	KUNIT_EXPECT_EQ_MSG(test, err, airy_u8_dec(seq, len, &cp),
			    "%s: error code", what);
	KUNIT_EXPECT_EQ_MSG(test, 0xffffffffu, cp,
			    "%s: code point must stay untouched", what);
}

static void u8_len_table_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 1u, airy_u8_len(0x00));
	KUNIT_EXPECT_EQ(test, 1u, airy_u8_len(0x7f));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0x80));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0xbf));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0xc0));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0xc1));
	KUNIT_EXPECT_EQ(test, 2u, airy_u8_len(0xc2));
	KUNIT_EXPECT_EQ(test, 2u, airy_u8_len(0xdf));
	KUNIT_EXPECT_EQ(test, 3u, airy_u8_len(0xe0));
	KUNIT_EXPECT_EQ(test, 3u, airy_u8_len(0xef));
	KUNIT_EXPECT_EQ(test, 4u, airy_u8_len(0xf0));
	KUNIT_EXPECT_EQ(test, 4u, airy_u8_len(0xf4));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0xf5));
	KUNIT_EXPECT_EQ(test, 0u, airy_u8_len(0xff));
}

static void u8_dec_widths_test(struct kunit *test)
{
	static const u8 a[] = "A";
	static const u8 c2[] = { 0xc2, 0xa9 };
	static const u8 e4[] = { 0xe4, 0xb8, 0xad };
	static const u8 f0[] = { 0xf0, 0x9f, 0x98, 0x80 };
	static const u8 top[] = { 0xf4, 0x8f, 0xbf, 0xbd };

	u8_ok(test, a, sizeof(a) - 1, 0x41, "ascii");
	u8_ok(test, c2, sizeof(c2), 0xa9, "two-byte");
	u8_ok(test, e4, sizeof(e4), 0x4e2d, "three-byte");
	u8_ok(test, f0, sizeof(f0), 0x1f600, "four-byte");
	u8_ok(test, top, sizeof(top), AIRY_U8_MAXCP - 2, "last scalar");
}

static void u8_dec_struct_faults_test(struct kunit *test)
{
	static const u8 trunc2[] = { 0xc2 };
	static const u8 trunc3[] = { 0xe4, 0xb8 };
	static const u8 trunc4[] = { 0xf0, 0x9f, 0x98 };
	static const u8 cont2[] = { 0xc2, 0x41 };
	static const u8 cont3[] = { 0xe4, 0x41, 0xad };
	static const u8 cont4[] = { 0xf0, 0x9f, 0x41, 0x80 };
	static const u8 over2[] = { 0xc0, 0x80 };
	static const u8 over3[] = { 0xe0, 0x80, 0x80 };
	static const u8 over4[] = { 0xf0, 0x80, 0x80, 0x80 };
	static const u8 lone[] = { 0x80 };

	u8_bad(test, trunc2, sizeof(trunc2), -AIRY_EENC_INVALID, "truncated 2");
	u8_bad(test, trunc3, sizeof(trunc3), -AIRY_EENC_INVALID, "truncated 3");
	u8_bad(test, trunc4, sizeof(trunc4), -AIRY_EENC_INVALID, "truncated 4");
	u8_bad(test, cont2, sizeof(cont2), -AIRY_EENC_INVALID, "bad continuation 2");
	u8_bad(test, cont3, sizeof(cont3), -AIRY_EENC_INVALID, "bad continuation 3");
	u8_bad(test, cont4, sizeof(cont4), -AIRY_EENC_INVALID, "bad continuation 4");
	u8_bad(test, over2, sizeof(over2), -AIRY_EENC_INVALID, "overlong 2 lead");
	u8_bad(test, over3, sizeof(over3), -AIRY_EENC_OVERLONG, "overlong 3");
	u8_bad(test, over4, sizeof(over4), -AIRY_EENC_OVERLONG, "overlong 4");
	u8_bad(test, lone, sizeof(lone), -AIRY_EENC_INVALID, "lone continuation");
}

static void u8_dec_policy_faults_test(struct kunit *test)
{
	static const u8 sur_lo[] = { 0xed, 0xa0, 0x80 };
	static const u8 sur_hi[] = { 0xed, 0xbf, 0xbf };
	static const u8 range[] = { 0xf4, 0x90, 0x80, 0x80 };
	static const u8 non_lo[] = { 0xef, 0xb7, 0x90 };
	static const u8 non_hi[] = { 0xef, 0xb7, 0xaf };
	static const u8 non_fffe[] = { 0xef, 0xbf, 0xbe };
	static const u8 non_ffff[] = { 0xef, 0xbf, 0xbf };
	static const u8 non_top1[] = { 0xf4, 0x8f, 0xbf, 0xbe };
	static const u8 non_top2[] = { 0xf4, 0x8f, 0xbf, 0xbf };
	static const u8 bom[] = { 0xef, 0xbb, 0xbf };

	u8_bad(test, sur_lo, sizeof(sur_lo), -AIRY_EENC_SURROGATE, "U+D800");
	u8_bad(test, sur_hi, sizeof(sur_hi), -AIRY_EENC_SURROGATE, "U+DFFF");
	u8_bad(test, range, sizeof(range), -AIRY_EENC_RANGE, "U+110000");
	u8_bad(test, non_lo, sizeof(non_lo), -AIRY_EENC_NONCHAR, "U+FDD0");
	u8_bad(test, non_hi, sizeof(non_hi), -AIRY_EENC_NONCHAR, "U+FDEF");
	u8_bad(test, non_fffe, sizeof(non_fffe), -AIRY_EENC_NONCHAR, "U+FFFE");
	u8_bad(test, non_ffff, sizeof(non_ffff), -AIRY_EENC_NONCHAR, "U+FFFF");
	u8_bad(test, non_top1, sizeof(non_top1), -AIRY_EENC_NONCHAR,
	       "U+10FFFE");
	u8_bad(test, non_top2, sizeof(non_top2), -AIRY_EENC_NONCHAR,
	       "U+10FFFF");
	u8_bad(test, bom, sizeof(bom), -AIRY_EENC_BOM, "U+FEFF");
}

static void u8_dec_args_test(struct kunit *test)
{
	static const u8 a[] = "A";
	airy_ucp_t cp = 0;

	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID,
			airy_u8_dec(NULL, 1, &cp));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID,
			airy_u8_dec(a, sizeof(a) - 1, NULL));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID, airy_u8_dec(a, 0, &cp));
}

static void u8_scan_strings_test(struct kunit *test)
{
	static const u8 mixed[] = "A\xc2\xa9\xe4\xb8\xad\xf0\x9f\x98\x80";
	static const u8 empty[] = "";
	static const u8 bad_tail[] = { 0x41, 0xc2 };
	static const u8 bare_cont[] = { 0x41, 0x80 };
	static const u8 bad_mid[] = { 0x41, 0xed, 0xa0, 0x80, 0x42 };
	static const u8 bad_first[] = { 0xef, 0xbb, 0xbf, 0x41 };

	KUNIT_EXPECT_EQ(test, 4, airy_u8_scan(mixed, sizeof(mixed) - 1));
	KUNIT_EXPECT_EQ(test, 0, airy_u8_scan(empty, 0));
	KUNIT_EXPECT_EQ(test, 0, airy_u8_scan(NULL, 0));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID, airy_u8_scan(NULL, 4));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID,
			airy_u8_scan(bad_tail, sizeof(bad_tail)));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_INVALID,
			airy_u8_scan(bare_cont, sizeof(bare_cont)));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_SURROGATE,
			airy_u8_scan(bad_mid, sizeof(bad_mid)));
	KUNIT_EXPECT_EQ(test, -AIRY_EENC_BOM,
			airy_u8_scan(bad_first, sizeof(bad_first)));
}

static struct kunit_case airy_utf8_cases[] = {
	KUNIT_CASE(u8_len_table_test),
	KUNIT_CASE(u8_dec_widths_test),
	KUNIT_CASE(u8_dec_struct_faults_test),
	KUNIT_CASE(u8_dec_policy_faults_test),
	KUNIT_CASE(u8_dec_args_test),
	KUNIT_CASE(u8_scan_strings_test),
	{}
};

static struct kunit_suite airy_utf8_suite = {
	.name = "airy_utf8_charset",
	.test_cases = airy_utf8_cases,
};

kunit_test_suites(&airy_utf8_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_crc32_test.c — KUnit coverage for the C-S12 header digest.
 *
 * Verifies airy_crc32_calc()/airy_crc32_ok() against known-answer
 * vectors computed with zlib.crc32(), and pins the coverage contract:
 * capability_badge is inside the digest while the crc32 field and the
 * zeroed reserved tail are excluded.
 *
 * Both entry points are non-static (declared in airy_ipc_internal.h),
 * so the test links against airy_ipc_crc32.o within the airy_ck_ipc
 * module without including the .c file.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

#define KAT_HDR_ONLY_CRC	0x95819BBFU
#define KAT_WITH_PAYLOAD_CRC	0x4BB4FDDAU

static const char kat_payload[] = "AirymaxOS";

static void fill_kat_hdr(struct airy_ipc_msg_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->opcode = 0x0001;
	hdr->capability_badge = 0x000100007777CCCCULL;
}

static void fill_kat_payload_hdr(struct airy_ipc_msg_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = AIRY_IPC_MAGIC;
	hdr->opcode = 0x0003;
	hdr->trace_id = 0x1122334455667788ULL;
	hdr->src_task = 0x2a;
	hdr->dst_task = 0x2b;
	hdr->capability_badge = 0x000200009999DDDDULL;
	hdr->payload_len = sizeof(kat_payload) - 1;
}

static void kat_header_only_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_hdr(&hdr);
	hdr.crc32 = KAT_HDR_ONLY_CRC;

	KUNIT_EXPECT_EQ(test, KAT_HDR_ONLY_CRC, airy_crc32_calc(&hdr, NULL));
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_crc32_ok(&hdr, NULL));
}

static void kat_with_payload_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_payload_hdr(&hdr);
	hdr.crc32 = KAT_WITH_PAYLOAD_CRC;

	KUNIT_EXPECT_EQ(test, KAT_WITH_PAYLOAD_CRC,
			airy_crc32_calc(&hdr, kat_payload));
	KUNIT_EXPECT_EQ(test, AIRY_EOK, airy_crc32_ok(&hdr, kat_payload));
}

static void tamper_badge_detected_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_hdr(&hdr);
	hdr.crc32 = KAT_HDR_ONLY_CRC;
	hdr.capability_badge ^= 1ULL;

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CRC32, airy_crc32_ok(&hdr, NULL));
}

static void tamper_opcode_detected_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_hdr(&hdr);
	hdr.crc32 = KAT_HDR_ONLY_CRC;
	hdr.opcode = 0x0002;

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CRC32, airy_crc32_ok(&hdr, NULL));
}

static void tamper_payload_len_detected_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_payload_hdr(&hdr);
	hdr.crc32 = KAT_WITH_PAYLOAD_CRC;
	hdr.payload_len--;

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_CRC32,
			airy_crc32_ok(&hdr, kat_payload));
}

static void crc_field_excluded_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_hdr(&hdr);
	KUNIT_EXPECT_EQ(test, KAT_HDR_ONLY_CRC, airy_crc32_calc(&hdr, NULL));

	hdr.crc32 = 0xA5A5A5A5U;
	KUNIT_EXPECT_EQ(test, KAT_HDR_ONLY_CRC, airy_crc32_calc(&hdr, NULL));
}

static void reserved_excluded_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_hdr(&hdr);
	KUNIT_EXPECT_EQ(test, KAT_HDR_ONLY_CRC, airy_crc32_calc(&hdr, NULL));

	memset(hdr.reserved, 0xFF, sizeof(hdr.reserved));
	KUNIT_EXPECT_EQ(test, KAT_HDR_ONLY_CRC, airy_crc32_calc(&hdr, NULL));
}

static void payload_without_buf_test(struct kunit *test)
{
	struct airy_ipc_msg_hdr hdr;

	fill_kat_payload_hdr(&hdr);
	hdr.crc32 = KAT_WITH_PAYLOAD_CRC;

	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_NOTSUPP, airy_crc32_ok(&hdr, NULL));
}

static void null_hdr_returns_einval_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_crc32_ok(NULL, NULL));
}

static struct kunit_case airy_ipc_crc32_cases[] = {
	KUNIT_CASE(kat_header_only_test),
	KUNIT_CASE(kat_with_payload_test),
	KUNIT_CASE(tamper_badge_detected_test),
	KUNIT_CASE(tamper_opcode_detected_test),
	KUNIT_CASE(tamper_payload_len_detected_test),
	KUNIT_CASE(crc_field_excluded_test),
	KUNIT_CASE(reserved_excluded_test),
	KUNIT_CASE(payload_without_buf_test),
	KUNIT_CASE(null_hdr_returns_einval_test),
	{}
};

static struct kunit_suite airy_ipc_crc32_suite = {
	.name = "airy_ipc_crc32_c_s12",
	.test_cases = airy_ipc_crc32_cases,
};

kunit_test_suites(&airy_ipc_crc32_suite);

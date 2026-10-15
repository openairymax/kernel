// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_crc32.c — fastpath C-S12 integrity digest for Layout C v4.
 *
 * The 128-byte header carries a crc32 field (offset 52) covering
 * header[0:52) plus the payload.  The covered range deliberately
 * includes capability_badge: a forged Badge that slips past C-S9 still
 * changes the digest, so tampering cannot survive to delivery.  The
 * crc32 field itself and the zeroed reserved[72] tail (C-S4) are
 * excluded, keeping the digest independent of its own output.
 *
 * crc32_le() with the usual pre/post inversion yields the reflected
 * IEEE 802.3 CRC-32 used by zlib, so userland producers compute the
 * same value with crc32(0, buf, len).
 *
 * SSoT: docs/docs-linux/30-interfaces/07-ipc-fastpath.md §3.1 (C-S12)
 */

#include <linux/compiler.h>
#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_internal.h"

__u32 airy_crc32_calc(const struct airy_ipc_msg_hdr *hdr, const void *payload)
{
	u32 crc;

	crc = crc32_le(~0U, (const u8 *)hdr,
		       offsetof(struct airy_ipc_msg_hdr, crc32));
	if (hdr->payload_len)
		crc = crc32_le(crc, payload, hdr->payload_len);

	return crc ^ ~0U;
}

__must_check int airy_crc32_ok(const struct airy_ipc_msg_hdr *hdr,
			       const void *payload)
{
	if (unlikely(!hdr))
		return -EINVAL;

	if (unlikely(hdr->payload_len && !payload))
		return -AIRY_EIPC_NOTSUPP;

	if (unlikely(airy_crc32_calc(hdr, payload) != hdr->crc32))
		return -AIRY_EIPC_CRC32;

	return AIRY_EOK;
}

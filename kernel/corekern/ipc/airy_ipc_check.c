// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check.c — stateless Layout C v4 header contract.
 *
 * Implements the field checks that depend on nothing but the header
 * itself, so the io_uring data plane and syscall 548 share one copy:
 * C-S1 magic, C-S3 payload ceiling, C-S10 flags and C-S4 reserved tail.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1;
 *       30-interfaces/08-sc-error-contract.md §2.3.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_check.h"

__must_check int airy_ipc_hdr_ok(const struct airy_ipc_msg_hdr *hdr)
{
	unsigned int i;

	if (unlikely(!hdr))
		return -EINVAL;

	/* C-S1: the buffer must announce itself as a Layout C v4 header. */
	if (unlikely(hdr->magic != AIRY_IPC_MAGIC))
		return -AIRY_EIPC_MAGIC;

	/*
	 * C-S3: payload_len must fit under the [SC] ceiling. A larger value
	 * can never map onto a legal frame, so it is rejected here rather
	 * than left for the data plane copy-in to choke on.
	 */
	if (unlikely(hdr->payload_len > AIRY_IPC_MAX_PAYLOAD))
		return -AIRY_EIPC_PAYLOAD;

	/* C-S10: reserved flag bits (5-15) are contractually zero. */
	if (unlikely(hdr->flags & AIRY_IPC_FLAG_RESERVED))
		return -AIRY_EIPC_FLAGS;

	/*
	 * C-S10: ENCRYPT/COMPRESS are declared in the [SC] header for
	 * forward ABI stability, but no v1.0.1 code path produces or
	 * consumes them. Accepting a message that sets either would let a
	 * caller assert a confidentiality/compression property the kernel
	 * never applies, so they are rejected as unsupported.
	 */
	if (unlikely(hdr->flags & (AIRY_IPC_FLAG_ENCRYPT |
				   AIRY_IPC_FLAG_COMPRESS)))
		return -AIRY_EIPC_NOTSUPP;

	/* C-S4: reserved[72] is a closed contract and must be all zero. */
	for (i = 0; i < sizeof(hdr->reserved); i++) {
		if (unlikely(hdr->reserved[i]))
			return -AIRY_EIPC_RESERVED;
	}

	return AIRY_EOK;
}

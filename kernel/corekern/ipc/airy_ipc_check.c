// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_check.c — Layout C v4 header contract and fastpath chain.
 *
 * The field checks depend on nothing but the header, so the io_uring
 * data plane and syscall 548 share one copy. airy_ipc_validate() layers
 * the context gate and the Badge checkpoint on top for the data plane,
 * whose callers must be in task context and own a header-borne Badge.
 *
 * SSoT: 30-interfaces/07-ipc-fastpath.md §3.1;
 *       30-interfaces/08-sc-error-contract.md §2.3;
 *       110-security/03-capability-model.md §2.6.1.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/preempt.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "../../../security/airy/airy_cap.h"

#include "airy_ipc_check.h"
#include "airy_ipc_op.h"

__must_check int airy_ipc_hdr_ok(const struct airy_ipc_msg_hdr *hdr)
{
	unsigned int i;

	if (unlikely(!hdr))
		return -EINVAL;

	if (unlikely(hdr->magic != AIRY_IPC_MAGIC))
		return -AIRY_EIPC_MAGIC;

	if (unlikely(airy_op_plane(hdr->opcode) == AIRY_PLANE_INVALID))
		return -AIRY_EIPC_OPCODE;

	if (unlikely(hdr->payload_len > AIRY_IPC_MAX_PAYLOAD))
		return -AIRY_EIPC_PAYLOAD;

	for (i = 0; i < sizeof(hdr->reserved); i++) {
		if (unlikely(hdr->reserved[i]))
			return -AIRY_EIPC_RESERVED;
	}

	return AIRY_EOK;
}

__must_check int airy_flags_ok(const struct airy_ipc_msg_hdr *hdr)
{
	if (unlikely(hdr->flags & AIRY_IPC_FLAG_RESERVED))
		return -AIRY_EIPC_FLAGS;

	if (unlikely(hdr->flags & (AIRY_IPC_FLAG_ENCRYPT |
				   AIRY_IPC_FLAG_COMPRESS)))
		return -AIRY_EIPC_NOTSUPP;

	return AIRY_EOK;
}

/*
 * C-S9. A CAP_REQUEST carries no Badge at all and may only address sec_d,
 * while a zero Badge is the normal agentrt and [DSL] shape and skips the
 * folded checks -- unless it claims to carry a capability. Only a
 * non-zero Badge is folded and compared against the sender's slot.
 */
static __must_check int cap_badge_ok(const struct airy_ipc_msg_hdr *hdr)
{
	__u64 badge = hdr->capability_badge;
	int ret;

	if (unlikely(hdr->opcode == AIRY_IPC_OP_CAP_REQUEST)) {
		if (unlikely(hdr->dst_task != AIRY_SEC_D_TASK_ID))
			return -AIRY_ECAP_BADGE;

		return AIRY_EOK;
	}

	if (!badge) {
		if (hdr->flags & AIRY_IPC_FLAG_CAP_CARRY)
			return -AIRY_ECAP_BADGE;

		return AIRY_EOK;
	}

	ret = airy_cap_badge_ok(badge, (__u32)hdr->src_task,
				airy_op_required_perms(hdr->opcode));
	if (unlikely(ret == -AIRY_ECAP_FORGED)) {
#if IS_ENABLED(CONFIG_SECURITY_AIRY)
		airy_security_fault((__u32)hdr->src_task,
				    AIRY_FAULT_CAP_FORGED);
#endif
	}

	return ret;
}

__must_check int airy_ipc_validate(const struct airy_ipc_msg_hdr *hdr)
{
	int ret;

	ret = airy_ipc_hdr_ok(hdr);
	if (unlikely(ret))
		return ret;

	if (unlikely(!in_task()))
		return -AIRY_EIPC_CONTEXT;

	ret = cap_badge_ok(hdr);
	if (unlikely(ret))
		return ret;

	return airy_flags_ok(hdr);
}

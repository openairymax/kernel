/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Core syscall registry: the four entry points of the 548-571 window
 * described as data. The operation ranges come from the [SC] enums
 * that own them, so the table cannot drift from the headers it
 * describes.
 *
 * SSoT: 140-application-development/07-syscall-registry.md §2-§4.
 */

#include <linux/airymax/cognition_types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/memory_types.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/syscalls.h>
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <asm/unistd.h>

#include "airy_sysabi.h"

/*
 * The registry has one entry per core syscall, and every entry must
 * carry the same number the ABI header and the generated unistd table
 * publish. The __NR_* half is compiled only where asm-generic owns the
 * numbering; x86_64 joins it when its syscall table gains the slots.
 */
static_assert(AIRY_DESC_COUNT == AIRY_SYS_CLT_NOTIFY - AIRY_SYS_CALL + 1);

#ifdef __NR_airy_sys_call
static_assert(__NR_airy_sys_call == AIRY_SYS_CALL,
	      "syscall registry: 548 disagrees with asm-generic");
static_assert(__NR_airy_sys_rovol_ctl == AIRY_SYS_ROVOL_CTL,
	      "syscall registry: 549 disagrees with asm-generic");
static_assert(__NR_airy_sys_sched_ctl == AIRY_SYS_SCHED_CTL,
	      "syscall registry: 550 disagrees with asm-generic");
static_assert(__NR_airy_sys_clt_notify == AIRY_SYS_CLT_NOTIFY,
	      "syscall registry: 551 disagrees with asm-generic");
#endif

const struct airy_sys_desc airy_sys_desc_tbl[AIRY_DESC_COUNT] = {
	{
		.nr	= AIRY_SYS_CALL,
		.nargs	= 2,
		.op_src	= AIRY_SYS_OP_SRC_MSG,
		.op_dom	= AIRY_SYS_OP_DOM_NONE,
		.op_err	= AIRY_EIPC_OPCODE,
		.name	= "airy_sys_call",
	},
	{
		.nr	= AIRY_SYS_ROVOL_CTL,
		.op_first = AIRY_ROVOL_SNAPSHOT,
		.op_last = AIRY_ROVOL_OP_MAX,
		.op_err	= AIRY_EINVAL,
		.nargs	= 3,
		.op_src	= AIRY_SYS_OP_SRC_ARG0,
		.op_dom	= AIRY_SYS_OP_DOM_RANGE,
		.name	= "airy_sys_rovol_ctl",
	},
	{
		.nr	= AIRY_SYS_SCHED_CTL,
		.op_first = AIRY_SCHED_SET_POLICY,
		.op_last = AIRY_SCHED_OP_MAX,
		.op_err	= AIRY_EINVAL,
		.nargs	= 3,
		.op_src	= AIRY_SYS_OP_SRC_ARG0,
		.op_dom	= AIRY_SYS_OP_DOM_RANGE,
		.name	= "airy_sys_sched_ctl",
	},
	{
		.nr	= AIRY_SYS_CLT_NOTIFY,
		.op_first = AIRY_COG_PERCEPT,
		.op_last = AIRY_COG_PHASE_MAX,
		.op_err	= AIRY_ECOG_PHASE,
		.nargs	= 2,
		.op_src	= AIRY_SYS_OP_SRC_ARG1,
		.op_dom	= AIRY_SYS_OP_DOM_RANGE,
		.name	= "airy_sys_clt_notify",
	},
};

const struct airy_sys_desc *airy_desc_find(u16 nr)
{
	int i;

	for (i = 0; i < AIRY_DESC_COUNT; i++)
		if (airy_sys_desc_tbl[i].nr == nr)
			return &airy_sys_desc_tbl[i];

	return NULL;
}

int airy_op_check(u16 nr, u32 op)
{
	const struct airy_sys_desc *desc = airy_desc_find(nr);

	if (!desc || desc->op_dom != AIRY_SYS_OP_DOM_RANGE)
		return -AIRY_EINVAL;

	if (op < desc->op_first || op >= desc->op_last)
		return -(int)desc->op_err;

	return AIRY_EOK;
}

int airy_abi_verdict(const struct airy_abi_hdr *hdr, u32 known)
{
	if (!hdr || known < sizeof(*hdr))
		return -EINVAL;

	if (hdr->size < sizeof(*hdr) || hdr->size < known || hdr->reserved)
		return -EINVAL;

	if (hdr->version != AIRY_ABI_VERSION)
		return -AIRY_ENOTSUP;

	return AIRY_EOK;
}

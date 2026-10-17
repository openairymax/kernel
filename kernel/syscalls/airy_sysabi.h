/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Syscall ABI registry for the four core agent-linux entry points:
 * one definition of their argument counts and operation ranges,
 * shared by 549/550/551 instead of three hand-written tests.
 *
 *   548 airy_sys_call       2 args  op: msg->opcode  ipc.h
 *   549 airy_sys_rovol_ctl  3 args  op: arg 0        memory_types.h
 *   550 airy_sys_sched_ctl  3 args  op: arg 0        sched.h
 *   551 airy_sys_clt_notify 2 args  op: arg 1        cognition_types.h
 *
 * 548's operation space belongs to the IPC message header, not to this
 * registry; its descriptor records that and leaves the test to IPC.
 *
 * SSoT: 07-syscall-registry.md §2-§4 (registry), §8.2 (version).
 */

#ifndef _AIRY_SYSABI_H
#define _AIRY_SYSABI_H

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * Where the entry point finds the operation code. A descriptor that
 * names no source describes a call without an operation argument.
 */
enum airy_sys_op_src {
	AIRY_SYS_OP_SRC_NONE = 0,
	AIRY_SYS_OP_SRC_MSG,
	AIRY_SYS_OP_SRC_ARG0,
	AIRY_SYS_OP_SRC_ARG1,
};

/*
 * How the operation code is bounded. RANGE means this registry owns
 * the space and airy_op_check() enforces [op_first, op_last); NONE
 * means another SSoT owns it and no value can be judged here.
 */
enum airy_sys_op_dom {
	AIRY_SYS_OP_DOM_NONE = 0,
	AIRY_SYS_OP_DOM_RANGE,
};

/**
 * struct airy_sys_desc - one entry of the core syscall registry
 * @nr: syscall number (548-551)
 * @op_first: first accepted operation code, inclusive
 * @op_last: first rejected operation code, exclusive
 * @op_err: AIRY_E* magnitude reported for a rejected code
 * @nargs: number of arguments the entry point takes
 * @op_src: argument that carries the operation code
 * @op_dom: whether @op_first and @op_last are meaningful
 * @name: entry point name, for diagnostics and registry tests
 */
struct airy_sys_desc {
	u16 nr;
	u16 op_first;
	u16 op_last;
	u16 op_err;
	u8 nargs;
	u8 op_src;
	u8 op_dom;
	const char *name;
};

#define AIRY_DESC_COUNT	4

extern const struct airy_sys_desc airy_sys_desc_tbl[AIRY_DESC_COUNT];

/**
 * airy_desc_find - look up a core syscall descriptor
 * @nr: syscall number
 *
 * Return: the descriptor for @nr, or NULL when @nr is not one of the
 *         four core agent-linux entry points.
 */
const struct airy_sys_desc *airy_desc_find(u16 nr);

/**
 * airy_op_check - validate an operation code against the registry
 * @nr: syscall number
 * @op: operation code taken from the descriptor's @op_src argument
 *
 * The single boundary test shared by the 549, 550 and 551 entries.
 * An unknown @nr, or a descriptor whose operation space belongs to
 * another SSoT, is an API misuse and yields -AIRY_EINVAL; a code
 * outside the descriptor's range yields -@op_err; a code inside it
 * yields AIRY_EOK.
 *
 * Return: AIRY_EOK when @op belongs to @nr; -AIRY_EINVAL when the
 *         registry cannot judge @nr; -@op_err otherwise.
 */
__must_check int airy_op_check(u16 nr, u32 op);

/*
 * Version negotiation (SSoT: 07-syscall-registry.md §8.2). Every
 * versioned parameter struct starts with this prefix, so a pointer to
 * the struct is also a pointer to the header and no separate copy is
 * needed.
 */
struct airy_abi_hdr {
	u32 size;
	u32 version;
	u32 reserved;
};

#define AIRY_ABI_VERSION	0x0100u

/**
 * airy_abi_verdict - apply the parameter struct version rule
 * @hdr: header at the start of an already copied parameter struct
 * @known: sizeof() of the kernel's definition of that struct
 *
 * The caller copies the user struct first, because it needs the
 * payload anyway, and then asks this function whether the embedded
 * prefix may be trusted. A size larger than @known is forward
 * compatible: the caller reads only @known bytes. A size smaller
 * than @known, a size that cannot even hold the prefix, and a
 * non-zero @reserved field are malformed requests. A version other
 * than AIRY_ABI_VERSION is a well-formed request for a contract this
 * kernel does not implement.
 *
 * @known below sizeof(struct airy_abi_hdr) is a caller bug.
 *
 * Return: AIRY_EOK when the prefix is trusted; -AIRY_ENOTSUP for a
 *         foreign version; -EINVAL for @hdr == NULL or a malformed
 *         prefix.
 */
__must_check int airy_abi_verdict(const struct airy_abi_hdr *hdr,
				  u32 known);

#endif /* _AIRY_SYSABI_H */

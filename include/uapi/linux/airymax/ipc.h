/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * A-IPC (Unified Airymax IPC Fabric) — [SC] shared contract header.
 *
 * 128-byte message header Layout C v4 with Capability Folding.
 * Badge 64-bit Native Word layout: Epoch<<48 | RandomTag<<16 | Perms.
 * magic: 0x41524531 ('ARE1').
 */

#ifndef _UAPI_AIRYMAX_IPC_H
#define _UAPI_AIRYMAX_IPC_H

#include <linux/airymax/uapi_compat.h>

/* ─── Constants ──────────────────────────────────────────────────────── */
#define AIRY_IPC_MAGIC          0x41524531u /* 'ARE1' */
#define AIRY_IPC_HDR_SIZE       128

/* ─── IPC Opcodes ────────────────────────────────────────────────────── */
#define AIRY_IPC_OP_SEND        0x0001  /* Unicast send */
#define AIRY_IPC_OP_RECV        0x0002  /* Unicast receive */
#define AIRY_IPC_OP_SEND_BATCH  0x0003  /* Batch send */
#define AIRY_IPC_OP_CANCEL      0x0004  /* Cancel pending operation */
#define AIRY_IPC_OP_FREEZE      0x0005  /* Freeze IPC ring */
#define AIRY_IPC_OP_CAP_REQUEST 0x0010  /* Capability request (bootstrap) */
#define AIRY_IPC_OP_CAP_RESPONSE 0x0011 /* Capability response */

/* ─── IPC Flags ────────────────────────────────────────────────────────
 * SSoT: docs/AirymaxOS/30-interfaces/02-ipc-protocol.md §3.1
 *
 * Bit assignment (16-bit __u16 flags field at offset 6):
 *   bits 0-4:   active flags (5 defined)
 *   bits 5-15:  reserved, must be zero (C-S10 validates via RESERVED mask)
 *
 * v1.0.1: NOWAIT/SIGNAL removed — superseded by io_uring IOSQE_ASYNC and
 * IORING_CQE_F_NOTIF (see 20-modules/01-kernel.md §6.3).
 */
#define AIRY_IPC_FLAG_ZEROCOPY   0x0001  /* Zero-copy path enabled */
#define AIRY_IPC_FLAG_CAP_CARRY  0x0002  /* Carrying a capability */
#define AIRY_IPC_FLAG_ENCRYPT    0x0004  /* Payload is encrypted (reserved, 0.1.1 inactive) */
#define AIRY_IPC_FLAG_COMPRESS   0x0008  /* Payload is compressed (reserved, 0.1.1 inactive) */
#define AIRY_IPC_FLAG_BATCH_TAIL 0x0010  /* Last SQE in a batch */
#define AIRY_IPC_FLAG_RESERVED   0xFFE0  /* Bits 5-15: must be zero (C-S10 check) */

/* ─── Badge 64-bit Native Word Bit Layout ────────────────────────────── */
#define AIRY_BADGE_EPOCH_SHIFT  48
#define AIRY_BADGE_RANDTAG_SHIFT 16
#define AIRY_BADGE_PERMS_SHIFT  0

#define AIRY_BADGE_EPOCH_MASK   ((__u64)0xFFFF << AIRY_BADGE_EPOCH_SHIFT)
#define AIRY_BADGE_RANDTAG_MASK ((__u64)0xFFFFFFFF << AIRY_BADGE_RANDTAG_SHIFT)
#define AIRY_BADGE_PERMS_MASK   ((__u64)0xFFFF << AIRY_BADGE_PERMS_SHIFT)

#define AIRY_BADGE_COMPILE(epoch, randtag, perms) \
	(((__u64)((epoch) & 0xFFFF) << AIRY_BADGE_EPOCH_SHIFT) | \
	 ((__u64)((randtag) & 0xFFFFFFFF) << AIRY_BADGE_RANDTAG_SHIFT) | \
	 ((__u64)((perms) & 0xFFFF) << AIRY_BADGE_PERMS_SHIFT))

#define AIRY_BADGE_EPOCH(b)   (((b) & AIRY_BADGE_EPOCH_MASK) >> AIRY_BADGE_EPOCH_SHIFT)
#define AIRY_BADGE_RANDTAG(b) (((b) & AIRY_BADGE_RANDTAG_MASK) >> AIRY_BADGE_RANDTAG_SHIFT)
#define AIRY_BADGE_PERMS(b)   (((b) & AIRY_BADGE_PERMS_MASK) >> AIRY_BADGE_PERMS_SHIFT)

/* ─── Capability Permission Bits ─────────────────────────────────────── */
#define AIRY_CAP_PERM_SEND      0x0001  /* Send messages */
#define AIRY_CAP_PERM_RECV      0x0002  /* Receive messages */
#define AIRY_CAP_PERM_CALL      0x0004  /* Call (RPC-style) */
#define AIRY_CAP_PERM_GRANT     0x0008  /* Grant (delegate) */
#define AIRY_CAP_PERM_REVOKE    0x0010  /* Revoke capabilities */
#define AIRY_CAP_PERM_FREEZE    0x0020  /* Freeze agent */
#define AIRY_CAP_PERM_BATCH     0x0040  /* Batch operations */
#define AIRY_CAP_PERM_ALL       (0x007Fu) /* all 7 perms */
#define AIRY_CAP_PERM_RESERVED  0xFF80  /* must be zero */

/* ─── IPC Message Header Layout C v4 ─────────────────────────────────── */
struct airy_ipc_msg_hdr {
	__u32   magic;             /* offset 0:  AIRY_IPC_MAGIC */
	__u16   opcode;            /* offset 4:  IPC opcode */
	__u16   flags;             /* offset 6:  message flags */
	__u64   trace_id;          /* offset 8:  distributed trace ID */
	__u64   timestamp_ns;      /* offset 16: monotonic ns timestamp */
	__u64   src_task;          /* offset 24: source task identifier */
	__u64   dst_task;          /* offset 32: destination task identifier */
	__u64   capability_badge;  /* offset 40: Capability Folding badge (64-bit) */
	__u32   payload_len;       /* offset 48: payload length in bytes */
	__u32   crc32;             /* offset 52: CRC32 of payload */
	__u8    reserved[72];      /* offset 56: reserved for future use */
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct airy_ipc_msg_hdr) == AIRY_IPC_HDR_SIZE,
	       "airy_ipc_msg_hdr must be exactly 128 bytes");

_Static_assert(offsetof(struct airy_ipc_msg_hdr, magic) == 0,
	       "airy_ipc_msg_hdr.magic must be at offset 0");
_Static_assert(offsetof(struct airy_ipc_msg_hdr, opcode) == 4,
	       "airy_ipc_msg_hdr.opcode must be at offset 4");
_Static_assert(offsetof(struct airy_ipc_msg_hdr, capability_badge) == 40,
	       "capability_badge must be at offset 40 (8-byte aligned, D-9 fix)");
_Static_assert(offsetof(struct airy_ipc_msg_hdr, payload_len) == 48,
	       "payload_len must be at offset 48");
_Static_assert(offsetof(struct airy_ipc_msg_hdr, crc32) == 52,
	       "crc32 must be at offset 52");
_Static_assert(offsetof(struct airy_ipc_msg_hdr, reserved) == 56,
	       "reserved must be at offset 56");

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, IPC degrades to a minimal 128-byte
 * header overlay (airy_ipc_msg_hdr_min) with capability_badge fixed to 0
 * (H6 hard constraint: fastpath C-S9 skips Badge validation). Only
 * SEND/RECV opcodes are supported; FREEZE/CAP_REQUEST/CAP_RESPONSE are
 * mapped to SEND to preserve compilability. See [DSL] §2.2 and §4.4.
 */
#ifdef AIRY_SC_FALLBACK
	/* H6: capability_badge fixed to 0 — fastpath C-S9 goto cap_pass */
	#define AIRY_DSL_CAPABILITY_BADGE   0ULL

	/* Only SEND/RECV are real opcodes in [DSL]; others map to SEND. */
	#define AIRY_DSL_IPC_OP_SEND         AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OP_RECV         AIRY_IPC_OP_RECV
	#define AIRY_DSL_IPC_OP_SEND_BATCH   AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OP_CANCEL       AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OP_FREEZE       AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OP_CAP_REQUEST  AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OP_CAP_RESPONSE AIRY_IPC_OP_SEND
	#define AIRY_DSL_IPC_OPCODES         2  /* Only SEND + RECV retained */

	/* Minimal 128-byte header overlay (Layout C v4 compatible). */
	struct airy_ipc_msg_hdr_min {
		__u32   magic;             /* offset  0: AIRY_IPC_MAGIC */
		__u16   opcode;            /* offset  4 */
		__u8    _pad0[34];         /* offset  6-39: zeroed (trace/ts/src/dst) */
		__u64   capability_badge;  /* offset 40: fixed 0 (H6) */
		__u32   payload_len;       /* offset 48 */
		__u32   crc32;             /* offset 52 */
		__u8    _pad1[72];         /* offset 56-127: zeroed reserved */
	} __attribute__((aligned(64)));

	_Static_assert(offsetof(struct airy_ipc_msg_hdr_min, capability_badge) == 40,
		       "H1: [DSL] capability_badge offset must be 40");
	_Static_assert(sizeof(struct airy_ipc_msg_hdr_min) == AIRY_IPC_HDR_SIZE,
		       "[DSL] airy_ipc_msg_hdr_min must overlay airy_ipc_msg_hdr (128 bytes)");

	#warning "AIRY_SC_FALLBACK active: ipc.h degraded to minimal 128B header, capability_badge=0 (H6), only SEND/RECV opcodes"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_IPC_H */

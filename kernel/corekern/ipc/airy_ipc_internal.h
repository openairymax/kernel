/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_internal.h — internal shared declarations for the Airymax
 * corekern IPC subdirectory.
 *
 * Defines struct airy_ipc_ring and declares the ring/fastpath/zero-copy
 * entry points shared across airy_ipc_ring.c, airy_ipc_fastpath.c,
 * airy_ipc_zero_copy.c.
 */

#ifndef _AIRY_IPC_INTERNAL_H
#define _AIRY_IPC_INTERNAL_H

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/airymax/ipc.h>

struct vm_area_struct;
struct page;

/* Ring is not pinned to a CPU: the C-S5 home-CPU test always passes. */
#define AIRY_IPC_CPU_ANY	(-1)

/* ─── Ring Buffer ────────────────────────────────────────────────────── */
struct airy_ipc_ring {
	u32	head;		/* producer cursor (next write slot) */
	u32	tail;		/* consumer cursor (next read slot)  */
	u32	mask;		/* capacity-1 (ring size must be 2^N) */
	u32	frozen;		/* non-zero when ring is quiesced    */
	int	home_cpu;	/* C-S5 owner CPU, or AIRY_IPC_CPU_ANY */
	u32	peak_depth;	/* high-water mark of pending slots  */
	u64	full_count;	/* posts rejected because ring full  */
	struct airy_ipc_msg_hdr *slots;	/* message storage array (entries) */
};

/**
 * struct airy_ipc_ring_depth - sampled occupancy of an IPC ring.
 * @entries:    declared capacity, i.e. the number of slots.
 * @depth:      messages posted but not yet consumed.
 * @pct:        @depth as a percentage of @entries (0-99).
 * @peak_depth: highest @depth reached since the ring was initialised.
 * @full_count: cumulative posts rejected because the ring was full.
 *
 * Sampled by the nightly ring-depth monitor (docs 80-testing §9.3) via
 * airy_ipc_ring_depth_stats().
 */
struct airy_ipc_ring_depth {
	u32	entries;
	u32	depth;
	u32	pct;
	u32	peak_depth;
	u64	full_count;
};

int airy_ipc_ring_init(struct airy_ipc_ring *ring, u32 entries);
void airy_ipc_ring_destroy(struct airy_ipc_ring *ring);

/**
 * airy_ipc_ring_bind() - pin a ring to its fastpath owner CPU.
 * @ring: initialised ring.
 * @cpu:  CPU index the ring's consumer runs on.
 *
 * C-S5 only lets the lock-free fastpath run when the sender executes on
 * the same CPU as the ring consumer.  A bound ring reports every other
 * sender with -EAGAIN so the caller can degrade to the slowpath; an
 * unbound ring accepts posts from any CPU.
 *
 * Return: 0 on success, -EINVAL for a NULL or uninitialised @ring or an
 *         out-of-range @cpu, -EBUSY when @ring is already pinned to a
 *         different CPU.
 */
int airy_ipc_ring_bind(struct airy_ipc_ring *ring, int cpu);

int airy_ipc_ring_post(struct airy_ipc_ring *ring,
		       const struct airy_ipc_msg_hdr *hdr);
int airy_ipc_ring_consume(struct airy_ipc_ring *ring,
			  struct airy_ipc_msg_hdr *out);
int airy_ipc_cancel_badged_sends(struct airy_ipc_ring *ring, __u64 badge);
int airy_ipc_ring_depth_stats(struct airy_ipc_ring *ring,
			      struct airy_ipc_ring_depth *out);

/* ─── Fastpath ──────────────────────────────────────────────────────── */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr);

/* ─── Trace emission (airy_ipc_trace.c) ─────────────────────────────── */
/*
 * The *_on() predicates let the hot paths skip timestamping unless a
 * consumer has enabled the matching event; emission is a no-op
 * otherwise.
 */
bool airy_send_on(void);
bool airy_recv_on(void);
void airy_send_emit(const struct airy_ipc_msg_hdr *hdr, u32 src_agent,
		    u8 fastpath, u64 latency_ns);
void airy_recv_emit(const struct airy_ipc_msg_hdr *hdr, u32 dst_agent,
		    u64 latency_ns);

/* ─── Fastpath C-S12 integrity digest ───────────────────────────────── */
/**
 * airy_crc32_calc() - compute the Layout C v4 header digest.
 * @hdr:     message header.
 * @payload: payload bytes, or NULL when @hdr->payload_len is zero.
 *
 * Covers bytes [0, offsetof(crc32)) of @hdr followed by @hdr->payload_len
 * bytes at @payload.  capability_badge lies inside the covered range so a
 * forged Badge still changes the digest; the crc32 field itself and the
 * zeroed reserved tail are excluded.
 *
 * Return: the reflected IEEE 802.3 CRC-32 (zlib-compatible).
 */
__u32 airy_crc32_calc(const struct airy_ipc_msg_hdr *hdr, const void *payload);

/**
 * airy_crc32_ok() - verify the C-S12 digest before delivery.
 * @hdr:     message header.
 * @payload: payload bytes, or NULL on the header-only fastpath.
 *
 * Return: AIRY_EOK on match, -EINVAL for a NULL @hdr,
 *         -AIRY_EIPC_NOTSUPP when a payload is declared but not supplied
 *         (the header-only fastpath cannot digest it), or
 *         -AIRY_EIPC_CRC32 on mismatch.
 */
__must_check int airy_crc32_ok(const struct airy_ipc_msg_hdr *hdr,
			       const void *payload);

/* ─── Zero-copy ─────────────────────────────────────────────────────── */
int airy_ipc_zero_copy_register(unsigned long base, size_t len,
				__u32 agent_id, __u64 token);
int airy_ipc_zero_copy_unregister(__u64 token);
int airy_ipc_zero_copy_map(struct vm_area_struct *vma, __u64 token,
			   struct page **pages, unsigned long nr_pages);

#endif /* _AIRY_IPC_INTERNAL_H */

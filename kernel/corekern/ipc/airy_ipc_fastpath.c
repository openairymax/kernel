// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_fastpath.c — Airymax IPC fast-path send.
 *
 * Implements the hot-path send: a single unlikely() check on the ring's
 * frozen flag, then delegation to airy_ipc_ring_post().  This is the
 * fast-path entry point for AIRY_IPC_OP_SEND.
 *
 * ─── 唯一合法入口声明 (E12) ───────────────────────────────────────────
 *
 * 本函数（以及 airy_ipc_ring_post()）不是独立可用的 IPC 入口。内核态
 * IPC 的**唯一合法入口**是 io_uring IORING_OP_URING_CMD 提交路径：
 *
 *   io_uring_cmd() → security_uring_cmd() LSM 钩子链
 *     → airy_uring_cmd()（security/airy/airy_lsm.c）
 *       → airy_uring_cmd_check() 五阶段 slowpath
 *         （security/airy/airy_cap_check.c，Phase 1-4 含 C-S9）
 *           → C-S9 PASS 后 → airy_ipc_fastpath_send()（本函数）
 *
 * 任何直接调用本函数、绕过 LSM 5-phase 校验的路径都是非法的（除
 * [DSL] 降级模式下 capability_badge=0 的 cap_pass 语义，H6）。此声明
 * 与 110-security/06-io-uring-hardening.md §3 的 io_uring 加固一致：
 * fastpath 是 LSM 校验通过后的**机制执行器**，不是安全边界。
 *
 * ─── Badge Decision Path (P1-7) ──────────────────────────────────────
 *
 * This function does NOT perform Badge validation.  The capability
 * Badge decision is made entirely by the caller via the C-S9 inline
 * check (airy_cap_badge_ok(), defined in security/airy/airy_cap.h)
 * BEFORE control reaches this function.  The full decision flow is:
 *
 *   1. io_uring_cmd IPC entry → airy_uring_cmd() LSM hook
 *      (security/airy/airy_lsm.c)
 *   2. airy_uring_cmd_check() five-phase slowpath
 *      (security/airy/airy_cap_check.c)
 *   3. Phase 4: C-S9 inline Badge validation via airy_cap_badge_ok():
 *        C-S9.1 — epoch check (badge epoch vs slot epoch)
 *        C-S9.2 — RandomTag check (forgery prevention)
 *        C-S9.3 — permission check (required_perms ⊆ badge perms)
 *      If C-S9 returns non-zero, the operation is rejected before
 *      reaching this function.
 *   4. On C-S9 PASS, the caller invokes airy_ipc_fastpath_send() to
 *      post the message to the ring.
 *
 * The separation is deliberate:
 *   - C-S9 is a pure capability check (no side effects, ~10 ns) that
 *     gates whether the agent is AUTHORISED to send at all.
 *   - fastpath_send handles ring MECHANICS (frozen gate, slot posting)
 *     and assumes the badge was already validated.
 *   - Re-validating the badge here would double the fastpath latency
 *     (~10 ns per extra C-S9 pass) without adding security: the ring's
 *     frozen flag is the only safety gate needed at this layer, because
 *     a frozen ring means the agent was administratively suspended by
 *     the Micro-Supervisor (e.g., after a security fault), rendering
 *     its badge irrelevant regardless of validity.
 *
 * The ring_post() function performs a second frozen check (defence in
 * depth) in case the ring was frozen between the fastpath check and
 * the actual post.
 */

#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/error.h>

#include "airy_ipc_internal.h"

/* ─── Fast-path send ─────────────────────────────────────────────────── */
/*
 * Post a message to the IPC ring after the caller has validated the
 * agent's Badge via C-S9 (airy_cap_badge_ok).  See the file-level
 * comment above for the full Badge decision path.
 *
 * ring:  destination ring (must be initialised via airy_ipc_ring_init)
 * hdr:   message header to post (caller ensures valid magic/payload)
 *
 * Returns 0 on success, -EINVAL for null arguments, -AIRY_EIPC_FROZEN
 * if the ring is administratively frozen.
 */
int airy_ipc_fastpath_send(struct airy_ipc_ring *ring,
			   const struct airy_ipc_msg_hdr *hdr)
{
	if (!ring || !hdr)
		return -EINVAL;

	/* Fast path: bail out immediately if the ring is quiesced.
	 * Return -AIRY_EIPC_FROZEN (not generic -EAGAIN) so userland can
	 * distinguish "ring administratively frozen" from "transient retry".
	 *
	 * This is the ONLY safety gate in the fastpath: the caller has
	 * already passed C-S9 Badge validation (see file-level comment),
	 * so a valid badge reaching this point is authoritative.  The
	 * frozen check catches the race where the Micro-Supervisor
	 * suspends the agent between C-S9 and ring_post.
	 */
	if (unlikely(READ_ONCE(ring->frozen)))
		return -AIRY_EIPC_FROZEN;

	/* Delegate to ring_post() which performs the actual slot write.
	 * ring_post() re-checks frozen (defence in depth) and validates
	 * magic before writing. */
	return airy_ipc_ring_post(ring, hdr);
}

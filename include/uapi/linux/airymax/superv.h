/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airymax/superv.h — Micro-Supervisor control protocol ([IND] layer).
 *
 * macro_d submits supervision commands through the io_uring data plane.
 * These opcodes sit outside the [SC] AIRY_IPC_OP_* namespace on purpose:
 * SEND/RECV/SEND_BATCH/CANCEL/FREEZE/CAP_REQUEST/CAP_RESPONSE are the
 * agent-facing IPC fabric, while adjudication, thaw and the heartbeat
 * liveness pulse are supervisor-only operations that no agent badge may
 * reach.
 *
 * SSoT: 20-modules/09-kernel-agent-supervisor.md §3.5
 *       20-modules/10-user-supervisor-daemon.md §8.3
 */

#ifndef _UAPI_LINUX_AIRYMAX_SUPERV_H
#define _UAPI_LINUX_AIRYMAX_SUPERV_H

#include <linux/airymax/uapi_compat.h>

/* ─── Supervisor Opcodes ([IND] layer) ──────────────────────────────── */
#define AIRY_IPC_OP_ADJUDICATE	0x0020	/* macro_d verdict on a fault */
#define AIRY_IPC_OP_UNFREEZE	0x0021	/* sec_d-serialised ring thaw */
#define AIRY_IPC_OP_HEARTBEAT	0x0022	/* macro_d liveness pulse */

/* ─── Adjudication Actions ──────────────────────────────────────────── */
/**
 * enum airy_adjud - macro_d verdict carried by ADJUDICATE
 * @AIRY_ADJUD_WARN: log only; no scheduling or signal change
 * @AIRY_ADJUD_DEGRADE: move the agent to the degraded scheduling class
 * @AIRY_ADJUD_PAUSE: SIGSTOP the agent and mark it stopped
 * @AIRY_ADJUD_TERMINATE: SIGKILL the agent and mark it dead
 * @AIRY_ADJUD_RESUME: SIGCONT a paused agent and restore its budget
 * @AIRY_ADJUD_NR: number of valid actions; never a command value
 */
enum airy_adjud {
	AIRY_ADJUD_WARN		= 0,
	AIRY_ADJUD_DEGRADE	= 1,
	AIRY_ADJUD_PAUSE	= 2,
	AIRY_ADJUD_TERMINATE	= 3,
	AIRY_ADJUD_RESUME	= 4,
	AIRY_ADJUD_NR,
};

/* ─── Wire Command ──────────────────────────────────────────────────── */
/**
 * struct airy_superv_cmd - one supervisor command
 * @opcode: AIRY_IPC_OP_ADJUDICATE, AIRY_IPC_OP_UNFREEZE or
 *          AIRY_IPC_OP_HEARTBEAT
 * @agent_id: target slot; must be below AIRY_CAP_MAX_AGENTS, and zero
 *            for HEARTBEAT, which has no target
 * @adjud: &enum airy_adjud value; zero for UNFREEZE and HEARTBEAT
 * @reason: AIRY_FAULT_* code that drove the command, or zero
 *
 * Fixed 16-byte layout, so the command crosses the kernel/user boundary
 * without a compat translation layer.
 */
struct airy_superv_cmd {
	__u32 opcode;
	__u32 agent_id;
	__u32 adjud;
	__u32 reason;
};

#define AIRY_SUPERV_CMD_SIZE	16

_Static_assert(sizeof(struct airy_superv_cmd) == AIRY_SUPERV_CMD_SIZE,
	       "airy_superv_cmd must be exactly 16 bytes");

#endif /* _UAPI_LINUX_AIRYMAX_SUPERV_H */

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
 * SSoT: 20-modules/09-kernel-agent-supervisor.md §3.6
 *       20-modules/10-user-supervisor-daemon.md §8.3
 */

#ifndef _UAPI_LINUX_AIRYMAX_SUPERV_H
#define _UAPI_LINUX_AIRYMAX_SUPERV_H

#include <linux/airymax/uapi_compat.h>
#include <linux/ioctl.h>

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

/* ─── Fault Channel Device ──────────────────────────────────────────── */
/*
 * /dev/airy_superv 是 Micro-Supervisor 交给 Macro-Supervisor 的故障通道。
 * 单消费者：同一时刻只允许一个进程打开；BIND_EFD 把 eventfd 交给内核用于
 * 唤醒，故障明细由 read 逐条排空（24B/条，空则 EAGAIN），丢失计数由 LOST
 * 读取。eventfd 只承载"有新故障"的计数，明细不随之丢失。
 */
#define AIRY_SUPERV_ABI		1
#define AIRY_SUPERV_DEV_PATH	"/dev/airy_superv"

struct airy_fault_event {
	__u32 ring_id;
	__u32 fault_code;
	__u64 timestamp_ns;
	__u32 agent_id;
	__u32 pad;
};

#define AIRY_FAULT_EVENT_SIZE	24

_Static_assert(sizeof(struct airy_fault_event) == AIRY_FAULT_EVENT_SIZE,
	       "airy_fault_event must be exactly 24 bytes");

#define AIRY_SUPERV_IOC_BIND_EFD	_IOW('A', 0x60, __s32)
#define AIRY_SUPERV_IOC_UNBIND		_IO('A', 0x61)
#define AIRY_SUPERV_IOC_LOST		_IOR('A', 0x62, __u32)

#endif /* _UAPI_LINUX_AIRYMAX_SUPERV_H */

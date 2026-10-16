/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 文件头（中文）：AirymaxOS 内核侧 [SC] 契约编译期绑定头（A-11）。
 *
 * [SC] 共享契约头（kernel/include/uapi/linux/airymax/，与 agentrt 逐字节
 * 共享、受 sc-dual-ci 校验）各自只钉死本文件自身的布局。本头把契约与
 * 内核侧消费点之间的**跨边界不变量**在编译期钉死：契约一旦漂移，或内核
 * 侧消费结构（io_uring SQE128 命令载荷、能力表、纯 C LSM 钩子表）不再与
 * 契约吻合，编译立即失败。
 *
 * 本头属内核内部头（不在 include/uapi 下，不参与 agentrt 逐字节共享），
 * 因此可以引用内核专用类型（struct io_uring_cmd）与内核构建宏。
 *
 * 断言一律用 static_assert()（C11 _Static_assert 的文件作用域形态）；
 * BUILD_BUG_ON() 展开为语句，不能出现在全局作用域。
 */

#ifndef _AIRY_CONTRACT_H
#define _AIRY_CONTRACT_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/build_bug.h>
#include <linux/io_uring.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/syscalls.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/lsm_types.h>
#include <linux/airymax/cognition_types.h>

/* 契约 ABI 版本快照：Layout C v4（对齐 ipc.h 文件头注释与 07-ipc-fastpath.md §5.7）。 */
#define AIRY_CONTRACT_ABI_VERSION	4

/* ─── io_uring SQE128 命令载荷 ──────────────────────────────────────────
 * 标准 SQE 的 cmd 字段仅 16 字节，放不下 IPC 命令；agent-linux 启用
 * IORING_SETUP_SQE128 后 cmd 扩展至 80 字节（07-ipc-fastpath.md §5.7）。
 * 命令前 32 字节与 struct io_uring_cmd::pdu[32] 内联副本一一对应，
 * fastpath 只消费这 32 字节，其余字段走 ioucmd->sqe->cmd 扩展区。
 */
#define AIRY_IPC_CMD_MAX	80

struct airy_ipc_cmd {
	struct airy_ipc_msg_hdr	*hdr;
	const void		*payload;
	size_t			payload_len;
	__u64			dst_task;
	__u32			ring_id;
	__u32			reserved;
};

static_assert(sizeof(struct airy_ipc_cmd) <= AIRY_IPC_CMD_MAX,
	      "airy_ipc_cmd must fit the 80-byte SQE128 cmd payload");

/* fastpath 只从 pdu[32] 取前 4 个字段，故 ring_id 之前的部分必须落在 32B 内。 */
static_assert(offsetof(struct airy_ipc_cmd, ring_id) <= 32,
	      "fastpath fields (hdr/payload/payload_len/dst_task) must fit pdu[32]");
static_assert(sizeof(((struct io_uring_cmd *)0)->pdu) == 32,
	      "struct io_uring_cmd inline pdu must stay 32 bytes");

/* ─── Layout C v4 消息头：契约字段在内核消费点复钉 ──────────────────────
 * ipc.h 已自钉一次；此处再钉一次，防止 [SC] 头内的断言在某些构建形态下
 * 被关闭后，内核侧消费点悄悄跑在漂移的布局上。
 */
static_assert(sizeof(struct airy_ipc_msg_hdr) == AIRY_IPC_HDR_SIZE,
	      "Layout C v4 header must stay 128 bytes");
static_assert(offsetof(struct airy_ipc_msg_hdr, opcode) == 4,
	      "Layout C v4 opcode offset must stay 4");
static_assert(offsetof(struct airy_ipc_msg_hdr, capability_badge) == 40,
	      "Layout C v4 capability_badge offset must stay 40");
static_assert(offsetof(struct airy_ipc_msg_hdr, payload_len) == 48,
	      "Layout C v4 payload_len offset must stay 48");
static_assert(offsetof(struct airy_ipc_msg_hdr, crc32) == 52,
	      "Layout C v4 crc32 offset must stay 52");
static_assert(offsetof(struct airy_ipc_msg_hdr, reserved) == 56,
	      "Layout C v4 reserved offset must stay 56");

/* ─── Badge 64 位分区：Epoch<<48 | RandomTag<<16 | Perms ────────────────
 * 三段掩码必须无缝铺满 64 位且互不重叠；任一移位量或掩码宽度漂移，
 * fastpath 的 C-S9 校验都会把伪造 badge 当成合法 badge。
 */
static_assert(AIRY_BADGE_EPOCH_SHIFT == 48, "badge epoch shift must stay 48");
static_assert(AIRY_BADGE_RANDTAG_SHIFT == 16, "badge randtag shift must stay 16");
static_assert(AIRY_BADGE_PERMS_SHIFT == 0, "badge perms shift must stay 0");
static_assert((AIRY_BADGE_EPOCH_MASK | AIRY_BADGE_RANDTAG_MASK |
	       AIRY_BADGE_PERMS_MASK) == ~(__u64)0,
	      "badge field masks must tile all 64 bits");
static_assert((AIRY_BADGE_EPOCH_MASK & AIRY_BADGE_RANDTAG_MASK) == 0,
	      "badge epoch/randtag masks must not overlap");
static_assert((AIRY_BADGE_EPOCH_MASK & AIRY_BADGE_PERMS_MASK) == 0,
	      "badge epoch/perms masks must not overlap");
static_assert((AIRY_BADGE_RANDTAG_MASK & AIRY_BADGE_PERMS_MASK) == 0,
	      "badge randtag/perms masks must not overlap");

/* ─── 能力 ID 与权限位 ────────────────────────────────────────────────
 * 41 个 POSIX ID + 3 个 Airymax 扩展 = 44；权限位与保留位在 16 位内互补。
 */
static_assert(AIRY_CAP_ID_MAX == 44, "capability ID space must stay 44 entries");
static_assert(AIRY_CAP_AGENT_SPAWN == 41, "AIRY_CAP_AGENT_SPAWN must stay 41");
static_assert(AIRY_CAP_GPU_SCHED == 42, "AIRY_CAP_GPU_SCHED must stay 42");
static_assert(AIRY_CAP_NPU_ACCESS == 43, "AIRY_CAP_NPU_ACCESS must stay 43");
static_assert((AIRY_CAP_PERM_ALL | AIRY_CAP_PERM_RESERVED) == 0xFFFF,
	      "capability perms and reserved bits must tile 16 bits");
static_assert((AIRY_CAP_PERM_ALL & AIRY_CAP_PERM_RESERVED) == 0,
	      "capability perms must not overlap reserved bits");

/* ─── 能力槽与任务安全上下文：内核侧按固定布局读写 ────────────────────
 * airy_cap_slot 的 80B（AIRY_ALIGNED(64)）布局、airy_task_sec 的 LSM blob
 * 尺寸，都是内核侧按偏移直接访问的结构；契约漂移会静默破坏内存。
 */
static_assert(offsetof(struct airy_cap_slot, _reserved) == 40,
	      "airy_cap_slot MDB block must start at offset 40");
static_assert(offsetof(struct airy_cap_slot, _reserved) +
	      sizeof(((struct airy_cap_slot *)0)->_reserved) == 80,
	      "airy_cap_slot field extent must stay 80 bytes");
static_assert(_Alignof(struct airy_cap_slot) == 64,
	      "airy_cap_slot must stay cacheline-aligned (AIRY_ALIGNED(64))");
static_assert(offsetof(struct airy_cap_slot, agent_id) == 8,
	      "airy_cap_slot agent_id offset must stay 8");
static_assert(offsetof(struct airy_cap_slot, randtag) == 16,
	      "airy_cap_slot randtag offset must stay 16");
static_assert(sizeof(struct airy_task_sec) == 48, "airy_task_sec must stay 48 bytes");
static_assert(offsetof(struct airy_task_sec, ipc_ring) == 40,
	      "airy_task_sec ipc_ring offset must stay 40");

/* ─── LSM blob 尺寸与 inode 安全上下文 ────────────────────────────────
 * airy_lsm.c 以 sizeof 设定 lsm_blob_sizes（.lbs_task/.lbs_inode），并按
 * airy_blob_sizes.lbs_* 手工定位每次 task/inode 的 security blob；blob
 * 尺寸或 inode 布局漂移会让钩子在错误偏移上读写，静默破坏内存。
 * AIRY_CAP_MAX_AGENTS 是 agent_caps[] 能力表的编译期数组上界，改动它即
 * 改变内核静态数据的尺寸。
 */
static_assert(sizeof(struct airy_inode_sec) == 8,
	      "airy_inode_sec blob must stay 8 bytes");
static_assert(offsetof(struct airy_inode_sec, cap_required) == 0,
	      "airy_inode_sec cap_required offset must stay 0");
static_assert(offsetof(struct airy_inode_sec, owner_agent) == 4,
	      "airy_inode_sec owner_agent offset must stay 4");
static_assert(AIRY_CAP_MAX_AGENTS == 1024,
	      "agent capability table must stay 1024 slots");

/* ─── syscall 号段（548-551 核心 + 552-571 预留） ──────────────────────
 * 号段是 ABI；arch 接线（A-30..A-36）与用户态 SDK 都以此为唯一权威。
 */
static_assert(AIRY_SYS_CALL == 548, "AIRY_SYS_CALL must stay 548");
static_assert(AIRY_SYS_ROVOL_CTL == 549, "AIRY_SYS_ROVOL_CTL must stay 549");
static_assert(AIRY_SYS_SCHED_CTL == 550, "AIRY_SYS_SCHED_CTL must stay 550");
static_assert(AIRY_SYS_CLT_NOTIFY == 551, "AIRY_SYS_CLT_NOTIFY must stay 551");
static_assert(AIRY_SYS_RESERVED_BASE == 552, "reserved syscall base must stay 552");
static_assert(AIRY_SYS_RESERVED_END == 571, "reserved syscall end must stay 571");
static_assert(AIRY_SYS_SLOTS_MAX == 24, "Airymax syscall slot count must stay 24");

/* ─── 认知阶段号段：syscall 551 phase 取值边界 ──────────────────────────
 * 551 的 phase 是统一操作码：0/1/2 为 CoreLoopThree 三阶段，AIRY_COG_PHASE_MAX
 * 起为保留给模块 F 的 kthread 类 op（本版本外）。核内 airy_clt_kind() 与
 * 551 入口的边界判定都以此为准；阶段常量漂移会让「拒绝保留区」与「接受
 * 第一阶段」的边界静默分叉。
 */
static_assert(AIRY_COG_PERCEPT == 0, "cognition phase PERCEPT must stay 0");
static_assert(AIRY_COG_THINK == 1, "cognition phase THINK must stay 1");
static_assert(AIRY_COG_ACT == 2, "cognition phase ACT must stay 2");
static_assert(AIRY_COG_PHASE_MAX == 3, "cognition phase count must stay 3");

/* ─── 纯 C LSM 钩子数 ────────────────────────────────────────────────
 * 契约声明注册 7 个钩子；其与 airy_hooks[] 实际条数的一致性在 airy_lsm.c
 * 内以 ARRAY_SIZE 断言（钩子表为 static，见该文件）。
 */
static_assert(AIRY_LSM_HOOK_IMPLEMENTED == 7, "Airy LSM must register 7 hooks");

/* ─── 启动期契约快照自检 ────────────────────────────────────────────────
 * 编译期断言覆盖不到的运行时形态（目标架构实际布局）由 airy_contract_check()
 * 在启动期实测复核；Airy LSM 在注册钩子前必须先通过该自检，失败即保持
 * 不启用（fail-closed）。实现见 security/airy/airy_contract_check.c。
 */
int airy_contract_check(void);

#endif /* _AIRY_CONTRACT_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * 文件头（中文）：AirymaxOS 启动期 [SC] 契约快照自检（A-11）。
 *
 * airy_contract.h 在编译期钉死契约与内核侧消费点之间的跨边界不变量；
 * 本文件在启动期把它们按同一份契约快照再实测一遍。检查对象都是内核侧
 * 按偏移直接读写、且由编译器在目标架构上最终决定的结构：Layout C v4
 * 消息头、io_uring SQE128 命令载荷、能力槽、任务安全上下文。
 *
 * 一旦实测布局与契约快照不符，就拒绝启用 Airy LSM（fail-closed）：宁可
 * 让能力校验缺席，也不能带着漂移的布局运行，否则 fastpath 会按错的偏移
 * 读写 agent_caps[] 而静默破坏内存。LSM 初始化失败只会触发 WARN 并让
 * 本 LSM 不注册，不影响其余内核继续启动（security/security.c
 * initialize_lsm()）。
 *
 * 自检为表驱动单循环，避免逐项 if 链抬高圈复杂度。
 */

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/array_size.h>
#include <linux/io_uring.h>

#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>

#include <airymax/airy_contract.h>

struct airy_contract_entry {
	const char	*name;
	u64		expected;
	u64		actual;
	bool		at_most;
};

#define AIRY_CE(nm, exp, act)						\
	{								\
		.name = (nm),						\
		.expected = (exp),					\
		.actual = (act),					\
		.at_most = false,					\
	}

#define AIRY_CE_AT_MOST(nm, exp, act)					\
	{								\
		.name = (nm),						\
		.expected = (exp),					\
		.actual = (act),					\
		.at_most = true,					\
	}

/* 契约快照：每行的实测值必须与 [SC] 契约常量一致（或在给定上界内）。
 *
 * 表与校验函数刻意不标 __init：boot 阶段由 airy_init() 调用，同时供
 * airy_contract_test.c 在同一进程内直接驱动，使这条防漂移逻辑可被回归
 * 测试覆盖，而不是只写在启动路径里无法验证。
 */
static const struct airy_contract_entry airy_contract_table[] = {
	AIRY_CE("ipc_hdr.size", AIRY_IPC_HDR_SIZE,
		sizeof(struct airy_ipc_msg_hdr)),
	AIRY_CE("ipc_hdr.opcode_off", 4,
		offsetof(struct airy_ipc_msg_hdr, opcode)),
	AIRY_CE("ipc_hdr.badge_off", 40,
		offsetof(struct airy_ipc_msg_hdr, capability_badge)),
	AIRY_CE("ipc_hdr.payload_len_off", 48,
		offsetof(struct airy_ipc_msg_hdr, payload_len)),
	AIRY_CE("ipc_hdr.crc32_off", 52,
		offsetof(struct airy_ipc_msg_hdr, crc32)),
	AIRY_CE("ipc_hdr.reserved_off", 56,
		offsetof(struct airy_ipc_msg_hdr, reserved)),
	AIRY_CE_AT_MOST("ipc_cmd.size", AIRY_IPC_CMD_MAX,
			sizeof(struct airy_ipc_cmd)),
	AIRY_CE_AT_MOST("ipc_cmd.pdu_prefix", 32,
			offsetof(struct airy_ipc_cmd, ring_id)),
	AIRY_CE("uring_cmd.pdu_size", 32,
		sizeof(((struct io_uring_cmd *)0)->pdu)),
	AIRY_CE("cap_slot.extent", 80,
		offsetof(struct airy_cap_slot, _reserved) +
		sizeof(((struct airy_cap_slot *)0)->_reserved)),
	AIRY_CE("cap_slot.align", 64, _Alignof(struct airy_cap_slot)),
	AIRY_CE("cap_slot.agent_id_off", 8,
		offsetof(struct airy_cap_slot, agent_id)),
	AIRY_CE("cap_slot.randtag_off", 16,
		offsetof(struct airy_cap_slot, randtag)),
	AIRY_CE("task_sec.size", 48, sizeof(struct airy_task_sec)),
	AIRY_CE("task_sec.ipc_ring_off", 40,
		offsetof(struct airy_task_sec, ipc_ring)),
};

static int airy_contract_verify(void)
{
	const struct airy_contract_entry *entry;
	unsigned int drifted = 0;

	for (entry = airy_contract_table;
	     entry < airy_contract_table + ARRAY_SIZE(airy_contract_table);
	     entry++) {
		bool ok = entry->at_most ?
			  (entry->actual <= entry->expected) :
			  (entry->actual == entry->expected);

		if (ok)
			continue;

		pr_err("airy contract: %s drifted (expected %llu, actual %llu)\n",
		       entry->name,
		       (unsigned long long)entry->expected,
		       (unsigned long long)entry->actual);
		drifted++;
	}

	return drifted;
}

/**
 * airy_contract_check - attest the [SC] contract snapshot at boot
 *
 * Verifies the kernel-side layout invariants against the [SC] contract and
 * reports any drift. The Airy LSM must call this before registering hooks
 * and stay disabled when it fails.
 *
 * Return: 0 when every invariant holds; -EINVAL when any has drifted.
 */
int airy_contract_check(void)
{
	unsigned int drifted = airy_contract_verify();

	if (drifted) {
		pr_err("airy contract: %u [SC] invariant(s) drifted; Airy LSM stays disabled\n",
		       drifted);
		return -EINVAL;
	}

	pr_info("airy contract: %zu [SC] invariants verified (ABI v%u)\n",
		ARRAY_SIZE(airy_contract_table), AIRY_CONTRACT_ABI_VERSION);
	return 0;
}

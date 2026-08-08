/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Syscall numbering — [SC] shared contract header.
 *
 * v1.0.1 唯一基线，v4.3 锁定（IRON-7：禁止双轨制）。
 * 4 core syscalls (548-551) + 20 reserved (552-571), avoiding the
 * x32 historical range 512-547. v1.0.1 起始编号统一为 548，对齐
 * SSoT docs/AirymaxOS/140-application-development/07-syscall-registry.md
 * 与 arch/x86/entry/syscalls/syscall_64.tbl + asm-generic/unistd.h
 * 三方一致性（ABI 铁律）。
 */

#ifndef _UAPI_AIRYMAX_SYSCALLS_H
#define _UAPI_AIRYMAX_SYSCALLS_H

#include <linux/airymax/uapi_compat.h>

/* ─── Core Syscalls (548-551) ────────────────────────────────────────── */
#define AIRY_SYS_CALL            548   /* IPC send/recv */
#define AIRY_SYS_ROVOL_CTL       549   /* MemoryRoVol control */
#define AIRY_SYS_SCHED_CTL       550   /* Scheduler control */
#define AIRY_SYS_CLT_NOTIFY      551   /* Cognition lifecycle notify */

/* ─── Reserved Syscall Slots (552-571, 20 slots) ─────────────────────── */
#define AIRY_SYS_RESERVED_BASE   552
#define AIRY_SYS_RESERVED_END    571
#define AIRY_SYS_SLOTS_MAX       24    /* 4 core + 20 reserved */

/* E1: 编译期钉死槽位一致性（UAPI 常量与 SSoT 注册表三方一致） */
AIRY_COMPILE_ASSERT(AIRY_SYS_SLOTS_MAX ==
	(AIRY_SYS_RESERVED_END - AIRY_SYS_CALL + 1),
	"Airymax syscall: SLOTS_MAX must equal 4 core + 20 reserved (24)");

/* ─── [预留→消费] 登记机制 (E14) ──────────────────────────────────────
 * 预留槽（552-571）消费时必须显式登记，防止编号冲突与越界。参考
 * openEuler include/linux/kabi.h L439/L443 的 KABI_USE 式"预留→消费"
 * 登记：消费方在此显式声明占用，编译期断言槽位在预留范围内。
 * 完整消费清单登记于 docs/AirymaxOS/140-application-development/
 * 07-syscall-registry.md（SSoT，编号不变性规则见 §2.3）。
 */
#define AIRY_SYS_RESERVED_CLAIM(num) \
	AIRY_COMPILE_ASSERT((num) >= AIRY_SYS_RESERVED_BASE && \
			    (num) <= AIRY_SYS_RESERVED_END, \
			    "Airymax syscall: reserved slot claim out of range")

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, only the 4 core syscalls (548-551)
 * are available; the 20 reserved slots (552-571) are marked unavailable
 * (-1). This aligns with Capability Folding v1.0.1 where the syscall
 * surface is intentionally restricted to 4 in degraded mode. The
 * AIRY_DSL_SYS_* aliases let callers detect fallback at compile time.
 * See [DSL] §2.2 (v1.0.1 update: 12→4 syscalls).
 *
 * Note: v1.0.1 起始编号统一为 548，避开 x86_64 x32 历史遗留区域
 * (512-547)，确保跨架构二进制兼容。SSoT 注册表
 * docs/AirymaxOS/140-application-development/07-syscall-registry.md
 * 为唯一权威源，syscall_64.tbl 与 unistd.h 必须与本文件保持三方一致。
 */
#ifdef AIRY_SC_FALLBACK
	#define AIRY_DSL_SYS_CALL        AIRY_SYS_CALL
	#define AIRY_DSL_SYS_ROVOL_CTL   AIRY_SYS_ROVOL_CTL
	#define AIRY_DSL_SYS_SCHED_CTL   AIRY_SYS_SCHED_CTL
	#define AIRY_DSL_SYS_CLT_NOTIFY  AIRY_SYS_CLT_NOTIFY
	#define AIRY_DSL_SYS_SLOTS_MAX   4    /* Only 4 core retained */
	#define AIRY_DSL_SYS_RESERVED    (-1) /* Reserved slots unavailable */

	#warning "AIRY_SC_FALLBACK active: syscalls.h degraded to 4 core syscalls (548-551), 20 reserved slots unavailable"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_SYSCALLS_H */

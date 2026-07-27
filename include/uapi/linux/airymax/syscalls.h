/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Syscall numbering — [SC] shared contract header.
 *
 * v1.1 唯一基线，v4.3 锁定（IRON-8：禁止双轨制）。
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

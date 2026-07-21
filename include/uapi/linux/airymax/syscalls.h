/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Syscall numbering — [SC] shared contract header.
 *
 * 4 core syscalls (454-457) + 20 reserved (458-477), avoiding the
 * x32 historical range 512-547.
 */

#ifndef _UAPI_AIRYMAX_SYSCALLS_H
#define _UAPI_AIRYMAX_SYSCALLS_H

#include <linux/airymax/uapi_compat.h>

/* ─── Core Syscalls (454-457) ────────────────────────────────────────── */
#define AIRY_SYS_CALL            454   /* IPC send/recv */
#define AIRY_SYS_ROVOL_CTL       455   /* MemoryRoVol control */
#define AIRY_SYS_SCHED_CTL       456   /* Scheduler control */
#define AIRY_SYS_CLT_NOTIFY      457   /* Cognition lifecycle notify */

/* ─── Reserved Syscall Slots (458-477, 20 slots) ─────────────────────── */
#define AIRY_SYS_RESERVED_BASE   458
#define AIRY_SYS_RESERVED_END    477
#define AIRY_SYS_SLOTS_MAX       24    /* 4 core + 20 reserved */

/* ─── [DSL] Degraded Survival Layer Fallback Block ──────────────────────
 * When AIRY_SC_FALLBACK is defined, only the 4 core syscalls (454-457)
 * are available; the 20 reserved slots (458-477) are marked unavailable
 * (-1). This aligns with Capability Folding v1.1 where the syscall
 * surface is intentionally restricted to 4 in degraded mode. The
 * AIRY_DSL_SYS_* aliases let callers detect fallback at compile time.
 * See [DSL] §2.2 (v1.1 update: 12→4 syscalls).
 *
 * Note: the [DSL] doc v1.1 example text references 512-515 from the
 * pre-x32-avoidance era; the authoritative numbers are 454-457 per
 * the main path (avoiding the x32 historical range 512-547).
 */
#ifdef AIRY_SC_FALLBACK
	#define AIRY_DSL_SYS_CALL        AIRY_SYS_CALL
	#define AIRY_DSL_SYS_ROVOL_CTL   AIRY_SYS_ROVOL_CTL
	#define AIRY_DSL_SYS_SCHED_CTL   AIRY_SYS_SCHED_CTL
	#define AIRY_DSL_SYS_CLT_NOTIFY  AIRY_SYS_CLT_NOTIFY
	#define AIRY_DSL_SYS_SLOTS_MAX   4    /* Only 4 core retained */
	#define AIRY_DSL_SYS_RESERVED    (-1) /* Reserved slots unavailable */

	#warning "AIRY_SC_FALLBACK active: syscalls.h degraded to 4 core syscalls (454-457), 20 reserved slots unavailable"
#endif /* AIRY_SC_FALLBACK */

#endif /* _UAPI_AIRYMAX_SYSCALLS_H */

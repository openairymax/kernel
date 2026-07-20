/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * Syscall numbering — [SC] shared contract header.
 *
 * 4 core syscalls (512-515) + 20 reserved (516-535).
 */

#ifndef _UAPI_AIRYMAX_SYSCALLS_H
#define _UAPI_AIRYMAX_SYSCALLS_H

#include <airymax/uapi_compat.h>

/* ─── Core Syscalls (454-457) ────────────────────────────────────────── */
#define AIRY_SYS_CALL            454   /* IPC send/recv */
#define AIRY_SYS_ROVOL_CTL       455   /* MemoryRoVol control */
#define AIRY_SYS_SCHED_CTL       456   /* Scheduler control */
#define AIRY_SYS_CLT_NOTIFY      457   /* Cognition lifecycle notify */

/* ─── Reserved Syscall Slots (458-477, 20 slots) ─────────────────────── */
#define AIRY_SYS_RESERVED_BASE   458
#define AIRY_SYS_RESERVED_END    477
#define AIRY_SYS_SLOTS_MAX       24    /* 4 core + 20 reserved */

#endif /* _UAPI_AIRYMAX_SYSCALLS_H */

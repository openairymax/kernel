/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_probe.h — Airy presence probe for the agentrt runtime.
 *
 * Publishes /proc/sys/agentrt/present.  The agentrt runtime treats a
 * successful open() of that file as proof that it runs on an agent-linux
 * kernel and may take the numbered-syscall fastpath; a missing file makes
 * it fall back to its user-space implementation (A-39).
 *
 * Design rationale: docs/AirymaxOS/30-interfaces/05-syscall-semantic-mapping.md
 * §7.2 (OS-IFACE-007).
 */

#ifndef _SECURITY_AIRY_PROBE_H
#define _SECURITY_AIRY_PROBE_H

/* Values exported through /proc/sys/agentrt/present. */
#define AIRY_PROBE_ABSENT	0
#define AIRY_PROBE_READY	1

int airy_probe_init(void);
void airy_probe_exit(void);
int airy_probe_val(void);

#endif /* _SECURITY_AIRY_PROBE_H */

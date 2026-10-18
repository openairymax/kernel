/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_sysctl.h — Read-only capability table observation.
 *
 * Publishes kernel.airy.cap_max_agents / cap_epoch_bits /
 * cap_randtag_bits / cap_used.  These entries replace the removed
 * airy_sys_capability_inspect() syscall (598): sec_d and agentrt read
 * the table geometry from procfs instead of issuing an inspection
 * request (SSoT 110-security/03-capability-model.md §5.3).
 */

#ifndef _SECURITY_AIRY_CAP_SYSCTL_H
#define _SECURITY_AIRY_CAP_SYSCTL_H

unsigned int airy_cap_used(void);
int airy_cap_sysctl_init(void);
void airy_cap_sysctl_exit(void);

#endif /* _SECURITY_AIRY_CAP_SYSCTL_H */

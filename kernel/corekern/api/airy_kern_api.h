/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_kern_api.h — internal header for the Airymax core-kernel API.
 *
 * Declares the late_initcall entry point that aggregates initialisation
 * of the corekern subdirectories.
 */

#ifndef _AIRY_KERN_API_H
#define _AIRY_KERN_API_H

#include <linux/types.h>

/* ─── Core API entry ─────────────────────────────────────────────────── */
int airy_kern_api_init(void);

#endif /* _AIRY_KERN_API_H */

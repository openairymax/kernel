/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_cap_check_superv.c — Micro-Supervisor fastpath capability check wrappers.
 *
 * Provides airy_cap_has_perm() for permission bit checking, delegating
 * badge validation to the shared inline airy_cap_badge_ok() defined in
 * security/airy/airy_cap.h.
 *
 * Renamed from airy_cap_check.c to airy_cap_check_superv.c per OS-STD-001
 * (global symbols must be descriptively named) to resolve the name clash
 * with security/airy/airy_cap_check.c.
 */

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/airymax/error.h>

#include "../../security/airy/airy_cap.h"

/**
 * airy_cap_has_perm - Check whether a badge carries a specific permission bit.
 * @badge:         The 64-bit capability badge.
 * @required_perm: The permission bit to test.
 *
 * This is a convenience wrapper that tests a single permission bit
 * against the badge's permission field.  It does NOT perform epoch
 * or RandomTag validation — use airy_cap_badge_ok() for full validation.
 *
 * Return: 1 if the permission is present, 0 otherwise.
 */
int airy_cap_has_perm(__u64 badge, __u16 required_perm)
{
	__u16 perms = (__u16)AIRY_BADGE_PERMS(badge);

	return (perms & required_perm) != 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_fs.c — the shared "airy" securityfs directory.
 *
 * The anchor is created on demand rather than from a module_init so the
 * lockdown and policy knobs can be added by ordinary late_initcalls in
 * any link order. A single mutex serialises the first creation; later
 * callers only take the lock to read the cached dentry.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/mutex.h>
#include <linux/security.h>

#include "airy_fs.h"

static DEFINE_MUTEX(airy_fs_lock);
static struct dentry *airy_fs_root;

struct dentry *airy_fs_dir(void)
{
	struct dentry *dir;

	if (!IS_ENABLED(CONFIG_SECURITYFS))
		return NULL;

	mutex_lock(&airy_fs_lock);
	if (airy_fs_root) {
		dir = airy_fs_root;
	} else {
		dir = securityfs_create_dir("airy", NULL);
		if (!IS_ERR(dir))
			airy_fs_root = dir;
	}
	mutex_unlock(&airy_fs_lock);

	return dir;
}

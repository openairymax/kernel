/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_fs.h — the shared "airy" securityfs directory.
 *
 * Every Airymax security component publishes its knobs below one
 * directory. Creating that directory from each component would race two
 * late_initcalls over the same dentry and leave the loser without a
 * place to put its files, so the anchor is created lazily once and
 * shared.
 *
 * SSoT: 110-security/10-policy-compiler.md §8.1.
 */

#ifndef _AIRY_FS_H
#define _AIRY_FS_H

struct dentry;

/**
 * airy_fs_dir - return the shared "airy" securityfs directory
 *
 * The directory is created on first use and never removed: the LSM
 * cannot be unloaded, so neither can its knobs.
 *
 * Return: the directory on success, NULL when securityfs is not built
 *         in, or an ERR_PTR() when creation failed.
 */
struct dentry *airy_fs_dir(void);

#endif /* _AIRY_FS_H */

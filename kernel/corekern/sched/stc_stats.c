// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * stc_stats.c — sched_tac dispatch statistics.
 *
 * Maintains a global atomic counter of stc_dispatch_enqueue() invocations
 * plus a per-policy breakdown, queryable via stc_stats_read() and exposed
 * to userspace via debugfs at /sys/kernel/debug/airy_stc/stats.
 */

#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/bug.h>
#include <linux/array_size.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/airymax/sched.h>

#include "stc_policy.h"

/* ─── Statistics counters ────────────────────────────────────────────── */
static atomic_t stc_dispatch_count = ATOMIC_INIT(0);
static atomic_t stc_policy_count[STC_POLICY_MAX] = {
	ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0), ATOMIC_INIT(0),
	ATOMIC_INIT(0)
};

/* ─── Record a dispatch event ────────────────────────────────────────── */
void stc_stats_record_dispatch(enum airy_sched_policy policy)
{
	unsigned int idx = (unsigned int)policy;

	atomic_inc(&stc_dispatch_count);

	if (idx < ARRAY_SIZE(stc_policy_count))
		atomic_inc(&stc_policy_count[idx]);
}

/* ─── Read aggregate dispatch count ──────────────────────────────────── */
int stc_stats_read(void)
{
	return atomic_read(&stc_dispatch_count);
}

/* ─── debugfs: /sys/kernel/debug/airy_stc/stats ──────────────────────── */
static int stc_stats_show(struct seq_file *m, void *v)
{
	unsigned int i;

	seq_printf(m, "total %d\n", atomic_read(&stc_dispatch_count));

	/* Index 0 is unused (policies start at STC_POLICY_REALTIME=1). */
	for (i = 1; i < ARRAY_SIZE(stc_policy_count); i++)
		seq_printf(m, "%-16s %d\n",
			   stc_policy_name(i),
			   atomic_read(&stc_policy_count[i]));

	return 0;
}

static int stc_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stc_stats_show, NULL);
}

static const struct file_operations stc_stats_fops = {
	.open		= stc_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init stc_debugfs_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("airy_stc", NULL);
	debugfs_create_file("stats", 0444, dir, NULL, &stc_stats_fops);

	return 0;
}
late_initcall(stc_debugfs_init);

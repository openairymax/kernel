// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_proc.c — /proc/airy 故障日志视图。
 *
 * 故障事件由 A-UEF 环保存，peek 不会取走事件：读取 /proc 只是复制
 * 当前环内容，macro_d 的消费游标不受影响。每行一条事件，字段顺序与
 * struct airy_fault_event 一致；环为空时只输出头部两行统计。
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/airymax/superv.h>

#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

static struct proc_dir_entry *airy_proc_dir;

static int fault_log_show(struct seq_file *m, void *v)
{
	struct airy_fault_event ev;
	unsigned int nr = airy_fev_pending();
	unsigned int i;

	seq_printf(m, "pending: %u\nlost: %u\n", nr, airy_fev_lost());

	for (i = 0; i < nr; i++) {
		if (airy_fev_peek(i, &ev))
			break;

		seq_printf(m, "%u %u %u %llu\n", i, ev.agent_id,
			   ev.fault_code, ev.timestamp_ns);
	}

	return 0;
}

static int fault_log_open(struct inode *inode, struct file *file)
{
	return single_open(file, fault_log_show, NULL);
}

static const struct proc_ops fault_log_ops = {
	.proc_open	= fault_log_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/**
 * airy_obs_proc_init - Create /proc/airy and the fault log.
 *
 * Only the fault log has a kernel-side data source.  The agents,
 * daemons and config subdirectories would be empty until their owner
 * daemons exist, and an empty directory reads as "nothing is running"
 * rather than "this interface is not up yet", so they are left out.
 *
 * Return: 0 on success; -ENOMEM when the directory or file cannot be
 *         created.
 */
int __init airy_obs_proc_init(void)
{
	airy_proc_dir = proc_mkdir("airy", NULL);
	if (!airy_proc_dir)
		return -ENOMEM;

	if (!proc_create("fault_log", 0444, airy_proc_dir, &fault_log_ops)) {
		remove_proc_subtree("airy", NULL);
		airy_proc_dir = NULL;
		return -ENOMEM;
	}

	return 0;
}

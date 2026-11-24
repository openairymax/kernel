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
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include <linux/airymax/superv.h>

#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

static struct proc_dir_entry *airy_proc_dir;

/* /proc/airy/agents 一级目录与其中每个 Agent 的目录，按 id 索引。 */
static DEFINE_XARRAY(airy_agent_dirs);
static DEFINE_MUTEX(airy_agent_lock);
static struct proc_dir_entry *airy_agents_root;

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
 * airy_obs_proc_root - Expose /proc/airy to sibling observation modules.
 *
 * Return: The directory entry, or NULL when procfs is not mounted.
 */
struct proc_dir_entry *airy_obs_proc_root(void)
{
	return airy_proc_dir;
}

/**
 * airy_obs_agent_dir - Return /proc/airy/agents/<id>, creating it on demand.
 * @id: Agent number, used verbatim as the directory name.
 * @create: Whether a missing directory may be created.
 *
 * Several meters publish under one Agent directory, so the directory can
 * not belong to any single one of them.  Creation is again lazy: an
 * agents subtree with no files would claim more than the kernel knows.
 * Name allocation goes through kasprintf() because the observation
 * contract forbids formatting through a fixed buffer.
 *
 * Return: The directory entry; NULL when procfs is unavailable, when the
 *         directory is missing and @create is false, or on allocation
 *         failure.
 */
struct proc_dir_entry *airy_obs_agent_dir(u32 id, bool create)
{
	struct proc_dir_entry *de;
	char *name;

	if (!airy_proc_dir)
		return NULL;

	de = xa_load(&airy_agent_dirs, id);
	if (de || !create)
		return de;

	mutex_lock(&airy_agent_lock);
	de = xa_load(&airy_agent_dirs, id);
	if (!de) {
		if (!airy_agents_root)
			airy_agents_root = proc_mkdir("agents", airy_proc_dir);
		name = kasprintf(GFP_KERNEL, "%u", id);
		if (airy_agents_root && name)
			de = proc_mkdir(name, airy_agents_root);
		kfree(name);
		if (de && xa_insert(&airy_agent_dirs, id, de, GFP_KERNEL)) {
			proc_remove(de);
			de = NULL;
		}
	}
	mutex_unlock(&airy_agent_lock);

	return de;
}

/**
 * airy_obs_proc_init - Create /proc/airy and the fault log.
 *
 * Only the fault log has a kernel-side data source here.  The daemons
 * and config subdirectories would be empty until their owner daemons
 * exist, and an empty directory reads as "nothing is running" rather
 * than "this interface is not up yet", so they are left out.  The
 * agents subtree is owned by the token meter, which creates it only
 * together with its first real data source.
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

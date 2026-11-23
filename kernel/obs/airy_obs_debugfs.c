// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_debugfs.c — /sys/kernel/debug/airy 调试面。
 *
 * 调试面只补充稳定面无法提供的原始信息：能力槽明细、
 * 最近一次裁决的完整字段与日志环原始字节。此处不重复
 * /sys/airy 的稳定计数，也不导出防伪随机标签——
 * 调试文件不应成为伪造徽章的读取口。
 *
 * 注册晚于 /sys/airy：debugfs 自身是 core_initcall，
 * 链接顺序不保证内核目录先于文件系统目录，因此用 fs_initcall。
 * 创建接口按需 pin 内部挂载，不依赖用户态是否挂载；创建失败
 * 只告警，调试面缺席不影响系统就绪。
 */

#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <linux/airymax/lsm_types.h>
#include <linux/airymax/superv.h>

#include "../log/airy_log_internal.h"
#include "../superv/airy_superv.h"
#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

static struct dentry *airy_dbg_root;

static int cap_show(struct seq_file *m, void *v)
{
	unsigned int id;

	for (id = 1; id < AIRY_CAP_MAX_AGENTS; id++) {
		unsigned int bkt = airy_cap_bucket(id);
		struct airy_cap_slot slot;
		unsigned long flags;
		char line[160];

		spin_lock_irqsave(&airy_cap_bucket_locks[bkt], flags);
		slot = agent_caps[id];
		spin_unlock_irqrestore(&airy_cap_bucket_locks[bkt], flags);

		if (!slot.badge && !slot.flags)
			continue;

		airy_obs_cap_fmt(line, sizeof(line), id, &slot);
		seq_puts(m, line);
	}

	return 0;
}

static int cap_open(struct inode *inode, struct file *file)
{
	return single_open(file, cap_show, NULL);
}

static const struct file_operations cap_fops = {
	.owner		= THIS_MODULE,
	.open		= cap_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int last_show(struct seq_file *m, void *v)
{
	struct airy_sv_obs obs;

	airy_sv_obs_snap(&obs);

	seq_printf(m, "op: %s\nagent: %u\nverdict: %s\ntimestamp_ns: %llu\n",
		   airy_sv_obs_op_name(obs.last_op), obs.last_agent,
		   obs.last_op == AIRY_SV_OBS_ADJUD ?
		   airy_sv_obs_adjud_name(obs.last_adjud) : "none",
		   obs.last_ns);

	return 0;
}

static int last_open(struct inode *inode, struct file *file)
{
	return single_open(file, last_show, NULL);
}

static const struct file_operations last_fops = {
	.owner		= THIS_MODULE,
	.open		= last_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#if IS_ENABLED(CONFIG_AIRY_LOG)
static ssize_t ring_dump_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct airy_log_ring *ring = airy_log_global();

	if (!ring || !ring->kaddr)
		return 0;

	return simple_read_from_buffer(ring->kaddr, ring->size, ppos, buf,
				       count);
}

static const struct file_operations ring_dump_fops = {
	.owner		= THIS_MODULE,
	.llseek		= default_llseek,
	.read		= ring_dump_read,
};
#endif

static int __init mk_node(struct dentry *parent, const char *name,
			  const struct file_operations *fops)
{
	struct dentry *node;

	node = debugfs_create_file(name, 0444, parent, NULL, fops);

	return IS_ERR(node) ? PTR_ERR(node) : 0;
}

static int __init dbg_group(const char *name, int (*fill)(struct dentry *))
{
	struct dentry *dir;

	dir = debugfs_create_dir(name, airy_dbg_root);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	if (!dir)
		return -ENOMEM;

	return fill(dir);
}

static int __init fill_sec(struct dentry *dir)
{
	return mk_node(dir, "cap_table", &cap_fops);
}

static int __init fill_superv(struct dentry *dir)
{
	return mk_node(dir, "last_decision", &last_fops);
}

#if IS_ENABLED(CONFIG_AIRY_LOG)
static int __init fill_log(struct dentry *dir)
{
	return mk_node(dir, "ring_buffer_dump", &ring_dump_fops);
}
#endif

static int __init airy_dbg_init(void)
{
	int rc;

	airy_dbg_root = debugfs_create_dir("airy", NULL);
	if (IS_ERR(airy_dbg_root)) {
		rc = PTR_ERR(airy_dbg_root);
		airy_dbg_root = NULL;
		return rc;
	}
	if (!airy_dbg_root)
		return -ENOMEM;

	rc = dbg_group("sec", fill_sec);
	if (rc)
		goto err;
	rc = dbg_group("superv", fill_superv);
	if (rc)
		goto err;
#if IS_ENABLED(CONFIG_AIRY_LOG)
	rc = dbg_group("log", fill_log);
	if (rc)
		goto err;
#endif

	return 0;

err:
	debugfs_remove_recursive(airy_dbg_root);
	airy_dbg_root = NULL;
	return rc;
}

static int __init airy_dbg_start(void)
{
	int rc;

	if (!airy_obs_ready)
		return 0;

	rc = airy_dbg_init();
	if (rc)
		pr_warn("airy: debugfs surface unavailable: %d\n", rc);

	return 0;
}
fs_initcall(airy_dbg_start);

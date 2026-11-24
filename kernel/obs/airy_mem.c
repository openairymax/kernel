// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_mem.c — 每 Agent 的四层记忆计量与配额档位。
 *
 * 内核只保存事实：每层的访问、命中、延迟、淘汰、页与字节吞吐、模式
 * 条数，以及当前占用与配额。比例一律 ppm；配额为 0 表示未设限，档位
 * 只用于让读者快速判断，处置（压缩、驱逐、拒绝写入）留给 macro_d，
 * 内核不跨层调用监管路径。
 *
 * 计量表是一张 xarray：按 Agent 号索引，首次上报时建立。所有读写都在
 * mem_lock 下完成；窗口推进只清窗口内最大延迟，累计计数保持单调。
 * 口径见 docs-linux/90-observability/09-memory-monitoring.md。
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/lockdep.h>
#include <linux/math64.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#include <linux/airymax/mem.h>
#include <linux/airymax/security_types.h>

#include "airy_mem.h"
#include "airy_obs.h"

#define MEM_DEV_NAME	"airy_mem"
#define MEM_FILE	"memory_stats"

static DEFINE_XARRAY(mem_map);
static DEFINE_MUTEX(mem_lock);

/**
 * airy_mem_alert - Classify quota usage into an alert level.
 * @used: KiB in use across all four levels.
 * @quota: Agent quota in KiB; zero means no limit is configured.
 *
 * Return: AIRY_MEM_NORMAL, SOFT, DEGRADE or EXCEED.
 */
u32 airy_mem_alert(u64 used, u64 quota)
{
	if (!quota)
		return AIRY_MEM_NORMAL;

	if (used >= quota)
		return AIRY_MEM_EXCEED;

	if (airy_obs_ppm(used, quota) >= AIRY_MEM_DEGRADE_PPM)
		return AIRY_MEM_DEGRADE;

	if (airy_obs_ppm(used, quota) >= AIRY_MEM_SOFT_PPM)
		return AIRY_MEM_SOFT;

	return AIRY_MEM_NORMAL;
}

/**
 * airy_mem_total - Sum the occupancy of all four levels.
 * @a: Agent record.
 *
 * Return: KiB in use.
 */
u64 airy_mem_total(const struct mem_agent *a)
{
	u64 total = 0;
	unsigned i;

	if (!a)
		return 0;

	for (i = AIRY_MEM_L1; i <= AIRY_MEM_LEVELS; i++)
		total += a->lv[i].used_kb;

	return total;
}

/**
 * airy_mem_roll - Advance the observation window to @now.
 * @a: Agent record; caller holds mem_lock.
 * @now: Monotonic timestamp in nanoseconds.
 *
 * Only the per-window latency ceiling is reset; counters and occupancy
 * are facts that must stay monotonic for the reader.
 */
void airy_mem_roll(struct mem_agent *a, u64 now)
{
	unsigned i;

	if (!a || !a->win_start ||
	    now - a->win_start < AIRY_MEM_WINDOW_NS)
		return;

	a->win_start = now;
	for (i = AIRY_MEM_L1; i <= AIRY_MEM_LEVELS; i++)
		a->lv[i].lat_max = 0;
}

/**
 * airy_mem_apply - Fold one delta into the record of its level.
 * @a: Agent record; caller holds mem_lock.
 * @d: Reported delta.
 * @now: Monotonic timestamp in nanoseconds.
 */
void airy_mem_apply(struct mem_agent *a, const struct airy_mem_delta *d,
		    u64 now)
{
	struct mem_level *l;

	if (!a || !d || d->level < AIRY_MEM_L1 || d->level > AIRY_MEM_L4)
		return;

	airy_mem_roll(a, now);
	l = &a->lv[d->level];

	l->access += d->access;
	l->hit += d->hit;
	l->lat_sum += d->lat_sum_ns;
	if (d->lat_max_ns > l->lat_max)
		l->lat_max = d->lat_max_ns;
	l->evict += d->evict;
	l->fill += d->fill_ns;
	l->page_in += d->page_in;
	l->page_out += d->page_out;
	l->read_bytes += d->read_bytes;
	l->write_bytes += d->write_bytes;
	l->pat_add += d->pat_add;
	l->pat_drop += d->pat_drop;
	a->updated = now;
}

/**
 * airy_mem_set - Store the occupancy of one level.
 * @a: Agent record; caller holds mem_lock.
 * @g: Reported gauge.
 *
 * Occupancy is absolute, not a delta: a producer that re-measures after
 * a restart must be able to lower the value.
 */
void airy_mem_set(struct mem_agent *a, const struct airy_mem_gauge *g)
{
	if (!a || !g || g->level < AIRY_MEM_L1 || g->level > AIRY_MEM_L4)
		return;

	a->lv[g->level].used_kb = g->used_kb;
}

/**
 * mem_alert_name - Stable text form of an alert level.
 * @alert: AIRY_MEM_NORMAL / SOFT / DEGRADE / EXCEED.
 *
 * Return: The name used by the procfs view.
 */
static const char *mem_alert_name(u32 alert)
{
	switch (alert) {
	case AIRY_MEM_SOFT:
		return "SOFT";
	case AIRY_MEM_DEGRADE:
		return "DEGRADE";
	case AIRY_MEM_EXCEED:
		return "EXCEED";
	default:
		return "NORMAL";
	}
}

/* 计数器行；格式只在这里出现一次，读者按「键: 值」逐行消费。 */
static void mem_row(struct seq_file *m, const char *key, u64 val)
{
	seq_printf(m, "%s: %llu\n", key, (unsigned long long)val);
}

/* 一层记忆的公共指标：访问、命中、延迟、淘汰、占用。 */
static void mem_lines(struct seq_file *m, const char *pfx,
		      const struct mem_level *l)
{
	seq_printf(m, "%s_access_total: %llu\n", pfx,
		   (unsigned long long)l->access);
	seq_printf(m, "%s_hit_total: %llu\n", pfx,
		   (unsigned long long)l->hit);
	seq_printf(m, "%s_hit_ppm: %u\n", pfx,
		   airy_obs_ppm(l->hit, l->access));
	seq_printf(m, "%s_lat_avg_ns: %llu\n", pfx,
		   l->access ? div64_u64(l->lat_sum, l->access) : 0);
	seq_printf(m, "%s_lat_p99_ns: %llu\n", pfx,
		   (unsigned long long)l->lat_max);
	seq_printf(m, "%s_evict_total: %llu\n", pfx,
		   (unsigned long long)l->evict);
	seq_printf(m, "%s_evict_ppm: %u\n", pfx,
		   airy_obs_ppm(l->evict, l->access + l->evict));
	seq_printf(m, "%s_used_kb: %llu\n", pfx,
		   (unsigned long long)l->used_kb);
}

static void mem_l2_extra(struct seq_file *m, const struct mem_level *l)
{
	seq_printf(m, "l2_fill_avg_ns: %llu\n",
		   l->page_in ? div64_u64(l->fill, l->page_in) : 0);
	mem_row(m, "l2_page_in_total", l->page_in);
	mem_row(m, "l2_page_out_total", l->page_out);
}

static void mem_l3_extra(struct seq_file *m, const struct mem_level *l)
{
	mem_row(m, "l3_read_bytes", l->read_bytes);
	mem_row(m, "l3_write_bytes", l->write_bytes);
}

static void mem_l4_extra(struct seq_file *m, const struct mem_level *l)
{
	/* 解压只发生在命中的检索上，因此以命中次数为分母。 */
	seq_printf(m, "l4_decomp_avg_ns: %llu\n",
		   l->hit ? div64_u64(l->fill, l->hit) : 0);
	mem_row(m, "l4_pattern_add_total", l->pat_add);
	mem_row(m, "l4_pattern_drop_total", l->pat_drop);
}

/**
 * mem_show - Print the snapshot of one Agent.
 * @m: Seq file positioned at the record passed as private data.
 * @v: Unused.
 *
 * The whole snapshot is taken under mem_lock so a reader never sees a
 * level updated halfway through its metric block.
 *
 * Return: 0.
 */
static int mem_show(struct seq_file *m, void *v)
{
	struct mem_agent *a = m->private;
	const struct mem_level *l;
	u64 now = ktime_get_mono_fast_ns();
	u64 used;
	u64 quota;

	mutex_lock(&mem_lock);
	airy_mem_roll(a, now);

	used = airy_mem_total(a);
	quota = a->quota_kb;

	mem_row(m, "agent_id", a->agent_id);
	mem_row(m, "report_time_ns", now);
	mem_row(m, "window_duration_s", AIRY_MEM_WINDOW_NS / 1000000000ULL);
	mem_row(m, "used_kb", used);
	mem_row(m, "quota_kb", quota);
	seq_printf(m, "usage_ppm: %u\n", airy_obs_ppm(used, quota));
	seq_printf(m, "alert_state: %s\n",
		   mem_alert_name(airy_mem_alert(used, quota)));
	mem_row(m, "updated_ns", a->updated);

	l = &a->lv[AIRY_MEM_L1];
	mem_lines(m, "l1", l);

	l = &a->lv[AIRY_MEM_L2];
	mem_lines(m, "l2", l);
	mem_l2_extra(m, l);

	l = &a->lv[AIRY_MEM_L3];
	mem_lines(m, "l3", l);
	mem_l3_extra(m, l);

	l = &a->lv[AIRY_MEM_L4];
	mem_lines(m, "l4", l);
	mem_l4_extra(m, l);

	mutex_unlock(&mem_lock);

	return 0;
}

/**
 * mem_proc_add - Publish /proc/airy/agents/<id>/memory_stats.
 * @a: Agent record, passed to the show callback.
 *
 * The Agent directory is shared with the other meters, so it is created
 * through airy_obs_agent_dir().
 */
static void mem_proc_add(struct mem_agent *a)
{
	struct proc_dir_entry *de;

	if (a->de)
		return;

	de = airy_obs_agent_dir(a->agent_id, true);
	if (de && proc_create_single_data(MEM_FILE, 0444, de, mem_show, a))
		a->de = de;
}

/**
 * mem_node - Look up an Agent record, creating it when asked.
 * @id: Agent number, already bounded by the caller.
 * @create: Whether a missing record may be allocated.
 *
 * Return: The record, or NULL when it is missing and @create is false,
 *         or when allocation fails.
 */
static struct mem_agent *mem_node(u32 id, bool create)
{
	struct mem_agent *a;
	u64 now;

	lockdep_assert_held(&mem_lock);

	a = xa_load(&mem_map, id);
	if (a || !create)
		return a;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return NULL;

	now = ktime_get_mono_fast_ns();
	a->agent_id = id;
	a->quota_kb = AIRY_MEM_QUOTA_DEFAULT;
	a->win_start = now;

	if (xa_insert(&mem_map, id, a, GFP_KERNEL)) {
		kfree(a);
		return NULL;
	}

	mem_proc_add(a);

	return a;
}

/* 每个增量字段都必须落在上限内，否则一次上报就能把累计值推到回绕。 */
static bool mem_delta_ok(const struct airy_mem_delta *d)
{
	const u64 *field[12];
	unsigned i;

	field[0] = &d->access;
	field[1] = &d->hit;
	field[2] = &d->lat_sum_ns;
	field[3] = &d->lat_max_ns;
	field[4] = &d->evict;
	field[5] = &d->fill_ns;
	field[6] = &d->page_in;
	field[7] = &d->page_out;
	field[8] = &d->read_bytes;
	field[9] = &d->write_bytes;
	field[10] = &d->pat_add;
	field[11] = &d->pat_drop;

	for (i = 0; i < 12; i++) {
		if (*field[i] > AIRY_MEM_DELTA_MAX)
			return false;
	}

	return true;
}

static long mem_report(const struct airy_mem_delta __user *up)
{
	struct airy_mem_delta d;
	struct mem_agent *a;
	long rc = 0;

	if (copy_from_user(&d, up, sizeof(d)))
		return -EFAULT;

	if (d.agent_id >= AIRY_CAP_MAX_AGENTS || d.pad[0] || d.pad[1] ||
	    d.pad[2])
		return -EINVAL;

	if (d.level < AIRY_MEM_L1 || d.level > AIRY_MEM_L4 ||
	    !mem_delta_ok(&d))
		return -EINVAL;

	if (!airy_obs_self(d.agent_id))
		return -EPERM;

	mutex_lock(&mem_lock);
	a = mem_node(d.agent_id, true);
	if (!a)
		rc = -ENOMEM;
	else
		airy_mem_apply(a, &d, ktime_get_mono_fast_ns());
	mutex_unlock(&mem_lock);

	return rc;
}

static long mem_gauge(const struct airy_mem_gauge __user *up)
{
	struct airy_mem_gauge g;
	struct mem_agent *a;
	long rc = 0;

	if (copy_from_user(&g, up, sizeof(g)))
		return -EFAULT;

	if (g.agent_id >= AIRY_CAP_MAX_AGENTS || g.pad[0] || g.pad[1] ||
	    g.pad[2])
		return -EINVAL;

	if (g.level < AIRY_MEM_L1 || g.level > AIRY_MEM_L4 ||
	    g.used_kb > AIRY_MEM_DELTA_MAX)
		return -EINVAL;

	if (!airy_obs_self(g.agent_id))
		return -EPERM;

	mutex_lock(&mem_lock);
	a = mem_node(g.agent_id, true);
	if (!a) {
		rc = -ENOMEM;
	} else {
		airy_mem_set(a, &g);
		a->updated = ktime_get_mono_fast_ns();
	}
	mutex_unlock(&mem_lock);

	return rc;
}

static long mem_quota(const struct airy_mem_quota __user *up)
{
	struct airy_mem_quota q;
	struct mem_agent *a;
	long rc = 0;

	if (copy_from_user(&q, up, sizeof(q)))
		return -EFAULT;

	if (q.agent_id >= AIRY_CAP_MAX_AGENTS || q.pad ||
	    q.quota_kb > AIRY_MEM_DELTA_MAX)
		return -EINVAL;

	if (!airy_obs_supervise())
		return -EPERM;

	mutex_lock(&mem_lock);
	a = mem_node(q.agent_id, true);
	if (!a)
		rc = -ENOMEM;
	else
		a->quota_kb = q.quota_kb;
	mutex_unlock(&mem_lock);

	return rc;
}

static long mem_query(struct airy_mem_stats __user *up)
{
	struct airy_mem_stats st;
	struct mem_agent *a;

	if (copy_from_user(&st, up, sizeof(st)))
		return -EFAULT;

	if (st.agent_id >= AIRY_CAP_MAX_AGENTS)
		return -EINVAL;

	mutex_lock(&mem_lock);
	a = mem_node(st.agent_id, false);
	if (!a) {
		mutex_unlock(&mem_lock);
		return -ENOENT;
	}

	airy_mem_roll(a, ktime_get_mono_fast_ns());
	st.used_kb = airy_mem_total(a);
	st.quota_kb = a->quota_kb;
	st.usage_ppm = airy_obs_ppm(st.used_kb, st.quota_kb);
	st.alert_state = airy_mem_alert(st.used_kb, st.quota_kb);
	st.updated_ns = a->updated;
	mutex_unlock(&mem_lock);

	return copy_to_user(up, &st, sizeof(st)) ? -EFAULT : 0;
}

static long mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case AIRY_MEM_IOC_REPORT:
		return mem_report((struct airy_mem_delta __user *)arg);
	case AIRY_MEM_IOC_GAUGE:
		return mem_gauge((struct airy_mem_gauge __user *)arg);
	case AIRY_MEM_IOC_QUOTA:
		return mem_quota((struct airy_mem_quota __user *)arg);
	case AIRY_MEM_IOC_QUERY:
		return mem_query((struct airy_mem_stats __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations mem_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= mem_ioctl,
	.compat_ioctl	= mem_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice mem_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= MEM_DEV_NAME,
	.fops	= &mem_fops,
	.mode	= 0666,
};

/**
 * airy_mem_init - Publish the memory meter.
 *
 * Return: 0 on success; otherwise the registration error.
 */
int __init airy_mem_init(void)
{
	return misc_register(&mem_misc);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_token.c — 每 Agent 的 token 计量、窗口与预算档位。
 *
 * 内核只保存事实：四类计数、60 秒观测窗口、1 小时预算窗口。上报走
 * /dev/airy_token 的 REPORT，读取走 /proc/airy/agents/<id>/token_stats
 * 与 QUERY，处置（降级、终止）留给 macro_d，内核不跨层调用监管路径。
 *
 * 计量表是一张 xarray：按 Agent 号索引，首次上报时建立。所有读写都在
 * tok_lock 下完成，窗口推进集中在 airy_tok_add() 与 tok_roll() 两个
 * 函数里，KUnit 因此可以直接覆盖进位与回绕而不需要设备上下文。
 *
 * 口径见 docs-linux/90-observability/07-token-efficiency.md §3.2：
 * 四类计数互不重叠，total 是其和，比例一律 ppm。
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/math64.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#include <linux/airymax/lsm_types.h>
#include <linux/airymax/security_types.h>
#include <linux/airymax/token.h>

#include "airy_obs.h"
#include "airy_token.h"

#define TOK_DEV_NAME	"airy_token"
#define TOK_FILE	"token_stats"

static DEFINE_XARRAY(tok_map);
static DEFINE_MUTEX(tok_lock);
static atomic64_t tok_alerts = ATOMIC64_INIT(0);

/**
 * tok_note - Record a new alert level, counting escalations only.
 * @a: Agent record; caller holds tok_lock.
 * @alert: Level recomputed from the current usage and budget.
 *
 * Escalation is what a supervisor reacts to, so the counter rises only
 * when the level moves up.  Recovery and repeats leave it alone; the
 * per-Agent text view still reports the current level.
 */
static void tok_note(struct tok_agent *a, u32 alert)
{
	if (alert > a->alert)
		atomic64_inc(&tok_alerts);

	a->alert = alert;
}

/**
 * airy_tok_alerts - Report the number of escalations since boot.
 *
 * Return: Escalation count across all Agents.
 */
u64 airy_tok_alerts(void)
{
	return (u64)atomic64_read(&tok_alerts);
}

/**
 * tok_roll - Advance the observation and budget windows to @now.
 * @a: Agent record; caller holds tok_lock.
 * @now: Monotonic timestamp in nanoseconds.
 */
static void tok_roll(struct tok_agent *a, u64 now)
{
	if (now - a->win_start >= AIRY_TOKEN_WINDOW_NS) {
		a->win_start = now;
		a->win_tokens = 0;
	}

	if (now - a->bstart >= AIRY_TOKEN_BUDGET_WINDOW_NS) {
		a->bstart = now;
		a->bused = 0;
	}
}

/**
 * airy_tok_ratio - Express @num / @den in parts per million.
 * @num: Numerator.
 * @den: Denominator; zero yields 0 instead of a division fault.
 *
 * Ratios above 1.0 are kept (a budget overrun must stay visible) and
 * saturate at U32_MAX.
 *
 * Return: The ratio in ppm.
 */
u32 airy_tok_ratio(u64 num, u64 den)
{
	return airy_obs_ppm(num, den);
}

/**
 * airy_tok_alert - Classify budget usage into an alert level.
 * @used: Tokens consumed in the current budget window.
 * @budget: Budget window limit; zero means no limit is configured.
 *
 * Return: AIRY_TOKEN_NORMAL, AIRY_TOKEN_SOFT or AIRY_TOKEN_HARD.
 */
u32 airy_tok_alert(u64 used, u64 budget)
{
	if (!budget)
		return AIRY_TOKEN_NORMAL;

	if (used >= budget)
		return AIRY_TOKEN_HARD;

	if (airy_tok_ratio(used, budget) >= AIRY_TOKEN_SOFT_PPM)
		return AIRY_TOKEN_SOFT;

	return AIRY_TOKEN_NORMAL;
}

/**
 * airy_tok_add - Fold one delta into an Agent record.
 * @a: Agent record; caller holds tok_lock.
 * @d: Reported delta.
 * @now: Monotonic timestamp in nanoseconds.
 */
void airy_tok_add(struct tok_agent *a, const struct airy_token_delta *d,
		  u64 now)
{
	u64 add;

	if (!a || !d)
		return;

	tok_roll(a, now);

	a->input += d->input;
	a->output += d->output;
	a->cache_hit += d->cache_hit;
	a->reasoning += d->reasoning;

	add = (u64)d->input + d->output + d->cache_hit + d->reasoning;

	a->win_tokens += add;
	a->bused += add;
	tok_note(a, airy_tok_alert(a->bused, a->budget));
	a->updated = now;
}

/**
 * tok_alert_name - Stable text form of an alert level.
 * @alert: AIRY_TOKEN_NORMAL / SOFT / HARD.
 *
 * Return: The name used by the procfs view.
 */
static const char *tok_alert_name(u32 alert)
{
	switch (alert) {
	case AIRY_TOKEN_SOFT:
		return "ALERT";
	case AIRY_TOKEN_HARD:
		return "EXCEEDED";
	default:
		return "NORMAL";
	}
}

/**
 * tok_show - Print the snapshot of one Agent.
 * @m: Seq file positioned at the record passed as private data.
 * @v: Unused.
 *
 * A single lock protects the whole snapshot, so the reader never sees a
 * half-updated window or counter set.
 *
 * Return: 0.
 */
static int tok_show(struct seq_file *m, void *v)
{
	struct tok_agent *a = m->private;
	u64 now = ktime_get_mono_fast_ns();
	u64 total;
	u64 bill;
	u32 alert;

	mutex_lock(&tok_lock);
	tok_roll(a, now);

	total = a->input + a->output + a->cache_hit + a->reasoning;
	bill = a->input + a->output;
	alert = airy_tok_alert(a->bused, a->budget);

	seq_printf(m, "agent_id: %u\n", a->agent_id);
	seq_printf(m, "report_time_ns: %llu\n", (unsigned long long)now);
	seq_printf(m, "input_tokens_total: %llu\n",
		   (unsigned long long)a->input);
	seq_printf(m, "output_tokens_total: %llu\n",
		   (unsigned long long)a->output);
	seq_printf(m, "cache_hit_tokens_total: %llu\n",
		   (unsigned long long)a->cache_hit);
	seq_printf(m, "reasoning_tokens_total: %llu\n",
		   (unsigned long long)a->reasoning);
	seq_printf(m, "total_tokens_total: %llu\n",
		   (unsigned long long)total);
	seq_printf(m, "billable_tokens_total: %llu\n",
		   (unsigned long long)bill);
	seq_printf(m, "window_tokens_total: %llu\n",
		   (unsigned long long)a->win_tokens);
	seq_printf(m, "window_start_ns: %llu\n",
		   (unsigned long long)a->win_start);
	seq_printf(m, "window_duration_s: %llu\n",
		   AIRY_TOKEN_WINDOW_NS / 1000000000ULL);
	seq_printf(m, "budget_tokens: %llu\n",
		   (unsigned long long)a->budget);
	seq_printf(m, "budget_used: %llu\n",
		   (unsigned long long)a->bused);
	seq_printf(m, "budget_ratio_ppm: %u\n",
		   airy_tok_ratio(a->bused, a->budget));
	seq_printf(m, "budget_period_s: %llu\n",
		   AIRY_TOKEN_BUDGET_WINDOW_NS / 1000000000ULL);
	seq_printf(m, "cache_hit_ratio_ppm: %u\n",
		   airy_tok_ratio(a->cache_hit, a->input + a->cache_hit));
	seq_printf(m, "output_input_ratio_ppm: %u\n",
		   airy_tok_ratio(a->output, a->input));
	seq_printf(m, "reasoning_overhead_ppm: %u\n",
		   airy_tok_ratio(a->reasoning, bill));
	seq_printf(m, "alert_state: %s\n", tok_alert_name(alert));
	seq_printf(m, "updated_ns: %llu\n",
		   (unsigned long long)a->updated);
	mutex_unlock(&tok_lock);

	return 0;
}

/**
 * tok_proc_add - Publish /proc/airy/agents/<id>/token_stats.
 * @a: Agent record, passed to the show callback.
 *
 * The Agent directory is shared with the other meters, so it is created
 * through airy_obs_agent_dir().  A missing procfs root is not an error:
 * the device still meters, only the text view is unavailable.
 */
static void tok_proc_add(struct tok_agent *a)
{
	struct proc_dir_entry *de;

	if (a->de)
		return;

	de = airy_obs_agent_dir(a->agent_id, true);
	if (de && proc_create_single_data(TOK_FILE, 0444, de, tok_show, a))
		a->de = de;
}

/**
 * struct tok_view - One file under /sys/airy/superv/budgets.
 * @attr: Attribute whose name is the Agent id.
 * @rec: Agent record the file reports on.
 *
 * An Agent id is reused across boots but never recycled within one, so
 * the file is created once and lives until reboot; no removal path is
 * needed and the name allocation has the same lifetime.
 */
struct tok_view {
	struct kobj_attribute attr;
	struct tok_agent *rec;
};

static ssize_t tok_budget_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct tok_view *v = container_of(attr, struct tok_view, attr);
	struct tok_agent *a = v->rec;
	u64 now = ktime_get_mono_fast_ns();
	u64 used;
	u64 left;
	u32 ratio;
	u32 alert;

	mutex_lock(&tok_lock);
	tok_roll(a, now);
	used = a->bused;
	left = used >= a->budget ? 0 : a->budget - used;
	ratio = airy_tok_ratio(used, a->budget);
	/* 视图按当前用量重算档位，窗口刚回绕时不显示残留档位。 */
	alert = airy_tok_alert(used, a->budget);
	mutex_unlock(&tok_lock);

	return sysfs_emit(buf,
			  "agent_id: %u\n"
			  "token_budget: %llu\n"
			  "token_used: %llu\n"
			  "token_remaining: %llu\n"
			  "budget_ratio: %u.%02u\n"
			  "alert_threshold: %u.%u\n"
			  "action_threshold: %u.%u\n"
			  "state: %s\n",
			  a->agent_id, a->budget, used, left,
			  ratio / 10000, (ratio % 10000) / 100,
			  AIRY_TOKEN_SOFT_PPM / 10000,
			  (AIRY_TOKEN_SOFT_PPM % 10000) / 100,
			  AIRY_TOKEN_HARD_PPM / 10000,
			  (AIRY_TOKEN_HARD_PPM % 10000) / 100,
			  tok_alert_name(alert));
}

/**
 * tok_view_add - Publish the budget file of one Agent.
 * @a: Agent record; caller holds tok_lock.
 *
 * A missing budgets directory is not an error: metering and the procfs
 * view still work, only the sysfs mirror is unavailable.
 */
static void tok_view_add(struct tok_agent *a)
{
	struct kobject *parent = airy_obs_budgets();
	struct tok_view *v;
	char *name;

	if (!parent || a->view)
		return;

	v = kzalloc(sizeof(*v), GFP_KERNEL);
	name = kasprintf(GFP_KERNEL, "%u", a->agent_id);
	if (!v || !name) {
		kfree(v);
		kfree(name);
		return;
	}

	v->rec = a;
	sysfs_attr_init(&v->attr.attr);
	v->attr.attr.name = name;
	v->attr.attr.mode = 0444;
	v->attr.show = tok_budget_show;

	if (sysfs_create_file(parent, &v->attr.attr)) {
		kfree(name);
		kfree(v);
		return;
	}

	a->view = v;
}

/**
 * tok_node - Look up an Agent record, creating it when asked.
 * @id: Agent number, already bounded by the caller.
 * @create: Whether a missing record may be allocated.
 *
 * Return: The record, or NULL when it is missing and @create is false,
 *         or when allocation fails.
 */
static struct tok_agent *tok_node(u32 id, bool create)
{
	struct tok_agent *a;
	u64 now;

	lockdep_assert_held(&tok_lock);

	a = xa_load(&tok_map, id);
	if (a || !create)
		return a;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return NULL;

	now = ktime_get_mono_fast_ns();
	a->agent_id = id;
	a->budget = AIRY_TOKEN_BUDGET_DEFAULT;
	a->win_start = now;
	a->bstart = now;

	if (xa_insert(&tok_map, id, a, GFP_KERNEL)) {
		kfree(a);
		return NULL;
	}

	tok_proc_add(a);
	tok_view_add(a);

	return a;
}

/**
 * tok_report_ok - Check that the reporter may report for @id.
 * @id: Agent the delta claims to belong to.
 *
 * Return: true when the report is authorized.
 */
static bool tok_report_ok(u32 id)
{
	return airy_obs_self(id);
}

/**
 * tok_sup_ok - Check that the caller holds supervisor authority.
 *
 * Return: true when the caller may adjust budgets.
 */
static bool tok_sup_ok(void)
{
	return airy_obs_supervise();
}

static long tok_report(const struct airy_token_delta __user *up)
{
	struct airy_token_delta d;
	struct tok_agent *a;
	u64 now;
	long rc = 0;

	if (copy_from_user(&d, up, sizeof(d)))
		return -EFAULT;

	if (d.agent_id >= AIRY_CAP_MAX_AGENTS || d.pad)
		return -EINVAL;

	if (d.input > AIRY_TOKEN_DELTA_MAX ||
	    d.output > AIRY_TOKEN_DELTA_MAX ||
	    d.cache_hit > AIRY_TOKEN_DELTA_MAX ||
	    d.reasoning > AIRY_TOKEN_DELTA_MAX)
		return -EINVAL;

	if (!tok_report_ok(d.agent_id))
		return -EPERM;

	now = ktime_get_mono_fast_ns();
	if (d.ts_ns && d.ts_ns <= now && now - d.ts_ns < AIRY_TOKEN_WINDOW_NS)
		now = d.ts_ns;

	mutex_lock(&tok_lock);
	a = tok_node(d.agent_id, true);
	if (!a)
		rc = -ENOMEM;
	else
		airy_tok_add(a, &d, now);
	mutex_unlock(&tok_lock);

	return rc;
}

static long tok_query(struct airy_token_stats __user *up)
{
	struct airy_token_stats st;
	struct tok_agent *a;
	u64 total;

	if (copy_from_user(&st, up, sizeof(st)))
		return -EFAULT;

	if (st.agent_id >= AIRY_CAP_MAX_AGENTS)
		return -EINVAL;

	mutex_lock(&tok_lock);
	a = tok_node(st.agent_id, false);
	if (!a) {
		mutex_unlock(&tok_lock);
		return -ENOENT;
	}

	tok_roll(a, ktime_get_mono_fast_ns());
	total = a->input + a->output + a->cache_hit + a->reasoning;

	st.alert_state = airy_tok_alert(a->bused, a->budget);
	st.input_total = a->input;
	st.output_total = a->output;
	st.cache_hit_total = a->cache_hit;
	st.reasoning_total = a->reasoning;
	st.total = total;
	st.window_tokens = a->win_tokens;
	st.budget_tokens = a->budget;
	st.budget_used = a->bused;
	st.cache_ratio_ppm = airy_tok_ratio(a->cache_hit,
					    a->input + a->cache_hit);
	st.output_input_ppm = airy_tok_ratio(a->output, a->input);
	st.overhead_ppm = airy_tok_ratio(a->reasoning,
					 a->input + a->output);
	st.budget_ratio_ppm = airy_tok_ratio(a->bused, a->budget);
	st.updated_ns = a->updated;
	mutex_unlock(&tok_lock);

	return copy_to_user(up, &st, sizeof(st)) ? -EFAULT : 0;
}

static long tok_budget(const struct airy_token_budget __user *up)
{
	struct airy_token_budget b;
	struct tok_agent *a;
	long rc = 0;

	if (copy_from_user(&b, up, sizeof(b)))
		return -EFAULT;

	if (b.agent_id >= AIRY_CAP_MAX_AGENTS || b.pad || !b.tokens)
		return -EINVAL;

	if (!tok_sup_ok())
		return -EPERM;

	mutex_lock(&tok_lock);
	a = tok_node(b.agent_id, true);
	if (!a) {
		rc = -ENOMEM;
	} else {
		a->budget = b.tokens;
		tok_note(a, airy_tok_alert(a->bused, a->budget));
	}
	mutex_unlock(&tok_lock);

	return rc;
}

static long tok_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case AIRY_TOKEN_IOC_REPORT:
		return tok_report((struct airy_token_delta __user *)arg);
	case AIRY_TOKEN_IOC_QUERY:
		return tok_query((struct airy_token_stats __user *)arg);
	case AIRY_TOKEN_IOC_BUDGET:
		return tok_budget((struct airy_token_budget __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tok_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tok_ioctl,
	.compat_ioctl	= tok_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice tok_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= TOK_DEV_NAME,
	.fops	= &tok_fops,
	.mode	= 0666,
};

/**
 * airy_token_init - Publish the token meter.
 *
 * The device is the only way a producer reports, so a failure is left
 * to the caller to log and does not withdraw the observation plane: the
 * rest of /sys/airy and /proc/airy remains valid, and the missing node
 * is itself a true signal.
 *
 * Return: 0 on success; otherwise the registration error.
 */
int __init airy_token_init(void)
{
	return misc_register(&tok_misc);
}

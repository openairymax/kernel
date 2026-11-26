// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_superv.c — /sys/airy/superv 监管面统计。
 *
 * 计数由 Micro-Supervisor 的命令路径在成功返回前记录，这里只做快照
 * 输出。最近一次命令的字段在同一把锁内发布，读取方不会看到代理号与
 * 裁决来自两条不同命令。设备绑定与看门狗状态同样直接取自运行时，
 * 时间一律换算成毫秒，便于运维脚本按固定阈值判断。
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/sysfs.h>
#include <linux/time64.h>

#include "../superv/airy_superv.h"
#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"
#include "airy_token.h"

static const char *const obs_op_name[] = {
	[AIRY_SV_OBS_NONE]	= "none",
	[AIRY_SV_OBS_FREEZE]	= "freeze",
	[AIRY_SV_OBS_THAW]	= "thaw",
	[AIRY_SV_OBS_ADJUD]	= "adjudicate",
	[AIRY_SV_OBS_FRZ_ALL]	= "freeze_all",
};

static const char *const obs_adjud_name[] = {
	[AIRY_ADJUD_WARN]	= "WARN",
	[AIRY_ADJUD_DEGRADE]	= "DEGRADE",
	[AIRY_ADJUD_PAUSE]	= "PAUSE",
	[AIRY_ADJUD_TERMINATE]	= "TERMINATE",
	[AIRY_ADJUD_RESUME]	= "RESUME",
};

const char *airy_sv_obs_op_name(u32 op)
{
	if (op >= ARRAY_SIZE(obs_op_name) || !obs_op_name[op])
		return "unknown";

	return obs_op_name[op];
}

const char *airy_sv_obs_adjud_name(u32 adjud)
{
	if (adjud >= ARRAY_SIZE(obs_adjud_name) || !obs_adjud_name[adjud])
		return "unknown";

	return obs_adjud_name[adjud];
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct airy_sv_obs obs;

	airy_sv_obs_snap(&obs);

	return sysfs_emit(buf,
			  "micro_enforcements: %llu\n"
			  "macro_adjudications: %llu\n"
			  "system_freezes: %llu\n"
			  "thaws: %llu\n"
			  "faults_pending: %u\n"
			  "faults_lost: %u\n",
			  obs.freeze_nr, obs.adjud_nr, obs.frz_all_nr,
			  obs.thaw_nr, airy_fev_pending(), airy_fev_lost());
}

static ssize_t enforcements_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct airy_sv_obs obs;

	airy_sv_obs_snap(&obs);

	return sysfs_emit(buf, "%llu\n", obs.freeze_nr);
}

static ssize_t last_action_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct airy_sv_obs obs;

	airy_sv_obs_snap(&obs);

	return sysfs_emit(buf, "timestamp_ns: %llu\nagent_id: %u\naction: %s\n",
			  obs.last_ns, obs.last_agent,
			  airy_sv_obs_op_name(obs.last_op));
}

static ssize_t adjudications_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct airy_sv_obs obs;

	airy_sv_obs_snap(&obs);

	return sysfs_emit(buf, "%llu\n", obs.adjud_nr);
}

static ssize_t last_adjudication_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	struct airy_sv_obs obs;
	const char *action;

	airy_sv_obs_snap(&obs);

	/* Verdict zero is a valid value (WARN), so only the last operation
	 * identifies whether the field carries one at all. */
	action = obs.last_op == AIRY_SV_OBS_ADJUD ?
		 airy_sv_obs_adjud_name(obs.last_adjud) : "none";

	return sysfs_emit(buf, "timestamp_ns: %llu\nagent_id: %u\naction: %s\n",
			  obs.last_ns, obs.last_agent, action);
}

static ssize_t device_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	struct airy_svdev_info dev;
	u64 now;

	airy_svdev_snapshot(&dev);
	now = ktime_get_mono_fast_ns();

	return sysfs_emit(buf, "active: %u\npid: %u\nuptime_ms: %llu\n",
			  dev.active, dev.pid,
			  dev.since_ns ? div_u64(now - dev.since_ns,
						 NSEC_PER_MSEC) : 0ULL);
}

static ssize_t watchdog_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	u64 last_ns;
	bool latched;

	airy_wdog_snapshot(&last_ns, &latched);

	return sysfs_emit(buf, "last_heartbeat_ms: %llu\nlatched: %d\n",
			  last_ns ? div_u64(ktime_get_mono_fast_ns() - last_ns,
					    NSEC_PER_MSEC) : 0ULL,
			  latched ? 1 : 0);
}

/*
 * 预算快照目录由 superv 发布、由 token 模块挂文件：谁持有记录谁建文件，
 * 读值因此与 /proc/airy/agents/<id>/token_stats 同源，不会出现两份账。
 */
static struct kobject *obs_budgets;

struct kobject *airy_obs_budgets(void)
{
	return obs_budgets;
}

static ssize_t budget_alerts_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%llu\n", airy_tok_alerts());
}

static const struct airy_obs_attr stats_attrs[] = {
	AIRY_OBS_ATTR(stats),
};

static const struct airy_obs_attr micro_attrs[] = {
	AIRY_OBS_ATTR(enforcements),
	AIRY_OBS_ATTR(last_action),
};

static const struct airy_obs_attr macro_attrs[] = {
	AIRY_OBS_ATTR(adjudications),
	AIRY_OBS_ATTR(last_adjudication),
	AIRY_OBS_ATTR(budget_alerts),
};

static const struct airy_obs_attr device_attrs[] = {
	AIRY_OBS_ATTR(device),
	AIRY_OBS_ATTR(watchdog),
};

int airy_obs_superv_init(struct kobject *root)
{
	struct kobject *dir;
	int rc;

	dir = airy_obs_dir(root, "superv");
	if (!dir)
		return -ENOMEM;

	rc = airy_obs_register(dir, NULL, stats_attrs,
			       ARRAY_SIZE(stats_attrs));
	if (rc)
		goto out;

	rc = airy_obs_register(dir, "micro", micro_attrs,
			       ARRAY_SIZE(micro_attrs));
	if (rc)
		goto out;

	rc = airy_obs_register(dir, "macro", macro_attrs,
			       ARRAY_SIZE(macro_attrs));
	if (rc)
		goto out;

	obs_budgets = airy_obs_dir(dir, "budgets");
	if (!obs_budgets) {
		rc = -ENOMEM;
		goto out;
	}

	rc = airy_obs_register(dir, NULL, device_attrs,
			       ARRAY_SIZE(device_attrs));
out:
	if (rc)
		obs_budgets = NULL;
	kobject_put(dir);
	return rc;
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_superv_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(stats_attrs);
	return stats_attrs;
}

const struct airy_obs_attr *airy_obs_macro_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(macro_attrs);
	return macro_attrs;
}
#endif

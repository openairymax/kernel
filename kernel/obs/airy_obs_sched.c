// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_sched.c — /sys/airy/sched 调度面统计。
 *
 * 数据直接取自 sched_tac 的分派计数器，不做二次累加；策略名同样来自
 * stc_policy_name()，保证观测面与调度器使用同一张分类表。
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "../corekern/sched/stc_policy.h"
#include "airy_obs.h"

static int emit_policies(char *buf, int off)
{
	enum airy_sched_policy policy;

	for (policy = STC_POLICY_REALTIME; policy < STC_POLICY_MAX; policy++) {
		int rc = sysfs_emit_at(buf, off, "%s: %d\n",
				       stc_policy_name(policy),
				       stc_stats_policy(policy));

		if (rc < 0)
			break;
		off += rc;
	}

	return off;
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	int off;

	off = sysfs_emit(buf, "total: %d\n", stc_stats_read());
	if (off < 0)
		return off;

	return emit_policies(buf, off);
}

static ssize_t class_stats_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return emit_policies(buf, 0);
}

static const struct airy_obs_attr sched_attrs[] = {
	AIRY_OBS_ATTR(stats),
	AIRY_OBS_ATTR(class_stats),
};

int airy_obs_sched_init(struct kobject *root)
{
	return airy_obs_register(root, "sched", sched_attrs,
				 ARRAY_SIZE(sched_attrs));
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_sched_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(sched_attrs);
	return sched_attrs;
}
#endif

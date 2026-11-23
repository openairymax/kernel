// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_daemons.c — /sys/airy/daemons 守护进程状态。
 *
 * 只发布内核侧真正掌握的状态：macro_d 通过 /dev/airy_superv 绑定，
 * 它的存活由看门狗心跳判定。其余 daemon 的运行状态归用户态守护进程
 * 自己所有，内核没有可信数据源，因此不生成它们的节点，避免把零值当
 * 成“已停止”误报。
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/sysfs.h>
#include <linux/time64.h>

#include "../superv/airy_superv.h"
#include "airy_obs.h"

static const char *macro_state(const struct airy_svdev_info *dev, bool latched)
{
	if (latched)
		return "FAULTED";

	return dev->active ? "RUNNING" : "STOPPED";
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	struct airy_svdev_info dev;
	bool latched;

	airy_svdev_snapshot(&dev);
	airy_wdog_snapshot(NULL, &latched);

	return sysfs_emit(buf, "%s\n",
			  latched ? "faulted" : (dev.active ? "running"
							     : "stopped"));
}

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct airy_svdev_info dev;
	bool latched;

	airy_svdev_snapshot(&dev);
	airy_wdog_snapshot(NULL, &latched);

	return sysfs_emit(buf, "%s\n", macro_state(&dev, latched));
}

static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	struct airy_svdev_info dev;

	airy_svdev_snapshot(&dev);

	return sysfs_emit(buf, "%u\n", dev.pid);
}

static ssize_t uptime_ms_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	struct airy_svdev_info dev;

	airy_svdev_snapshot(&dev);

	return sysfs_emit(buf, "%llu\n",
			  dev.since_ns ? div_u64(ktime_get_mono_fast_ns() -
						 dev.since_ns, NSEC_PER_MSEC)
				       : 0ULL);
}

static ssize_t last_heartbeat_ms_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	u64 last_ns;

	airy_wdog_snapshot(&last_ns, NULL);

	return sysfs_emit(buf, "%llu\n",
			  last_ns ? div_u64(ktime_get_mono_fast_ns() - last_ns,
					    NSEC_PER_MSEC) : 0ULL);
}

static const struct airy_obs_attr macro_attrs[] = {
	AIRY_OBS_ATTR(status),
	AIRY_OBS_ATTR(state),
	AIRY_OBS_ATTR(pid),
	AIRY_OBS_ATTR(uptime_ms),
	AIRY_OBS_ATTR(last_heartbeat_ms),
};

int airy_obs_daemons_init(struct kobject *root)
{
	struct kobject *dir;
	int rc;

	dir = airy_obs_dir(root, "daemons");
	if (!dir)
		return -ENOMEM;

	rc = airy_obs_register(dir, "macro_d", macro_attrs,
			       ARRAY_SIZE(macro_attrs));
	kobject_put(dir);

	return rc;
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_daemons_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(macro_attrs);
	return macro_attrs;
}
#endif

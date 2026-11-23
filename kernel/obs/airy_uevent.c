// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_uevent.c — /sys/airy/events 用户态 trace 事件契约。
 *
 * 守护进程用 user_events 上报 trace 事件，事件名与注册格式串必须与
 * 内核侧发布的一致：名字差一个前缀，事件在 tracefs 里就归到另一个
 * 目录；字段顺序或类型写错，user_events 仍会接受注册，只是之后每个
 * 字段都读到错误的位置。这两种错误在注册调用返回 0 时都看不出来。
 *
 * 因此把 UAPI 里的名字与格式串整理成一张只读表挂到 /sys/airy/events：
 * 用户态在注册前自检，运维对照现场注册结果，KUnit 校验格式串与结构体
 * 布局。表只有一份，sysfs 输出与测试都读 airy_uevents[]，不再另抄清单。
 *
 * 本文件不实现传输：注册、写入与使能位都由 user_events 自己负责
 * （OS-OBS-061 禁止自创通道）。transport 只报告内核是否编译了该通道，
 * 供运维在事件缺失时先分清是内核没开还是用户态没注册。
 */

#include <linux/airymax/user_events.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "airy_obs.h"

/* 契约表：名字与格式串都来自 UAPI，避免两处各写一份而悄悄分叉。 */
static const struct airy_uevent_def airy_uevents[] = {
	{ AIRY_UEVENT_COGN_START, AIRY_UEVENT_FMT_COGN_START },
	{ AIRY_UEVENT_COGN_END, AIRY_UEVENT_FMT_COGN_END },
	{ AIRY_UEVENT_MEM_ACCESS, AIRY_UEVENT_FMT_MEM_ACCESS },
	{ AIRY_UEVENT_TOOL_CALL, AIRY_UEVENT_FMT_TOOL_CALL },
	{ AIRY_UEVENT_SUPERV_ENFORCE, AIRY_UEVENT_FMT_SUPERV_ENFORCE },
};

static ssize_t abi_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "abi: %u\nevents: %zu\n", AIRY_UEVENT_ABI,
			  ARRAY_SIZE(airy_uevents));
}

static ssize_t transport_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	return sysfs_emit(buf, "%s\n", IS_ENABLED(CONFIG_USER_EVENTS) ?
			  "user_events" : "absent");
}

static ssize_t catalog_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	ssize_t off = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(airy_uevents) && off < PAGE_SIZE; i++)
		off += sysfs_emit_at(buf, off, "%s %s\n",
				     airy_uevents[i].name,
				     airy_uevents[i].format);

	return off;
}

static const struct airy_obs_attr uevent_attrs[] = {
	AIRY_OBS_ATTR(abi),
	AIRY_OBS_ATTR(transport),
	AIRY_OBS_ATTR(catalog),
};

/**
 * airy_obs_uevent_init - Publish the event contract under /sys/airy/events.
 * @root: The /sys/airy kobject.
 *
 * Return: 0 on success, or the first registration error.
 */
int airy_obs_uevent_init(struct kobject *root)
{
	return airy_obs_register(root, "events", uevent_attrs,
				 ARRAY_SIZE(uevent_attrs));
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_uevent_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(uevent_attrs);
	return uevent_attrs;
}

const struct airy_uevent_def *airy_uevent_defs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(airy_uevents);
	return airy_uevents;
}
#endif /* CONFIG_AIRY_KUNIT */

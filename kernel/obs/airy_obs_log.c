// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_log.c — /sys/airy/log 日志环统计。
 *
 * 环几何与游标直接读共享头，覆盖计数与提交计数由写路径维护。写入
 * 速率按两次读取之间的增量计算，首次读取返回 0，避免用开机以来的
 * 平均值冒充当前速率。
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/time64.h>
#include <linux/ktime.h>

#include <linux/airymax/log_ring.h>

#include "../log/airy_log_internal.h"
#include "airy_obs.h"

static DEFINE_MUTEX(rate_lock);
static u64 rate_last_writes;
static u64 rate_last_ns;

static const struct airy_log_ring *log_ring(void)
{
	const struct airy_log_ring *ring = airy_log_global();

	if (!ring || !ring->kaddr)
		return NULL;

	return ring;
}

static u64 ring_used(const struct airy_log_ring *ring)
{
	const struct airy_log_ring_header *hdr = ring->kaddr;
	u64 used;

	if (hdr->committed_head <= hdr->tail)
		return 0;

	used = hdr->committed_head - hdr->tail;

	return used > hdr->capacity ? hdr->capacity : used;
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	const struct airy_log_ring *ring = log_ring();
	const struct airy_log_ring_header *hdr;

	if (!ring)
		return sysfs_emit(buf, "initialized: 0\n");

	hdr = ring->kaddr;

	return sysfs_emit(buf,
			  "initialized: 1\n"
			  "capacity: %u\n"
			  "record_size: %u\n"
			  "used: %llu\n"
			  "frozen: %u\n"
			  "overrun: %llu\n"
			  "writes: %llu\n",
			  hdr->capacity, hdr->record_size, ring_used(ring),
			  hdr->frozen, atomic64_read(&ring->overrun),
			  atomic64_read(&ring->writes));
}

static ssize_t size_kb_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	const struct airy_log_ring *ring = log_ring();

	if (!ring)
		return sysfs_emit(buf, "0\n");

	return sysfs_emit(buf, "%llu\n", (u64)ring->size >> 10);
}

static ssize_t used_kb_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	const struct airy_log_ring *ring = log_ring();
	u64 bytes;

	if (!ring)
		return sysfs_emit(buf, "0\n");

	bytes = ring_used(ring) *
		((const struct airy_log_ring_header *)ring->kaddr)->record_size;

	return sysfs_emit(buf, "%llu\n", bytes >> 10);
}

static ssize_t overrun_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	const struct airy_log_ring *ring = log_ring();

	if (!ring)
		return sysfs_emit(buf, "0\n");

	return sysfs_emit(buf, "%llu\n", atomic64_read(&ring->overrun));
}

static ssize_t write_rate_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	const struct airy_log_ring *ring = log_ring();
	u64 writes, now, delta;
	unsigned int rate = 0;

	if (!ring)
		return sysfs_emit(buf, "0\n");

	writes = atomic64_read(&ring->writes);
	now = ktime_get_mono_fast_ns();

	mutex_lock(&rate_lock);
	if (rate_last_ns && now > rate_last_ns && writes >= rate_last_writes) {
		delta = now - rate_last_ns;
		rate = (unsigned int)div64_u64((writes - rate_last_writes) *
					       NSEC_PER_SEC, delta);
	}
	rate_last_writes = writes;
	rate_last_ns = now;
	mutex_unlock(&rate_lock);

	return sysfs_emit(buf, "%u\n", rate);
}

static const struct airy_obs_attr log_attrs[] = {
	AIRY_OBS_ATTR(stats),
};

static const struct airy_obs_attr ring_attrs[] = {
	AIRY_OBS_ATTR(size_kb),
	AIRY_OBS_ATTR(used_kb),
	AIRY_OBS_ATTR(overrun),
	AIRY_OBS_ATTR(write_rate),
};

int airy_obs_log_init(struct kobject *root)
{
	struct kobject *dir;
	int rc;

	dir = airy_obs_dir(root, "log");
	if (!dir)
		return -ENOMEM;

	rc = airy_obs_register(dir, NULL, log_attrs, ARRAY_SIZE(log_attrs));
	if (rc)
		goto out;

	rc = airy_obs_register(dir, "ring_buffer", ring_attrs,
			       ARRAY_SIZE(ring_attrs));
out:
	kobject_put(dir);
	return rc;
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_log_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(log_attrs);
	return log_attrs;
}
#endif

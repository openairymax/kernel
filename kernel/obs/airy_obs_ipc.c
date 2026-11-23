// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_ipc.c — /sys/airy/ipc 通信面统计。
 *
 * 计数器由 kfifo 邮箱在快慢路径上直接维护，这里只做跨 CPU 汇总与
 * 比例换算。环形队列按任务持有，没有全局注册表，因此不生成 per-ring
 * 目录：没有真实归属的节点不发布。
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/math64.h>
#include <linux/sysfs.h>

#include "../corekern/ipc/airy_ipc_internal.h"
#include "airy_obs.h"

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct airy_ipc_stats st;
	u64 fast, total;
	unsigned int ratio = 0;

	airy_ipc_stats_read(&st);

	fast  = st.fast_send_hit + st.fast_recv_hit;
	total = fast + st.slow_send_hit + st.slow_recv_hit;
	if (total)
		ratio = (unsigned int)div64_u64(fast * 100, total);

	return sysfs_emit(buf,
			  "fast_send: %llu\n"
			  "fast_recv: %llu\n"
			  "slow_send: %llu\n"
			  "slow_recv: %llu\n"
			  "batch: %llu\n"
			  "cancel: %llu\n"
			  "error: %llu\n"
			  "backpressure: %llu\n"
			  "fast_ratio_pct: %u\n",
			  st.fast_send_hit, st.fast_recv_hit,
			  st.slow_send_hit, st.slow_recv_hit,
			  st.batch_hit, st.cancel_hit,
			  st.error_hit, st.backpressure_hit, ratio);
}

static const struct airy_obs_attr ipc_attrs[] = {
	AIRY_OBS_ATTR(stats),
};

int airy_obs_ipc_init(struct kobject *root)
{
	return airy_obs_register(root, "ipc", ipc_attrs,
				 ARRAY_SIZE(ipc_attrs));
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_ipc_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(ipc_attrs);
	return ipc_attrs;
}
#endif

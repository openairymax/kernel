// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_ipc.c — /sys/airy/ipc 通信面统计。
 *
 * 计数器由 kfifo 邮箱在快慢路径上直接维护，这里只做跨 CPU 汇总与
 * 比例换算。环形队列按任务持有，没有全局注册表，因此不生成 per-ring
 * 目录：没有真实归属的节点不发布。
 *
 * capabilities 是能力槽的紧凑稳定面：每个持有槽的 Agent 一行，权限位
 * 用 UAPI 名字拼接，供运维脚本按固定字段 grep。原始掩码、epoch 与继承
 * 关系留在 debugfs 的 cap_table，两个面分工而不重复。
 */

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/math64.h>
#include <linux/seq_buf.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>

#include "../corekern/ipc/airy_ipc_internal.h"
#include "../../security/airy/airy_cap.h"
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

/*
 * 每行最大长度：id 至多 4 位、七个权限名全选时约 60 字节，留一倍余量。
 * 一页放不下时不再硬塞，末尾给出 shown/total，读方不会把截断当成全量。
 */
#define OBS_CAP_LINE	96
#define OBS_CAP_TAIL	32

static ssize_t capabilities_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	unsigned int id, shown = 0, total = 0, off = 0;

	for (id = 0; id < AIRY_CAP_MAX_AGENTS; id++) {
		unsigned int bkt = airy_cap_bucket(id);
		struct airy_cap_slot slot;
		unsigned long flags;
		char perms[64];
		char line[OBS_CAP_LINE];
		struct seq_buf sb;

		spin_lock_irqsave(&airy_cap_bucket_locks[bkt], flags);
		slot = agent_caps[id];
		spin_unlock_irqrestore(&airy_cap_bucket_locks[bkt], flags);

		if (!slot.badge && !slot.flags)
			continue;

		total++;
		airy_obs_cap_perms(perms, sizeof(perms), slot.perms);

		seq_buf_init(&sb, line, sizeof(line));
		seq_buf_printf(&sb, "agent_id: %u  caps: %s\n", id, perms);
		if (seq_buf_has_overflowed(&sb) ||
		    off + sb.len + OBS_CAP_TAIL > PAGE_SIZE)
			break;

		off += sysfs_emit_at(buf, off, "%s", line);
		shown++;
	}

	if (shown < total)
		off += sysfs_emit_at(buf, off, "truncated: %u of %u\n",
				     shown, total);
	else if (!total)
		off += sysfs_emit_at(buf, off, "agents: 0\n");

	return off;
}

static const struct airy_obs_attr ipc_attrs[] = {
	AIRY_OBS_ATTR(stats),
	AIRY_OBS_ATTR(capabilities),
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

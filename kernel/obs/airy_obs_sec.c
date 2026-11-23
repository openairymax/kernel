// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_sec.c — /sys/airy/sec 安全面统计。
 *
 * 两个文件都只聚合已有计数器：策略表的判定计数来自 airy_policy.c，
 * 能力表规模来自 agent_caps[]，故障明细的丢失数来自 A-UEF 环。
 * 这里不引入新的计量点，避免观测值与执行路径出现两份真相。
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <linux/airymax/lsm_types.h>
#include <airymax/airy_policy.h>

#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct airy_pol_cnt total = { };
	struct airy_pol_cnt cur;
	unsigned int agents = 0;
	u8 slot;
	int i;

	for (slot = 0; slot < AIRY_POLICY_MAX_TABLES; slot++) {
		airy_pol_stat(slot, &cur);
		total.evals	+= cur.evals;
		total.allow	+= cur.allow;
		total.deny	+= cur.deny;
		total.audit	+= cur.audit;
		total.complain	+= cur.complain;
		total.fault	+= cur.fault;
	}

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		if (airy_cap_lookup(i))
			agents++;
	}

	return sysfs_emit(buf,
			  "evaluations: %llu\n"
			  "allow: %llu\n"
			  "deny: %llu\n"
			  "audit: %llu\n"
			  "complain: %llu\n"
			  "fault: %llu\n"
			  "agents: %u\n"
			  "epoch: %d\n"
			  "faults_lost: %u\n",
			  total.evals, total.allow, total.deny, total.audit,
			  total.complain, total.fault, agents,
			  atomic_read(&airy_cap_global_epoch),
			  airy_fev_lost());
}

static ssize_t lsm_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "enabled: %d\nhooks: %u\nsuperv_hooks: %u\n",
			  airy_lsm_enabled(),
			  (unsigned int)AIRY_LSM_HOOK_IMPLEMENTED,
			  airy_superv_hook_count());
}

static const struct airy_obs_attr sec_attrs[] = {
	AIRY_OBS_ATTR(stats),
	AIRY_OBS_ATTR(lsm),
};

int airy_obs_sec_init(struct kobject *root)
{
	return airy_obs_register(root, "sec", sec_attrs,
				 ARRAY_SIZE(sec_attrs));
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_sec_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(sec_attrs);
	return sec_attrs;
}
#endif

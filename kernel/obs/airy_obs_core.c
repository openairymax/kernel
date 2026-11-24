// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_core.c — /sys/airy 根节点与属性表注册。
 *
 * 观测面在 core_initcall 阶段发布，而不是在 LSM 的 airy_init() 内：
 * security_init() 早于 vfs_caches_init()，此时 kernfs 尚未建立，
 * kobject_add() 只能返回 -ENOENT（见 init/main.c 的启动顺序）。
 * core_initcall 是 sysfs 可用之后最早的时刻，且仍早于任何用户态进程，
 * 因此用户态永远看不到不完整的观测树。
 *
 * 发布失败时撤回 agentrt 就绪标记（OS-KER-132/133）：让运行时退回
 * 用户态路径，而不是在不可观测的状态下宣称就绪。子目录只在与真实
 * 数据源同时存在时创建，未实现的功能面不会出现空目录或零值文件。
 */

#include <generated/compile.h>
#include <generated/utsrelease.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sysfs.h>

#include <airymax/airy_agent.h>

#include "../../security/airy/airy_cap.h"
#include "../../security/airy/airy_probe.h"
#include "airy_mem.h"
#include "airy_obs.h"
#include "airy_token.h"

static struct kset *airy_obs_kset;

bool airy_obs_ready;

/**
 * airy_obs_ppm - Express @num / @den in parts per million.
 * @num: Numerator.
 * @den: Denominator; zero yields 0 instead of a division fault.
 *
 * Ratios above 1.0 are kept (an overrun must stay visible) and saturate at
 * U32_MAX.  Every meter reports ppm through this one conversion so two
 * observation surfaces can never disagree on rounding.
 *
 * Return: The ratio in ppm.
 */
u32 airy_obs_ppm(u64 num, u64 den)
{
	u64 ratio;

	if (!den)
		return 0;

	if (num > div64_u64(U64_MAX, 1000000ULL))
		return U32_MAX;

	ratio = div64_u64(num * 1000000ULL, den);

	return ratio > U32_MAX ? U32_MAX : (u32)ratio;
}

/**
 * airy_obs_self - Check that the caller may report for @id.
 * @id: Agent the report claims to belong to.
 *
 * The slot check only proves that agent @id is live and holds SEND; it
 * does not prove that the caller is that agent.  Identity comes from the
 * LSM task blob, which the kernel owns, so the two are combined: a task
 * may only report for its own agent id.
 *
 * Return: true when the report is authorized.
 */
bool airy_obs_self(u32 id)
{
	if (capable(CAP_SYS_PTRACE))
		return true;

	return airy_agent_id(current) == id &&
	       airy_cap_check(id, AIRY_CAP_PERM_SEND) == 0;
}

/**
 * airy_obs_supervise - Check that the caller holds supervisor authority.
 *
 * Cross-agent controls (budgets, quotas) read the permission bit from the
 * caller's own slot, never from the target's.
 *
 * Return: true when the caller may adjust limits.
 */
bool airy_obs_supervise(void)
{
	u32 self = airy_agent_id(current);

	if (capable(CAP_SYS_PTRACE))
		return true;

	return self && airy_cap_check(self, AIRY_CAP_PERM_SUPERVISE) == 0;
}

/**
 * airy_obs_dir - Create a child directory under an observation node.
 * @parent: Parent kobject; must not be NULL.
 * @name: Directory name.
 *
 * Return: The new kobject, or NULL when allocation fails.
 */
struct kobject *airy_obs_dir(struct kobject *parent, const char *name)
{
	if (!parent || !name)
		return NULL;

	return kobject_create_and_add(name, parent);
}

/**
 * airy_obs_register - Publish one attribute table.
 * @root: Parent kobject.
 * @dir: Child directory name, or NULL to publish directly in @root.
 * @attrs: Read-only attribute descriptors.
 * @nr: Number of descriptors in @attrs.
 *
 * Return: 0 on success; -EINVAL on a bad descriptor set; -ENOMEM when
 *         the child directory cannot be created; otherwise the error
 *         from sysfs_create_file().
 */
int airy_obs_register(struct kobject *root, const char *dir,
		      const struct airy_obs_attr *attrs, unsigned int nr)
{
	struct kobject *kobj = root;
	unsigned int i;
	int rc;

	if (!root || !attrs || !nr)
		return -EINVAL;

	if (dir) {
		kobj = airy_obs_dir(root, dir);
		if (!kobj)
			return -ENOMEM;
	}

	for (i = 0; i < nr; i++) {
		rc = sysfs_create_file(kobj, &attrs[i].attr.attr);
		if (rc) {
			if (dir)
				kobject_put(kobj);
			return rc;
		}
	}

	return 0;
}

static ssize_t version_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "abi: %u\nkernel: %s\narch: %s\n",
			  AIRY_OBS_ABI, UTS_RELEASE, UTS_MACHINE);
}

static const struct airy_obs_attr version_attrs[] = {
	AIRY_OBS_ATTR(version),
};

/**
 * airy_obs_init - Bring the /sys/airy and /proc/airy trees up.
 *
 * Return: 0 on success; otherwise the first registration error.
 */
static int __init airy_obs_init(void)
{
	struct kobject *root;
	int rc;

	airy_obs_kset = kset_create_and_add("airy", NULL, NULL);
	if (!airy_obs_kset)
		return -ENOMEM;

	root = &airy_obs_kset->kobj;

	rc = airy_obs_register(root, NULL, version_attrs,
			       ARRAY_SIZE(version_attrs));
	if (rc)
		goto err;

	rc = airy_obs_sec_init(root);
	if (rc)
		goto err;

	rc = airy_obs_superv_init(root);
	if (rc)
		goto err;

	rc = airy_obs_daemons_init(root);
	if (rc)
		goto err;

	rc = airy_obs_uevent_init(root);
	if (rc)
		goto err;

#if IS_ENABLED(CONFIG_AIRY_COREKERN)
	rc = airy_obs_sched_init(root);
	if (rc)
		goto err;

	rc = airy_obs_ipc_init(root);
	if (rc)
		goto err;
#endif

#if IS_ENABLED(CONFIG_AIRY_LOG)
	rc = airy_obs_log_init(root);
	if (rc)
		goto err;
#endif

#if IS_ENABLED(CONFIG_PROC_FS)
	rc = airy_obs_proc_init();
	if (rc)
		goto err;
#endif

	rc = airy_token_init();
	if (rc)
		pr_warn("airy: token meter unavailable: %d\n", rc);

	rc = airy_mem_init();
	if (rc)
		pr_warn("airy: memory meter unavailable: %d\n", rc);

	airy_obs_ready = true;

	return 0;

err:
	kset_unregister(airy_obs_kset);
	airy_obs_kset = NULL;
	return rc;
}

static int __init airy_obs_start(void)
{
	int rc = airy_obs_init();

	if (!rc)
		return 0;

	pr_err("airy: observation plane unavailable: %d\n", rc);
	airy_probe_exit();

	return rc;
}
core_initcall(airy_obs_start);

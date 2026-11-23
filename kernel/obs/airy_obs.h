/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs.h — /sys/airy 与 /proc/airy 观测面的内部接口。
 *
 * 每个子模块导出一张只读属性表，由 airy_obs_core.c 统一挂到根 kobject
 * 下。属性表同时是 KUnit 的断言对象：测试直接调用 show 回调校验模式与
 * 内容，不依赖 kernfs 内部结构。没有真实数据源的功能面不会出现在表
 * 中，避免用零值冒充观测结果。
 */

#ifndef _AIRY_OBS_H
#define _AIRY_OBS_H

#include <linux/kobject.h>
#include <linux/sysfs.h>

/* /sys/airy 属性布局的版本，供使用者判断字段集合是否变化。 */
#define AIRY_OBS_ABI	1

/**
 * struct airy_obs_attr - 一个只读属性的描述符
 * @attr: kernfs 属性；名字与模式都由 AIRY_OBS_ATTR() 固定
 */
struct airy_obs_attr {
	struct kobj_attribute attr;
};

/**
 * AIRY_OBS_ATTR() - 由同名 show 回调构造一个 0444 属性
 * @_name: 属性名；同文件内必须存在 _name##_show()
 */
#define AIRY_OBS_ATTR(_name)						\
	{								\
		.attr = __ATTR(_name, 0444, _name##_show, NULL),	\
	}

struct kobject *airy_obs_dir(struct kobject *parent, const char *name);
int airy_obs_register(struct kobject *root, const char *dir,
		      const struct airy_obs_attr *attrs, unsigned int nr);
int __init airy_obs_proc_init(void);

int airy_obs_sec_init(struct kobject *root);
int airy_obs_superv_init(struct kobject *root);
int airy_obs_daemons_init(struct kobject *root);

#if IS_ENABLED(CONFIG_AIRY_COREKERN)
int airy_obs_sched_init(struct kobject *root);
int airy_obs_ipc_init(struct kobject *root);
#endif
#if IS_ENABLED(CONFIG_AIRY_LOG)
int airy_obs_log_init(struct kobject *root);
#endif

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_sec_attrs(unsigned int *nr);
const struct airy_obs_attr *airy_obs_superv_attrs(unsigned int *nr);
const struct airy_obs_attr *airy_obs_daemons_attrs(unsigned int *nr);
#if IS_ENABLED(CONFIG_AIRY_COREKERN)
const struct airy_obs_attr *airy_obs_sched_attrs(unsigned int *nr);
const struct airy_obs_attr *airy_obs_ipc_attrs(unsigned int *nr);
#endif
#if IS_ENABLED(CONFIG_AIRY_LOG)
const struct airy_obs_attr *airy_obs_log_attrs(unsigned int *nr);
#endif
#endif /* CONFIG_AIRY_KUNIT */

#endif /* _AIRY_OBS_H */

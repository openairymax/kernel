// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_test.c — /sys/airy 属性表契约测试。
 *
 * 属性表本身就是观测面的单一真相：注册路径遍历它，测试也遍历它。
 * 每个用例校验模式固定为 0444、show 回调存在、回调在空 kobject 下
 * 仍能产出以换行结尾的非空内容——KUnit 没有 kernfs 节点，这条约束
 * 同时保证了回调不依赖参数。内容校验只断言键名，不比对具体数值，
 * 因为计数器随引导过程变化。
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <linux/airymax/superv.h>
#include <linux/airymax/user_events.h>

#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

/*
 * sysfs_emit() 要求缓冲区页对齐（offset_in_page 检查），而 KUnit 直接
 * 调用 show 回调、没有 kernfs 提供的页面。这里显式对齐，使真实回调
 * 的写入路径与运行时完全一致。
 */
static char obs_buf[PAGE_SIZE] __aligned(PAGE_SIZE);

static void obs_table(struct kunit *test, const struct airy_obs_attr *attrs,
		      unsigned int nr)
{
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, attrs);
	KUNIT_ASSERT_GT(test, nr, 0);

	for (i = 0; i < nr; i++) {
		ssize_t rc;

		KUNIT_ASSERT_NOT_NULL(test, attrs[i].attr.attr.name);
		KUNIT_EXPECT_EQ(test, 0444, attrs[i].attr.attr.mode);
		KUNIT_ASSERT_NOT_NULL(test, attrs[i].attr.show);

		memset(obs_buf, 0, sizeof(obs_buf));
		rc = attrs[i].attr.show(NULL, &attrs[i].attr, obs_buf);
		KUNIT_ASSERT_GT(test, rc, 0);
		KUNIT_EXPECT_EQ(test, '\n', obs_buf[rc - 1]);
		KUNIT_EXPECT_EQ(test, '\0', obs_buf[rc]);
	}
}

static const char *obs_show(const struct airy_obs_attr *attrs, unsigned int nr,
			    const char *name)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		if (!strcmp(attrs[i].attr.attr.name, name)) {
			memset(obs_buf, 0, sizeof(obs_buf));
			if (attrs[i].attr.show(NULL, &attrs[i].attr, obs_buf) < 0)
				return NULL;
			return obs_buf;
		}
	}

	return NULL;
}

static void obs_sec_table(struct kunit *test)
{
	const struct airy_obs_attr *attrs;
	const char *out;
	unsigned int nr;

	attrs = airy_obs_sec_attrs(&nr);
	obs_table(test, attrs, nr);

	out = obs_show(attrs, nr, "stats");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "evaluations:"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "agents:"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "faults_lost:"));

	out = obs_show(attrs, nr, "lsm");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "hooks:"));
}

static void obs_superv_table(struct kunit *test)
{
	const struct airy_obs_attr *attrs;
	const char *out;
	unsigned int nr;

	attrs = airy_obs_superv_attrs(&nr);
	obs_table(test, attrs, nr);

	out = obs_show(attrs, nr, "stats");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "micro_enforcements:"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "macro_adjudications:"));
}

static void obs_daemons_table(struct kunit *test)
{
	const struct airy_obs_attr *attrs;
	const char *out;
	unsigned int nr;

	attrs = airy_obs_daemons_attrs(&nr);
	obs_table(test, attrs, nr);

	out = obs_show(attrs, nr, "state");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_TRUE(test, !strcmp(out, "STOPPED\n") ||
				!strcmp(out, "RUNNING\n") ||
				!strcmp(out, "FAULTED\n"));

	/* With no supervisor bound, the pid must read back as zero. */
	out = obs_show(attrs, nr, "pid");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_STREQ(test, "0\n", out);
}

static void obs_cap_fmt(struct kunit *test)
{
	struct airy_cap_slot slot = { };
	char line[160];

	slot.badge = 0x0001000000000001ULL;
	slot.randtag = 0xdeadbeef;
	slot.perms = 0x00ff;
	slot.epoch = 7;
	slot.flags = AIRY_CAP_FL_REVOKED;
	slot.generation = 3;
	slot.parent_agent = 42;

	airy_obs_cap_fmt(line, sizeof(line), 9, &slot);

	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "agent 9:"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "perms=0x00ff"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "epoch=7"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "flags=0x00000001"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "gen=3"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(line, "parent=42"));
	/* The anti-forgery tag must never reach a readable surface. */
	KUNIT_EXPECT_NULL(test, strstr(line, "deadbeef"));
	KUNIT_EXPECT_EQ(test, '\n', line[strlen(line) - 1]);
}

static void obs_cap_fmt_short(struct kunit *test)
{
	struct airy_cap_slot slot = { };
	char line[8];

	airy_obs_cap_fmt(line, sizeof(line), 1, &slot);

	/* Truncation must still leave a terminated string in the buffer. */
	KUNIT_EXPECT_LT(test, strlen(line), sizeof(line));
}

static void obs_dir_guard(struct kunit *test)
{
	KUNIT_EXPECT_NULL(test, airy_obs_dir(NULL, "airy"));
}

static void obs_fev_guard(struct kunit *test)
{
	struct airy_fault_event ev;

	KUNIT_EXPECT_EQ(test, -AIRY_EINVAL, airy_fev_peek(0, NULL));

	if (!airy_fev_pending())
		KUNIT_EXPECT_EQ(test, -AIRY_ENOENT, airy_fev_peek(0, &ev));
}

static void obs_uevent_table(struct kunit *test)
{
	const struct airy_obs_attr *attrs;
	const struct airy_uevent_def *defs;
	const char *out;
	unsigned int nr, n, i;

	attrs = airy_obs_uevent_attrs(&nr);
	obs_table(test, attrs, nr);

	/* 名字必须落在同一个 tracefs 命名空间，否则运维按前缀找不到事件。 */
	defs = airy_uevent_defs(&n);
	KUNIT_ASSERT_NOT_NULL(test, defs);
	KUNIT_ASSERT_EQ(test, 5U, n);
	for (i = 0; i < n; i++)
		KUNIT_EXPECT_EQ(test, 0, strncmp(defs[i].name,
						 AIRY_UEVENT_PREFIX,
						 strlen(AIRY_UEVENT_PREFIX)));

	out = obs_show(attrs, nr, "abi");
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_EXPECT_NOT_NULL(test, strstr(out, "events: 5"));

	out = obs_show(attrs, nr, "catalog");
	KUNIT_ASSERT_NOT_NULL(test, out);
	for (i = 0; i < n; i++)
		KUNIT_EXPECT_NOT_NULL(test, strstr(out, defs[i].name));
}

/* 一个格式串字段的期望布局，由结构体本身算出，避免手写数字。 */
struct uev_field {
	const char *name;
	unsigned int size;
	unsigned int off;
};

#define UE_FIELD(s, f)	{ #f, sizeof(((struct s *)0)->f), offsetof(struct s, f) }

static const struct uev_field cog_start_fields[] = {
	UE_FIELD(airy_user_cognition_start, agent_id),
	UE_FIELD(airy_user_cognition_start, input_tokens),
	UE_FIELD(airy_user_cognition_start, timestamp_ns),
};

static const struct uev_field cog_end_fields[] = {
	UE_FIELD(airy_user_cognition_end, agent_id),
	UE_FIELD(airy_user_cognition_end, output_tokens),
	UE_FIELD(airy_user_cognition_end, latency_ns),
};

static const struct uev_field mem_access_fields[] = {
	UE_FIELD(airy_user_memory_access, agent_id),
	UE_FIELD(airy_user_memory_access, level),
	UE_FIELD(airy_user_memory_access, hit),
	UE_FIELD(airy_user_memory_access, latency_ns),
	UE_FIELD(airy_user_memory_access, addr),
};

static const struct uev_field tool_call_fields[] = {
	UE_FIELD(airy_user_tool_call, agent_id),
	UE_FIELD(airy_user_tool_call, tool_id),
	UE_FIELD(airy_user_tool_call, latency_ns),
	UE_FIELD(airy_user_tool_call, result),
	UE_FIELD(airy_user_tool_call, output_tokens),
};

static const struct uev_field superv_fields[] = {
	UE_FIELD(airy_user_superv_enforce, agent_id),
	UE_FIELD(airy_user_superv_enforce, action),
	UE_FIELD(airy_user_superv_enforce, reason),
};

static unsigned int uev_size(const char *type, unsigned int len)
{
	if (len == 2 && !strncmp(type, "u8", 2))
		return 1;
	if (len == 3 && !strncmp(type, "u32", 3))
		return 4;
	if (len == 3 && !strncmp(type, "u64", 3))
		return 8;

	return 0;
}

/*
 * 逐 token 解析格式串，按自然对齐推字段偏移，与结构体布局比对。
 * user_events 接受任何格式串，字段错位只在读 trace 时才暴露，因此
 * 这层校验必须由内核侧测试承担。
 */
static void uev_layout(struct kunit *test, const char *fmt,
		       const struct uev_field *exp, unsigned int nr)
{
	const char *p = fmt;
	unsigned int i = 0;
	unsigned int off = 0;

	KUNIT_ASSERT_NOT_NULL(test, fmt);
	while (*p) {
		const char *type = p;
		const char *name;
		unsigned int sz;

		while (*p && *p != ' ')
			p++;
		sz = uev_size(type, p - type);
		KUNIT_ASSERT_GT(test, sz, 0U);

		while (*p == ' ')
			p++;
		name = p;
		while (*p && *p != ' ')
			p++;

		KUNIT_ASSERT_LT(test, i, nr);
		off = (off + sz - 1) & ~(sz - 1);
		KUNIT_EXPECT_EQ(test, sz, exp[i].size);
		KUNIT_EXPECT_EQ(test, off, exp[i].off);
		KUNIT_EXPECT_EQ(test, (unsigned int)(p - name),
				strlen(exp[i].name));
		KUNIT_EXPECT_EQ(test, 0,
				strncmp(name, exp[i].name, p - name));

		off += sz;
		i++;
		while (*p == ' ')
			p++;
	}
	KUNIT_EXPECT_EQ(test, nr, i);
}

static const char *uev_format(const struct airy_uevent_def *defs,
			      unsigned int nr, const char *name)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		if (!strcmp(defs[i].name, name))
			return defs[i].format;

	return NULL;
}

static void obs_uevent_layout(struct kunit *test)
{
	const struct airy_uevent_def *defs;
	unsigned int n;

	defs = airy_uevent_defs(&n);
	KUNIT_ASSERT_NOT_NULL(test, defs);

	uev_layout(test, uev_format(defs, n, AIRY_UEVENT_COGN_START),
		   cog_start_fields, ARRAY_SIZE(cog_start_fields));
	uev_layout(test, uev_format(defs, n, AIRY_UEVENT_COGN_END),
		   cog_end_fields, ARRAY_SIZE(cog_end_fields));
	uev_layout(test, uev_format(defs, n, AIRY_UEVENT_MEM_ACCESS),
		   mem_access_fields, ARRAY_SIZE(mem_access_fields));
	uev_layout(test, uev_format(defs, n, AIRY_UEVENT_TOOL_CALL),
		   tool_call_fields, ARRAY_SIZE(tool_call_fields));
	uev_layout(test, uev_format(defs, n, AIRY_UEVENT_SUPERV_ENFORCE),
		   superv_fields, ARRAY_SIZE(superv_fields));
}

static struct kunit_case airy_obs_cases[] = {
	KUNIT_CASE(obs_sec_table),
	KUNIT_CASE(obs_superv_table),
	KUNIT_CASE(obs_daemons_table),
	KUNIT_CASE(obs_uevent_table),
	KUNIT_CASE(obs_uevent_layout),
	KUNIT_CASE(obs_cap_fmt),
	KUNIT_CASE(obs_cap_fmt_short),
	KUNIT_CASE(obs_dir_guard),
	KUNIT_CASE(obs_fev_guard),
	{}
};

static struct kunit_suite airy_obs_suite = {
	.name = "airy_obs",
	.test_cases = airy_obs_cases,
};

kunit_test_suites(&airy_obs_suite);

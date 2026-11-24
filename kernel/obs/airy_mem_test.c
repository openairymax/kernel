// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_mem_test.c — 记忆计量的窗口、档位与占用契约测试。
 *
 * 计量记录不依赖设备与 procfs：用例把 struct mem_agent 放在栈上，
 * 直接驱动 airy_mem_apply() 与 airy_mem_set()。窗口滚动、档位边界、
 * 多级占用求和都能被确定性覆盖，不需要等待真实的 60 秒。
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/types.h>

#include <linux/airymax/mem.h>

#include "airy_mem.h"
#include "airy_obs.h"

#define MEM_T0	1000000000ULL

static void mem_ratio_edges(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0U, airy_obs_ppm(7, 0));
	KUNIT_EXPECT_EQ(test, 1000000U, airy_obs_ppm(9, 9));
	KUNIT_EXPECT_EQ(test, 1500000U, airy_obs_ppm(3, 2));
	KUNIT_EXPECT_EQ(test, U32_MAX, airy_obs_ppm(U64_MAX, 1));
}

static void mem_alert_edges(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, AIRY_MEM_NORMAL, airy_mem_alert(0, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_NORMAL, airy_mem_alert(799, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_SOFT, airy_mem_alert(800, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_SOFT, airy_mem_alert(949, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_DEGRADE, airy_mem_alert(950, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_DEGRADE, airy_mem_alert(999, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_EXCEED, airy_mem_alert(1000, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_EXCEED, airy_mem_alert(1500, 1000));
	KUNIT_EXPECT_EQ(test, AIRY_MEM_NORMAL, airy_mem_alert(500, 0));
}

static void mem_apply_delta(struct kunit *test)
{
	struct mem_agent a = { };
	struct airy_mem_delta d = {
		.agent_id = 7,
		.level = AIRY_MEM_L2,
		.access = 10,
		.hit = 6,
		.lat_sum_ns = 1000,
		.lat_max_ns = 400,
		.evict = 2,
		.fill_ns = 300,
		.page_in = 3,
		.page_out = 1,
	};

	a.win_start = MEM_T0;

	airy_mem_apply(&a, &d, MEM_T0 + 10);

	KUNIT_EXPECT_EQ(test, 10ULL, a.lv[AIRY_MEM_L2].access);
	KUNIT_EXPECT_EQ(test, 6ULL, a.lv[AIRY_MEM_L2].hit);
	KUNIT_EXPECT_EQ(test, 1000ULL, a.lv[AIRY_MEM_L2].lat_sum);
	KUNIT_EXPECT_EQ(test, 400ULL, a.lv[AIRY_MEM_L2].lat_max);
	KUNIT_EXPECT_EQ(test, 2ULL, a.lv[AIRY_MEM_L2].evict);
	KUNIT_EXPECT_EQ(test, 3ULL, a.lv[AIRY_MEM_L2].page_in);
	KUNIT_EXPECT_EQ(test, MEM_T0 + 10, a.updated);

	/* L1 不受影响：层号由上报方给出，内核不跨层复制。 */
	KUNIT_EXPECT_EQ(test, 0ULL, a.lv[AIRY_MEM_L1].access);
}

static void mem_window_roll(struct kunit *test)
{
	struct mem_agent a = { };
	struct airy_mem_delta d = {
		.level = AIRY_MEM_L3,
		.access = 1,
		.lat_max_ns = 900,
	};

	a.win_start = MEM_T0;

	airy_mem_apply(&a, &d, MEM_T0 + 1);
	KUNIT_EXPECT_EQ(test, 900ULL, a.lv[AIRY_MEM_L3].lat_max);

	/* 窗口内：最大值保留。 */
	d.lat_max_ns = 500;
	airy_mem_apply(&a, &d, MEM_T0 + AIRY_MEM_WINDOW_NS / 2);
	KUNIT_EXPECT_EQ(test, 900ULL, a.lv[AIRY_MEM_L3].lat_max);

	/* 窗口到期：只清窗口最大值，累计计数保持单调。 */
	d.lat_max_ns = 300;
	airy_mem_apply(&a, &d, MEM_T0 + AIRY_MEM_WINDOW_NS);
	KUNIT_EXPECT_EQ(test, 300ULL, a.lv[AIRY_MEM_L3].lat_max);
	KUNIT_EXPECT_EQ(test, 3ULL, a.lv[AIRY_MEM_L3].access);
}

static void mem_total_set(struct kunit *test)
{
	struct mem_agent a = { };
	struct airy_mem_gauge g = {
		.agent_id = 7,
		.level = AIRY_MEM_L1,
		.used_kb = 64,
	};

	KUNIT_EXPECT_EQ(test, 0ULL, airy_mem_total(&a));

	airy_mem_set(&a, &g);
	g.level = AIRY_MEM_L4;
	g.used_kb = 256;
	airy_mem_set(&a, &g);

	KUNIT_EXPECT_EQ(test, 320ULL, airy_mem_total(&a));

	/* 占用是绝对值：重新测量后允许下调。 */
	g.level = AIRY_MEM_L1;
	g.used_kb = 32;
	airy_mem_set(&a, &g);
	KUNIT_EXPECT_EQ(test, 288ULL, airy_mem_total(&a));
}

static void mem_bad_level(struct kunit *test)
{
	struct mem_agent a = { };
	struct airy_mem_delta d = { .level = 0, .access = 1 };
	struct airy_mem_gauge g = { .level = AIRY_MEM_LEVELS + 1,
				    .used_kb = 8 };

	airy_mem_apply(&a, &d, MEM_T0);
	KUNIT_EXPECT_EQ(test, 0ULL, a.lv[AIRY_MEM_L1].access);

	airy_mem_set(&a, &g);
	KUNIT_EXPECT_EQ(test, 0ULL, airy_mem_total(&a));
}

static struct kunit_case airy_mem_cases[] = {
	KUNIT_CASE(mem_ratio_edges),
	KUNIT_CASE(mem_alert_edges),
	KUNIT_CASE(mem_apply_delta),
	KUNIT_CASE(mem_window_roll),
	KUNIT_CASE(mem_total_set),
	KUNIT_CASE(mem_bad_level),
	{}
};

static struct kunit_suite airy_mem_suite = {
	.name = "airy_mem",
	.test_cases = airy_mem_cases,
};

kunit_test_suites(&airy_mem_suite);

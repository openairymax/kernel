// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_token_test.c — token 计量窗口与档位判定的契约测试。
 *
 * 计量记录不依赖设备与 procfs：用例把 struct tok_agent 放在栈上，
 * 直接驱动 airy_tok_add() 的时间轴。这样窗口进位、预算回绕和告警
 * 档位都能被确定性覆盖，不需要等待真实的 60 秒或 1 小时。
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/airymax/token.h>

#include "airy_token.h"

#define TOK_T0	1000000000ULL

static void tok_ratio_zero(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0U, airy_tok_ratio(7, 0));
	KUNIT_EXPECT_EQ(test, 0U, airy_tok_ratio(0, 9));
	KUNIT_EXPECT_EQ(test, 1000000U, airy_tok_ratio(9, 9));
}

static void tok_ratio_half(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 250000U, airy_tok_ratio(1, 4));
	KUNIT_EXPECT_EQ(test, 500000U, airy_tok_ratio(1, 2));
	KUNIT_EXPECT_EQ(test, 1500000U, airy_tok_ratio(3, 2));
}

static void tok_alert_edges(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_NORMAL, airy_tok_alert(0, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_NORMAL, airy_tok_alert(79, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_SOFT, airy_tok_alert(80, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_SOFT, airy_tok_alert(99, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_HARD, airy_tok_alert(100, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_HARD, airy_tok_alert(150, 100));
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_NORMAL, airy_tok_alert(5, 0));
}

static void tok_apply_delta(struct kunit *test)
{
	struct tok_agent a = { };
	struct airy_token_delta d = {
		.agent_id = 7,
		.input = 10,
		.output = 20,
		.cache_hit = 5,
		.reasoning = 15,
	};

	a.budget = 1000;
	a.win_start = TOK_T0;
	a.bstart = TOK_T0;

	airy_tok_add(&a, &d, TOK_T0 + 1000);

	KUNIT_EXPECT_EQ(test, 10ULL, a.input);
	KUNIT_EXPECT_EQ(test, 20ULL, a.output);
	KUNIT_EXPECT_EQ(test, 5ULL, a.cache_hit);
	KUNIT_EXPECT_EQ(test, 15ULL, a.reasoning);
	KUNIT_EXPECT_EQ(test, 50ULL, a.win_tokens);
	KUNIT_EXPECT_EQ(test, 50ULL, a.bused);
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_NORMAL, a.alert);
	KUNIT_EXPECT_EQ(test, TOK_T0 + 1000, a.updated);
}

static void tok_window_roll(struct kunit *test)
{
	struct tok_agent a = { };
	struct airy_token_delta d = { .input = 10 };

	a.budget = 1000;
	a.win_start = TOK_T0;
	a.bstart = TOK_T0;

	airy_tok_add(&a, &d, TOK_T0);
	KUNIT_EXPECT_EQ(test, 10ULL, a.win_tokens);
	KUNIT_EXPECT_EQ(test, 10ULL, a.bused);

	/* 窗口内累加：两个窗口都不回绕。 */
	d.input = 5;
	airy_tok_add(&a, &d, TOK_T0 + AIRY_TOKEN_WINDOW_NS / 2);
	KUNIT_EXPECT_EQ(test, 15ULL, a.win_tokens);
	KUNIT_EXPECT_EQ(test, 15ULL, a.bused);

	/* 预算窗口到期：已用量清零并重新开始累计。 */
	d.input = 7;
	airy_tok_add(&a, &d, TOK_T0 + AIRY_TOKEN_BUDGET_WINDOW_NS);
	KUNIT_EXPECT_EQ(test, 7ULL, a.win_tokens);
	KUNIT_EXPECT_EQ(test, 7ULL, a.bused);

	/* 预算满额后档位必须变成 HARD。 */
	a.budget = 7;
	KUNIT_EXPECT_EQ(test, AIRY_TOKEN_HARD, airy_tok_alert(a.bused, a.budget));
}

static struct kunit_case airy_token_cases[] = {
	KUNIT_CASE(tok_ratio_zero),
	KUNIT_CASE(tok_ratio_half),
	KUNIT_CASE(tok_alert_edges),
	KUNIT_CASE(tok_apply_delta),
	KUNIT_CASE(tok_window_roll),
	{}
};

static struct kunit_suite airy_token_suite = {
	.name = "airy_token",
	.test_cases = airy_token_cases,
};

kunit_test_suites(&airy_token_suite);

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_policy_test.c — KUnit coverage for the Airy policy runtime (B-06).
 *
 * The runtime is the only component that turns a compiled decision
 * table into a verdict, so these cases pin the whole contract from
 * SSoT 110-security/10-policy-compiler.md §10: the seven predicate
 * operators, conjunction, first-match order, default fallback, the four
 * verdict classes and their counters, pessimistic cross-table merge,
 * fault attribution, and every registration error path.  Each case
 * starts from an empty registry through airy_policy_reset(), so the
 * suite does not depend on which tables a board links in.
 *
 * All tables bind to uring_cmd, the hook no UML test can trigger by
 * accident: an inode or task event during the run therefore cannot
 * evaluate a test table behind the case's back.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/airymax/security_types.h>

#include <airymax/airy_policy.h>

#define POL_HOOK "uring_cmd"

static const char *const pol_op[] = { "op" };
static const char *const pol_op_flags[] = { "op", "cmd_flags" };
static const char *const pol_bad[] = { "bogus" };

static const struct airy_policy_cond pol_cond_op1[] = {
	{ .field = 0, .op = AIRY_CMP_EQ, .value = 1 },
};

static const struct airy_policy_cond pol_cond_op99[] = {
	{ .field = 0, .op = AIRY_CMP_EQ, .value = 99 },
};

static const struct airy_policy_cond pol_cond_pair[] = {
	{ .field = 0, .op = AIRY_CMP_EQ, .value = 1 },
	{ .field = 1, .op = AIRY_CMP_MASK, .value = 0x3 },
};

#define POL_ROW(_conds, _verdict, _fault)				\
	{								\
		.conds = (_conds),					\
		.cond_count = ARRAY_SIZE(_conds),			\
		.verdict = (_verdict),					\
		.fault = (_fault),					\
	}

#define POL_TBL(_name, _rows, _fields, _default)			\
	{								\
		.name = (_name),					\
		.hook = POL_HOOK,					\
		.rows = (_rows),					\
		.row_count = ARRAY_SIZE(_rows),				\
		.field_count = ARRAY_SIZE(_fields),			\
		.field_names = (_fields),				\
		.default_verdict = (_default),				\
	}

static const struct airy_policy_row pol_row_allow[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_ALLOW, 0),
};

static const struct airy_policy_row pol_row_deny[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_DENY, 0x11),
};

static const struct airy_policy_row pol_row_deny2[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_DENY, 0x22),
};

static const struct airy_policy_row pol_row_audit[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_AUDIT, 0),
};

static const struct airy_policy_row pol_row_complain[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_COMPLAIN, 0),
};

static const struct airy_policy_row pol_row_first[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_ALLOW, 0),
	POL_ROW(pol_cond_op1, AIRY_VERDICT_DENY, 0x33),
};

static const struct airy_policy_row pol_row_pair[] = {
	POL_ROW(pol_cond_pair, AIRY_VERDICT_DENY, 0),
};

static const struct airy_policy_row pol_row_never[] = {
	POL_ROW(pol_cond_op99, AIRY_VERDICT_DENY, 0),
};

static const struct airy_policy_row pol_row_bad_verdict[] = {
	POL_ROW(pol_cond_op1, AIRY_VERDICT_COMPLAIN + 1, 0),
};

static const struct airy_policy_table pol_allow =
	POL_TBL("t-allow", pol_row_allow, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_deny =
	POL_TBL("t-deny", pol_row_deny, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_deny2 =
	POL_TBL("t-deny2", pol_row_deny2, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_audit =
	POL_TBL("t-audit", pol_row_audit, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_complain =
	POL_TBL("t-complain", pol_row_complain, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_first =
	POL_TBL("t-first", pol_row_first, pol_op, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_pair =
	POL_TBL("t-pair", pol_row_pair, pol_op_flags, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_default =
	POL_TBL("t-default", pol_row_never, pol_op, AIRY_VERDICT_COMPLAIN);
static const struct airy_policy_table pol_bad_field =
	POL_TBL("t-bad-field", pol_row_allow, pol_bad, AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_bad_verdict =
	POL_TBL("t-bad-verdict", pol_row_bad_verdict, pol_op,
		AIRY_VERDICT_ALLOW);
static const struct airy_policy_table pol_bad_default =
	POL_TBL("t-bad-default", pol_row_allow, pol_op,
		AIRY_VERDICT_COMPLAIN + 1);
static const struct airy_policy_table pol_bad_hook = {
	.name = "t-bad-hook",
	.hook = "no_such_hook",
	.rows = pol_row_allow,
	.row_count = ARRAY_SIZE(pol_row_allow),
	.field_count = ARRAY_SIZE(pol_op),
	.field_names = pol_op,
	.default_verdict = AIRY_VERDICT_ALLOW,
};

static const char *const pol_full_names[AIRY_POLICY_MAX_TABLES + 1] = {
	"full-0",  "full-1",  "full-2",  "full-3",
	"full-4",  "full-5",  "full-6",  "full-7",
	"full-8",  "full-9",  "full-10", "full-11",
	"full-12", "full-13", "full-14", "full-15",
	"full-16",
};

static struct airy_policy_table pol_full[AIRY_POLICY_MAX_TABLES + 1];

static void policy_cmp(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(7, AIRY_CMP_EQ, 7));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(7, AIRY_CMP_EQ, 6));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(7, AIRY_CMP_NE, 6));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(7, AIRY_CMP_NE, 7));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(6, AIRY_CMP_LT, 7));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(7, AIRY_CMP_LT, 7));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(7, AIRY_CMP_LE, 7));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(8, AIRY_CMP_LE, 7));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(8, AIRY_CMP_GT, 7));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(7, AIRY_CMP_GT, 7));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(7, AIRY_CMP_GE, 7));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(6, AIRY_CMP_GE, 7));

	KUNIT_EXPECT_TRUE(test, airy_policy_cmp(0x7, AIRY_CMP_MASK, 0x3));
	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(0x5, AIRY_CMP_MASK, 0x3));

	KUNIT_EXPECT_FALSE(test, airy_policy_cmp(7, AIRY_CMP_MASK + 1, 7));
}

static void policy_match(struct kunit *test)
{
	static const struct airy_policy_row row = {
		.conds = pol_cond_pair,
		.cond_count = ARRAY_SIZE(pol_cond_pair),
		.verdict = AIRY_VERDICT_DENY,
	};
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1, 0x3 };

	KUNIT_EXPECT_TRUE(test, airy_policy_row_match(&row, fields));

	fields[0] = 2;
	KUNIT_EXPECT_FALSE(test, airy_policy_row_match(&row, fields));

	fields[0] = 1;
	fields[1] = 0x1;
	KUNIT_EXPECT_FALSE(test, airy_policy_row_match(&row, fields));

	fields[1] = 0x7;
	KUNIT_EXPECT_TRUE(test, airy_policy_row_match(&row, fields));
}

static void policy_first(struct kunit *test)
{
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0xdead;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_first));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0, fault);
}

static void policy_default(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0xdead;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_default));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0, fault);

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.evals);
	KUNIT_EXPECT_EQ(test, 1, cnt.complain);
}

static void policy_deny(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny));

	KUNIT_EXPECT_EQ(test, -EACCES,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0x11, fault);

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.evals);
	KUNIT_EXPECT_EQ(test, 1, cnt.deny);
	KUNIT_EXPECT_EQ(test, 1, cnt.fault);
}

static void policy_allow(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0xdead;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_allow));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0, fault);

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.allow);
	KUNIT_EXPECT_EQ(test, 0, cnt.fault);
}

static void policy_audit(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_audit));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.audit);
}

static void policy_complain(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_complain));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.complain);
}

static void policy_merge(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_allow));
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_complain));

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0, fault);

	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.allow);
	airy_pol_stat(1, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.complain);

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_audit));
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny));

	KUNIT_EXPECT_EQ(test, -EACCES,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny));
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_audit));

	KUNIT_EXPECT_EQ(test, -EACCES,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));
}

static void policy_fault(struct kunit *test)
{
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };
	u16 fault = 0;

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny));
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny2));

	KUNIT_EXPECT_EQ(test, -EACCES,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, &fault));
	KUNIT_EXPECT_EQ(test, 0x11, fault);
}

static void policy_field(struct kunit *test)
{
	airy_policy_reset();

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_policy_register(&pol_bad_field));
}

static void policy_hook(struct kunit *test)
{
	airy_policy_reset();

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_policy_register(&pol_bad_hook));
}

static void policy_verdict(struct kunit *test)
{
	airy_policy_reset();

	KUNIT_EXPECT_EQ(test, -EINVAL, airy_policy_register(&pol_bad_verdict));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_policy_register(&pol_bad_default));
}

static void policy_dup(struct kunit *test)
{
	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_allow));

	KUNIT_EXPECT_EQ(test, -EEXIST, airy_policy_register(&pol_allow));
}

static void policy_full(struct kunit *test)
{
	unsigned int i;

	airy_policy_reset();

	for (i = 0; i < ARRAY_SIZE(pol_full); i++) {
		pol_full[i].name = pol_full_names[i];
		pol_full[i].hook = POL_HOOK;
		pol_full[i].rows = pol_row_allow;
		pol_full[i].row_count = ARRAY_SIZE(pol_row_allow);
		pol_full[i].field_count = ARRAY_SIZE(pol_op);
		pol_full[i].field_names = pol_op;
		pol_full[i].default_verdict = AIRY_VERDICT_ALLOW;
	}

	for (i = 0; i < AIRY_POLICY_MAX_TABLES; i++)
		KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_full[i]));

	KUNIT_EXPECT_EQ(test, -ENOSPC,
			airy_policy_register(&pol_full[AIRY_POLICY_MAX_TABLES]));
}

static void policy_reset(struct kunit *test)
{
	struct airy_pol_cnt cnt;
	u64 fields[AIRY_POLICY_MAX_FIELDS] = { 1 };

	airy_policy_reset();
	KUNIT_ASSERT_EQ(test, 0, airy_policy_register(&pol_deny));

	KUNIT_EXPECT_EQ(test, -EACCES,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));
	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 1, cnt.evals);

	airy_policy_reset();
	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 0, cnt.evals);
	KUNIT_EXPECT_EQ(test, 0, cnt.deny);

	KUNIT_EXPECT_EQ(test, 0,
			airy_policy_check(AIRY_POLICY_HOOK_URING_CMD,
					  fields, NULL));
	airy_pol_stat(0, &cnt);
	KUNIT_EXPECT_EQ(test, 0, cnt.evals);
}

static struct kunit_case airy_policy_cases[] = {
	KUNIT_CASE(policy_cmp),
	KUNIT_CASE(policy_match),
	KUNIT_CASE(policy_first),
	KUNIT_CASE(policy_default),
	KUNIT_CASE(policy_deny),
	KUNIT_CASE(policy_allow),
	KUNIT_CASE(policy_audit),
	KUNIT_CASE(policy_complain),
	KUNIT_CASE(policy_merge),
	KUNIT_CASE(policy_fault),
	KUNIT_CASE(policy_field),
	KUNIT_CASE(policy_hook),
	KUNIT_CASE(policy_verdict),
	KUNIT_CASE(policy_dup),
	KUNIT_CASE(policy_full),
	KUNIT_CASE(policy_reset),
	{}
};

static struct kunit_suite airy_policy_suite = {
	.name = "airy_policy",
	.test_cases = airy_policy_cases,
};

kunit_test_suites(&airy_policy_suite);

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_policy.h — the airy policy decision table mechanism.
 *
 * A policy is data, not code: tools/dsl/ compiles an .adl source into
 * constant struct airy_policy_table arrays, and airy_policy.c only
 * registers tables, remaps hook field vectors and evaluates the first
 * matching row.  Verdict constants come from the shared contract in
 * <linux/airymax/security_types.h>.
 *
 * SSoT: 110-security/10-policy-compiler.md §4-§7.
 */

#ifndef _AIRY_POLICY_H
#define _AIRY_POLICY_H

#include <linux/kconfig.h>
#include <linux/types.h>

/* Hooks a table may bind to. The order is the runtime dispatch order. */
enum airy_policy_hook {
	AIRY_POLICY_HOOK_URING_CMD = 0,
	AIRY_POLICY_HOOK_TASK_ALLOC,
	AIRY_POLICY_HOOK_TASK_FREE,
	AIRY_POLICY_HOOK_TASK_KILL,
	AIRY_POLICY_HOOK_FILE_OPEN,
	AIRY_POLICY_HOOK_INODE_ALLOC,
	AIRY_POLICY_HOOK_INODE_FREE,
	AIRY_POLICY_HOOK_MAX
};

/* Registration slots and per-table field ceiling. */
#define AIRY_POLICY_MAX_TABLES	16
#define AIRY_POLICY_MAX_FIELDS	8

#ifndef AIRY_POLICY_MECHANISM_DEFINED
#define AIRY_POLICY_MECHANISM_DEFINED

/* Condition comparison operators; codes match dsl_types.CompareOp. */
enum airy_policy_cmp_op {
	AIRY_CMP_EQ = 0,
	AIRY_CMP_NE,
	AIRY_CMP_LT,
	AIRY_CMP_LE,
	AIRY_CMP_GT,
	AIRY_CMP_GE,
	AIRY_CMP_MASK,
};

/* One predicate: fields[field] op value. */
struct airy_policy_cond {
	u8 field;	/* table-local index, 0 .. field_count - 1 */
	u8 op;		/* enum airy_policy_cmp_op */
	u64 value;
};

/* One decision row: the conjunction of its predicates picks the row. */
struct airy_policy_row {
	const struct airy_policy_cond *conds;
	u16 cond_count;
	u8 verdict;	/* enum airy_verdict */
	u16 fault;	/* AIRY_FAULT_* or 0 */
};

/* A decision table bound to exactly one hook. */
struct airy_policy_table {
	const char *name;
	const char *hook;
	const struct airy_policy_row *rows;
	u16 row_count;
	u8 field_count;
	const char *const *field_names;
	u8 default_verdict;	/* enum airy_verdict */
};

/* Evaluate one predicate; MASK means every bit of value is set in lhs. */
static inline bool airy_policy_cmp(u64 lhs, u8 op, u64 rhs)
{
	switch (op) {
	case AIRY_CMP_EQ:
		return lhs == rhs;
	case AIRY_CMP_NE:
		return lhs != rhs;
	case AIRY_CMP_LT:
		return lhs < rhs;
	case AIRY_CMP_LE:
		return lhs <= rhs;
	case AIRY_CMP_GT:
		return lhs > rhs;
	case AIRY_CMP_GE:
		return lhs >= rhs;
	case AIRY_CMP_MASK:
		return (lhs & rhs) == rhs;
	default:
		return false;
	}
}

/* True when every predicate of @row holds against @fields. */
static inline bool airy_policy_row_match(const struct airy_policy_row *row,
					 const u64 *fields)
{
	u16 i;

	for (i = 0; i < row->cond_count; i++) {
		const struct airy_policy_cond *cond = &row->conds[i];

		if (!airy_policy_cmp(fields[cond->field], cond->op, cond->value))
			return false;
	}

	return true;
}

#endif /* AIRY_POLICY_MECHANISM_DEFINED */

#if IS_ENABLED(CONFIG_SECURITY_AIRY)

/**
 * airy_policy_register - publish a compiled decision table
 * @table: read-only table, immutable after this call
 *
 * Registration happens during LSM initialisation, once per table. Every
 * structural and naming check runs here; the evaluation path trusts the
 * stored data. Registration order is the evaluation order for tables on
 * the same hook.
 *
 * Return: 0 on success, -EINVAL on a malformed table or unknown hook or
 *         field name, -EEXIST when the name is taken, -ENOSPC when all
 *         AIRY_POLICY_MAX_TABLES slots are in use.
 */
__must_check int airy_policy_register(const struct airy_policy_table *table);

/**
 * airy_policy_check - evaluate the policy for one hook invocation
 * @hook: hook whose tables are evaluated
 * @fields: hook field vector, AIRY_POLICY_MAX_FIELDS entries
 * @fault: receives the winning row's fault code, or 0
 *
 * Tables are merged pessimistically (DENY > COMPLAIN > AUDIT > ALLOW),
 * so no table can widen another table's refusal. Observation hooks
 * (task_free, inode_free_security) cannot be blocked and ignore the
 * return value; they still record the verdict.
 *
 * Return: 0 to let the operation proceed, -EACCES on a DENY verdict.
 */
int airy_policy_check(enum airy_policy_hook hook, const u64 *fields,
		      u16 *fault);

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
/**
 * struct airy_pol_cnt - counter snapshot of one registered table
 *
 * Field meaning matches the securityfs row: @evals counts evaluations,
 * the four verdict fields count the winning class and @fault counts
 * winners that carried a non-zero fault code.
 */
struct airy_pol_cnt {
	u64 evals;
	u64 allow;
	u64 deny;
	u64 audit;
	u64 complain;
	u64 fault;
};

/**
 * airy_policy_reset - drop every registration and zero all counters
 *
 * Test-only: a KUnit suite has to start each case from an empty registry.
 */
void airy_policy_reset(void);

/**
 * airy_pol_stat - snapshot one table's counters
 * @slot: registration slot, 0 .. AIRY_POLICY_MAX_TABLES - 1
 * @out: receives the snapshot, untouched when @slot is out of range
 *
 * Test-only companion of airy_policy_reset(); production builds expose
 * the same numbers through /sys/kernel/security/airy/policy.
 */
void airy_pol_stat(u8 slot, struct airy_pol_cnt *out);
#endif

#else /* !CONFIG_SECURITY_AIRY */

static inline int
airy_policy_register(const struct airy_policy_table *table)
{
	return 0;
}

static inline int airy_policy_check(enum airy_policy_hook hook,
				    const u64 *fields, u16 *fault)
{
	return 0;
}

#endif /* CONFIG_SECURITY_AIRY */

#endif /* _AIRY_POLICY_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_policy.c — the Airy policy decision table runtime.
 *
 * Registers compiled tables, maps field names onto the hook field
 * vector, evaluates the first matching row and merges verdicts
 * pessimistically.  Two registration paths share one registry: the
 * boot path registers const tables compiled from .adl sources, and
 * the securityfs write path adds `rule <hook> <field>=<value>
 * <allow|deny>` predicates at runtime.
 *
 * SSoT: 110-security/10-policy-compiler.md §5-§9.
 */

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/security_types.h>
#include <airymax/airy_policy.h>

#include "airy_fs.h"

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

/* Field contract: names a table may use, mapped to hook vector slots. */
struct airy_pol_field {
	const char *name;
	u8 index;
};

static const struct airy_pol_field
airy_pol_fields[AIRY_POLICY_HOOK_MAX][AIRY_POLICY_MAX_FIELDS] = {
	[AIRY_POLICY_HOOK_URING_CMD] = {
		{ "op", 0 },
		{ "cmd_flags", 1 },
		{ "agent_id", 2 },
	},
	[AIRY_POLICY_HOOK_TASK_ALLOC] = {
		{ "clone_flags", 0 },
		{ "task_type", 1 },
		{ "agent_id", 2 },
	},
	[AIRY_POLICY_HOOK_TASK_FREE] = {
		{ "agent_id", 0 },
		{ "agent_state", 1 },
	},
	[AIRY_POLICY_HOOK_TASK_KILL] = {
		{ "sig", 0 },
		{ "target_agent", 1 },
		{ "target_state", 2 },
		{ "caller_agent", 3 },
	},
	[AIRY_POLICY_HOOK_FILE_OPEN] = {
		{ "open_flags", 0 },
		{ "acc_mode", 1 },
		{ "agent_id", 2 },
	},
	[AIRY_POLICY_HOOK_INODE_ALLOC] = {
		{ "inode_type", 0 },
	},
	[AIRY_POLICY_HOOK_INODE_FREE] = {
		{ "inode_type", 0 },
	},
};

static const char *const airy_pol_hooks[AIRY_POLICY_HOOK_MAX] = {
	[AIRY_POLICY_HOOK_URING_CMD]	= "uring_cmd",
	[AIRY_POLICY_HOOK_TASK_ALLOC]	= "task_alloc",
	[AIRY_POLICY_HOOK_TASK_FREE]	= "task_free",
	[AIRY_POLICY_HOOK_TASK_KILL]	= "task_kill",
	[AIRY_POLICY_HOOK_FILE_OPEN]	= "file_open",
	[AIRY_POLICY_HOOK_INODE_ALLOC]	= "inode_alloc_security",
	[AIRY_POLICY_HOOK_INODE_FREE]	= "inode_free_security",
};

/* Runtime counters kept apart from the immutable table. */
struct airy_pol_acc {
	atomic64_t evals;
	atomic64_t allow;
	atomic64_t deny;
	atomic64_t audit;
	atomic64_t complain;
	atomic64_t fault;
};

struct airy_pol_slot {
	const struct airy_policy_table *table;
	u8 hook;
	u8 field_map[AIRY_POLICY_MAX_FIELDS];
	struct airy_pol_acc acc;
};

static struct airy_pol_slot airy_pol_slots[AIRY_POLICY_MAX_TABLES];
static unsigned int airy_pol_count;
static DEFINE_MUTEX(airy_pol_lock);

/* Strictness order used when merging tables: DENY > COMPLAIN > AUDIT > ALLOW. */
static u8 pol_rank(u8 verdict)
{
	switch (verdict) {
	case AIRY_VERDICT_DENY:
		return 3;
	case AIRY_VERDICT_COMPLAIN:
		return 2;
	case AIRY_VERDICT_AUDIT:
		return 1;
	default:
		return 0;
	}
}

static int pol_hook_of(const char *name, u8 *hook)
{
	u8 i;

	for (i = 0; i < AIRY_POLICY_HOOK_MAX; i++) {
		if (!strcmp(name, airy_pol_hooks[i])) {
			*hook = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int pol_field_of(u8 hook, const char *name, u8 *index)
{
	const struct airy_pol_field *field = airy_pol_fields[hook];

	for (; field->name; field++) {
		if (!strcmp(field->name, name)) {
			*index = field->index;
			return 0;
		}
	}

	return -EINVAL;
}

static int pol_row_ok(const struct airy_policy_row *row, u8 field_count)
{
	u16 i;

	if (row->cond_count && !row->conds)
		return -EINVAL;
	if (row->verdict > AIRY_VERDICT_COMPLAIN)
		return -EINVAL;

	for (i = 0; i < row->cond_count; i++) {
		if (row->conds[i].field >= field_count ||
		    row->conds[i].op > AIRY_CMP_MASK)
			return -EINVAL;
	}

	return 0;
}

static int pol_meta_ok(const struct airy_policy_table *table)
{
	u16 row;
	u8 i;

	if (!table || !table->name || !table->name[0] ||
	    !table->hook || !table->hook[0] ||
	    !table->rows || !table->field_names)
		return -EINVAL;
	if (!table->field_count ||
	    table->field_count > AIRY_POLICY_MAX_FIELDS)
		return -EINVAL;
	if (!table->row_count)
		return -EINVAL;
	if (table->default_verdict > AIRY_VERDICT_COMPLAIN)
		return -EINVAL;

	for (i = 0; i < table->field_count; i++)
		if (!table->field_names[i])
			return -EINVAL;

	for (row = 0; row < table->row_count; row++)
		if (pol_row_ok(&table->rows[row], table->field_count))
			return -EINVAL;

	return 0;
}

static int pol_map(u8 hook, const struct airy_policy_table *table, u8 *map)
{
	u8 i, j;
	int rc;

	for (i = 0; i < table->field_count; i++) {
		rc = pol_field_of(hook, table->field_names[i], &map[i]);
		if (rc)
			return rc;
		for (j = 0; j < i; j++)
			if (map[j] == map[i])
				return -EINVAL;
	}

	return 0;
}

static u8 pol_eval(const struct airy_pol_slot *slot, const u64 *fields,
		   u16 *fault)
{
	const struct airy_policy_table *table = slot->table;
	u64 local[AIRY_POLICY_MAX_FIELDS];
	u16 row;
	u8 i;

	for (i = 0; i < table->field_count; i++)
		local[i] = fields[slot->field_map[i]];

	for (row = 0; row < table->row_count; row++) {
		const struct airy_policy_row *rule = &table->rows[row];

		if (airy_policy_row_match(rule, local)) {
			*fault = rule->fault;
			return rule->verdict;
		}
	}

	*fault = 0;
	return table->default_verdict;
}

static void pol_note(struct airy_pol_slot *slot, u8 verdict, u16 fault)
{
	atomic64_inc(&slot->acc.evals);

	switch (verdict) {
	case AIRY_VERDICT_DENY:
		atomic64_inc(&slot->acc.deny);
		break;
	case AIRY_VERDICT_AUDIT:
		atomic64_inc(&slot->acc.audit);
		break;
	case AIRY_VERDICT_COMPLAIN:
		atomic64_inc(&slot->acc.complain);
		break;
	default:
		atomic64_inc(&slot->acc.allow);
		break;
	}

	if (fault)
		atomic64_inc(&slot->acc.fault);
}

static void pol_trace(unsigned int slot, u8 hook, u8 verdict, u16 fault)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	if (verdict != AIRY_VERDICT_ALLOW || fault)
		trace_airy_policy_decision(hook, slot, verdict, fault);
#endif
}

/**
 * airy_policy_register - publish a compiled decision table
 * @table: read-only table, immutable after this call
 *
 * Return: 0 on success, or a negative error code as documented in the
 *         header and SSoT §7.
 */
int airy_policy_register(const struct airy_policy_table *table)
{
	u8 map[AIRY_POLICY_MAX_FIELDS];
	u8 hook;
	unsigned int i, count;
	int rc;

	rc = pol_meta_ok(table);
	if (rc)
		return rc;

	rc = pol_hook_of(table->hook, &hook);
	if (rc)
		return rc;

	rc = pol_map(hook, table, map);
	if (rc)
		return rc;

	mutex_lock(&airy_pol_lock);

	count = airy_pol_count;
	if (count == AIRY_POLICY_MAX_TABLES) {
		rc = -ENOSPC;
		goto out;
	}

	for (i = 0; i < count; i++) {
		if (!strcmp(airy_pol_slots[i].table->name, table->name)) {
			rc = -EEXIST;
			goto out;
		}
	}

	airy_pol_slots[count].table = table;
	airy_pol_slots[count].hook = hook;
	memcpy(airy_pol_slots[count].field_map, map, table->field_count);
	/* Publish the fully initialised slot to lockless readers. */
	smp_store_release(&airy_pol_count, count + 1);

out:
	mutex_unlock(&airy_pol_lock);
	return rc;
}

/**
 * airy_policy_check - evaluate the policy for one hook invocation
 * @hook: hook whose tables are evaluated
 * @fields: hook field vector, AIRY_POLICY_MAX_FIELDS entries
 * @fault: receives the winning row's fault code, or 0
 *
 * Return: 0 to proceed, -EACCES on a DENY verdict, -EINVAL on a caller
 *         bug (invalid hook or missing field vector).
 */
int airy_policy_check(enum airy_policy_hook hook, const u64 *fields,
		      u16 *fault)
{
	unsigned int i, count;
	u8 verdict = AIRY_VERDICT_ALLOW;
	u8 rank = 0;
	u16 best = 0;

	if (WARN_ON_ONCE(hook >= AIRY_POLICY_HOOK_MAX || !fields))
		return -EINVAL;

	if (fault)
		*fault = 0;

	/* Pair with the release store in airy_policy_register(). */
	count = smp_load_acquire(&airy_pol_count);
	for (i = 0; i < count; i++) {
		struct airy_pol_slot *slot = &airy_pol_slots[i];
		u8 row_rank;
		u16 row_fault;
		u8 row_verdict;

		if (slot->hook != hook)
			continue;

		row_verdict = pol_eval(slot, fields, &row_fault);
		pol_note(slot, row_verdict, row_fault);
		pol_trace(i, hook, row_verdict, row_fault);

		row_rank = pol_rank(row_verdict);
		if (row_rank > rank) {
			rank = row_rank;
			verdict = row_verdict;
			best = row_fault;
		} else if (row_rank == rank && row_rank && !best) {
			best = row_fault;
		}
	}

	if (fault)
		*fault = best;

	return verdict == AIRY_VERDICT_DENY ? -EACCES : 0;
}

static int pol_show(struct seq_file *m, void *unused)
{
	unsigned int i, count;
	u64 evals, allow, deny, audit, complain, fault;

	seq_puts(m, "# name hook rows evals allow deny audit complain fault\n");

	/* Pair with the release store in airy_policy_register(). */
	count = smp_load_acquire(&airy_pol_count);
	for (i = 0; i < count; i++) {
		const struct airy_pol_slot *slot = &airy_pol_slots[i];

		evals = atomic64_read(&slot->acc.evals);
		allow = atomic64_read(&slot->acc.allow);
		deny = atomic64_read(&slot->acc.deny);
		audit = atomic64_read(&slot->acc.audit);
		complain = atomic64_read(&slot->acc.complain);
		fault = atomic64_read(&slot->acc.fault);

		seq_printf(m, "%s %s %u %llu %llu %llu %llu %llu %llu\n",
			   slot->table->name, slot->table->hook,
			   slot->table->row_count,
			   (unsigned long long)evals,
			   (unsigned long long)allow,
			   (unsigned long long)deny,
			   (unsigned long long)audit,
			   (unsigned long long)complain,
			   (unsigned long long)fault);
	}

	return 0;
}

static int pol_open(struct inode *inode, struct file *file)
{
	return single_open(file, pol_show, NULL);
}

/*
 * Runtime rule intake
 *
 * One line installs one table with a single row and a single predicate:
 *
 *	rule <hook> <field>=<value> <allow|deny>
 *
 * Every line is parsed and validated before any table is registered, so a
 * multi-line write installs all of its rules or none. The table and its
 * row, predicate, name and field name live in one allocation; the
 * registry keeps the pointer and evaluation is lock-free, so a registered
 * table is never freed and is immutable for the life of the kernel.
 *
 * Names carry a monotonic suffix, so a batch can never collide with a
 * compiled table name or with a previous write.
 */
#define POL_CLI_LINES	8
#define POL_CLI_NAME	24
#define POL_CLI_FIELD	24

struct airy_pol_cli {
	struct airy_policy_table table;
	struct airy_policy_row row;
	struct airy_policy_cond cond;
	const char *field_names[1];
	char name[POL_CLI_NAME];
	char field[POL_CLI_FIELD];
};

/* Serialises intake: capacity and name allocation are decided under it. */
static DEFINE_MUTEX(airy_pol_write_lock);
static atomic_t airy_pol_seq = ATOMIC_INIT(0);

static char *pol_tok(char **cursor)
{
	char *p = *cursor;
	char *tok;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p)
		return NULL;
	tok = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;
	if (*p)
		*p++ = '\0';
	*cursor = p;

	return tok;
}

static int pol_verdict(const char *word, u8 *verdict)
{
	if (!strcmp(word, "allow")) {
		*verdict = AIRY_VERDICT_ALLOW;
		return 0;
	}
	if (!strcmp(word, "deny")) {
		*verdict = AIRY_VERDICT_DENY;
		return 0;
	}

	return -EINVAL;
}

static int pol_cli_parse(char *line, struct airy_pol_cli *cli)
{
	char *cursor = line;
	char *word, *eq;
	u8 hook, slot;
	u64 value;
	int rc;

	word = pol_tok(&cursor);
	if (!word || strcmp(word, "rule"))
		return -EINVAL;

	word = pol_tok(&cursor);
	if (!word)
		return -EINVAL;
	rc = pol_hook_of(word, &hook);
	if (rc)
		return rc;

	word = pol_tok(&cursor);
	if (!word)
		return -EINVAL;
	eq = strchr(word, '=');
	if (!eq || eq == word || !eq[1])
		return -EINVAL;
	*eq = '\0';
	rc = pol_field_of(hook, word, &slot);
	if (rc)
		return rc;
	rc = kstrtoull(eq + 1, 0, &value);
	if (rc)
		return -EINVAL;
	rc = strscpy(cli->field, word, sizeof(cli->field));
	if (rc < 0)
		return -EINVAL;

	word = pol_tok(&cursor);
	if (!word || pol_tok(&cursor))
		return -EINVAL;

	cli->cond.field = 0;
	cli->cond.op = AIRY_CMP_EQ;
	cli->cond.value = value;
	cli->row.conds = &cli->cond;
	cli->row.cond_count = 1;
	cli->row.fault = 0;
	rc = pol_verdict(word, &cli->row.verdict);
	if (rc)
		return rc;

	cli->table.name = cli->name;
	cli->table.hook = airy_pol_hooks[hook];
	cli->table.rows = &cli->row;
	cli->table.row_count = 1;
	cli->table.field_count = 1;
	cli->table.field_names = cli->field_names;
	cli->table.default_verdict = AIRY_VERDICT_ALLOW;
	cli->field_names[0] = cli->field;

	return 0;
}

static int pol_cli_check(const struct airy_pol_cli *cli)
{
	u8 hook, map[AIRY_POLICY_MAX_FIELDS];
	int rc;

	rc = pol_meta_ok(&cli->table);
	if (rc)
		return rc;
	rc = pol_hook_of(cli->table.hook, &hook);
	if (rc)
		return rc;

	return pol_map(hook, &cli->table, map);
}

static ssize_t pol_write(struct file *file, const char __user *ubuf,
			 size_t len, loff_t *ppos)
{
	struct airy_pol_cli *batch[POL_CLI_LINES];
	struct airy_pol_cli *cli;
	unsigned int i, n = 0, committed = 0;
	unsigned int count;
	char *buf, *line, *cursor;
	ssize_t ret = len;
	int rc;

	if (!len)
		return 0;
	if (len > PAGE_SIZE)
		return -EINVAL;

	buf = memdup_user_nul(ubuf, len);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	mutex_lock(&airy_pol_write_lock);

	cursor = buf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		line = strim(line);
		if (!*line)
			continue;
		if (n == POL_CLI_LINES) {
			ret = -E2BIG;
			goto out;
		}
		batch[n] = kzalloc(sizeof(*batch[n]), GFP_KERNEL);
		if (!batch[n]) {
			ret = -ENOMEM;
			goto out;
		}
		cli = batch[n++];
		snprintf(cli->name, sizeof(cli->name), "wire-%u",
			 atomic_inc_return(&airy_pol_seq));
		rc = pol_cli_parse(line, cli);
		if (!rc)
			rc = pol_cli_check(cli);
		if (rc) {
			ret = rc;
			goto out;
		}
	}

	if (!n) {
		ret = -EINVAL;
		goto out;
	}

	/* Pair with the release store in airy_policy_register(). */
	count = smp_load_acquire(&airy_pol_count);
	if (count + n > AIRY_POLICY_MAX_TABLES) {
		ret = -ENOSPC;
		goto out;
	}

	for (i = 0; i < n; i++) {
		rc = airy_policy_register(&batch[i]->table);
		if (unlikely(rc)) {
			ret = rc;
			committed = i;
			goto out;
		}
	}
	committed = n;

out:
	mutex_unlock(&airy_pol_write_lock);
	while (n > committed)
		kfree(batch[--n]);
	kfree(buf);

	return ret;
}

static const struct file_operations airy_pol_ops = {
	.open		= pol_open,
	.read		= seq_read,
	.write		= pol_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init airy_pol_fs(void)
{
	struct dentry *dir, *file;

	dir = airy_fs_dir();
	if (!dir)
		return 0;
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	file = securityfs_create_file("policy", 0600, dir, NULL,
				      &airy_pol_ops);
	if (IS_ERR(file))
		return PTR_ERR(file);

	return 0;
}

late_initcall(airy_pol_fs);

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
void airy_policy_reset(void)
{
	mutex_lock(&airy_pol_lock);
	/* Withdraw the slots before their storage is zeroed for the next case. */
	smp_store_release(&airy_pol_count, 0);
	memset(airy_pol_slots, 0, sizeof(airy_pol_slots));
	mutex_unlock(&airy_pol_lock);
}

void airy_pol_stat(u8 slot, struct airy_pol_cnt *out)
{
	if (!out || slot >= AIRY_POLICY_MAX_TABLES)
		return;

	out->evals = atomic64_read(&airy_pol_slots[slot].acc.evals);
	out->allow = atomic64_read(&airy_pol_slots[slot].acc.allow);
	out->deny = atomic64_read(&airy_pol_slots[slot].acc.deny);
	out->audit = atomic64_read(&airy_pol_slots[slot].acc.audit);
	out->complain = atomic64_read(&airy_pol_slots[slot].acc.complain);
	out->fault = atomic64_read(&airy_pol_slots[slot].acc.fault);
}
#endif

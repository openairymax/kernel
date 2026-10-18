// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lockdown.c — the Airymax lockdown ladder.
 *
 * Holds the monotonic level, the per-interface rule table, the
 * security_locked_down() provider, the boot parameter and the
 * root-only securityfs knob.  The level starts at the Kconfig default:
 * early_param handlers run after early LSM initialisation, so the boot
 * command line can only raise it further, never seed it.
 *
 * SSoT: 110-security/09-lockdown.md §3, §4, §5, §6, §7.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <airymax/airy_lockdown.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

/* Trace domains carried by airy_lockdown_reject. */
#define AIRY_LOCK_DOM_IFACE	0u
#define AIRY_LOCK_DOM_REASON	1u

struct airy_lock_rule {
	const char *name;
	u8 level;
};

/* Lowest level that closes each agent-facing interface. */
static const struct airy_lock_rule airy_lock_rules[AIRY_LOCK_IF_MAX] = {
	[AIRY_LOCK_IF_CAP_GRANT] = { .name = "cap-grant", .level = AIRY_LOCK_EARLY },
	[AIRY_LOCK_IF_ROVOL]	 = { .name = "rovol",	  .level = AIRY_LOCK_EARLY },
	[AIRY_LOCK_IF_SCHED]	 = { .name = "sched",	  .level = AIRY_LOCK_EARLY },
};

static const char *const airy_lock_names[AIRY_LOCK_MAX] = {
	[AIRY_LOCK_NONE]	= "none",
	[AIRY_LOCK_EARLY]	= "early",
	[AIRY_LOCK_LATE]	= "late",
	[AIRY_LOCK_FULL]	= "full",
};

static const char *const airy_lock_src[AIRY_LOCK_TRIGGER_MAX] = {
	[AIRY_LOCK_BY_CONFIG]	= "config",
	[AIRY_LOCK_BY_CMDLINE]	= "command line",
	[AIRY_LOCK_BY_SECFS]	= "securityfs",
};

/*
 * Lowest level that closes a kernel facility, indexed by
 * enum lockdown_reason.  A zero entry leaves the facility open at
 * every level.
 */
static const u8 airy_lock_reason[LOCKDOWN_CONFIDENTIALITY_MAX] = {
	[LOCKDOWN_MODULE_SIGNATURE]	= AIRY_LOCK_EARLY,
	[LOCKDOWN_DEV_MEM]		= AIRY_LOCK_EARLY,
	[LOCKDOWN_EFI_TEST]		= AIRY_LOCK_EARLY,
	[LOCKDOWN_KEXEC]		= AIRY_LOCK_EARLY,
	[LOCKDOWN_BPF_WRITE_USER]	= AIRY_LOCK_EARLY,
	[LOCKDOWN_MODULE_PARAMETERS]	= AIRY_LOCK_LATE,
	[LOCKDOWN_DEBUGFS]		= AIRY_LOCK_LATE,
	[LOCKDOWN_KCORE]		= AIRY_LOCK_LATE,
	[LOCKDOWN_KPROBES]		= AIRY_LOCK_LATE,
	[LOCKDOWN_BPF_READ_KERNEL]	= AIRY_LOCK_LATE,
	[LOCKDOWN_PERF]			= AIRY_LOCK_LATE,
	[LOCKDOWN_TRACEFS]		= AIRY_LOCK_LATE,
	[LOCKDOWN_HIBERNATION]		= AIRY_LOCK_FULL,
	[LOCKDOWN_PCI_ACCESS]		= AIRY_LOCK_FULL,
	[LOCKDOWN_IOPORT]		= AIRY_LOCK_FULL,
	[LOCKDOWN_MSR]			= AIRY_LOCK_FULL,
	[LOCKDOWN_ACPI_TABLES]		= AIRY_LOCK_FULL,
	[LOCKDOWN_DEVICE_TREE]		= AIRY_LOCK_FULL,
	[LOCKDOWN_PCMCIA_CIS]		= AIRY_LOCK_FULL,
	[LOCKDOWN_TIOCSSERIAL]		= AIRY_LOCK_FULL,
	[LOCKDOWN_MMIOTRACE]		= AIRY_LOCK_FULL,
	[LOCKDOWN_XMON_WR]		= AIRY_LOCK_FULL,
	[LOCKDOWN_DBG_WRITE_KERNEL]	= AIRY_LOCK_FULL,
	[LOCKDOWN_RTAS_ERROR_INJECTION]	= AIRY_LOCK_FULL,
	[LOCKDOWN_XEN_USER_ACTIONS]	= AIRY_LOCK_FULL,
	[LOCKDOWN_DBG_READ_KERNEL]	= AIRY_LOCK_FULL,
	[LOCKDOWN_XMON_RW]		= AIRY_LOCK_FULL,
	[LOCKDOWN_XFRM_SECRET]		= AIRY_LOCK_FULL,
};

static atomic_t airy_lock_level = ATOMIC_INIT(AIRY_LOCK_NONE);

static_assert(ARRAY_SIZE(airy_lock_rules) == AIRY_LOCK_IF_MAX);
static_assert(ARRAY_SIZE(airy_lock_names) == AIRY_LOCK_MAX);
static_assert(ARRAY_SIZE(airy_lock_src) == AIRY_LOCK_TRIGGER_MAX);

static void lock_trace_change(u32 prev, u32 level, u32 trigger)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_lockdown_change(prev, level, trigger);
#endif
}

static void lock_trace_reject(u32 domain, u32 id, u32 need, u32 cur)
{
#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_lockdown_reject(domain, id, need, cur);
#endif
}

u8 airy_lock_get(void)
{
	return atomic_read(&airy_lock_level);
}

/**
 * airy_lock_set - raise the ladder to at least @level
 * @level: requested level
 * @by: trigger recorded with the transition
 *
 * Return: 0 when the ladder already sits at @level or above and the
 *         request was applied or was a no-op at the same level;
 *         -EPERM when @level would lower the ladder or is out of range.
 */
int airy_lock_set(u8 level, enum airy_lock_trigger by)
{
	int cur;

	if (level >= AIRY_LOCK_MAX || by >= AIRY_LOCK_TRIGGER_MAX)
		return -EPERM;

	cur = atomic_read(&airy_lock_level);
	do {
		if (cur > level)
			return -EPERM;
		if (cur == level)
			return 0;
	} while (!atomic_try_cmpxchg(&airy_lock_level, &cur, level));

	pr_info("airy: lockdown raised to %s by %s\n",
		airy_lock_names[level], airy_lock_src[by]);
	lock_trace_change(cur, level, by);
	return 0;
}

__must_check int airy_lock_gate(enum airy_lock_iface iface)
{
	u8 need, cur;

	if (WARN_ON_ONCE(iface >= AIRY_LOCK_IF_MAX))
		return -AIRY_ELOCKDOWN;

	need = airy_lock_rules[iface].level;
	cur = airy_lock_get();
	if (cur < need)
		return 0;

	pr_info_ratelimited("airy: lockdown refuses %s at level %s\n",
			    airy_lock_rules[iface].name, airy_lock_names[cur]);
	lock_trace_reject(AIRY_LOCK_DOM_IFACE, iface, need, cur);
	return -AIRY_ELOCKDOWN;
}

int airy_lock_down(enum lockdown_reason what)
{
	u8 need, cur;

	if (WARN_ON_ONCE(what >= LOCKDOWN_CONFIDENTIALITY_MAX))
		return -EPERM;

	need = airy_lock_reason[what];
	if (!need)
		return 0;

	cur = airy_lock_get();
	if (cur < need)
		return 0;

	lock_trace_reject(AIRY_LOCK_DOM_REASON, what, need, cur);
	return -EPERM;
}

int airy_lock_arg(const char *s, u8 *level)
{
	u8 i;

	if (!s || !level)
		return -EINVAL;

	for (i = 0; i < AIRY_LOCK_MAX; i++) {
		if (!strcmp(s, airy_lock_names[i])) {
			*level = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int __init airy_lock_param(char *s)
{
	u8 level;
	int rc;

	rc = airy_lock_arg(s, &level);
	if (rc)
		return rc;

	return airy_lock_set(level, AIRY_LOCK_BY_CMDLINE);
}

early_param("airy.lockdown", airy_lock_param);

static ssize_t airy_lock_read(struct file *filp, char __user *buf,
			      size_t count, loff_t *ppos)
{
	char temp[16];
	int len;

	len = scnprintf(temp, sizeof(temp), "%s\n",
			airy_lock_names[airy_lock_get()]);
	return simple_read_from_buffer(buf, count, ppos, temp, len);
}

static ssize_t airy_lock_write(struct file *filp, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	char *state;
	size_t len;
	u8 level;
	int rc;

	state = memdup_user_nul(buf, count);
	if (IS_ERR(state))
		return PTR_ERR(state);

	len = strlen(state);
	if (len && state[len - 1] == '\n')
		state[len - 1] = '\0';

	rc = airy_lock_arg(state, &level);
	if (!rc)
		rc = airy_lock_set(level, AIRY_LOCK_BY_SECFS);

	kfree(state);
	return rc ? rc : count;
}

static const struct file_operations airy_lock_ops = {
	.read	= airy_lock_read,
	.write	= airy_lock_write,
};

static int __init airy_lock_fs(void)
{
	struct dentry *dir, *file;

	if (!IS_ENABLED(CONFIG_SECURITYFS))
		return 0;

	dir = securityfs_create_dir("airy", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	file = securityfs_create_file("lockdown", 0600, dir, NULL,
				      &airy_lock_ops);
	if (IS_ERR(file)) {
		securityfs_remove(dir);
		return PTR_ERR(file);
	}

	return 0;
}

/* late_initcall stays ahead of every userspace task and is immune to
 * the link order between security/inode.o and security/airy/.
 */
late_initcall(airy_lock_fs);

static struct security_hook_list airy_lock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(locked_down, airy_lock_down),
};

static int __init airy_lock_init(void)
{
	security_add_hooks(airy_lock_hooks, ARRAY_SIZE(airy_lock_hooks),
			   "airy_lockdown");
	return airy_lock_set(CONFIG_AIRY_LOCKDOWN_DEFAULT_LEVEL,
			     AIRY_LOCK_BY_CONFIG);
}

DEFINE_EARLY_LSM(airy_lockdown) = {
	.name = "airy_lockdown",
	.init = airy_lock_init,
};

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
void airy_lock_clr(void)
{
	atomic_set(&airy_lock_level, AIRY_LOCK_NONE);
}
#endif

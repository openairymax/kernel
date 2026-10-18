// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_cap_sysctl.c — Read-only capability table observation.
 *
 * airy_sys_capability_inspect() (syscall 598) was removed in favour of
 * procfs entries under kernel.airy (SSoT 110-security/03-capability-model
 * §5.3).  The entries expose the geometry that sec_d and agentrt need to
 * size their own structures, plus a live occupancy counter for watching
 * slot exhaustion.
 *
 * Every entry is mode 0444.  The table size is the UAPI constant
 * AIRY_CAP_MAX_AGENTS and the badge field widths are fixed by
 * <linux/airymax/ipc.h>, so there is nothing to tune at runtime: writes
 * are rejected instead of silently ignored.
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>

#include "airy_cap.h"
#include "airy_cap_sysctl.h"

#define AIRY_CAP_SYSCTL_DIR	"kernel/airy"

/* Width of the badge fields declared in <linux/airymax/ipc.h>. */
#define AIRY_CAP_EPOCH_BITS	(8U * sizeof(__u16))
#define AIRY_CAP_RANDTAG_BITS	(8U * sizeof(__u32))

/**
 * airy_cap_used - Count occupied capability slots.
 *
 * Walks the table bucket by bucket and holds each bucket's spinlock
 * while scanning its slots.  Register and derive guard the same locks,
 * so every badge read is consistent with respect to a single slot
 * without blocking the whole table for one observation.
 *
 * The result is a live estimate: a registration that lands after its
 * bucket was scanned is not counted.  That is acceptable for an
 * operator-facing counter, which no in-kernel decision consumes.
 *
 * Return: number of slots whose badge is not AIRY_CAP_NULL.
 */
unsigned int airy_cap_used(void)
{
	unsigned int used = 0;
	unsigned int bucket;

	for (bucket = 0; bucket < AIRY_CAP_BUCKET_NR; bucket++) {
		unsigned long flags;
		unsigned int agent;

		spin_lock_irqsave(&airy_cap_bucket_locks[bucket], flags);
		for (agent = bucket; agent < AIRY_CAP_MAX_AGENTS;
		     agent += AIRY_CAP_BUCKET_NR) {
			if (agent_caps[agent].badge != AIRY_CAP_NULL)
				used++;
		}
		spin_unlock_irqrestore(&airy_cap_bucket_locks[bucket],
				       flags);
	}

	return used;
}

#ifdef CONFIG_SYSCTL

static unsigned int airy_cap_max_agents = AIRY_CAP_MAX_AGENTS;
static unsigned int airy_cap_epoch_bits = AIRY_CAP_EPOCH_BITS;
static unsigned int airy_cap_randtag_bits = AIRY_CAP_RANDTAG_BITS;

/*
 * cap_used is computed per read, so hand proc_douintvec a stack-local
 * copy of the entry that points at the fresh value.  A shared global
 * scratch word would let concurrent readers observe each other's count.
 */
static int cap_used_proc(struct ctl_table *entry, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *entry;
	unsigned int used;

	if (write)
		return -EPERM;

	used = airy_cap_used();
	tmp.data = &used;
	tmp.maxlen = sizeof(used);

	return proc_douintvec(&tmp, 0, buffer, lenp, ppos);
}

static struct ctl_table airy_cap_table[] = {
	{
		.procname	= "cap_max_agents",
		.data		= &airy_cap_max_agents,
		.maxlen		= sizeof(airy_cap_max_agents),
		.mode		= 0444,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "cap_epoch_bits",
		.data		= &airy_cap_epoch_bits,
		.maxlen		= sizeof(airy_cap_epoch_bits),
		.mode		= 0444,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "cap_randtag_bits",
		.data		= &airy_cap_randtag_bits,
		.maxlen		= sizeof(airy_cap_randtag_bits),
		.mode		= 0444,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "cap_used",
		.maxlen		= sizeof(unsigned int),
		.mode		= 0444,
		.proc_handler	= cap_used_proc,
	},
	{ }
};

static struct ctl_table_header *airy_cap_hdr;

/**
 * airy_cap_sysctl_init - Publish the capability observation entries.
 *
 * Return: 0 on success or when already published; -ENOMEM when the
 * sysctl tree cannot be registered.
 */
int airy_cap_sysctl_init(void)
{
	if (airy_cap_hdr)
		return 0;

	airy_cap_hdr = register_sysctl(AIRY_CAP_SYSCTL_DIR, airy_cap_table);
	if (!airy_cap_hdr) {
		pr_err("airy: cannot register /proc/sys/%s\n",
		       AIRY_CAP_SYSCTL_DIR);
		return -ENOMEM;
	}

	pr_info("airy: capability table published under /proc/sys/%s\n",
		AIRY_CAP_SYSCTL_DIR);
	return 0;
}

/**
 * airy_cap_sysctl_exit - Withdraw the capability observation entries.
 *
 * Used by the KUnit suite; production kernels keep the entries for
 * their entire lifetime.
 */
void airy_cap_sysctl_exit(void)
{
	if (!airy_cap_hdr)
		return;

	unregister_sysctl_table(airy_cap_hdr);
	airy_cap_hdr = NULL;
}

#else /* !CONFIG_SYSCTL */

int airy_cap_sysctl_init(void)
{
	return 0;
}

void airy_cap_sysctl_exit(void)
{
}

#endif /* CONFIG_SYSCTL */

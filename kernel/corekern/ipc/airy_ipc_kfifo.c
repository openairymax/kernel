// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_kfifo.c — per-CPU lock-free kthread mailbox.
 *
 * Every possible CPU owns one single-producer/single-consumer kfifo of
 * 128-byte message headers.  The sending fastpath enqueues on its own
 * CPU only (C-S5), so the ring needs no lock; the owning kthread
 * dequeues and is woken through recv_wq.  Occupancy is sampled into
 * water_mark for the backpressure thresholds of docs 07-ipc-fastpath
 * §6.4.
 */

#include <linux/errno.h>
#include <linux/kfifo.h>
#include <linux/log2.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/airymax/error.h>
#include <linux/airymax/ipc.h>

#include "airy_ipc_internal.h"

DEFINE_PER_CPU(struct airy_ipc_stats, airy_ipc_stats_cpu);

static DEFINE_PER_CPU(struct airy_ipc_kfifo, airy_ipc_kfifo);

/* ─── Initialise one CPU mailbox ─────────────────── */
int airy_ipc_kfifo_init(struct airy_ipc_kfifo *kf, int cpu, u32 entries)
{
	int ret;

	if (!kf || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	/* kfifo_alloc() derives its mask from the entry count, so the
	 * capacity must be a power of two and stay inside the ceiling.
	 */
	if (!is_power_of_2(entries) || entries < 2 ||
	    entries > AIRY_IPC_KFIFO_MAX_ENTRIES)
		return -EINVAL;

	if (kfifo_initialized(&kf->fifo))
		return -EBUSY;

	ret = kfifo_alloc(&kf->fifo, entries, GFP_KERNEL);
	if (ret)
		return ret;

	init_waitqueue_head(&kf->recv_wq);
	kf->water_mark = 0;
	kf->home_cpu   = cpu;
	kf->stats      = &airy_ipc_stats_cpu;
	return 0;
}

/* ─── Release one CPU mailbox ────────────────── */
void airy_ipc_kfifo_exit(struct airy_ipc_kfifo *kf)
{
	if (!kf)
		return;

	kfifo_free(&kf->fifo);
	kf->water_mark = 0;
	kf->home_cpu   = AIRY_IPC_CPU_ANY;
	kf->stats      = NULL;
}

/* ─── Resolve a CPU's mailbox ────────────── */
struct airy_ipc_kfifo *airy_ipc_kfifo_cpu(int cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return NULL;

	return per_cpu_ptr(&airy_ipc_kfifo, cpu);
}

/* ─── Enqueue a header on the calling CPU's mailbox (C-S5/C-S6) ──────── */
int airy_ipc_kfifo_send(struct airy_ipc_kfifo *kf,
			const struct airy_ipc_msg_hdr *hdr)
{
	int ret = 0;

	if (!kf || !hdr || !kfifo_initialized(&kf->fifo))
		return -EINVAL;

	preempt_disable();

	/* C-S5: the mailbox is SPSC, so only its owner may produce. */
	if (kf->home_cpu != AIRY_IPC_CPU_ANY &&
	    smp_processor_id() != kf->home_cpu) {
		ret = -EAGAIN;
		goto out;
	}

	if (kfifo_in(&kf->fifo, hdr, 1) != 1) {
		this_cpu_inc(kf->stats->error_hit);
		ret = -AIRY_EIPC_KFIFO;	/* C-S6: mailbox full */
		goto out;
	}

	WRITE_ONCE(kf->water_mark, kfifo_len(&kf->fifo));
	this_cpu_inc(kf->stats->fast_send_hit);

	/* Publish the enqueued header before the consumer is woken. */
	smp_wmb();
out:
	preempt_enable();

	if (!ret)
		wake_up_interruptible(&kf->recv_wq);

	return ret;
}

/* ─── Dequeue a header from the calling CPU's mailbox (C-S5) ───────── */
int airy_ipc_kfifo_recv(struct airy_ipc_kfifo *kf,
			struct airy_ipc_msg_hdr *out)
{
	int ret = 0;

	if (!kf || !out || !kfifo_initialized(&kf->fifo))
		return -EINVAL;

	preempt_disable();

	/* C-S5: the mailbox consumer must run on the owning CPU. */
	if (kf->home_cpu != AIRY_IPC_CPU_ANY &&
	    smp_processor_id() != kf->home_cpu) {
		ret = -EAGAIN;
		goto out;
	}

	/* Pair with the producer's smp_wmb() before reading the slot. */
	smp_rmb();

	if (kfifo_out(&kf->fifo, out, 1) != 1) {
		ret = -ENOMSG;
		goto out;
	}

	WRITE_ONCE(kf->water_mark, kfifo_len(&kf->fifo));
	this_cpu_inc(kf->stats->fast_recv_hit);
out:
	preempt_enable();
	return ret;
}

/* ─── Sum the per-CPU counters into a caller buffer ──────────── */
void airy_ipc_stats_read(struct airy_ipc_stats *out)
{
	int cpu;

	if (!out)
		return;

	memset(out, 0, sizeof(*out));

	for_each_possible_cpu(cpu) {
		const struct airy_ipc_stats *st;

		st = per_cpu_ptr(&airy_ipc_stats_cpu, cpu);
		out->fast_send_hit     += READ_ONCE(st->fast_send_hit);
		out->fast_recv_hit     += READ_ONCE(st->fast_recv_hit);
		out->slow_send_hit     += READ_ONCE(st->slow_send_hit);
		out->slow_recv_hit     += READ_ONCE(st->slow_recv_hit);
		out->batch_hit         += READ_ONCE(st->batch_hit);
		out->cancel_hit        += READ_ONCE(st->cancel_hit);
		out->error_hit         += READ_ONCE(st->error_hit);
		out->backpressure_hit  += READ_ONCE(st->backpressure_hit);
	}
}

/* ─── Bring up one mailbox per possible CPU ─────────────── */
static int __init airy_ipc_kfifo_setup(void)
{
	u32 entries = roundup_pow_of_two(CONFIG_AIRY_IPC_KFIFO_SIZE);
	int cpu;

	for_each_possible_cpu(cpu) {
		struct airy_ipc_kfifo *kf;
		int ret;

		kf = per_cpu_ptr(&airy_ipc_kfifo, cpu);
		ret = airy_ipc_kfifo_init(kf, cpu, entries);
		if (ret)
			pr_err("airy_ipc_kfifo: cpu%u mailbox disabled: %d\n",
			       cpu, ret);
	}

	return 0;
}
subsys_initcall(airy_ipc_kfifo_setup);

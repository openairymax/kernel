// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_wdog.c — Macro-Supervisor liveness guard.
 *
 * macro_d is the only component allowed to adjudicate faults, so its
 * disappearance must not leave agents trading capabilities unsupervised.
 * The daemon sends the [IND] HEARTBEAT opcode and this file watches that
 * pulse, freezing every IPC ring and retiring every outstanding badge
 * when it stops.  The loss is then reported so user space can restart
 * the daemon; the kernel does not power the machine off, because the
 * daemon's service manager owns its lifecycle.
 *
 * The guard stays disarmed until the first pulse: a system that never
 * runs macro_d has no supervisor to lose, and arming at boot would freeze it.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §7.5
 */

#include <asm/barrier.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/printk.h>
#include <linux/time64.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <linux/airymax/error.h>
#include <airymax/airy_trace.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

#include "../../security/airy/airy_cap.h"
#include "../ipc/airy_ipc_capability.h"
#include "airy_superv.h"

static atomic64_t wdog_last;
static atomic_t wdog_latch = ATOMIC_INIT(0);
static bool wdog_armed;
static struct timer_list wdog_timer;
static struct work_struct wdog_work;

void airy_wdog_at(__u64 now_ns)
{
	atomic64_set(&wdog_last, now_ns);
	atomic_set(&wdog_latch, 0);
	smp_store_release(&wdog_armed, true);
}

void airy_wdog_beat(void)
{
	airy_wdog_at(ktime_get_mono_fast_ns());
}

bool airy_wdog_late(__u64 now_ns)
{
	__u64 last;

	if (!smp_load_acquire(&wdog_armed))
		return false;
	if (atomic_read(&wdog_latch))
		return false;

	last = atomic64_read(&wdog_last);

	return now_ns > last && now_ns - last > AIRY_WDOG_TMO_NS;
}

bool airy_wdog_fire(__u64 now_ns)
{
	if (!airy_wdog_late(now_ns))
		return false;

	if (atomic_cmpxchg(&wdog_latch, 0, 1))
		return false;

	pr_emerg("airy: macro_d silent for %us, containing the system\n",
		 AIRY_WDOG_TIMEOUT_SEC);

	airy_sv_frz_all(AIRY_FAULT_DOUBLE_FAULT);
	airy_cap_epoch_bump_all();

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_superv_enforce(0, AIRY_SUPERV_ACTION_FREEZE,
				  AIRY_FAULT_DOUBLE_FAULT);
#endif

	airy_eventfd_signal_fault(AIRY_FAULT_DOUBLE_FAULT, 0, now_ns);

	return true;
}

/*
 * wdog_take - contain a loss detected from the poll timer.
 * @work: the guard's work item; unused.
 *
 * Running from a work item keeps the containment out of softirq
 * context: freezing a ring set takes a mutex, which the timer callback
 * may not.
 */
static void wdog_take(struct work_struct *work)
{
	airy_wdog_fire(ktime_get_mono_fast_ns());
}

static void wdog_poll(struct timer_list *t)
{
	if (airy_wdog_late(ktime_get_mono_fast_ns()))
		schedule_work(&wdog_work);

	mod_timer(&wdog_timer, jiffies + AIRY_WDOG_POLL_SEC * HZ);
}

void airy_wdog_reset(void)
{
	smp_store_release(&wdog_armed, false);
	atomic_set(&wdog_latch, 0);
	atomic64_set(&wdog_last, 0);
	cancel_work_sync(&wdog_work);
}

void __init airy_wdog_init(void)
{
	INIT_WORK(&wdog_work, wdog_take);
	timer_setup(&wdog_timer, wdog_poll, 0);
	mod_timer(&wdog_timer, jiffies + AIRY_WDOG_POLL_SEC * HZ);
}

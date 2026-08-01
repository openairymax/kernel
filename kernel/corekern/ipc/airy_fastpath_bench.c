// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_fastpath_bench.c — KUnit micro-benchmark for the Airymax IPC fastpath.
 *
 * The v3.6 review flagged the ~10ns Badge check (C-S9, airy_cap_badge_ok())
 * and ~158ns fastpath (airy_ipc_fastpath_send() + airy_ipc_ring_post()) as
 * design estimates without measurement (08-closure-summary-v3.6.md L109,
 * 18-closure-summary-v3.6b.md L151).  This suite replaces those estimates
 * with real numbers collected under KUnit (UML or real hardware).
 *
 * Measured metrics (ktime_get_ns, warm-up then batched loop, mean/p50/p99):
 *   a) airy_cap_badge_ok() hit and miss latency          (C-S9 inline)
 *   b) airy_ipc_fastpath_send() full-path latency        (frozen gate + post)
 *   c) airy_ipc_ring_post() / airy_ipc_ring_consume()    (SPSC mem-order cost)
 *   d) simulated 5-phase slowpath                        (phase1/4/5 of
 *      airy_uring_cmd_check(), no io_uring_cmd needed)
 *
 * Methodology:
 *   - Samples are batched (BATCH ops per ktime_get_ns() pair) so the timer
 *     call overhead is amortised well below 1 ns/op resolution.
 *   - mean comes from the batched per-op distribution; p50/p99 use
 *     quickselect (no full sort).  bulk is a single whole-loop timing and
 *     carries no per-batch timer overhead at all.
 *   - An identical empty-loop baseline is measured per metric; the net
 *     mean (raw - baseline) isolates the operation cost from the loop and
 *     the indirect-call overhead shared by every metric.
 *   - The benchmark calls the REAL production functions via the headers the
 *     production code uses (no re-implementation).  It runs against a
 *     dedicated ring (airy_ipc_ring) and a dedicated agent slot
 *     (BENCH_AGENT); the slot is saved/restored around each case so
 *     production agent_caps state is untouched.
 */

#include <kunit/test.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/airymax/error.h>
#include <linux/airymax/sched.h>

#include "airy_ipc_internal.h"
/*
 * airy_cap_badge_ok() is a static inline defined in security/airy/airy_cap.h.
 * The benchmark must #include it (not re-declare) to exercise the real C-S9
 * inline.  Same cross-directory include pattern already used by the suite's
 * tests, and both sides are Airy modules under CONFIG_AIRY_KUNIT.
 */
#include "../../../security/airy/airy_cap.h"

#define BENCH_AGENT		1000u	/* dedicated slot (saved/restored) */
#define BENCH_RING_ENTRIES	(1U << 18)	/* 262144 x 128B = 32MiB */
#define BENCH_WARMUP		1000u	/* cache + branch predictor fill */
#define BENCH_BADGE_ITERS	1000000u	/* badge: 1e6 to bury timer noise */
#define BENCH_RING_ITERS	100000u	/* ring/fastpath: 1e5 */
#define BENCH_BATCH_BADGE	64u	/* ops per timer pair (badge) */
#define BENCH_BATCH_RING	32u	/* ops per timer pair (ring) */
/*
 * Total ring ops per bench_run(): warm-up + batched samples + bulk loop.
 * The ring must never fill, otherwise post() takes the cheap -ENOSPC path
 * and the latency no longer reflects a successful send.  Capacity of a
 * 2^18-entry ring is 262143 > 201000.
 */
#define BENCH_RING_TOTAL	(BENCH_RING_ITERS * 2 + BENCH_WARMUP)

struct bench_ctx {
	int (*op)(struct bench_ctx *ctx);	/* performs ONE operation */
	u32 iters;				/* total operations */
	u32 batch;				/* ops per timed sample */
	u64 sink;				/* result sink, blocks elision */
	/* badge inputs */
	u64 badge;
	u32 agent_id;
	u16 required;
	/* ring inputs */
	struct airy_ipc_ring *ring;
	struct airy_ipc_msg_hdr *hdr;		/* header to post */
	struct airy_ipc_msg_hdr *out;		/* consume output */
	/* slowpath-sim inputs */
	u32 frozen;				/* C-S0 ring-frozen flag */
	u32 agent_state;			/* phase 3 agent state */
};

struct bench_fixture {
	struct bench_ctx ctx;
	struct bench_ctx base;
	struct airy_ipc_ring ring;
	struct airy_ipc_msg_hdr hdr;
	struct airy_ipc_msg_hdr out;
	struct airy_cap_slot saved_slot;
	bool slot_saved;
	bool ring_up;
	bool ring_vmalloc;	/* slots[] vmalloc-backed (UML fallback) */
};

struct bench_result {
	u64 mean;		/* per-op mean from batched samples */
	u64 p50;
	u64 p99;
	u64 bulk_per_op;	/* whole-loop timing / iters */
};

/* ─── Operation stubs (each performs exactly one production call) ─────── */

static int bench_noop(struct bench_ctx *c)
{
	c->sink += 1;
	return 0;
}

static int op_badge(struct bench_ctx *c)
{
	int ret = airy_cap_badge_ok(c->badge, c->agent_id, c->required);

	c->sink += (u64)ret + 1;
	return ret;
}

static int op_fastpath_send(struct bench_ctx *c)
{
	int ret = airy_ipc_fastpath_send(c->ring, c->hdr);

	c->sink += (u64)ret + 1;
	return ret;
}

static int op_ring_post(struct bench_ctx *c)
{
	int ret = airy_ipc_ring_post(c->ring, c->hdr);

	c->sink += (u64)ret + 1;
	return ret;
}

static int op_ring_consume(struct bench_ctx *c)
{
	int ret = airy_ipc_ring_consume(c->ring, c->out);

	c->sink += (u64)ret + 1;
	return ret;
}

/*
 * Simulated 5-phase slowpath core (phase1 frozen / phase3 state / phase4
 * fastpath C-S9 re-check / phase5 full badge+perms), mirroring the
 * structure of airy_uring_cmd_check() without requiring a real
 * io_uring_cmd or a task security blob.  With a forged badge this
 * exercises every phase down to the phase5 rejection — the slowpath's
 * full enforcement cost.
 */
static int op_slowpath_sim(struct bench_ctx *c)
{
	struct airy_cap_slot *slot;
	u64 slot_badge;
	u16 slot_perms;
	int ret;

	/* Phase 1: C-S0 ring frozen check. */
	if (READ_ONCE(c->frozen) != 0)
		return -AIRY_EIPC_FROZEN;
	/* Phase 3: STOPPED-agent degradation. */
	if (c->agent_state == AIRY_AGENT_STOPPED)
		return -AIRY_EIPC_FROZEN;
	/* Phase 4: fastpath C-S9 re-check (race resolution). */
	ret = airy_cap_badge_ok(c->badge, c->agent_id, c->required);
	if (ret == 0)
		goto out;
	/* Phase 5: slowpath enforcement with full badge + perms. */
	slot = &agent_caps[c->agent_id];
	slot_badge = READ_ONCE(slot->badge);
	if (slot_badge != c->badge) {
		ret = -AIRY_ECAP_FORGED;
		goto out;
	}
	slot_perms = READ_ONCE(slot->perms);
	if ((slot_perms & c->required) != c->required) {
		ret = -AIRY_ECAP_PERM;
		goto out;
	}
	ret = 0;
out:
	c->sink += (u64)ret + 1;
	return ret;
}

/* ─── Statistics ───────────────────────────────────────────────────────── */

/* Quickselect: k-th smallest (0-based), no full sort required. */
static u64 bench_select(u64 *a, u32 n, u32 k)
{
	u32 lo = 0, hi = n - 1;

	while (lo < hi) {
		u64 pivot = a[hi];
		u32 i = lo, j;

		for (j = lo; j < hi; j++) {
			if (a[j] < pivot) {
				u64 tmp = a[i];

				a[i] = a[j];
				a[j] = tmp;
				i++;
			}
		}
		a[hi] = a[i];
		a[i] = pivot;
		if (i == k)
			return a[i];
		if (k < i)
			hi = i - 1;
		else
			lo = i + 1;
	}
	return a[lo];
}

static struct bench_result bench_run(struct kunit *test, struct bench_ctx *ctx)
{
	struct bench_result r = { 0 };
	u32 samples = ctx->iters / ctx->batch;
	u64 *per, sum = 0, bulk_start, bulk_total;
	u32 i;

	if (samples < 2) {
		kunit_info(test, "BENCH %s: too few samples (%u)\n",
			   "run", samples);
		return r;
	}
	per = kunit_kzalloc(test, samples * sizeof(*per), GFP_KERNEL);
	if (!per) {
		kunit_info(test, "BENCH run: kunit_kzalloc failed\n");
		return r;
	}

	/* Warm-up: fill caches and train branch predictors. */
	for (i = 0; i < BENCH_WARMUP; i++)
		(void)ctx->op(ctx);

	/* Batched samples: one ktime_get_ns() pair per batch. */
	for (i = 0; i < samples; i++) {
		u64 start, end;
		u32 k;

		start = ktime_get_ns();
		for (k = 0; k < ctx->batch; k++)
			(void)ctx->op(ctx);
		end = ktime_get_ns();
		per[i] = (end - start) / ctx->batch;
		sum += per[i];
	}
	r.mean = sum / samples;
	r.p50 = bench_select(per, samples, samples / 2);
	r.p99 = bench_select(per, samples, (samples * 99) / 100);

	/* Whole-loop bulk timing: no per-batch timer overhead at all. */
	bulk_start = ktime_get_ns();
	for (i = 0; i < ctx->iters; i++)
		(void)ctx->op(ctx);
	bulk_total = ktime_get_ns() - bulk_start;
	r.bulk_per_op = bulk_total / ctx->iters;

	return r;
}

static void bench_report(struct kunit *test, const char *name,
			 struct bench_ctx *op, struct bench_ctx *base)
{
	struct bench_result ro = bench_run(test, op);
	struct bench_result rb = bench_run(test, base);
	u64 net = ro.mean > rb.mean ? ro.mean - rb.mean : 0;

	kunit_info(test,
		"BENCH %-22s mean=%llu p50=%llu p99=%llu bulk=%llu ns/op"
		" (iters=%u batch=%u samples=%u) | baseline mean=%llu"
		" p50=%llu | net mean=%llu | sink=%llu\n",
		name, (unsigned long long)ro.mean,
		(unsigned long long)ro.p50, (unsigned long long)ro.p99,
		(unsigned long long)ro.bulk_per_op,
		op->iters, op->batch, op->iters / op->batch,
		(unsigned long long)rb.mean, (unsigned long long)rb.p50,
		(unsigned long long)net, (unsigned long long)op->sink);
}

/* ─── Suite init/exit ─────────────────────────────────────────────────── */

static bool bench_env_printed;

static void bench_print_env(struct kunit *test)
{
	if (bench_env_printed)
		return;
	kunit_info(test, "BENCH env: release=%s nrcpus=%u\n",
		   init_uts_ns.name.release, num_online_cpus());
	bench_env_printed = true;
}

static int bench_init(struct kunit *test)
{
	struct bench_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f);
	test->priv = f;

	/* Dedicated agent slot: save production state, install benchmark
	 * state (epoch=7 / randtag=0x13579BDF / perms=SEND). */
	f->saved_slot = agent_caps[BENCH_AGENT];
	f->slot_saved = true;
	agent_caps[BENCH_AGENT].badge = AIRY_BADGE_COMPILE(7u, 0x13579BDFu,
							  AIRY_CAP_PERM_SEND);
	agent_caps[BENCH_AGENT].epoch = 7u;
	agent_caps[BENCH_AGENT].randtag = 0x13579BDFu;
	agent_caps[BENCH_AGENT].perms = AIRY_CAP_PERM_SEND;

	/* Dedicated benchmark ring: never touches production rings.
	 * airy_ipc_ring_init() kcallocs the slot array; under UML the 32MiB
	 * order-13 allocation can fail even with plenty of free memory, so
	 * fall back to vmalloc (ring_post/consume/fastpath_send access
	 * slots[] as a flat array — the backing store does not affect the
	 * measured per-op cost). */
	if (airy_ipc_ring_init(&f->ring, BENCH_RING_ENTRIES) == 0) {
		f->ring_up = true;
	} else {
		f->ring.slots = vzalloc(BENCH_RING_ENTRIES *
					sizeof(struct airy_ipc_msg_hdr));
		KUNIT_ASSERT_NOT_NULL(test, f->ring.slots);
		f->ring.head = 0;
		f->ring.tail = 0;
		f->ring.mask = BENCH_RING_ENTRIES - 1;
		f->ring.frozen = 0;
		f->ring_vmalloc = true;
	}

	/* Default ctx plumbing. */
	f->ctx.ring = &f->ring;
	f->ctx.hdr = &f->hdr;
	f->ctx.out = &f->out;
	f->ctx.agent_id = BENCH_AGENT;
	f->ctx.required = AIRY_CAP_PERM_SEND;
	f->base.op = bench_noop;

	memset(&f->hdr, 0, sizeof(f->hdr));
	f->hdr.magic = AIRY_IPC_MAGIC;
	f->hdr.opcode = AIRY_IPC_OP_SEND;
	f->hdr.capability_badge = AIRY_BADGE_COMPILE(7u, 0x13579BDFu,
						    AIRY_CAP_PERM_SEND);
	return 0;
}

static void bench_exit(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	if (!f)
		return;
	if (f->ring_up)
		airy_ipc_ring_destroy(&f->ring);
	else if (f->ring_vmalloc)
		vfree(f->ring.slots);
	if (f->slot_saved)
		agent_caps[BENCH_AGENT] = f->saved_slot;
}

/* ─── Test cases ──────────────────────────────────────────────────────── */

static void badge_hit_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	bench_print_env(test);
	f->ctx.op = op_badge;
	f->ctx.badge = AIRY_BADGE_COMPILE(7u, 0x13579BDFu,
					  AIRY_CAP_PERM_SEND);
	f->ctx.iters = BENCH_BADGE_ITERS;
	f->ctx.batch = BENCH_BATCH_BADGE;
	f->base.iters = BENCH_BADGE_ITERS;
	f->base.batch = BENCH_BATCH_BADGE;
	bench_report(test, "badge_ok_hit", &f->ctx, &f->base);
	/* Sanity: the configured badge must keep passing (C-S9.1-.3). */
	KUNIT_EXPECT_EQ(test, 0, airy_cap_badge_ok(f->ctx.badge,
			 f->ctx.agent_id, f->ctx.required));
}

static void badge_miss_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	f->ctx.op = op_badge;
	/* Forged randtag: fails C-S9.2 after the epoch read. */
	f->ctx.badge = AIRY_BADGE_COMPILE(7u, 0x13579BE0u,
					  AIRY_CAP_PERM_SEND);
	f->ctx.iters = BENCH_BADGE_ITERS;
	f->ctx.batch = BENCH_BATCH_BADGE;
	f->base.iters = BENCH_BADGE_ITERS;
	f->base.batch = BENCH_BATCH_BADGE;
	bench_report(test, "badge_ok_miss", &f->ctx, &f->base);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			airy_cap_badge_ok(f->ctx.badge,
					  f->ctx.agent_id, f->ctx.required));
}

static void fastpath_send_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	f->ctx.op = op_fastpath_send;
	f->ctx.iters = BENCH_RING_ITERS;
	f->ctx.batch = BENCH_BATCH_RING;
	f->base.iters = BENCH_RING_ITERS;
	f->base.batch = BENCH_BATCH_RING;
	bench_report(test, "fastpath_send", &f->ctx, &f->base);
	/* Every send must land (warm-up + batched + bulk iterations). */
	KUNIT_EXPECT_EQ(test, BENCH_RING_TOTAL, READ_ONCE(f->ring.head));
}

static void fastpath_frozen_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	WRITE_ONCE(f->ring.frozen, 1);
	f->ctx.op = op_fastpath_send;
	f->ctx.iters = BENCH_RING_ITERS;
	f->ctx.batch = BENCH_BATCH_RING;
	f->base.iters = BENCH_RING_ITERS;
	f->base.batch = BENCH_BATCH_RING;
	bench_report(test, "fastpath_frozen", &f->ctx, &f->base);
	/* Frozen gate bails before posting: head must not move. */
	KUNIT_EXPECT_EQ(test, 0, READ_ONCE(f->ring.head));
	KUNIT_EXPECT_EQ(test, -AIRY_EIPC_FROZEN,
			airy_ipc_fastpath_send(&f->ring, &f->hdr));
	WRITE_ONCE(f->ring.frozen, 0);
}

static void ring_post_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	f->ctx.op = op_ring_post;
	f->ctx.iters = BENCH_RING_ITERS;
	f->ctx.batch = BENCH_BATCH_RING;
	f->base.iters = BENCH_RING_ITERS;
	f->base.batch = BENCH_BATCH_RING;
	bench_report(test, "ring_post", &f->ctx, &f->base);
	KUNIT_EXPECT_EQ(test, BENCH_RING_TOTAL, READ_ONCE(f->ring.head));
}

static void ring_consume_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;
	u32 i;

	/* Pre-fill enough messages for warm-up + batched + bulk consumes,
	 * so no consume ever hits the empty (-ENOMSG) path. */
	for (i = 0; i < BENCH_RING_TOTAL; i++)
		KUNIT_ASSERT_EQ(test, 0, airy_ipc_ring_post(&f->ring, &f->hdr));

	f->ctx.op = op_ring_consume;
	f->ctx.iters = BENCH_RING_ITERS;
	f->ctx.batch = BENCH_BATCH_RING;
	f->base.iters = BENCH_RING_ITERS;
	f->base.batch = BENCH_BATCH_RING;
	bench_report(test, "ring_consume", &f->ctx, &f->base);
	/* All pre-filled messages consumed: tail catches head. */
	KUNIT_EXPECT_EQ(test, READ_ONCE(f->ring.head), READ_ONCE(f->ring.tail));
}

static void slowpath_sim_test(struct kunit *test)
{
	struct bench_fixture *f = test->priv;

	f->ctx.op = op_slowpath_sim;
	/* Forged badge drives phase4 to fail, so phase5 (full badge + perms)
	 * executes — the slowpath's complete 5-phase enforcement path. */
	f->ctx.badge = AIRY_BADGE_COMPILE(7u, 0x13579BE0u,
					  AIRY_CAP_PERM_SEND);
	f->ctx.iters = BENCH_RING_ITERS;
	f->ctx.batch = BENCH_BATCH_RING;
	f->base.iters = BENCH_RING_ITERS;
	f->base.batch = BENCH_BATCH_RING;
	bench_report(test, "slowpath_5phase", &f->ctx, &f->base);
	KUNIT_EXPECT_EQ(test, -AIRY_ECAP_FORGED,
			op_slowpath_sim(&f->ctx));
}

static struct kunit_case airy_fastpath_bench_cases[] = {
	KUNIT_CASE(badge_hit_test),
	KUNIT_CASE(badge_miss_test),
	KUNIT_CASE(fastpath_send_test),
	KUNIT_CASE(fastpath_frozen_test),
	KUNIT_CASE(ring_post_test),
	KUNIT_CASE(ring_consume_test),
	KUNIT_CASE(slowpath_sim_test),
	{}
};

static struct kunit_suite airy_fastpath_bench_suite = {
	.name = "airy_fastpath_bench",
	.init = bench_init,
	.exit = bench_exit,
	.test_cases = airy_fastpath_bench_cases,
};

kunit_test_suites(&airy_fastpath_bench_suite);

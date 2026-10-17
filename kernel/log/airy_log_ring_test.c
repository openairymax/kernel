// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_ring_test.c — KUnit coverage for the A-ULP log ring buffer.
 *
 * Exercises the producer contract against the real tracepoint: every
 * committed write must emit airy_ring_buffer_write with the record
 * level, the clipped payload length and the overrun flag the cmpxchg
 * loop actually observed. Capacity, slot layout, reserve/commit
 * publication and the freeze path are asserted from the shared ring
 * header rather than from a second copy of the accounting.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/airymax/error.h>
#include <linux/airymax/log_types.h>

#include "airy_log_internal.h"

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)

#include <trace/events/airy.h>

struct ring_evt {
	u32	level;
	u32	size;
	u32	overrun;
};

struct ring_cap {
	struct ring_evt	evt[32];
	unsigned int	nr;
};

static void ring_probe(void *data, u32 level, u32 size, u32 overrun)
{
	struct ring_cap *cap = data;

	if (cap->nr < ARRAY_SIZE(cap->evt))
		cap->evt[cap->nr] = (struct ring_evt) {
			.level = level,
			.size = size,
			.overrun = overrun,
		};
	cap->nr++;
}

static void ring_probe_off(void *data)
{
	tracepoint_probe_unregister(&__tracepoint_airy_ring_buffer_write,
				    ring_probe, data);
}

static struct ring_cap *ring_capture(struct kunit *test)
{
	struct ring_cap *cap;
	int ret;

	cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cap);

	ret = tracepoint_probe_register(&__tracepoint_airy_ring_buffer_write,
					ring_probe, cap);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, ring_probe_off, cap));
	return cap;
}

static int ring_test_init(struct kunit *test)
{
	struct airy_log_ring *ring;

	ring = kunit_kzalloc(test, sizeof(*ring), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ring);
	KUNIT_ASSERT_EQ(test, 0, airy_log_ring_init(ring, PAGE_SIZE));
	test->priv = ring;
	return 0;
}

static void ring_test_exit(struct kunit *test)
{
	airy_log_ring_destroy(test->priv);
}

static void init_shapes_capacity_after_header_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct airy_log_ring_header *hdr = ring->kaddr;
	u32 want = rounddown_pow_of_two((u32)((PAGE_SIZE - sizeof(*hdr)) /
					      AIRY_LOG_RECORD_SIZE));

	KUNIT_EXPECT_EQ(test, (size_t)PAGE_SIZE, ring->size);
	KUNIT_EXPECT_EQ(test, want, hdr->capacity);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_LOG_RECORD_SIZE, hdr->record_size);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->head);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->committed_head);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->tail);
	KUNIT_EXPECT_EQ(test, (u32)0, hdr->frozen);
}

static void append_writes_emit_without_overrun_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct airy_log_ring_header *hdr = ring->kaddr;
	struct ring_cap *cap = ring_capture(test);
	u32 i;

	for (i = 0; i < hdr->capacity; i++)
		KUNIT_ASSERT_EQ(test, 0,
				airy_log_write(ring, AIRY_LOG_INFO,
					       AIRY_LOG_FAC_KERN, "x", 1));

	KUNIT_ASSERT_EQ(test, hdr->capacity, cap->nr);
	for (i = 0; i < hdr->capacity; i++) {
		KUNIT_EXPECT_EQ(test, (u32)AIRY_LOG_INFO, cap->evt[i].level);
		KUNIT_EXPECT_EQ(test, (u32)1, cap->evt[i].size);
		KUNIT_EXPECT_EQ(test, (u32)0, cap->evt[i].overrun);
	}
	KUNIT_EXPECT_EQ(test, (u64)hdr->capacity, hdr->committed_head);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->tail);
}

static void full_ring_overrun_advances_tail_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct airy_log_ring_header *hdr = ring->kaddr;
	struct ring_cap *cap = ring_capture(test);
	u32 i;

	for (i = 0; i <= hdr->capacity; i++)
		KUNIT_ASSERT_EQ(test, 0,
				airy_log_write(ring, AIRY_LOG_WARN,
					       AIRY_LOG_FAC_KERN, "y", 1));

	KUNIT_ASSERT_EQ(test, hdr->capacity + 1, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)0, cap->evt[hdr->capacity - 1].overrun);
	KUNIT_EXPECT_EQ(test, (u32)1, cap->evt[hdr->capacity].overrun);
	KUNIT_EXPECT_EQ(test, (u64)1, hdr->tail);
	KUNIT_EXPECT_EQ(test, (u64)(hdr->capacity + 1), hdr->committed_head);
}

static void payload_is_clipped_to_slot_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct ring_cap *cap = ring_capture(test);
	u8 big[2 * AIRY_LOG_RECORD_SIZE];

	memset(big, 0x5a, sizeof(big));
	KUNIT_ASSERT_EQ(test, 0,
			airy_log_write(ring, AIRY_LOG_DEBUG, AIRY_LOG_FAC_KERN,
				       big, sizeof(big)));

	KUNIT_ASSERT_EQ(test, 1u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)AIRY_LOG_DEBUG, cap->evt[0].level);
	KUNIT_EXPECT_EQ(test, (u32)sizeof_field(struct airy_log_record,
						payload),
			cap->evt[0].size);
}

static void frozen_ring_rejects_without_emitting_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct airy_log_ring_header *hdr = ring->kaddr;
	struct ring_cap *cap = ring_capture(test);

	airy_log_ring_freeze(ring);
	KUNIT_EXPECT_EQ(test, (u32)1, hdr->frozen);
	KUNIT_EXPECT_EQ(test, -AIRY_ELOG_FULL,
			airy_log_write(ring, AIRY_LOG_ERROR, AIRY_LOG_FAC_KERN,
				       "z", 1));
	KUNIT_EXPECT_EQ(test, 0u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->head);
	KUNIT_EXPECT_EQ(test, (u64)0, hdr->committed_head);
}

static void reserve_commit_publishes_without_event_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;
	struct airy_log_ring_header *hdr = ring->kaddr;
	struct airy_log_record *rec;
	struct ring_cap *cap = ring_capture(test);
	bool overrun = true;

	rec = airy_log_reserve(ring, &overrun);
	KUNIT_ASSERT_NOT_NULL(test, rec);
	KUNIT_EXPECT_FALSE(test, overrun);
	KUNIT_EXPECT_EQ(test, (u64)1, hdr->head);

	rec->magic = AIRY_LOG_MAGIC;
	airy_log_commit(ring, rec);
	KUNIT_EXPECT_EQ(test, (u64)1, hdr->committed_head);
	KUNIT_EXPECT_EQ(test, 0u, cap->nr);
}

static void entry_guards_test(struct kunit *test)
{
	struct airy_log_ring uninit;
	struct airy_log_ring_header *hdr;
	bool overrun;

	memset(&uninit, 0, sizeof(uninit));
	KUNIT_EXPECT_EQ(test, -EINVAL, airy_log_ring_init(NULL, PAGE_SIZE));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_log_ring_init(&uninit, PAGE_SIZE - 1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_log_write(NULL, AIRY_LOG_INFO, AIRY_LOG_FAC_KERN,
				       "x", 1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			airy_log_write(test->priv, AIRY_LOG_INFO,
				       AIRY_LOG_FAC_KERN, NULL, 1));
	KUNIT_EXPECT_NULL(test, airy_log_reserve(NULL, &overrun));
	KUNIT_EXPECT_NULL(test, airy_log_reserve(&uninit, &overrun));

	airy_log_commit(NULL, NULL);
	airy_log_ring_freeze(NULL);
	airy_log_ring_destroy(NULL);

	hdr = ((struct airy_log_ring *)test->priv)->kaddr;
	KUNIT_EXPECT_EQ(test, (u32)0, hdr->frozen);
}

static void destroy_releases_backing_store_test(struct kunit *test)
{
	struct airy_log_ring *ring = test->priv;

	airy_log_ring_destroy(ring);
	KUNIT_EXPECT_NULL(test, ring->pages);
	KUNIT_EXPECT_NULL(test, ring->kaddr);
	KUNIT_EXPECT_EQ(test, (size_t)0, ring->size);
	KUNIT_EXPECT_EQ(test, 0u, ring->order);
}

static struct kunit_case airy_log_ring_cases[] = {
	KUNIT_CASE(init_shapes_capacity_after_header_test),
	KUNIT_CASE(append_writes_emit_without_overrun_test),
	KUNIT_CASE(full_ring_overrun_advances_tail_test),
	KUNIT_CASE(payload_is_clipped_to_slot_test),
	KUNIT_CASE(frozen_ring_rejects_without_emitting_test),
	KUNIT_CASE(reserve_commit_publishes_without_event_test),
	KUNIT_CASE(entry_guards_test),
	KUNIT_CASE(destroy_releases_backing_store_test),
	{}
};

static struct kunit_suite airy_log_ring_suite = {
	.name = "airy_log_ring",
	.init = ring_test_init,
	.exit = ring_test_exit,
	.test_cases = airy_log_ring_cases,
};

kunit_test_suites(&airy_log_ring_suite);

#endif /* CONFIG_AIRY_AGENT_TRACING */

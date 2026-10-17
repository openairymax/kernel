// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_ipc_trace_test.c — KUnit coverage for the IPC trace emission.
 *
 * Drives airy_send_emit() and airy_recv_emit() with real
 * tracepoint_probe handlers attached to airy_ipc_send and airy_ipc_recv,
 * then checks that the emitted fields are the header opcode, the caller
 * supplied agent ids and latency, and that header task ids outside the
 * capability namespace collapse to agent 0.  The *_on() predicates must
 * follow probe registration exactly, because they gate the fastpath
 * timestamping in the send and receive paths.
 */

#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/types.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/lsm_types.h>

#include "airy_ipc_internal.h"

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)

#include <trace/events/airy.h>

struct ipc_evt {
	u32	src;
	u32	dst;
	u32	op;
	u8	fastpath;
	u64	latency_ns;
};

struct ipc_cap {
	struct ipc_evt	evt[8];
	unsigned int	nr;
};

static void send_probe(void *data, u32 src_agent, u32 dst_agent, u32 op,
		       u8 fastpath, u64 latency_ns)
{
	struct ipc_cap *cap = data;

	if (cap->nr < ARRAY_SIZE(cap->evt))
		cap->evt[cap->nr] = (struct ipc_evt) {
			.src = src_agent,
			.dst = dst_agent,
			.op = op,
			.fastpath = fastpath,
			.latency_ns = latency_ns,
		};
	cap->nr++;
}

static void recv_probe(void *data, u32 src_agent, u32 dst_agent, u32 op,
		       u64 latency_ns)
{
	struct ipc_cap *cap = data;

	if (cap->nr < ARRAY_SIZE(cap->evt))
		cap->evt[cap->nr] = (struct ipc_evt) {
			.src = src_agent,
			.dst = dst_agent,
			.op = op,
			.latency_ns = latency_ns,
		};
	cap->nr++;
}

static void send_probe_off(void *data)
{
	tracepoint_probe_unregister(&__tracepoint_airy_ipc_send, send_probe,
				    data);
}

static void recv_probe_off(void *data)
{
	tracepoint_probe_unregister(&__tracepoint_airy_ipc_recv, recv_probe,
				    data);
}

static struct ipc_cap *ipc_cap_alloc(struct kunit *test)
{
	struct ipc_cap *cap;

	cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cap);
	return cap;
}

static void ipc_cap_send(struct kunit *test, struct ipc_cap *cap)
{
	KUNIT_ASSERT_EQ(test, 0,
			tracepoint_probe_register(&__tracepoint_airy_ipc_send,
						  send_probe, cap));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, send_probe_off, cap));
}

static void ipc_cap_recv(struct kunit *test, struct ipc_cap *cap)
{
	KUNIT_ASSERT_EQ(test, 0,
			tracepoint_probe_register(&__tracepoint_airy_ipc_recv,
						  recv_probe, cap));
	KUNIT_ASSERT_EQ(test, 0,
			kunit_add_action_or_reset(test, recv_probe_off, cap));
}

static void predicates_track_registration_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;
	int ret;

	KUNIT_EXPECT_FALSE(test, airy_send_on());
	KUNIT_EXPECT_FALSE(test, airy_recv_on());

	ret = tracepoint_probe_register(&__tracepoint_airy_ipc_send,
					send_probe, cap);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_TRUE(test, airy_send_on());
	KUNIT_EXPECT_FALSE(test, airy_recv_on());

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x21;
	airy_send_emit(&hdr, 3, 0, 0);
	KUNIT_EXPECT_EQ(test, 1u, cap->nr);

	ret = tracepoint_probe_unregister(&__tracepoint_airy_ipc_send,
					  send_probe, cap);
	KUNIT_EXPECT_EQ(test, 0, ret);
	KUNIT_EXPECT_FALSE(test, airy_send_on());
	KUNIT_EXPECT_EQ(test, 1u, cap->nr);
}

static void send_emit_reports_header_and_arguments_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;

	ipc_cap_send(test, cap);
	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x44;
	hdr.dst_task = 42;

	airy_send_emit(&hdr, 9, 1, 123456);

	KUNIT_ASSERT_EQ(test, 1u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)9, cap->evt[0].src);
	KUNIT_EXPECT_EQ(test, (u32)42, cap->evt[0].dst);
	KUNIT_EXPECT_EQ(test, (u32)0x44, cap->evt[0].op);
	KUNIT_EXPECT_EQ(test, (u8)1, cap->evt[0].fastpath);
	KUNIT_EXPECT_EQ(test, (u64)123456, cap->evt[0].latency_ns);
}

static void send_emit_normalises_unknown_dst_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;

	ipc_cap_send(test, cap);
	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x55;
	hdr.dst_task = AIRY_CAP_MAX_AGENTS;

	airy_send_emit(&hdr, 1, 0, 0);
	hdr.dst_task = AIRY_CAP_MAX_AGENTS - 1;
	airy_send_emit(&hdr, 1, 0, 0);

	KUNIT_ASSERT_EQ(test, 2u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)0, cap->evt[0].dst);
	KUNIT_EXPECT_EQ(test, (u32)(AIRY_CAP_MAX_AGENTS - 1),
			cap->evt[1].dst);
}

static void recv_emit_reports_header_and_arguments_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;

	ipc_cap_recv(test, cap);
	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x66;
	hdr.src_task = 11;

	airy_recv_emit(&hdr, 12, 98765);

	KUNIT_ASSERT_EQ(test, 1u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)11, cap->evt[0].src);
	KUNIT_EXPECT_EQ(test, (u32)12, cap->evt[0].dst);
	KUNIT_EXPECT_EQ(test, (u32)0x66, cap->evt[0].op);
	KUNIT_EXPECT_EQ(test, (u64)98765, cap->evt[0].latency_ns);
}

static void recv_emit_normalises_unknown_src_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;

	ipc_cap_recv(test, cap);
	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x77;
	hdr.src_task = AIRY_CAP_MAX_AGENTS;

	airy_recv_emit(&hdr, 5, 0);
	hdr.src_task = AIRY_CAP_MAX_AGENTS - 1;
	airy_recv_emit(&hdr, 5, 0);

	KUNIT_ASSERT_EQ(test, 2u, cap->nr);
	KUNIT_EXPECT_EQ(test, (u32)0, cap->evt[0].src);
	KUNIT_EXPECT_EQ(test, (u32)(AIRY_CAP_MAX_AGENTS - 1),
			cap->evt[1].src);
}

static void emit_without_consumer_is_silent_test(struct kunit *test)
{
	struct ipc_cap *cap = ipc_cap_alloc(test);
	struct airy_ipc_msg_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = 0x88;

	KUNIT_EXPECT_FALSE(test, airy_send_on());
	KUNIT_EXPECT_FALSE(test, airy_recv_on());
	airy_send_emit(&hdr, 1, 0, 0);
	airy_recv_emit(&hdr, 2, 0);
	KUNIT_EXPECT_EQ(test, 0u, cap->nr);
}

static struct kunit_case airy_ipc_trace_cases[] = {
	KUNIT_CASE(predicates_track_registration_test),
	KUNIT_CASE(send_emit_reports_header_and_arguments_test),
	KUNIT_CASE(send_emit_normalises_unknown_dst_test),
	KUNIT_CASE(recv_emit_reports_header_and_arguments_test),
	KUNIT_CASE(recv_emit_normalises_unknown_src_test),
	KUNIT_CASE(emit_without_consumer_is_silent_test),
	{}
};

static struct kunit_suite airy_ipc_trace_suite = {
	.name = "airy_ipc_trace",
	.test_cases = airy_ipc_trace_cases,
};

kunit_test_suites(&airy_ipc_trace_suite);

#endif /* CONFIG_AIRY_AGENT_TRACING */

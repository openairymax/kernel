// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_fault.c — security fault observer for the supervisor.
 *
 * airy_security_fault() raises unrecoverable capability violations on
 * airy_die_chain. This file is that chain's consumer: it validates the
 * fault code, records the enforcement in the trace stream and wakes the
 * Macro-Supervisor through the eventfd channel.
 *
 * The observer must exist for the chain to mean anything: without a
 * registered callback a forged badge or a corrupt ring was detected in
 * the slowpath and then dropped on the floor.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §6
 */

#include <linux/notifier.h>
#include <linux/types.h>

#include <linux/airymax/error.h>
#include <airymax/airy_trace.h>

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
#include <trace/events/airy.h>
#endif

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

bool airy_fault_ok(__u32 code)
{
	switch (code) {
	case AIRY_FAULT_CAP_FORGED:
	case AIRY_FAULT_CAP_LEAK:
	case AIRY_FAULT_RING_CORRUPT:
	case AIRY_FAULT_TIMEOUT:
	case AIRY_FAULT_ABNORMAL_CAP:
	case AIRY_FAULT_VM_FAULT:
		return true;
	default:
		return false;
	}
}

/*
 * sv_fault_cb - turn one security fault into a supervisor notification.
 * @nb: this observer; unused
 * @val: fault code published by airy_security_fault()
 * @data: the struct airy_fault_rec that names the offending agent
 *
 * The record is authoritative for the identity and the timestamp; the
 * chain value must agree with it, otherwise the event is not a
 * well-formed fault and is ignored. An unbound or out-of-range agent id
 * is refused through airy_sv_id_chk() for the same reason a command
 * naming it would be: there is no agent to supervise.
 *
 * Runs at the tail of an atomic notifier chain in process context, so
 * the tracepoint and the non-blocking eventfd signal are both allowed.
 *
 * Return: NOTIFY_DONE, always; the chain has no veto to express.
 */
static int sv_fault_cb(struct notifier_block *nb, unsigned long val,
		       void *data)
{
	const struct airy_fault_rec *rec = data;

	if (!rec || rec->fault_code != (__u32)val)
		return NOTIFY_DONE;
	if (!airy_fault_ok(rec->fault_code))
		return NOTIFY_DONE;
	if (airy_sv_id_chk(rec->agent_id))
		return NOTIFY_DONE;

#if IS_ENABLED(CONFIG_AIRY_AGENT_TRACING)
	trace_airy_superv_enforce(rec->agent_id, AIRY_SUPERV_ACTION_FREEZE,
				  rec->fault_code);
#endif

	airy_eventfd_signal_fault(rec->fault_code, rec->agent_id,
				  rec->timestamp_ns);

	return NOTIFY_DONE;
}

static struct notifier_block sv_fault_nb = {
	.notifier_call = sv_fault_cb,
};

int __init airy_fault_init(void)
{
	return atomic_notifier_chain_register(&airy_die_chain, &sv_fault_nb);
}

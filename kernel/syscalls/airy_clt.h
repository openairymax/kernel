/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * Cognition lifecycle (CLT) notification contract for syscall 551
 * (airy_sys_clt_notify). The argument that carries meaning is `phase`,
 * a unified operation code: 0/1/2 are the [SC] CoreLoopThree phases
 * PERCEPT/THINK/ACT of cognition_types.h, and any value from
 * AIRY_COG_PHASE_MAX upwards is reserved for the kthread-class
 * operations owned by module F, which this release does not
 * implement. 551 answers only its own phase space instead of standing
 * in for those operations.
 *
 * SSoT: 30-interfaces/01-syscalls.md §3.3;
 *       140-application-development/07-syscall-registry.md.
 */

#ifndef _AIRY_CLT_H
#define _AIRY_CLT_H

#include <linux/types.h>
#include <linux/compiler.h>

#include <linux/airymax/cognition_types.h>

/* Phase-op classification */
/*
 * The `phase` argument of syscall 551 doubles as an operation code. Its
 * phase half is exactly the [SC] airy_cog_phase space; everything at or
 * above AIRY_COG_PHASE_MAX belongs to the kthread-class operations of
 * module F. Keeping the two halves explicit stops a future edit from
 * reading a reserved operation as merely "not yet implemented here".
 */
enum airy_clt_class {
	AIRY_CLT_CLASS_PHASE,
	AIRY_CLT_CLASS_RESERVED,
};

/**
 * airy_clt_kind - classify the syscall 551 phase argument
 * @op: Value taken from the 551 `phase` argument.
 *
 * Pure classifier with no state and no dependency on current, so KUnit
 * drives it directly and the 551 entry uses it as its boundary check. It
 * is the single definition of which phase values 551 accepts.
 *
 * SSoT: 140-application-development/07-syscall-registry.md (op-dispatch).
 *
 * Return: AIRY_CLT_CLASS_PHASE when @op is a CoreLoopThree phase,
 *         AIRY_CLT_CLASS_RESERVED otherwise.
 */
static inline enum airy_clt_class airy_clt_kind(__u32 op)
{
	if (op < AIRY_COG_PHASE_MAX)
		return AIRY_CLT_CLASS_PHASE;

	return AIRY_CLT_CLASS_RESERVED;
}

/* Phase record seeding */
/*
 * Sentinel returned by airy_clt_query() for a task whose phase has never
 * been notified. It lies outside the [SC] airy_cog_phase space
 * (0..AIRY_COG_PHASE_MAX - 1) so it can never be mistaken for a live
 * phase.
 */
#define AIRY_CLT_PHASE_UNSET	0xFFFFFFFFu

/* Notification entry points (defined in airy_clt.c) */
/**
 * airy_clt_serve - serve the phase half of syscall 551
 * @task_id: Target cognition agent identity.
 * @phase:   Unified 551 operation code.
 *
 * The single definition of the 551 entry decision, kept non-static so
 * KUnit drives it directly instead of through the syscall ABI. It
 * classifies @phase with airy_clt_kind() first — validation precedes
 * mutation — so the reserved kthread-class space is refused with
 * -AIRY_ECOG_PHASE, the [SC] magnitude for an invalid cognition phase,
 * before the identity is examined and the table is touched. Only a
 * CoreLoopThree phase reaches airy_clt_notify().
 *
 * Return: AIRY_EOK on success; -AIRY_ECOG_PHASE when @phase is reserved
 *         for module F; otherwise what airy_clt_notify() returns.
 */
__must_check int airy_clt_serve(int task_id, __u32 phase);

/**
 * airy_clt_notify - record a CoreLoopThree phase notification
 * @task_id: Target cognition agent identity.
 * @phase:   CoreLoopThree phase (AIRY_COG_PERCEPT/THINK/ACT).
 *
 * Handler for the phase half of syscall 551. The caller must pass a phase
 * value: the entry classifies @phase with airy_clt_kind() and answers the
 * reserved space with -AIRY_ECOG_PHASE before this function is reached, so
 * only 0/1/2 arrive here.
 *
 * The notification is recorded in the per-agent phase table so a later
 * consumer (sched_tac admission, airy_clt_query) can observe the agent's
 * current phase; an entry that has never been written reads back as
 * AIRY_CLT_PHASE_UNSET.
 *
 * Return: AIRY_EOK on success; -EINVAL when @task_id is negative;
 *         -AIRY_ECAP_OVERFLOW when @task_id is outside the agent table.
 */
__must_check int airy_clt_notify(int task_id, __u32 phase);

/**
 * airy_clt_query - read back the last notified phase of a task
 * @task_id: Target cognition agent identity.
 * @phase:   Out-parameter receiving the recorded phase.
 *
 * Read side of the phase table behind syscall 551, and the test hook for
 * it: a supervisor observes an agent's phase before admitting it. @phase is
 * written only on success; AIRY_CLT_PHASE_UNSET means the task has never
 * notified a phase.
 *
 * Return: AIRY_EOK on success; -EINVAL when @phase is NULL or @task_id is
 *         negative; -AIRY_ECAP_OVERFLOW when @task_id is out of range.
 */
__must_check int airy_clt_query(int task_id, __u32 *phase);

#endif /* _AIRY_CLT_H */

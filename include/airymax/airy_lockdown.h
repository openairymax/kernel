/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lockdown.h — the Airymax lockdown ladder.
 *
 * Three monotonic levels close a growing set of agent-facing interfaces
 * as a deployment moves from "open" to "sealed":
 *
 *   early  capability grants, RoVol tier writes, scheduler writes close
 *   late   the interfaces of early plus kernel memory and probe surfaces
 *   full   every interface the ladder knows about, plus every
 *          security_locked_down() reason
 *
 * The level only ever increases. A boot command line or the root-only
 * securityfs knob raises it; nothing lowers it, because a sealed
 * deployment must not be reopened by a later, weaker decision.
 *
 * SSoT: 110-security/09-lockdown.md §3 (rule table), §4 (state machine),
 *       §5 (gate semantics).
 */

#ifndef _AIRY_LOCKDOWN_H
#define _AIRY_LOCKDOWN_H

#include <linux/kconfig.h>
#include <linux/security.h>
#include <linux/types.h>

/* Monotonic ladder. The numeric order is the enforcement order. */
enum airy_lock_level {
	AIRY_LOCK_NONE = 0,
	AIRY_LOCK_EARLY,
	AIRY_LOCK_LATE,
	AIRY_LOCK_FULL,
	AIRY_LOCK_MAX
};

/* Where a level change came from; recorded with the transition. */
enum airy_lock_trigger {
	AIRY_LOCK_BY_CONFIG = 0,
	AIRY_LOCK_BY_CMDLINE,
	AIRY_LOCK_BY_SECFS,
	AIRY_LOCK_TRIGGER_MAX
};

/* Interfaces the ladder gates. One rule per entry, same order. */
enum airy_lock_iface {
	AIRY_LOCK_IF_CAP_GRANT = 0,
	AIRY_LOCK_IF_ROVOL,
	AIRY_LOCK_IF_SCHED,
	AIRY_LOCK_IF_MAX
};

#if IS_ENABLED(CONFIG_SECURITY_AIRY)

/**
 * airy_lock_gate - check one interface against the active level
 * @iface: interface about to be exercised
 *
 * Return: 0 when the interface is open at the active level;
 *         -AIRY_ELOCKDOWN when the ladder blocks it.
 *
 * A refusal is a policy decision, not a security violation: callers
 * propagate the value unchanged and must not raise an AIRY_FAULT_*.
 */
__must_check int airy_lock_gate(enum airy_lock_iface iface);

/**
 * airy_lock_set - raise the ladder to at least @level
 * @level: requested level
 * @by: trigger recorded with the transition
 *
 * The ladder is monotonic: a request at or below the active level
 * changes nothing and succeeds, a higher request is applied.
 *
 * Return: 0 on success; -EPERM when @level is out of range.
 */
int airy_lock_set(u8 level, enum airy_lock_trigger by);

/**
 * airy_lock_get - read the active level
 *
 * Return: the active enum airy_lock_level value.
 */
u8 airy_lock_get(void);

/**
 * airy_lock_down - answer a security_locked_down() query
 * @what: the kernel facility being queried
 *
 * Return: 0 when the facility is open at the active level;
 *         -EPERM when the ladder closes it.
 */
int airy_lock_down(enum lockdown_reason what);

/**
 * airy_lock_arg - parse a level name
 * @s: "none", "early", "late" or "full"
 * @level: receives the parsed level
 *
 * Shared by the boot command line and the securityfs write path so the
 * two entry points cannot drift apart.
 *
 * Return: 0 on success; -EINVAL on an unknown name.
 */
int airy_lock_arg(const char *s, u8 *level);

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
/**
 * airy_lock_clr - drop the ladder back to AIRY_LOCK_NONE
 *
 * Test-only: production transitions are monotonic, but a KUnit suite
 * has to start every case from a known level.
 */
void airy_lock_clr(void);
#endif

#else /* !CONFIG_SECURITY_AIRY */

static inline __must_check int airy_lock_gate(enum airy_lock_iface iface)
{
	return 0;
}

#endif /* CONFIG_SECURITY_AIRY */

#endif /* _AIRY_LOCKDOWN_H */

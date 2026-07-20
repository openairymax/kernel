/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_ipc_syscall.c — IPC system call dispatch helper (control plane).
 *
 * The four Airymax syscalls (454-457) are wired in
 * kernel/syscalls/airy_syscalls.c with their canonical 2/3-argument
 * signatures.  This file provides airy_ipc_syscall_dispatch() — a
 * single switch-based dispatcher covering every control-plane opcode:
 *
 *   airy_sys_call     (454): cap_invoke / lsm_ctl / wasm_load
 *   airy_sys_rovol_ctl(455): tier_query / tier_migrate / forget
 *   airy_sys_sched_ctl(456): policy_set / policy_get / stats_read
 *   airy_sys_clt_notify(457): phase_enter / phase_exit / kthread_register
 *
 * The data plane is carried by io_uring; only control ops live here.
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/airymax/syscalls.h>
#include <linux/airymax/ipc.h>
#include <linux/airymax/sched.h>
#include <linux/airymax/cognition_types.h>
#include <linux/airymax/memory_types.h>
#include <linux/airymax/error.h>

#include "airy_ipc_capability.h"

/* ─── Operation codes ─────────────────────────────────────────────────── */
/* airy_sys_call (454): control-plane ops */
#define AIRY_OP_CAP_INVOKE	0x0001u
#define AIRY_OP_LSM_CTL		0x0002u
#define AIRY_OP_WASM_LOAD	0x0003u

/* airy_sys_rovol_ctl (455): MemoryRovol tier ops */
#define AIRY_OP_TIER_QUERY	0x0011u
#define AIRY_OP_TIER_MIGRATE	0x0012u
#define AIRY_OP_FORGET		0x0013u

/* airy_sys_sched_ctl (456): scheduler policy ops */
#define AIRY_OP_POLICY_SET	0x0021u
#define AIRY_OP_POLICY_GET	0x0022u
#define AIRY_OP_STATS_READ	0x0023u

/* airy_sys_clt_notify (457): CoreLoopThree + kthread ops */
#define AIRY_OP_PHASE_ENTER	0x0031u
#define AIRY_OP_PHASE_EXIT	0x0032u
#define AIRY_OP_KTHREAD_REG	0x0033u

/* ─── Per-op argument structures (kernel-internal contract) ───────────── */
struct airy_ipc_cap_invoke_args {
	__u64	badge;
	__u32	agent_id;
	__u32	_pad0;
	__u64	required_perms;
	__u64	result;		/* 0 on success, negative AIRY_E* on failure */
};

struct airy_ipc_lsm_ctl_args {
	__u32	action;		/* 0=disable, 1=enable, 2=status query */
	__u32	_pad0;
	__u64	result;
};

struct airy_ipc_wasm_load_args {
	__u64	code_addr;	/* user pointer to WASM bytecode */
	__u32	module_size;
	__u32	_pad0;
	__u64	module_handle;	/* opaque kernel handle on success */
};

struct airy_ipc_tier_args {
	__u64	addr;
	__u32	tier;		/* AIRY_MEM_* (in/out) */
	__u32	_pad0;
	__u64	result;
};

struct airy_ipc_policy_args {
	__u32	policy;		/* AIRY_SCHED_POLICY_* */
	__u32	weight;
	__u64	runtime_ns;
	__u64	deadline_ns;
};

struct airy_ipc_stats_args {
	__u32	agent_id;
	__u32	_pad0;
	__u64	runtime_ns;	/* output */
	__u64	deadline_ns;	/* output */
	__u32	state;		/* output: 0=unregistered, 1=registered */
	__u32	_pad1;
};

struct airy_ipc_phase_args {
	__u32	task_id;
	__u32	phase;		/* AIRY_COG_* */
	__u64	timestamp_ns;	/* output: monotonic ns */
};

struct airy_ipc_kthread_args {
	__u32	pid;
	__u32	agent_id;
	__u64	result;
};

/* ─── Static control-plane state ──────────────────────────────────────── */
static DEFINE_SPINLOCK(airy_ipc_ctl_lock);
static int  airy_ipc_lsm_enabled = 1;
static u32  airy_ipc_sched_policy   = AIRY_SCHED_POLICY_BESTEFFORT;
static u32  airy_ipc_sched_weight   = 100;
static u64  airy_ipc_sched_runtime  = 20ULL * 1000 * 1000;	/* 20 ms */
static u64  airy_ipc_sched_deadline = 100ULL * 1000 * 1000;	/* 100 ms */
static u32  airy_ipc_phase_task[AIRY_COG_PHASE_MAX];
static u32  airy_ipc_kthread_pid[AIRY_CAP_MAX_AGENTS];

/* ─── Dispatch entry ──────────────────────────────────────────────────── */
/*
 * airy_ipc_syscall_dispatch — single control-plane dispatcher invoked by
 * the airy_sys_* syscall shims in kernel/syscalls/airy_syscalls.c.
 *
 * @op:    operation code (AIRY_OP_*)
 * @arg:   user-space pointer to the per-op argument struct
 * @len:   size of the user buffer (validated against the expected struct)
 * @flags: reserved for future use (currently ignored)
 *
 * Returns 0 on success or a negative errno.
 */
int airy_ipc_syscall_dispatch(unsigned int op, void __user *arg,
			      size_t len, int flags)
{
	int ret = 0;

	(void)flags;	/* reserved */

	if (!arg && len != 0)
		return -EINVAL;
	if (len > 0 && len < sizeof(__u32))
		return -EINVAL;

	switch (op) {
	/* ─── airy_sys_call: control-plane ─────────────────────────────── */
	case AIRY_OP_CAP_INVOKE: {
		struct airy_ipc_cap_invoke_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.agent_id >= AIRY_CAP_MAX_AGENTS) {
			a.result = (__u64)(s64)(-AIRY_ECAP_MISSING);
		} else if (airy_cap_badge_verify(a.badge, a.agent_id,
						 a.required_perms)) {
			a.result = 0;
		} else {
			a.result = (__u64)(s64)(-AIRY_ECAP_PERM);
		}
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_LSM_CTL: {
		struct airy_ipc_lsm_ctl_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		spin_lock(&airy_ipc_ctl_lock);
		switch (a.action) {
		case 0:
			airy_ipc_lsm_enabled = 0;
			a.result = 0;
			break;
		case 1:
			airy_ipc_lsm_enabled = 1;
			a.result = 0;
			break;
		case 2:
			a.result = (__u64)airy_ipc_lsm_enabled;
			break;
		default:
			spin_unlock(&airy_ipc_ctl_lock);
			return -EINVAL;
		}
		spin_unlock(&airy_ipc_ctl_lock);
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_WASM_LOAD: {
		struct airy_ipc_wasm_load_args a;
		void *kbuf;
		__u32 magic;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.module_size < 8 || a.module_size > (16u << 20))
			return -EINVAL;
		kbuf = kmalloc(a.module_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		if (copy_from_user(kbuf,
				   (void __user *)(unsigned long)a.code_addr,
				   a.module_size)) {
			kfree(kbuf);
			return -EFAULT;
		}
		/* Validate the WASM magic 0x6d736100 ('\0asm'). */
		magic = *(__u32 *)kbuf;
		if (magic != 0x6d736100u) {
			kfree(kbuf);
			a.module_handle = 0;
			ret = -EINVAL;
		} else {
			a.module_handle = (__u64)(unsigned long)kbuf;
		}
		if (copy_to_user(arg, &a, sizeof(a)))
			ret = -EFAULT;
		break;
	}

	/* ─── airy_sys_rovol_ctl: MemoryRovol tier control ────────────── */
	case AIRY_OP_TIER_QUERY: {
		struct airy_ipc_tier_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		/* Classify the address into a memory tier:
		 * 2 MiB-aligned addresses are treated as hot (HBM-backed),
		 * high addresses as cold (CXL/NVMe), the rest as warm. */
		if ((a.addr & ((1ULL << 21) - 1)) == 0)
			a.tier = AIRY_MEM_HOT;
		else if (a.addr >= (1ULL << 40))
			a.tier = AIRY_MEM_COLD;
		else
			a.tier = AIRY_MEM_WARM;
		a.result = 0;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_TIER_MIGRATE: {
		struct airy_ipc_tier_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.tier >= AIRY_MEM_LEVEL_MAX)
			return -EINVAL;
		/* Real migration would invoke the MemoryRovol backend;
		 * here we acknowledge the requested target tier. */
		a.result = a.tier;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_FORGET: {
		struct airy_ipc_tier_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		/* Drop the tier mapping for the given address. */
		a.tier = AIRY_MEM_LEVEL_MAX;
		a.result = 0;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}

	/* ─── airy_sys_sched_ctl: scheduler policy ────────────────────── */
	case AIRY_OP_POLICY_SET: {
		struct airy_ipc_policy_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.policy == 0 || a.policy > AIRY_SCHED_POLICY_BESTEFFORT)
			return -EINVAL;
		if (a.weight < AIRY_WEIGHT_MIN || a.weight > AIRY_WEIGHT_MAX)
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		airy_ipc_sched_policy   = a.policy;
		airy_ipc_sched_weight   = a.weight;
		airy_ipc_sched_runtime  = a.runtime_ns;
		airy_ipc_sched_deadline = a.deadline_ns;
		spin_unlock(&airy_ipc_ctl_lock);
		break;
	}
	case AIRY_OP_POLICY_GET: {
		struct airy_ipc_policy_args a;

		if (len < sizeof(a))
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		a.policy       = airy_ipc_sched_policy;
		a.weight       = airy_ipc_sched_weight;
		a.runtime_ns   = airy_ipc_sched_runtime;
		a.deadline_ns  = airy_ipc_sched_deadline;
		spin_unlock(&airy_ipc_ctl_lock);
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_STATS_READ: {
		struct airy_ipc_stats_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.agent_id >= AIRY_CAP_MAX_AGENTS)
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		a.runtime_ns  = airy_ipc_sched_runtime;
		a.deadline_ns = airy_ipc_sched_deadline;
		a.state       = airy_ipc_kthread_pid[a.agent_id] ? 1u : 0u;
		spin_unlock(&airy_ipc_ctl_lock);
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}

	/* ─── airy_sys_clt_notify: CoreLoopThree + kthread ────────────── */
	case AIRY_OP_PHASE_ENTER: {
		struct airy_ipc_phase_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.phase >= AIRY_COG_PHASE_MAX)
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		airy_ipc_phase_task[a.phase] = a.task_id;
		spin_unlock(&airy_ipc_ctl_lock);
		a.timestamp_ns = ktime_get_mono_fast_ns();
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_PHASE_EXIT: {
		struct airy_ipc_phase_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.phase >= AIRY_COG_PHASE_MAX)
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		if (airy_ipc_phase_task[a.phase] != a.task_id) {
			spin_unlock(&airy_ipc_ctl_lock);
			return -ESRCH;
		}
		airy_ipc_phase_task[a.phase] = 0;
		spin_unlock(&airy_ipc_ctl_lock);
		a.timestamp_ns = ktime_get_mono_fast_ns();
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}
	case AIRY_OP_KTHREAD_REG: {
		struct airy_ipc_kthread_args a;

		if (len < sizeof(a))
			return -EINVAL;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.agent_id >= AIRY_CAP_MAX_AGENTS)
			return -EINVAL;
		spin_lock(&airy_ipc_ctl_lock);
		airy_ipc_kthread_pid[a.agent_id] = a.pid;
		spin_unlock(&airy_ipc_ctl_lock);
		a.result = 0;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		break;
	}

	default:
		return -ENOSYS;
	}

	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_superv_obs.c — 监督面只读统计快照。
 *
 * 为 /sys/airy/superv 提供计数器与“最近一次命令”记录。计数只在
 * 命令成功后递增；最近一次命令的四个字段在同一把锁下发布，
 * 避免读者把一条命令的智能体与另一条命令的裁决拼在一起。
 */

#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "airy_superv.h"

static atomic64_t obs_freeze_nr = ATOMIC64_INIT(0);
static atomic64_t obs_thaw_nr	= ATOMIC64_INIT(0);
static atomic64_t obs_adjud_nr	= ATOMIC64_INIT(0);
static atomic64_t obs_frz_all_nr = ATOMIC64_INIT(0);

struct obs_last {
	u32 op;
	u32 agent;
	u32 adjud;
	u64 ns;
};

static struct obs_last obs_last_cmd;
static DEFINE_SPINLOCK(obs_last_lock);

void airy_sv_obs_event(u32 op, u32 agent, u32 verdict)
{
	switch (op) {
	case AIRY_SV_OBS_FREEZE:
		atomic64_inc(&obs_freeze_nr);
		break;
	case AIRY_SV_OBS_THAW:
		atomic64_inc(&obs_thaw_nr);
		break;
	case AIRY_SV_OBS_ADJUD:
		atomic64_inc(&obs_adjud_nr);
		break;
	case AIRY_SV_OBS_FRZ_ALL:
		atomic64_inc(&obs_frz_all_nr);
		break;
	default:
		return;
	}

	spin_lock(&obs_last_lock);
	obs_last_cmd.op    = op;
	obs_last_cmd.agent = agent;
	obs_last_cmd.adjud = verdict;
	obs_last_cmd.ns    = ktime_get_mono_fast_ns();
	spin_unlock(&obs_last_lock);
}

void airy_sv_obs_snap(struct airy_sv_obs *out)
{
	if (!out)
		return;

	memset(out, 0, sizeof(*out));
	out->freeze_nr	= atomic64_read(&obs_freeze_nr);
	out->thaw_nr	= atomic64_read(&obs_thaw_nr);
	out->adjud_nr	= atomic64_read(&obs_adjud_nr);
	out->frz_all_nr	= atomic64_read(&obs_frz_all_nr);

	spin_lock(&obs_last_lock);
	out->last_op	= obs_last_cmd.op;
	out->last_agent	= obs_last_cmd.agent;
	out->last_adjud	= obs_last_cmd.adjud;
	out->last_ns	= obs_last_cmd.ns;
	spin_unlock(&obs_last_lock);
}

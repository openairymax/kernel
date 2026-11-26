// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_obs_sec.c — /sys/airy/sec 安全面统计。
 *
 * 两个文件都只聚合已有计数器：策略表的判定计数来自 airy_policy.c，
 * 能力表规模来自 agent_caps[]，故障明细的丢失数来自 A-UEF 环。
 * 这里不引入新的计量点，避免观测值与执行路径出现两份真相。
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/seq_buf.h>
#include <linux/sysfs.h>

#include <linux/airymax/lsm_types.h>
#include <airymax/airy_policy.h>

#include "../../security/airy/airy_cap.h"
#include "airy_obs.h"

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct airy_pol_cnt total = { };
	struct airy_pol_cnt cur;
	unsigned int agents = 0;
	u8 slot;
	int i;

	for (slot = 0; slot < AIRY_POLICY_MAX_TABLES; slot++) {
		airy_pol_stat(slot, &cur);
		total.evals	+= cur.evals;
		total.allow	+= cur.allow;
		total.deny	+= cur.deny;
		total.audit	+= cur.audit;
		total.complain	+= cur.complain;
		total.fault	+= cur.fault;
	}

	for (i = 0; i < AIRY_CAP_MAX_AGENTS; i++) {
		if (airy_cap_lookup(i))
			agents++;
	}

	return sysfs_emit(buf,
			  "evaluations: %llu\n"
			  "allow: %llu\n"
			  "deny: %llu\n"
			  "audit: %llu\n"
			  "complain: %llu\n"
			  "fault: %llu\n"
			  "agents: %u\n"
			  "epoch: %d\n"
			  "faults_lost: %u\n",
			  total.evals, total.allow, total.deny, total.audit,
			  total.complain, total.fault, agents,
			  atomic_read(&airy_cap_global_epoch),
			  airy_fev_lost());
}

static ssize_t lsm_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "enabled: %d\nhooks: %u\nsuperv_hooks: %u\n",
			  airy_lsm_enabled(),
			  (unsigned int)AIRY_LSM_HOOK_IMPLEMENTED,
			  airy_superv_hook_count());
}

/**
 * airy_obs_cap_fmt - Format one capability slot as a single text line.
 * @buf: Destination buffer.
 * @len: Capacity of @buf in bytes.
 * @id: Agent id owning the slot.
 * @slot: Slot snapshot, already copied out of the bucket lock.
 *
 * The random tag is deliberately omitted: it is the anti-forgery secret
 * that makes a badge valid, so no observation surface may echo it.
 */
void airy_obs_cap_fmt(char *buf, size_t len, u32 id,
		      const struct airy_cap_slot *slot)
{
	struct seq_buf sb;

	if (!len)
		return;

	seq_buf_init(&sb, buf, (unsigned int)len);
	seq_buf_printf(&sb,
		       "agent %u: perms=0x%04x epoch=%u flags=0x%08x gen=%u parent=%u\n",
		       id, slot->perms, slot->epoch, slot->flags,
		       slot->generation, slot->parent_agent);
	seq_buf_str(&sb);
}

/*
 * 权限位与名字一一对应，顺序与 UAPI 的 AIRY_CAP_PERM_* 保持一致：
 * 新增权限位时必须同时补在这里，否则 sysfs 认不出这一位。
 */
static const struct {
	u16 bit;
	const char *name;
} obs_perm_names[] = {
	{ AIRY_CAP_PERM_SEND,		"SEND" },
	{ AIRY_CAP_PERM_RECV,		"RECV" },
	{ AIRY_CAP_PERM_DERIVE,		"DERIVE" },
	{ AIRY_CAP_PERM_KILL,		"KILL" },
	{ AIRY_CAP_PERM_FILE_OPEN,	"FILE_OPEN" },
	{ AIRY_CAP_PERM_ROTATE,		"ROTATE" },
	{ AIRY_CAP_PERM_SUPERVISE,	"SUPERVISE" },
};

/**
 * airy_obs_cap_perms - Render a permission mask as pipe-separated names.
 * @buf: Destination buffer.
 * @len: Capacity of @buf in bytes.
 * @perms: Permission bits of one slot.
 *
 * A slot with no bit set renders as NONE, so the reader can tell "no
 * permission" from a truncated line.  Bits unknown to this table are
 * ignored; the raw mask stays available in the debugfs cap table.
 */
void airy_obs_cap_perms(char *buf, size_t len, u16 perms)
{
	struct seq_buf sb;
	bool first = true;
	unsigned int i;

	if (!len)
		return;

	seq_buf_init(&sb, buf, (unsigned int)len);

	if (!perms) {
		seq_buf_puts(&sb, "NONE");
	} else {
		for (i = 0; i < ARRAY_SIZE(obs_perm_names); i++) {
			if (!(perms & obs_perm_names[i].bit))
				continue;
			if (!first)
				seq_buf_puts(&sb, "|");
			seq_buf_puts(&sb, obs_perm_names[i].name);
			first = false;
		}
		/* 只剩保留位：UAPI 不允许授予，按"无已知权限"呈现。 */
		if (first)
			seq_buf_puts(&sb, "NONE");
	}

	seq_buf_str(&sb);
}

static const struct airy_obs_attr sec_attrs[] = {
	AIRY_OBS_ATTR(stats),
	AIRY_OBS_ATTR(lsm),
};

int airy_obs_sec_init(struct kobject *root)
{
	return airy_obs_register(root, "sec", sec_attrs,
				 ARRAY_SIZE(sec_attrs));
}

#if IS_ENABLED(CONFIG_AIRY_KUNIT)
const struct airy_obs_attr *airy_obs_sec_attrs(unsigned int *nr)
{
	*nr = ARRAY_SIZE(sec_attrs);
	return sec_attrs;
}
#endif

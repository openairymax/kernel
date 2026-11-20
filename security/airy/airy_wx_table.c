// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_wx_table.c — W^X 例外表，由 ci/tools/wx-table-gen.py 生成。
 *
 * 不要手改本文件：唯一可编辑源是 distro/lockfile/wx-exceptions.toml，
 * CI 以 wx-table-gen.py --check 逐字节断言两者一致。
 *
 * 表只装 ALLOW 行：命中的请求由拒绝转为受理；未命中落回
 * default_verdict = DENY，因此空清单也是 fail-closed 的，而每一条例外
 * 都能在同一处被评审。
 *
 * SSoT: 110-security/10-policy-compiler.md §7;
 *       0.0.5 施工图纸 §14.11。
 */

#include <linux/kernel.h>

#include <linux/airymax/security_types.h>
#include <airymax/airy_policy.h>

static const char *const wx_flds[] = {
	"req_prot",
	"old_prot",
	"agent_id",
};

/*
 * 源清单为空：唯一的行不设谓词并给出 DENY，与 default_verdict 相同。
 * 注册面要求 row_count 非零（airy_policy.c 的 pol_meta_ok()），空数组
 * 表达不了「表存在但没有例外」，因此保留这一行。
 */
static const struct airy_policy_row wx_rows[] = {
	{ .conds = NULL, .cond_count = 0,
	  .verdict = AIRY_VERDICT_DENY, .fault = 0 },
};

const struct airy_policy_table airy_wx_table = {
	.name = "wx-exceptions",
	.hook = "file_mprotect",
	.rows = wx_rows,
	.row_count = ARRAY_SIZE(wx_rows),
	.field_count = ARRAY_SIZE(wx_flds),
	.field_names = wx_flds,
	.default_verdict = AIRY_VERDICT_DENY,
};

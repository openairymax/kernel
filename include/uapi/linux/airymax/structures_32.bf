-- SPDX-License-Identifier: GPL-2.0-only
-- Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
--
-- structures_32.bf — 32-bit 位域契约源（R-02 SSoT）
-- 物理宿主: kernel/include/uapi/linux/airymax/structures_32.bf
-- 生成器:   tools/codegen/bitfield_gen.py
-- 生成产物: kernel/include/uapi/linux/airymax/structures_32_gen.h（禁止手工修改）
--
-- .bf DSL 速查（06-codegen-pipeline.md §3.2）:
--   block <name>(<width_bits>) { ... }   声明位宽为 width 的位域块
--   bind struct <ctype> from <header>    绑定到 [SC] 头中的结构体（生成访问层）
--   bind word <ctype>                    绑定到原生字容器类型
--   field <name> <high>..<low>           可读写字段（生成 get + set）
--   field_high <name> <high>..<low>      高位字段（布局提示，语义同 field）
--   mask <name> <high>..<low>            只读掩码字段（仅生成 get）
--   padding [<name>] <high>..<low>       填充位（不生成访问器）
--   pivot <name>                         联合体判别字段（须引用已有字段）
--
-- 说明: 位宽单位为「位」(bits)；struct 容器要求字段按字节对齐，
--       word 容器字段为原生字内子位域；本文件布局须与 structures_64.bf
--       逐位一致（由 bitfield_gen.py 强制跨文件一致性校验）。

-- IPC 128 字节定长消息头位域（与 ipc.h struct airy_ipc_msg_hdr 逐字节对齐）
-- D-9 修复后字段顺序：capability_badge 前移至 offset 40 恢复 8 字节自然对齐
-- magic 0x41524531 'ARE1' 由 ipc_gen.py 注入，此处仅定义位域布局
block ipc_msg_hdr(1024) {
    bind struct airy_ipc_msg_hdr from linux/airymax/ipc.h
    field magic             31..0       -- offset 0,  4B, 魔数 'ARE1'
    field opcode            47..32      -- offset 4,  2B, SQE/CQE 操作码
    field flags             63..48      -- offset 6,  2B, 标志位
    field trace_id          127..64     -- offset 8,  8B, OpenTelemetry trace ID
    field timestamp_ns      191..128    -- offset 16, 8B, 纳秒时间戳
    field src_task          255..192    -- offset 24, 8B, 源任务 ID
    field dst_task          319..256    -- offset 32, 8B, 目标任务 ID
    field capability_badge  383..320    -- offset 40, 8B, [SS] Capability Badge (D-9)
    field payload_len       415..384    -- offset 48, 4B, payload 字节数
    field crc32             447..416    -- offset 52, 4B, CRC32 校验
    padding reserved        1023..448   -- offset 56, 72B, 保留字段 (CL1 + CL2)
}

-- Capability Badge 位布局（[SC] ipc.h: Epoch<<48 | RandTag<<16 | Perms）
-- 64 位 Native Word Badge（Capability Folding，fastpath C-S9 内联校验）
block cap_badge(64) {
    bind word __u64
    field perms          15..0       -- 权限位（AIRY_CAP_PERM_*）
    field randtag        47..16      -- 随机标签（32 位）
    field epoch          63..48      -- 时代号（16 位）
}

-- 任务描述符位域（magic 0x41475453 'AGTS'）
-- 11 字段，对齐 [SC] sched.h struct airy_task_desc（64B）
block task_desc(512) {
    bind struct airy_task_desc from linux/airymax/sched.h
    field magic          31..0       -- 'AGTS' 0x41475453
    field prio           47..32      -- 优先级 0-139
    field _pad           63..48      -- 对齐填充
    field runtime_ns     127..64     -- runtime 预算（ns）
    field deadline_ns    191..128    -- 截止时间（ns）
    field period_ns      255..192    -- 周期（ns）
    field vtime          287..256    -- Q16.16 定点虚拟时间
    field agent_id       319..288    -- agent 标识 [0,1023]
    field sched_policy   351..320    -- AIRY_SCHED_POLICY_*
    field weight         383..352    -- EEVDF 权重
    field state          415..384    -- 生命周期状态
    padding _reserved    511..416    -- 保留 12B（offset 52）
}

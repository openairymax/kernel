<!-- SPDX-License-Identifier: GPL-2.0-only -->

<!--
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * README_zh.md — 极境内核（ALK-6.6）中文说明
 *
 * 本文件是极境内核的专门描述文档，与英文 README（保留 Linux 上游原样）
 * 不同，本文档系统性地介绍 Airymax 在 Linux 6.6.144 LTS 之上进行的
 * 微内核化改造、目录组织、关键技术与构建方式，便于开发者快速、准确的理解极境内核的物理形态与工程取向。
 *
 * 权威源：docs/AirymaxOS/10-architecture/00-alk-kernel-overview.md (v1.0.1)
 * 对应代码：agentrt-linux/kernel/（Linux 6.6.144 LTS 完整 fork + 增量改造）
-->

# Airymax Kernel 极境内核（ALK-6.6）

> 定位：在 Linux 6.6 完整内核之上，借鉴 seL4 的微内核工程思想，进行微内核化改造的**智能体原生操作系统**内核。  
> 设计：基于开源极境团队发布的**策略内核 Policy Kernel**进行设计。   

| 维度       | 值                                           |
| -------- | ------------------------------------------- |
| **上游基线** | Linux 6.6.144 LTS                           |
| **改造方式** | 完整 git fork + 增量添加。不修改主线源码                  |
| **思想来源** | seL4                                        |
| **技术路线** | 基于 Linux 改造，非从零开发微内核                        |
| **版本基线** | 1.x.x 锁定 Linux 6.6 LTS / 2.x.x 锁定 Linux 7.1 |
| **当前版本** | v1.0.1                                      |
| **维护者**  | 开源极境工程与规范委员会                                |

***

## 一、设计哲学

极境内核不是全量改动 Linux 内核，而是"在 Linux 6.6 LTS 之上增量添加 agentrt-linux 所需的内核能力"。

所有 Airymax 代码必须在新增目录中，与主线源码物理隔离。

### 1.1 三大设计支柱

| 支柱                 | 内容                                                  | 物理载体                                                     |
| -------------------- | --------------------------------------------------- | -------------------------------------------------------- |
| **微内核化改造**         | 遵循 Liedtke 最小性原则；内核核心代码预算 5-10 万行；改造补丁控制在 2 万行以内    | `kernel/corekern/` + `kernel/superv/` + `security/airy/` |
| **Linux 6.6 工程基线** | 复用上游成熟的调度、内存、网络、文件系统基础设施，不做无谓重新发明                   | 完整保留 Linux 6.6 主线源码                                      |
| **Agent 原生设计**     | 调度器感知 Agent 优先级与截止时间；IPC 专为高频小消息设计；安全模型面向多 Agent 隔离 | `sched_tac` + `io_uring` + `Capability Folding`          |

### 1.2 Liedtke 最小性原则的极境诠释

**seL4 工程验证**：真正的"微内核必需代码"约 1.44 万行 C，五大内核对象（TCB + CNode + Endpoint + Notification + Untyped）合计仅约 4,353 行。  

> "A concept is tolerated inside the microkernel only if moving it outside the kernel, i.e., permitting competing implementations, would prevent the implementation of the system's required functionality." — Jochen Liedtke  

**极境内核的诠释**：不从零开发微内核，因此"极简"不意味着将 Linux 缩减到 1.44 万行，而是遵循以下体量控制策略：

| 维度          | seL4 基线           | ALK-6.6 预算            | 控制策略                                  |
| ----------- | ----------------- | --------------------- | ------------------------------------- |
| 内核核心代码      | \~1.44 万行         | 5-10 万行（含 agent 调度原语） | 每新增子系统需论证"无法在用户态安全实现"                 |
| 微内核化改造补丁    | —                 | 控制在 2 万行以内            | VFS / 网络栈 / 驱动用户态化补丁                  |
| \[SC] 共享契约层 | —                 | 10 个头文件（IRON-9 v3）    | 单一物理宿主，禁止重复定义                         |
| Syscall 数量  | 7（非 MCS）/ 11（MCS） | 4 核心 + 20 预留 = 24 槽位  | Capability Folding 后 IPC 数据面零 syscall |

### 1.3 机制与策略分离

| 机制（内核态）            | 策略（用户态）         | 落地方式                                                  |
| ------------------ | --------------- | ----------------------------------------------------- |
| `sched_tac` 框架     | Agent 调度策略      | SCHED\_DEADLINE / SCHED\_FIFO / EEVDF 调度类组合在内核，策略在用户态 |
| `io_uring` ring 机制 | IPC 路由策略        | 12 daemons 在用户态路由                                     |
| Capability 令牌验证    | Capability 授权策略 | `sec_d` 守护进程                                          |

***

## 二、十大不可妥协技术原则（IRON 铁律）

| #  | 原则                               | 说明                                                        |
| -- | -------------------------------- | --------------------------------------------------------- |
| 1  | 调度原语在内核，调度策略在用户态                 | 内核只提供 EEVDF + sched\_tac 原语，策略配置由用户态 daemon 决定            |
| 2  | IPC 是唯一的跨进程通信通道                  | 不引入额外的 RPC 层或通信协议；所有 daemon 间通信通过 io\_uring SQE/CQ ring   |
| 3  | 能力（Capability）是唯一的权限模型           | 不依赖 UID/GID 或 SELinux 上下文进行进程间授权                          |
| 4  | 内核最小化                            | 用户态可实现的功能不下沉到内核态                                          |
| 5  | 同源优先                             | 与 agentrt 共享架构设计，通过 IRON-9 v3 保持互操作                       |
| 6  | \[SC] 共享契约层不可破坏                  | 任何违反 `include/uapi/linux/airymax/` 契约的代码禁止合并              |
| 7  | 不引入实验性上游特性                       | 所有技术选型锁定在 Linux 6.6 稳定接口                                  |
| 8  | 版本基线锁定                           | 0.1.1 后直接 1.0.1，禁止 0.1.2/0.2.0/1.0.0 中间过渡版本               |
| 9  | 最小完备集                            | 每个子系统接口数量精简到极致（syscall 24 槽位、IPC opcode 7 个、CNode 操作 7 个） |
| 10 | Capability Folding 是唯一 IPC 数据面路径 | 控制面与数据面分离，fastpath 内联校验                                   |

***

## 三、物理形态定义

### 3.1 ALK-6.6 等式

```
ALK-6.6
  = Linux 6.6.144 LTS 完整 fork（不修改主线源码）
  + 新增 [SC] 共享契约层 10 个 UAPI 头文件
  + 新增 security/airy/ 纯 C LSM 模块（14 文件）
  + 新增 kernel/superv/ Micro-Supervisor 内核模块（6 文件）
  + 新增 kernel/syscalls/ 4 个 Airymax syscall（编号 454-457）
  + 新增 kernel/corekern/ 微核心抽象层（10 子目录，22 文件）
  + 新增 kernel/log/ A-ULP 内核侧（4 文件）
  + 新增 kernel/ipc/ A-IPC 内核基础设施（4 文件）
  + 新增 include/airymax/ 构建内部类型（2 头文件）
  + 新增 config/Kconfig.alk ALK 顶层 Kconfig 入口
  + 新增 configs/ 预置配置（3 fragment + hardening.config）
  + 新增 arch/{x86,arm64,riscv,loongarch}/configs/airy_defconfig
  + 复用 io_uring IORING_OP_URING_CMD（不新增 opcode）
  + 复用 SCHED_DEADLINE / SCHED_FIFO / EEVDF（不新增调度类）
  + 复用 MGLRU / userfaultfd / alloc_pages（不修改 mm/）
```

### 3.2 与 vanilla Linux 6.6 的差异矩阵

| #  | 维度                                            | vanilla 6.6.144 | ALK-6.6                   |       修改主线？      |
| -- | --------------------------------------------- | --------------- | ------------------------- | :--------------: |
| 1  | `include/uapi/linux/airymax/`                 | 不存在             | 新增 10 头文件                 |         否        |
| 2  | `include/airymax/`                            | 不存在             | 新增 2 内部类型                 |         否        |
| 3  | `security/airy/`                              | 不存在             | 新增 14 文件纯 C LSM           |         否        |
| 4  | `kernel/superv/`                              | 不存在             | 新增 6 文件 Micro-Supervisor  |         否        |
| 5  | `kernel/syscalls/airy_syscalls.c`             | 不存在             | 新增 4 syscall（454-457）     |         否        |
| 6  | `kernel/corekern/`                            | 不存在             | 新增 10 子目录 22 文件微核心抽象层     |         否        |
| 7  | `kernel/log/`                                 | 不存在             | 新增 4 文件 A-ULP 内核侧         |         否        |
| 8  | `kernel/ipc/`                                 | 不存在             | 新增 4 文件 A-IPC 内核基础设施      |         否        |
| 9  | `configs/`                                    | 不存在             | 新增 4 fragment             |         否        |
| 10 | `arch/*/configs/airy_defconfig`               | 不存在             | 新增 4 架构 defconfig         |         否        |
| 11 | `include/uapi/asm-generic/unistd.h`           | vanilla 原样      | 扩展 4 syscall 编号 454-457   | **是**（仅扩展，不修改已有） |
| 12 | `kernel/`、`mm/`、`net/`、`drivers/` 等           | vanilla 原样      | 不修改                       |         否        |
| 13 | `security/selinux/`、`apparmor/`、`landlock/` 等 | vanilla 原样      | 不修改                       |         否        |
| 14 | `io_uring/`                                   | vanilla 原样      | 复用 IORING\_OP\_URING\_CMD |         否        |

**唯一的主线文件扩展**：`include/uapi/asm-generic/unistd.h` 新增 4 个 syscall 编号条目（454-457，避开 x32 历史占用区间 512-547），不修改已有条目。这是 Linux 内核标准的 syscall 注册方式，符合上游规范。

***

## 四、目录结构

> 以下仅列出 Airymax 专属代码路径。本仓是 Linux 6.6 完整内核树，其余目录（`arch/`、`block/`、`crypto/`、`drivers/`、`fs/`、`mm/`、`net/` 等）为标准上游代码，不修改。

```
agentrt-linux/kernel/                              # Linux 6.6.144 LTS fork
│
├── 【Linux 6.6 主线源码（不修改，OS-ARCH-001 约束）】
│   ├── arch/  block/  certs/  crypto/  drivers/
│   ├── fs/  init/  ipc/  kernel/  lib/  mm/  net/
│   ├── security/  sound/  tools/  usr/  virt/
│   ├── io_uring/  include/
│   └── Kbuild  Kconfig  Makefile  COPYING  CREDITS  MAINTAINERS
│
├── 【Airymax 增量内容（新增，不修改主线）】
│   │
│   ├── init/airy_core.c                           # ALK 启动入口（late_initcall）
│   │
│   ├── include/uapi/linux/airymax/                # ★ [SC] 共享契约层（10 头文件）
│   │   ├── error.h                                #   A-UEF 错误码 / Fault 码
│   │   ├── log_types.h                            #   A-ULP 日志类型（128B 记录 + 5 级枚举）
│   │   ├── ipc.h                                  #   A-IPC 128B 消息头（magic 0x41524531）
│   │   ├── sched.h                                #   A-ULS 调度类型（task_desc 12B + vtime Q16.16）
│   │   ├── memory_types.h                         #   MemoryRovol L1-L4 数据结构
│   │   ├── security_types.h                       #   Capability 41 ID + Badge 64-bit
│   │   ├── cognition_types.h                      #   CoreLoopThree 三阶段枚举
│   │   ├── syscalls.h                             #   4 核心 + 20 预留 syscall
│   │   ├── uapi_compat.h                          #   UAPI 兼容层（三路类型桥接）
│   │   └── lsm_types.h                            #   纯 C LSM 类型契约
│   │      # 每个 [SC] 头文件底部含 #ifdef AIRY_SC_FALLBACK 降级块（[DSL] 降级生存层）
│   │
│   ├── include/airymax/                           # 非 [SC] 内部类型
│   │   ├── build_types.h                          #   构建派生类型
│   │   └── kconfig_types.h                        #   Kconfig 派生类型
│   │
│   ├── security/airy/                             # ★ 纯 C LSM 模块（13 文件）
│   │   ├── Kbuild                                 #   构建配置
│   │   ├── Kconfig                                #   CONFIG_SECURITY_AIRY 定义
│   │   ├── airy_lsm.c                             #   DEFINE_LSM(airy) + 5 核心钩子 + airy_cap_agent_caps_init()
│   │   ├── airy_cap_array.c                       #   静态数组管理（v1.0.1 替代 radix_tree）
│   │   ├── airy_cap_derive.c                      #   seL4 CNode 7 派生操作
│   │   ├── airy_cap_check.c                       #   slowpath 校验
│   │   ├── airy_cap_revoke.c                      #   atomic_inc(&global_epoch) O(1) 撤销
│   │   ├── airy_cap_rotate.c                      #   per-Agent Epoch 轮换
│   │   ├── airy_superv_lsm.c                      #   Micro-Supervisor 5 supplemental 钩子
│   │   ├── airy_ipc_freeze.c                      #   IPC Ring 冻结
│   │   ├── airy_die_notify.c                      #   die_notifier 注册（priority INT_MAX）
│   │   ├── airy_eventfd.c                         #   eventfd 通知 Macro-Supervisor
│   │   └── airy_cap.h                             #   capability 内部头文件（fastpath 内联 + extern 声明）
│   │
│   ├── kernel/superv/                             # ★ Micro-Supervisor（6 文件）
│   │   ├── Kbuild                                 #   构建配置
│   │   ├── airy_superv_lsm.c                      #   Micro-Supervisor 初始化入口（late_initcall）
│   │   ├── airy_cap_check_superv.c                #   fastpath C-S9 Badge 校验（~10ns）
│   │   ├── airy_die_notify_superv.c               #   die_notifier 注册
│   │   ├── airy_eventfd_superv.c                  #   eventfd 通知 Macro-Supervisor
│   │   └── airy_ipc_freeze_superv.c               #   IPC Ring 冻结
│   │      # 注：4 个文件加 _superv 后缀，避免与 security/airy/ 同名冲突（OS-STD-001）
│   │
│   ├── kernel/corekern/                           # ★ 微核心抽象层（10 子目录，22 文件）
│   │   ├── Kbuild                                 #   顶层聚合（obj-y += api/ sched/ ...）
│   │   ├── api/                                   #   聚合初始化入口
│   │   │   ├── airy_kern_api.c                    #     late_initcall(airy_kern_api_init)
│   │   │   └── airy_kern_api.h
│   │   ├── sched/                                 #   sched_tac 4 策略 + 派发
│   │   │   ├── stc_policy.c                       #     STC_POLICY_REALTIME/INTERACTIVE/AGENT/BATCH
│   │   │   ├── stc_dispatch.c                     #     派发到 SCHED_DEADLINE/FIFO/EEVDF
│   │   │   ├── stc_mcs_map.c                      #     seL4 MCS 语义映射
│   │   │   ├── stc_stats.c                        #     atomic_t 统计
│   │   │   └── stc_policy.h
│   │   ├── ipc/                                   #   IPC 内核原语（独立于 kernel/ipc/）
│   │   │   ├── airy_uring_cmd.c                   #     IORING_OP_URING_CMD 处理
│   │   │   ├── airy_ipc_ring.c                    #     Ring Buffer 管理
│   │   │   ├── airy_ipc_fastpath.c                #     unlikely(READ_ONCE(ring->frozen)) 快速路径
│   │   │   ├── airy_ipc_zero_copy.c               #     vm_insert_pages 零拷贝
│   │   │   └── airy_ipc_internal.h                #     共享 struct airy_ipc_ring
│   │   ├── taskflow/                              #   8 态生命周期状态机
│   │   │   ├── airy_task_lifecycle.c              #     INACTIVE→SPAWNING→READY→RUNNING→...→DEAD
│   │   │   └── airy_task_desc.c                   #     magic 0x41475453 校验
│   │   ├── memory/                                #   L1-L4 分层内存
│   │   │   ├── airy_mem_alloc.c                   #     alloc_pages + mmap
│   │   │   └── airy_mem_tier.c                    #     AIRY_MEM_TIER_L1/L2/L3/L4
│   │   ├── time/                                  #   高精度时间戳
│   │   │   └── airy_time.c                        #     ktime_get_ns 包装
│   │   ├── object/                                #   内核对象管理
│   │   │   └── airy_object.c                      #     DEFINE_SPINLOCK + LIST_HEAD
│   │   ├── locking/                               #   自旋锁包装
│   │   │   └── airy_locking.c                     #     spin_lock_nested 包装
│   │   ├── irq/                                   #   IRQ 注册/释放
│   │   │   └── airy_irq.c                         #     request_irq/free_irq
│   │   └── bpf/                                   #   BPF 兼容层（无 BPF 依赖）
│   │       ├── airy_struct_ops.c                  #     struct airy_struct_ops_value
│   │       └── airy_bpf_probe.c                   #     pr_info("%pV") 替代 BPF trace
│   │
│   ├── kernel/log/                                # ★ A-ULP 内核侧（4 文件）
│   │   ├── Kbuild
│   │   ├── airy_log_kern.c                        #   printk 8 级→A-ULP 5 级映射
│   │   ├── airy_log_ring.c                        #   alloc_pages + 128B 记录 Ring Buffer
│   │   └── airy_log_persist.c                     #   filp_open + kernel_write PMEM 持久化
│   │
│   ├── kernel/ipc/                                # ★ A-IPC 内核基础设施（3 文件）
│   │   ├── Kbuild
│   │   ├── airy_ipc_capability.h                  #   slowpath 包装声明，引用 security/airy/airy_cap.h
│   │   └── airy_ipc_capability.c                  #   权威定义 agent_caps[] + airy_cap_global_epoch
│   │
│   ├── kernel/syscalls/                           # ★ 4 新增 syscall（454-457）
│   │   └── airy_syscalls.c                        #   airy_sys_call + airy_sys_rovol_ctl
│   │                                              #   + airy_sys_sched_ctl + airy_sys_clt_notify
│   │
│   ├── config/Kconfig.alk                         # ALK Kconfig 入口（顶层 Kconfig 通过 source 引用）
│   │
│   ├── configs/                                   # ★ 预置配置（4 fragment）
│   │   ├── defconfig                              #   默认基线（5 个 CONFIG_AIRY_*）
│   │   ├── defconfig-agent                        #   Agent 优化（CGROUP/DRM_SCHED/CXL/THP）
│   │   ├── defconfig-embedded                     #   最小化（禁用 AIRY_LOG/AIRY_IPC/BPF/CGROUPS）
│   │   └── hardening.config                       #   安全加固配置
│   │
│   └── arch/{x86,arm64,riscv,loongarch}/configs/  # ★ 4 架构 defconfig fragment
│       └── airy_defconfig
│
└── 【Airymax 工程元数据】
    ├── MAINTAINERS                                #   新增 AIRYMAX SECURITY MODULE 条目
    ├── .github/workflows/ci-kernel.yml            #   CI：32 configs 编译矩阵 + 静态分析
    ├── .github/workflows/ci-airy.yml              #   CI：Airymax 专属验证（4 jobs）
    └── README_zh.md                               #   本文件
```

***

## 五、核心改造技术

### 5.1 调度体系：EEVDF + sched\_tac 三位一体

标准 Linux 6.6 的 EEVDF 调度器之上，新增 `sched_tac` 策略框架，将 seL4 MCS（Mixed Criticality System）语义映射到 Linux 调度体系。

- **4 种调度策略**：`stc_realtime`（硬实时）/ `stc_interactive`（交互式 Agent）/ `stc_agent`（批处理 Agent）/ `stc_batch`（后台任务）
- **优先级范围**：0-139（`AIRY_PRIO_MIN` / `AIRY_PRIO_MAX`），兼容 Linux 原生优先级体系
- **cgroup cpuset 隔离**：每个 cgroup 独立 cpuset，per-CPU 本地队列 + 全局共享队列
- **任务描述符**：`struct airy_task_desc`（12 字节：`magic` + `prio` + `_pad` + `vtime`），magic = `0x41475453`（'AGTS'）
- **vtime**：`airy_vtime_t` = `int32_t`，Q16.16 定点数格式，精确追踪任务执行时间
- **调度延迟**：sched\_tac 各策略调度延迟 60-150ns（对比 sched\_ext 的 200-400ns），Agent 调度延迟 P99 < 50μs
- **Task 扩展**：不替换 Linux `task_struct`，通过 `task_struct->airy_ext` 指针附加 `airy_tcb_ext`

**关键决策**：不采用 `sched_ext`，理由详见 [§6.1](#61-为什么使用-sched_tac-而非-sched_ext)。

### 5.2 IPC 体系：io\_uring 零拷贝 + Capability Folding v1.1

极境内核的标志性架构创新——将 seL4 的 Capability 校验从独立的控制面 syscall "折叠"到 io\_uring 数据面 fastpath 中。

**控制面/数据面分离**：

| 平面           | 路径                                  | 延迟                   | 用途                        |
| ------------ | ----------------------------------- | -------------------- | ------------------------- |
| 控制面          | 用户态 → syscall → 内核 → 返回             | \~1μs                | 4 核心 syscall              |
| 数据面 fastpath | 用户态 → SQE → io\_uring → CQE → 用户态   | ≤ 50ns（\~200 cycles） | IPC 收发 + 内联 Badge 校验      |
| 数据面 slowpath | 用户态 → SQE → io\_uring → io-wq → CQE | \~1μs                | 异步回退 / 大 payload / LSM 审计 |

**关键指标**：

- 128B 定长消息头（2 cache lines），magic = `0x41524531`（'ARE1'）
- 零 syscall 提交（SQPOLL 内核轮询）
- 消息吞吐：≥ 10M msg/s
- fastpath Badge 校验（Epoch + RandomTag + Perms 三阶段 C-S9 内联）：\~10ns
- Ring 容量：默认 256 entries，最大 32768

**7 个 IPC opcode（v1.1 Capability Folding）**：

| opcode                     | 编号     | 用途                     |
| -------------------------- | ------ | ---------------------- |
| `AIRY_IPC_OP_SEND`         | 0x0001 | 单消息发送                  |
| `AIRY_IPC_OP_RECV`         | —      | 单消息接收                  |
| `AIRY_IPC_OP_SEND_BATCH`   | —      | 批量发送                   |
| `AIRY_IPC_OP_CANCEL`       | —      | 取消操作                   |
| `AIRY_IPC_OP_FREEZE`       | —      | Ring 冻结（v1.1 新增）       |
| `AIRY_IPC_OP_CAP_REQUEST`  | —      | Capability 请求（v1.1 新增） |
| `AIRY_IPC_OP_CAP_RESPONSE` | 0x0011 | Capability 响应（v1.1 新增） |

### 5.3 安全体系：Capability + 纯 C LSM 纵深防御

**Capability 系统（借鉴 seL4）**：

- `agent_caps[1024]` 静态数组（64KB，每槽 64 字节 cacheline 对齐），O(1) 查表
- **sec\_d 唯一写者**：用户态串行化，消除内核并发同步
- Badge 64-bit 编码：`Epoch<<48 | RandomTag<<16 | Perms`
- 7 种 CNode 操作：Copy / Mint / Move / Mutate / Revoke / Delete / Rotate
- O(1) 全局撤销：`atomic_inc(&airy_cap_global_epoch)` 使所有旧 Badge 自动失效
- fastpath C-S9 三阶段内联校验（Epoch → RandomTag → Perms）+ 令牌桶限流

**纯 C LSM（airy\_lsm）**：

- 14 个源文件，编译为 `airy.o`
- **5 核心钩子**（`airy_lsm.c`）：`uring_cmd` / `task_alloc` / `task_free` / `task_kill` / `file_open`
- **5 supplemental 钩子**（`airy_superv_lsm.c`）：`task_fix_setuid` / `mmap_addr` / `file_mprotect` / `capset` / `capable`
- `LSM_ORDER_MUTABLE`，与 Linux 原生 capability（`LSM_ORDER_FIRST`）协同
- `__ro_after_init` 保护只读安全数据
- 决策四值枚举：`ALLOW` / `DENY` / `AUDIT` / `COMPLAIN`

### 5.4 系统调用体系

标准 Linux \~400 syscall + 4 个 Airymax 专属系统调用（4 核心 + 20 预留 = 24 槽位）：

| 编号      | syscall               | 独占 Daemon | 功能                                                             |
| ------- | --------------------- | --------- | -------------------------------------------------------------- |
| 454     | `airy_sys_call`       | sec\_d    | Capability Invocation 总入口——Badge 编译/撤销 + LSM\_ctl + Wasm\_load |
| 455     | `airy_sys_rovol_ctl`  | mem\_d    | 记忆卷载控制                                                         |
| 456     | `airy_sys_sched_ctl`  | sched\_d  | 调度策略配置                                                         |
| 457     | `airy_sys_clt_notify` | cogn\_d   | CoreLoopThree 通知 + kthread 注册                                  |
| 458-477 | —                     | —         | 预留                                                             |

**编号选择理由**：避开 x32 历史占用区间 512-547，选用 454-457 空闲编号。

### 5.5 记忆卷载（MemoryRovol）内核态

L1-L4 四层递进记忆系统，内核态负责 CXL 内存分层、PMEM 持久化、MGLRU 多代回收。

| 层级        | 含义                   | GFP 标志          |
| --------- | -------------------- | --------------- |
| `L1_HOT`  | 热数据（HBM/DDR hot）     | `AIRY_GFP_HOT`  |
| `L2_WARM` | 温数据（DDR warm）        | `AIRY_GFP_WARM` |
| `L3_COLD` | 冷数据（CXL/NVMe cold）   | `AIRY_GFP_COLD` |
| `L4_PMEM` | 持久化（PMEM persistent） | `AIRY_GFP_PMEM` |

**关键设计**：per-tier size shift 表（L1=0/L2=3/L3=6/L4=9）允许批量化分配，L4 一次分配 512 页（2MB）以减少 PMEM 写放大。

### 5.6 12 Daemon 内核切入点映射

| Daemon     | 职责                                       | 内核切入点                                    | syscall                        |
| ---------- | ---------------------------------------- | ---------------------------------------- | ------------------------------ |
| sec\_d     | Capability 编译/撤销 + Badge 生命周期            | `agent_caps[1024]` 静态数组写者 + `airy_lsm.c` | `airy_sys_call`（454）           |
| cogn\_d    | 认知循环调度（CoreLoopThree: PERCEPT→THINK→ACT） | kthread 注册 + 阶段通知                        | `airy_sys_clt_notify`（457）     |
| mem\_d     | 记忆卷载管理（快照/恢复/迁移）                         | userfaultfd + MGLRU + CXL bus            | `airy_sys_rovol_ctl`（455）      |
| sched\_d   | sched\_tac 策略守护                          | sched\_tac 策略框架 + cgroup cpuset          | `airy_sys_sched_ctl`（456）      |
| logger\_d  | 统一日志（128B 记录 + 5 级枚举）                    | printk bridge + char dev `/dev/airy_log` | char dev + \[SC] `log_types.h` |
| audit\_d   | 审计哈希链                                    | eBPF ringbuf 上报审计事件                      | eBPF ringbuf + kfunc           |
| gateway\_d | 跨节点 IPC                                  | io\_uring ring + 网络栈                     | io\_uring + gRPC/QUIC          |
| macro\_d   | 宏观监管（看门狗 + daemon 重启）                    | systemd watchdog + panic 回调              | systemd watchdog               |
| vfs\_d     | VFS 用户态化                                 | io\_uring + 上游 `fs/` 改造                  | io\_uring + VFIO               |
| net\_d     | 网络栈用户态化                                  | io\_uring + 上游 `net/` 改造                 | io\_uring + VFIO               |
| dev\_d     | 设备驱动用户态化                                 | io\_uring + 上游 `drivers/` 改造             | io\_uring + VFIO               |
| config\_d  | 统一配置管理                                   | sysfs + procfs 接口                        | sysfs + procfs                 |

### 5.7 内核工程约束

- **kthread 间通信**：kthread 间使用 `kfifo + wait_event_interruptible`，**禁止 io\_uring 用于 kthread 间通信**
- **禁止浮点运算**：内核态禁 float（`arch/x86/Makefile:137` `-mno-80387`），全局使用 Q16.16 定点数 `airy_q16_t`（=`int32_t`）

***

## 六、关键设计决策

### 6.1 为什么使用 sched\_tac 而非 sched\_ext？

**决策**：不采用 sched\_ext，采用 sched\_tac（SCHED\_DEADLINE/SCHED\_FIFO/EEVDF + cgroup cpuset 隔离 + seL4 MCS 语义映射）。

| # | 理由                      | 证据                                                                                     |
| - | ----------------------- | -------------------------------------------------------------------------------------- |
| 1 | **BPF 依赖与纯 C LSM 原则冲突** | sched\_ext 依赖 `BPF_SYSCALL && BPF_JIT && DEBUG_INFO_BTF`（`kernel/Kconfig.preempt:138`） |
| 2 | **x86 默认禁用**            | `include/linux/sched.h:1663-1667` 注释明确 "SCHED\_EXT is disabled by default on x86"      |
| 3 | **形式化验证可行性**            | BPF verifier 在调度路径的语义不确定性影响形式化验证可行性                                                    |
| 4 | **体系一致性**               | sched\_ext 的 BPF struct\_ops 模型与 agentrt-linux 纯 C 体系不一致                               |

### 6.2 为什么使用纯 C LSM 而非 BPF LSM？

**决策**：采用纯 C LSM 模块（`security/airy/`），不使用 BPF LSM。

1. **对齐 openEuler 纯 C 模式**：OLK-6.6 的 SELinux/AppArmor/Landlock/Tomoyo 全部纯 C 实现
2. **Landlock 源码验证**：OLK-6.6 的 `security/landlock/` 全部纯 C，无 BPF 依赖
3. **形式化验证友好**：纯 C 代码可被静态分析与形式化验证工具处理
4. **fastpath 性能**：纯 C fastpath \~160ns，无 BPF 间接调用开销

### 6.3 为什么使用 io\_uring 而非新增 IPC syscall？

**决策**：复用 io\_uring `IORING_OP_URING_CMD` 承载 IPC 数据面，不新增 IPC syscall。

1. **零 syscall**：io\_uring 提交队列用户态直接写，内核态消费，无 syscall 开销
2. **零拷贝**：registered buffer + mmap 实现零拷贝
3. **不新增 opcode**：复用 `IORING_OP_URING_CMD`，通过 `cmd_op` 子命令区分操作
4. **异步 I/O 基础设施**：io\_uring 已是 Linux 6.6 标准 async I/O 接口

### 6.4 为什么 Capability 系统集成在 security/airy/ 而非独立 security/capability/？

**决策**：`agent_caps[1024]` 静态数组管理集成在 `security/airy/` 内，不创建独立 `security/capability/` 目录。

1. **LSM 钩子与 Capability 校验紧耦合**：fastpath C-S9 Badge 校验是 LSM 钩子的一部分
2. **单一模块编译单元**：`airy_lsm` 作为一个 LSM 模块统一编译
3. **seL4 CNode 哲学**：seL4 的 CNode 也是内核对象的一部分

***

## 七、IRON-9 v3 四层共享模型

极境内核与 agentrt 用户态运行时的代码共享通过四层模型实现：

| 层级        | 缩写     | 含义                | 实现                                            |
| --------- | ------ | ----------------- | --------------------------------------------- |
| **共享契约层** | \[SC]  | 二进制完全一致，跨仓共享头文件   | `include/uapi/linux/airymax/` 下 10 个头文件       |
| **语义同源层** | \[SS]  | 接口语义等价，实现独立       | 调度策略语义、IPC 协议语义、Capability 操作语义               |
| **完全独立层** | \[IND] | 各自独立实现，无共享约束      | 内核态驱动、用户态 SDK、平台特定实现                          |
| **降级生存层** | \[DSL] | \[SC] 不可用时的最小存活路径 | 每个 \[SC] 头文件底部含 `#ifdef AIRY_SC_FALLBACK` 降级块 |

### 7.1 \[SC] 共享契约层 10 个头文件

| 头文件                 | 关键符号                                                      | seL4 对应概念            |
| ------------------- | --------------------------------------------------------- | -------------------- |
| `error.h`           | `AIRY_E*` 错误码 + `AIRY_FAULT_*` 故障码                        | 错误码契约                |
| `log_types.h`       | `AIRY_LOG_MAGIC` + 128B 记录 + 5 级日志枚举                      | 诊断/审计                |
| `ipc.h`             | magic `0x41524531`（'ARE1'）+ 128B 消息头                      | Endpoint / Message   |
| `sched.h`           | magic `0x41475453`（'AGTS'）+ task\_desc 12B + vtime Q16.16 | TCB 调度               |
| `memory_types.h`    | MemoryRovol L1-L4 + GFP 掩码 + PMEM 接口                      | Untyped / Frame      |
| `security_types.h`  | 41 cap ID + 250 LSM 钩子 + Cupolas blob 布局                  | CNode / Capability   |
| `cognition_types.h` | CoreLoopThree 三阶段 + Thinkdual 双模式                         | —                    |
| `syscalls.h`        | 4 核心 + 20 预留 = 24 槽位                                      | seL4 7-11 syscall 模型 |
| `uapi_compat.h`     | 三路类型桥接（`__KERNEL__` / `__linux__` / `#else`）              | 用户态 ABI 桥接           |
| `lsm_types.h`       | 纯 C LSM 类型定义 + `DEFINE_LSM(airy)` 骨架                      | 安全钩子契约               |

### 7.2 \[DSL] 降级生存层

每个 \[SC] 头文件底部包含 `#ifdef AIRY_SC_FALLBACK` 降级块，确保 \[SC] 损坏时系统仍具备最小可运行子集：

- 38 POSIX 错误码
- `printk` 最小日志
- 最小 128B IPC
- EEVDF 默认调度
- POSIX capability
- 统一 Panic

***

## 八、seL4 机制映射

依据 ADR-014（seL4 唯一思想来源），ALK-6.6 借鉴 seL4 的以下机制：

| seL4 机制          | seL4 源码位置                   | ALK-6.6 实现                                 | 物理载体                                  | 借鉴程度 |
| ---------------- | --------------------------- | ------------------------------------------ | ------------------------------------- | :--: |
| CNode Capability | `src/object/cnode.c`        | `agent_caps[1024]` 静态数组 + Badge 64-bit     | `security/airy/`                      | 机制借鉴 |
| CNode 派生操作（7 种）  | `src/object/cnode.c`        | Copy/Mint/Move/Mutate/Revoke/Delete/Rotate | `security/airy/airy_cap_derive.c`     | 完整借鉴 |
| handleFault()    | `src/api/faults.c`          | Micro-Supervisor 冷酷执法                      | `kernel/superv/`                      | 模式借鉴 |
| Endpoint IPC     | `src/object/endpoint.c`     | io\_uring + 128B 消息头                       | 复用 `io_uring/` + \[SC] `ipc.h`        | 语义借鉴 |
| Notification 位图  | `src/object/notification.c` | eventfd + 位图聚合                             | `kernel/superv/airy_eventfd_superv.c` | 语义借鉴 |
| MCS 调度上下文        | `src/object/schedcontext.c` | sched\_tac（SCHED\_DEADLINE 映射）             | 复用 `kernel/sched/deadline.c`          | 映射借鉴 |
| fastpath         | `src/fastpath/fastpath.c`   | C-S0\~C-S12 校验链 + C-S9 Badge 内联            | `airy_cap_badge_ok()`                 | 模式借鉴 |
| 服务用户态化           | seL4 用户态服务                  | 12 daemon 用户态运行                            | `services/` 子仓                        | 架构借鉴 |
| 机制/策略分离          | seL4 内核机制 + 用户态策略           | 内核冷酷执法 + 用户态温情裁决                           | `kernel/superv/` + `services/macro_d` | 哲学借鉴 |

***

## 九、构建与开发

### 9.1 编译

```bash
# x86_64（默认架构）
make ARCH=x86_64 defconfig
./scripts/kconfig/merge_config.sh -m .config arch/x86/configs/airy_defconfig
make ARCH=x86_64 olddefconfig
make ARCH=x86_64 -j$(nproc)

# arm64（交叉编译）
make ARCH=arm64 defconfig
./scripts/kconfig/merge_config.sh -m .config arch/arm64/configs/airy_defconfig
make ARCH=arm64 olddefconfig
make ARCH=arm64 -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-

# riscv64
make ARCH=riscv64 defconfig
./scripts/kconfig/merge_config.sh -m .config arch/riscv/configs/airy_defconfig
make ARCH=riscv64 olddefconfig
make ARCH=riscv64 -j$(nproc) CROSS_COMPILE=riscv64-linux-gnu-

# loongarch
make ARCH=loongarch defconfig
./scripts/kconfig/merge_config.sh -m .config arch/loongarch/configs/airy_defconfig
make ARCH=loongarch olddefconfig
make ARCH=loongarch -j$(nproc) CROSS_COMPILE=loongarch64-linux-gnu-
```

### 9.2 关键 CONFIG 项

```kconfig
# ===== Airymax ALK-6.6 关键 CONFIG =====
CONFIG_SECURITY=y                  # 必须启用（SECURITY_AIRY 依赖）
CONFIG_SECURITY_AIRY=y             # 纯 C LSM 模块
CONFIG_AIRY_SYSCALL=y              # Airymax 4 核心 syscall
CONFIG_AIRY_COREKERN=y             # 微核心抽象层（10 子目录）
CONFIG_AIRY_LOG=y                  # A-ULP 统一日志
CONFIG_AIRY_IPC=y                  # A-IPC 内核基础设施
CONFIG_AIRY_CAP_TABLE_SIZE=1024    # Capability 表大小（默认 1024 agents）

# ===== 复用的 Linux 6.6 能力 =====
CONFIG_IO_URING=y                  # io_uring（IPC 数据面载体）
CONFIG_SCHED_DEADLINE=y            # SCHED_DEADLINE（sched_tac 策略之一）
# CONFIG_SCHED_CLASS_EXT is not set  # 禁用 sched_ext（H5 纯 C LSM 原则）
CONFIG_LRU_GEN=y                   # MGLRU 多代回收
CONFIG_LRU_GEN_ENABLED=y
CONFIG_EVENTFD=y                   # eventfd（Notification 语义）

# ===== 显式禁用 =====
# CONFIG_BPF_LSM is not set        # 禁用 BPF LSM（采用纯 C LSM）
CONFIG_DEBUG_INFO_BTF=n            # 禁用 BTF（与纯 C 原则一致）
```

### 9.3 预置配置 fragment

```bash
# 默认基线
make ARCH=x86_64 defconfig
./scripts/kconfig/merge_config.sh -m .config configs/defconfig

# Agent 优化部署（启用 CGROUPS/DRM_SCHED/CXL/THP）
./scripts/kconfig/merge_config.sh -m .config configs/defconfig-agent

# 嵌入式最小化（禁用 AIRY_LOG/AIRY_IPC/BPF/CGROUPS，节省 ROM/RAM）
./scripts/kconfig/merge_config.sh -m .config configs/defconfig-embedded

# 安全加固
./scripts/kconfig/merge_config.sh -m .config configs/hardening.config
```

### 9.4 运行时验证

```bash
# 查看 Airymax 专属内核模块
lsmod | grep airy

# 查看启动日志
dmesg | grep -E "airy|Airymax ALK"
# 预期输出：
#   airy: Airymax Pure-C LSM initialised
#   airy_superv: registered 5 Micro-Supervisor hooks
#   airy_superv: Micro-Supervisor initialised
#   airy corekern: api ready
#   Airymax ALK-1.0.1 -- Agent Lifecycle Kernel
```

### 9.5 CI/CD

| Workflow        | 文件                                | 作用                                                                                                                                      |
| --------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `ci-kernel.yml` | `.github/workflows/ci-kernel.yml` | 32 configs 编译矩阵（4 configs × 4 archs × 2 compilers）+ checkpatch + sparse + coccinelle + KUnit + kselftest                                |
| `ci-airy.yml`   | `.github/workflows/ci-airy.yml`   | Airymax 专属验证：`airy-defconfig-verify`（4 archs 编译 + CONFIG 验证 + .o 产物验证）+ `airy-checkpatch` + `airy-spdx-audit` + `airy-symbol-integrity` |

***

## 十、SPDX 许可证标识

| 文件类型                                          | SPDX 标识                   | 说明                       |
| --------------------------------------------- | ------------------------- | ------------------------ |
| Airymax `.c` / `.h` / `Kbuild` / `Kconfig`    | `GPL-2.0-only`            | 与 Linux 主线一致             |
| \[SC] 共享契约层头文件（`include/uapi/linux/airymax/`） | `BSD-3-Clause OR GPL-2.0` | 允许 agentrt 用户态以 BSD 方式链接 |
| `arch/*/configs/airy_defconfig`               | `GPL-2.0-only`            | 配置 fragment              |

***

## 十一、Linux 7.1 前瞻性预留

2.x.x 升级到 Linux 7.1 时，10 条前瞻性设计均已预留运行时能力探测框架 `airy_kernel_cap_query(cap_id)`，所有预留以"运行时探测 + 条件降级"实现，禁止 `#ifdef` 污染：

1. 调度类复用 sched\_ext（禁用 SCHED\_AGENT 自定义类）——预留 `airy_sched_ops`
2. 进程生命周期 API 全面 pidfd 化——预留 `CLONE_AUTOREAP` 等 flags
3. 容器 mount 树构造抽象
4. io\_uring + ublk 作为 I/O 一等公民——预留 `AIRY_IO_URING_BPF` 能力位
5. Landlock 沙箱覆盖 UNIX socket——预留 `AIRY_LANDLOCK_SOCKET` 能力位
6. 后量子密码预留——ML-DSA (FIPS 204) + PQ 混合签名扩展位
7. PREEMPT 模型运行时选择——`PREEMPT_LAZY` + `PREEMPT_FULL` + `PREEMPT_RT`
8. NPU/GPU 调度基于 accel 子系统
9. 构建工具链基线锁定与渐进升级（Rust 1.85 + Clang 15 → 17）
10. 版本能力探测框架 `airy_kernel_cap_query(cap_id)` 集中管理

***

## 十二、配套设计文档

极境内核的完整设计文档位于 `docs/AirymaxOS/`，以下是关键文档索引：

### 12.1 架构与原则

| 文档     | 路径                                                          | 说明                                    |
| ------ | ----------------------------------------------------------- | ------------------------------------- |
| 极境内核总览 | `docs/AirymaxOS/10-architecture/00-alk-kernel-overview.md`  | **SSoT 权威源**，物理形态、改造方式、6 大改造点、4 大技术支柱 |
| 系统架构   | `docs/AirymaxOS/10-architecture/01-system-architecture.md`  | 8 子仓架构总览                              |
| 微内核策略  | `docs/AirymaxOS/10-architecture/03-microkernel-strategy.md` | seL4 思想借鉴与实践落地                        |
| 工程基线   | `docs/AirymaxOS/10-architecture/04-engineering-baseline.md` | Linux 6.6 基线 + Linux 7.1 前瞻性预留        |
| 架构决策记录 | `docs/AirymaxOS/10-architecture/05-adrs.md`                 | ADR-001 \~ ADR-017                    |

### 12.2 内核模块设计

| 文档               | 路径                                                        | 说明                 |
| ---------------- | --------------------------------------------------------- | ------------------ |
| 内核设计             | `docs/AirymaxOS/20-modules/01-kernel.md`                  | **核心文档**——内核子仓完整设计 |
| Micro-Supervisor | `docs/AirymaxOS/20-modules/09-kernel-agent-supervisor.md` | 冷酷执法机制             |
| Macro-Supervisor | `docs/AirymaxOS/20-modules/10-user-supervisor-daemon.md`  | 温情裁决机制             |

### 12.3 接口与数据流

| 文档     | 路径                                                      | 说明                                     |
| ------ | ------------------------------------------------------- | -------------------------------------- |
| 系统调用接口 | `docs/AirymaxOS/30-interfaces/01-syscalls.md`           | syscall 分类/编号/C 接口/错误码                 |
| IPC 协议 | `docs/AirymaxOS/30-interfaces/02-ipc-protocol.md`       | 128B 消息头 + 5 种 payload + io\_uring 零拷贝 |
| 调度扩展   | `docs/AirymaxOS/30-interfaces/10-sc-sched-extension.md` | sched\_tac 定义                          |

### 12.4 安全

| 文档            | 路径                                                     | 说明                      |
| ------------- | ------------------------------------------------------ | ----------------------- |
| Capability 模型 | `docs/AirymaxOS/110-security/03-capability-model.md`   | seL4 风格 Capability 完整设计 |
| 纯 C LSM 设计    | `docs/AirymaxOS/110-security/07-airy-lsm-design.md`    | 10 钩子覆盖 + 250 钩子枚举      |
| io\_uring 加固  | `docs/AirymaxOS/110-security/06-io-uring-hardening.md` | opcode 白名单              |

### 12.5 工程规范

| 文档     | 路径                                                                             | 说明                               |
| ------ | ------------------------------------------------------------------------------ | -------------------------------- |
| 工程标准手册 | `docs/AirymaxOS/50-engineering-standards/00-engineering-standards-handbook.md` | SSoT 规则注册表；IRON-9 v3；禁词清单        |
| 编码规范   | `docs/AirymaxOS/50-engineering-standards/01-coding-standards.md`               | C/Rust 编码规范；安全编码                 |
| 契约总览   | `docs/AirymaxOS/50-engineering-standards/20-contracts/README.md`               | \[SC]/\[SS]/\[IND]/\[DSL] 四层契约模型 |

### 12.6 性能与测试

| 文档     | 路径                                                            | 说明                                        |
| ------ | ------------------------------------------------------------- | ----------------------------------------- |
| 调度性能   | `docs/AirymaxOS/170-performance/01-scheduling-performance.md` | sched\_tac 性能基准（60-150ns）与 P99 < 50μs SLA |
| IPC 性能 | `docs/AirymaxOS/170-performance/03-ipc-performance.md`        | io\_uring 零拷贝延迟 ≤ 50ns / 吞吐 ≥ 10M msg/s   |
| 测试框架   | `docs/AirymaxOS/80-testing/01-kunit-framework.md`             | KUnit 内核单元测试                              |

***

## 十三、版本与变更历史

| 版本     | 日期         | 变更内容                                |
| ------ | ---------- | ----------------------------------- |
| v1.0.1 | 2026-07-21 | 版本号统一：按 IRON-8 铁律，所有文档版本号统一为 v1.0.1 |

**注**：遵循 IRON-8 铁律，0.1.1（奠基版本）后直接过渡到 1.0.1（开发版本），禁止 0.1.2/0.2.0/0.3.0/1.0.0 任何中间过渡版本。

***

## 十四、致谢与参考

### 14.1 上游致敬

- **Linux 内核社区**：感谢 Linus Torvalds 及全体内核维护者维护的 Linux 6.6 LTS，这是极境内核不可动摇的工程基线
- **seL4 项目**：感谢 Gernot Heiser 及 NICTA/Data61 团队，seL4 是极境内核微内核化改造的唯一思想来源
- **openEuler 社区**：感谢 openEuler 内核团队，OLK-6.6 的纯 C LSM 工程实践为极境内核安全模块提供了重要参考

### 14.2 参考文献

- Liedtke, J. "On μ-Kernel Construction" (1995)
- Heiser, G. "seL4: Operating Systems With the Reliability of Mathematics"
- Linux 6.6 release notes
- Documentation/io\_uring/
- seL4 CAVEATS.md（验证范围声明）

### 14.3 治理

- **治理主体**：开源极境工程与规范委员会（TSC）
- **贡献协议**：DCO sign-off（与 Linux 一致）
- **安全披露**：agentrt-linux-SA
- **贡献指南**：CONTRIBUTING.md

***

**文档版本**：v1.0.1（开发版）\
**最后更新**：2026-07-22\
**设计文档**：[docs/AirymaxOS/](../docs/AirymaxOS/)\
**文档编写**：开源极境工程与规范委员会

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

# 极境内核（Airymax Kernel / ALK）

> AirymaxOS 内核仓。基于 Linux 6.6 LTS，借鉴 seL4 微内核工程思想进行微内核化改造的智能体原生操作系统内核。

---

## 一、核心思想

极境内核不是从零开发的微内核，而是在 Linux 6.6 完整内核树（~60K 文件）上，通过系统化改造落地三条设计支柱：

**支柱一：微内核化改造（借鉴 seL4）**

遵循 Liedtke 最小性原则——只有移出内核会导致系统无法实现功能时，才保留在内核态。内核核心代码预算控制在 5-10 万行，改造补丁 2 万行以内。

内核态保留 6 类职责：Capability 管理、IPC 消息传递、调度原语、地址空间管理、中断/异常处理、内存 Retype。VFS 具体文件系统、网络协议栈、设备驱动、POSIX 接口逐步下沉到用户态。

**支柱二：Linux 6.6 工程基线**

以 Linux 6.6 LTS 为不可动摇的内核基线（1.x.x 锁定 6.6，2.x.x 锁定 7.1），复用其成熟的调度、内存、网络、文件系统基础设施，不做无谓的重新发明。支持 x86、ARM、RISC-V、鲲鹏、飞腾。

**支柱三：Agent 原生设计**

内核专为 Agent 工作负载优化——调度器感知 Agent 优先级与截止时间，IPC 专为高频小消息设计，安全模型面向多 Agent 隔离场景，与 agentrt 用户态运行时通过 IRON-9 v3 四层共享模型保持同源。

### 关键设计决策

| 维度 | 选定方案 | 明确不采用 |
|------|---------|-----------|
| 调度 | sched_tac（SCHED_DEADLINE/SCHED_FIFO/EEVDF + seL4 MCS 映射 + cgroup cpuset） | **不使用 sched_ext**（不引入 eBPF 调度器） |
| IPC | io_uring 零拷贝 + `IORING_OP_URING_CMD` + Capability Folding | 不使用 page flipping |
| 安全 | 纯 C LSM（airy）+ seL4 风格 Capability | 不使用 BPF LSM |
| 代码组织 | Model A：完整 fork，Airymax 代码注入内核树 | 不使用 patches 隔离模型 |

### 十大不可妥协技术原则（IRON 铁律）

1. **调度原语在内核，调度策略在用户态**：内核只提供 EEVDF + sched_tac 原语（机制），策略配置和调度类组合由用户态 daemon 决定
2. **IPC 是唯一的跨进程通信通道**：不引入额外的 RPC 层或通信协议；所有 daemon 间通信通过 io_uring SQE/CQ ring
3. **能力（Capability）是唯一的权限模型**：不依赖 UID/GID 或 SELinux 上下文进行进程间授权
4. **内核最小化**：用户态可实现的功能不下沉到内核态
5. **同源优先**：与 agentrt 共享架构设计，通过 IRON-9 v3 保持互操作
6. **[SC] 共享契约层不可破坏**：任何违反 `include/uapi/linux/airymax/` 契约的代码禁止合并
7. **不引入实验性上游特性**：所有技术选型锁定在 Linux 6.6 稳定接口
8. **形式化验证优先**：安全关键路径必须有形式化模型（借鉴 seL4），代码中使用 `/** MODIFIES */` `/** FNSPEC */` `/** GHOSTUPD */` `/** DONT_TRANSLATE */` 四种预留注解，验证 artifacts 独立存放于 `tests-linux` 子仓
9. **最小完备集**：每个子系统接口数量精简到极致（syscall 4 核心 + 20 预留 = 24 槽位、IPC opcode 7 个、CNode 操作 7 个）
10. **Capability Folding 是唯一 IPC 数据面路径**：控制面与数据面分离，fastpath 内联校验

### IRON-9 v3 四层共享模型

极境内核（agentrt-linux）与 agentrt 用户态运行时的代码共享通过四层模型实现：

| 层级 | 缩写 | 含义 | 实现 |
|------|------|------|------|
| **共享契约层** | [SC] | 二进制完全一致，跨仓共享头文件 | `include/uapi/linux/airymax/` 下 10 个头文件，agentrt 和 agentrt-linux 同步维护 |
| **语义同源层** | [SS] | 接口语义等价，实现独立 | 调度策略语义、IPC 协议语义、Capability 操作语义保持一致 |
| **完全独立层** | [IND] | 各自独立实现，无共享约束 | 内核态驱动、用户态 SDK、平台特定实现 |
| **降级生存层** | [DSL] | 内核不可用时的最小存活路径 | 每个 [SC] 头文件底部含 `#ifdef AIRY_SC_FALLBACK` 降级块（38 POSIX 错误码 + printk + 最小 128B IPC + EEVDF 默认 + POSIX capability + 统一 Panic） |

---

## 二、核心改造概要

### 2.1 调度体系：EEVDF + sched_tac 三位一体

标准 Linux 6.6 的 EEVDF 调度器之上，新增 sched_tac 策略框架，将 seL4 MCS（Mixed Criticality System）语义映射到 Linux 调度体系。

- **四种调度策略**：`stc_realtime`（硬实时）、`stc_interactive`（交互式 Agent）、`stc_agent`（批处理 Agent）、`stc_batch`（后台任务）
- **优先级范围**：0-139（`AIRY_PRIO_MIN` / `AIRY_PRIO_MAX`），兼容 Linux 原生优先级体系
- **cgroup cpuset 隔离**：每个 cgroup 独立 cpuset，per-CPU 本地队列 + 全局共享队列
- **任务描述符**：`struct airy_task_desc`（12 字节：`magic` + `prio` + `_pad` + `vtime`），magic = 0x41475453 ('AGTS')
- **vtime**：`airy_vtime_t` = `int32_t`，Q16.16 定点数格式，精确追踪任务执行时间
- **调度延迟**：sched_tac 各策略调度延迟 60-150ns（对比 sched_ext 的 200-400ns），Agent 调度延迟 P99 < 50μs，实时响应 < 10ms
- **安全回退**：调度器故障/超时时所有任务自动迁入 EEVDF 兜底
- **Task 扩展**：不替换 Linux `task_struct`，通过 `task_struct->airy_ext` 指针附加 `airy_tcb_ext` 扩展结构（6 字段：`agent_id` / `capability_set` / `ipc_buffer` / `sched_context` / `bound_notification` / `badge`）
- **seL4 对象映射**：

| seL4 对象 | agentrt-linux 对应 |
|-----------|-------------------|
| TCB | Linux `task_struct` + `airy_tcb_ext` 扩展 |
| CNode | capability 表节点 |
| Endpoint | io_uring ring + Endpoint 语义 |
| Notification | eventfd + signal 语义 |
| Untyped | Retype 接口层 |

### 2.2 IPC 体系：io_uring 零拷贝 + Capability Folding v1.1

这是极境内核的标志性架构创新。将 seL4 的 Capability 校验从独立的控制面 syscall"折叠"到 io_uring 数据面 fastpath 中——IPC 消息传递即能力校验。

**控制面/数据面分离：**

| 平面 | 路径 | 延迟 | 用途 |
|------|------|------|------|
| 控制面 | 用户态 → syscall → 内核 → 返回 | ~1μs | 4 核心 syscall |
| 数据面 fastpath | 用户态 → SQE → io_uring → CQE → 用户态 | ≤ 50ns（~200 cycles） | IPC 收发 + 内联 Badge 校验 |
| 数据面 slowpath | 用户态 → SQE → io_uring → io-wq → CQE | ~1μs | 异步回退 / 大 payload / LSM 审计 |

**关键指标：**
- 128B 定长消息头（2 cache lines），magic = 0x41524531 ('ARE1')
- 零 syscall 提交（SQPOLL 内核轮询）
- 消息吞吐：≥ 10M msg/s
- fastpath Badge 校验（Epoch + RandomTag + Perms 三阶段 C-S9 内联）：~10ns
- Ring 容量：默认 256 entries，最大 32768

**7 个 IPC opcode（v1.1 Capability Folding）：**

| opcode | 编号 | 用途 |
|--------|------|------|
| `AIRY_IPC_OP_SEND` | 0x0001 | 单消息发送 |
| `AIRY_IPC_OP_RECV` | — | 单消息接收 |
| `AIRY_IPC_OP_SEND_BATCH` | — | 批量发送 |
| `AIRY_IPC_OP_CANCEL` | — | 取消操作 |
| `AIRY_IPC_OP_FREEZE` | — | Ring 冻结（v1.1 新增） |
| `AIRY_IPC_OP_CAP_REQUEST` | — | Capability 请求（v1.1 新增） |
| `AIRY_IPC_OP_CAP_RESPONSE` | 0x0011 | Capability 响应（v1.1 新增） |

### 2.3 安全体系：Capability + 纯 C LSM 纵深防御

**Capability 系统（借鉴 seL4）：**
- `agent_caps[1024]` 静态数组（16KB，每槽 16 字节），O(1) 查表
- **sec_d 唯一写者**：用户态串行化，消除内核并发同步
- Badge 64-bit 编码：`Epoch<<48 | RandomTag<<16 | Perms`
- 7 种 CNode 操作：Copy / Mint / Move / Mutate / Revoke / Delete / Rotate
- O(1) 全局撤销：`atomic_inc(&airy_cap_global_epoch)` 使所有旧 Badge 自动失效
- fastpath C-S9 三阶段内联校验（Epoch → RandomTag → Perms）+ 令牌桶限流，Badge 编译 SLO = 50ms

**纯 C LSM（airy_lsm）：**
- 10 个源文件，编译为 `airy.o`
- 注册 250 个 LSM 钩子
- LSM_ORDER_MUTABLE，与 Linux 原生 capability（LSM_ORDER_FIRST）协同
- 决策四值枚举：`ALLOW` / `DENY` / `AUDIT` / `COMPLAIN`

### 2.4 系统调用体系

标准 Linux ~400 syscall + 4 个 Airymax 专属系统调用（4 核心 + 20 预留 = 24 槽位）：

| 编号 | syscall | 独占 Daemon | 功能 |
|------|---------|------------|------|
| 0 | `airy_sys_call` | sec_d | Capability Invocation 总入口——Badge 编译/撤销 + LSM_ctl + Wasm_load。操作类型由 capability 类型决定，按 cap 类型分派到 CNode / TCB / Endpoint / Security / Module 五种调用路径 |
| 1 | `airy_sys_rovol_ctl` | mem_d | 记忆卷载控制 |
| 2 | `airy_sys_sched_ctl` | sched_d | 调度策略配置 |
| 3 | `airy_sys_clt_notify` | cogn_d | CoreLoopThree 通知 + kthread 注册 |
| 4-23 | — | — | 预留 |

### 2.5 记忆卷载（MemoryRovol）内核态

L1-L4 四层递进记忆系统，内核态负责 CXL 内存分层、PMEM 持久化、MGLRU 多代回收，用户态 MemoryRovol 负责语义理解与模式挖掘。四层为 `L1_HOT`（热数据）→ `L2_WARM`（温数据）→ `L3_COLD`（冷数据）→ `L4_PMEM`（持久化），内核通过 `AIRY_GFP_HOT/WARM/COLD/PMEM` 分配标志控制数据放置。

### 2.6 可观测性

基于 eBPF struct_ops + kfunc + ringbuf 的 Agent 感知可观测性框架。`airy_struct_ops_state` 四状态状态机（`INIT=0` → `REGISTERED=1` → `ACTIVE=2` → `DRAINING=3`），覆盖调度追踪、IPC 延迟采样、Capability 审计、MemoryRovol 回收追踪四大数据流。

### 2.7 12 Daemon 内核切入点映射

| Daemon | 职责 | 内核切入点 | 通道路径 |
|--------|------|-----------|----------|
| sec_d | Capability 编译/撤销 + Badge 生命周期 | `agent_caps[1024]` 静态数组写者 + `airy_lsm.c` | `airy_sys_call`（编号 0） + LSM 钩子 |
| cogn_d | 认知循环调度（CoreLoopThree: PERCEPT→THINK→ACT） | kthread 注册 + 阶段通知 | `airy_sys_clt_notify`（编号 3） |
| mem_d | 记忆卷载管理（快照/恢复/迁移） | userfaultfd + MGLRU + CXL bus | `airy_sys_rovol_ctl`（编号 1） |
| sched_d | sched_tac 策略守护 | sched_tac 策略框架 + cgroup cpuset | `airy_sys_sched_ctl`（编号 2） |
| logger_d | 统一日志（128B 记录 + 5 级枚举） | printk bridge + char dev `/dev/airy_log` | char dev + [SC] `log_types.h` |
| audit_d | 审计哈希链 | eBPF ringbuf 上报审计事件 | eBPF ringbuf + kfunc |
| gateway_d | 跨节点 IPC | io_uring ring + 网络栈 | io_uring + gRPC/QUIC |
| macro_d | 宏观监管（看门狗 + daemon 重启） | systemd watchdog + panic 回调 | systemd watchdog |
| vfs_d | VFS 用户态化 | io_uring + 上游 `fs/` 改造 | io_uring + VFIO |
| net_d | 网络栈用户态化 | io_uring + 上游 `net/` 改造 | io_uring + VFIO |
| dev_d | 设备驱动用户态化 | io_uring + 上游 `drivers/` 改造 | io_uring + VFIO |
| config_d | 统一配置管理 | sysfs + procfs 接口 | sysfs + procfs |

### 2.8 内核工程约束

- **kthread 间通信**：kthread 间使用 `kfifo + wait_event_interruptible`，**禁止 io_uring 用于 kthread 间通信**
- **禁止浮点运算**：内核态禁 float（`arch/x86/Makefile:137` `-mno-80387`），全局使用 Q16.16 定点数 `airy_q16_t`（=`int32_t`）

### 2.9 Linux 7.1 前瞻性预留

2.x.x 升级到 Linux 7.1 时，10 条前瞻性设计均已预留运行时能力探测框架 `airy_kernel_cap_query(cap_id)`，所有预留以"运行时探测 + 条件降级"实现，禁止 `#ifdef` 污染：

1. 调度类复用 sched_ext（禁用 SCHED_AGENT 自定义类）——预留 `airy_sched_ops`
2. 进程生命周期 API 全面 pidfd 化——预留 `CLONE_AUTOREAP` 等 flags
3. 容器 mount 树构造抽象
4. io_uring + ublk 作为 I/O 一等公民——预留 `AIRY_IO_URING_BPF` 能力位
5. Landlock 沙箱覆盖 UNIX socket——预留 `AIRY_LANDLOCK_SOCKET` 能力位
6. 后量子密码预留——ML-DSA (FIPS 204) + PQ 混合签名扩展位
7. PREEMPT 模型运行时选择——`PREEMPT_LAZY` + `PREEMPT_FULL` + `PREEMPT_RT`
8. NPU/GPU 调度基于 accel 子系统
9. 构建工具链基线锁定与渐进升级（Rust 1.85 + Clang 15 → 17）
10. 版本能力探测框架 `airy_kernel_cap_query(cap_id)` 集中管理

### 2.10 [SC] 共享契约层头文件关键符号

| 头文件 | 关键符号 |
|--------|---------|
| `sched.h` | `AIRY_TASK_MAGIC=0x41475453`, `struct airy_task_desc`（4 字段 12B）, `airy_vtime_t=int32_t`, `airy_vtime_decay()`, 优先级 0-139, 权重 1-10000, 默认时间片 20ms |
| `ipc.h` | `AIRY_IPC_MAGIC=0x41524531`, `AIRY_IPC_HDR_SIZE=128`, `struct airy_ipc_msg_hdr`（11 字段）, 7 opcode, SQE/CQE flags, ring 容量 256-32768 |
| `bpf_struct_ops.h` | `airy_struct_ops_state` 四状态枚举（INIT/REGISTERED/ACTIVE/DRAINING） |
| `memory_types.h` | `airy_mem_level` 四层枚举（L1_HOT→L4_PMEM）, `AIRY_GFP_HOT/WARM/COLD/PMEM` |
| `security_types.h` | 41 POSIX cap ID + 3 Airymax 扩展（AGENT_SPAWN/GPU_SCHED/NPU_ACCESS）, 250 LSM 钩子, 7 CNode 操作枚举, `airy_verdict` 四值（ALLOW/DENY/AUDIT/COMPLAIN） |
| `cognition_types.h` | `airy_cog_phase` 三阶段（PERCEPT/THINK/ACT）, `airy_think_mode` 双模式（FAST=System-1 / SLOW=System-2） |
| `syscalls.h` | v1.1: 4 核心 + 20 预留 = 24 槽位, 编号 0-3 已分配, 4-23 预留 |
| `error.h` | 13 错误码 + 故障码 |
| `log_types.h` | 128B 日志记录 + 5 级日志枚举 |
| `lsm_types.h` | 纯 C LSM 类型契约 |
| `uapi_compat.h` | 三路类型桥接（`__KERNEL__` / `__linux__` / `#else`） |

---


## 三、目录结构

> 以下仅列出 Airymax 专属代码路径。本仓是 Linux 6.6 完整内核树，其余目录（arch/、block/、crypto/、drivers/、fs/、mm/、net/ 等）为标准上游代码。

```
kernel/                                    # Linux 6.6 内核树（仅展示 Airymax 专属部分）
│
├── init/
│   └── airy_core.c                        # ALK 启动入口（late_initcall）
│
├── kernel/
│   ├── corekern/                          # 极境微核心抽象层（CoreKern）—— 10 个子系统
│   │   ├── sched/                         #   sched_tac 策略框架（stc_policy / dispatch / stats / mcs_map）
│   │   ├── ipc/                           #   io_uring IPC 命令分派（fastpath / ring / zero_copy）
│   │   ├── bpf/                           #   eBPF struct_ops 扩展 + kfunc 探测
│   │   ├── object/                        #   Capability 内核对象
│   │   ├── taskflow/                      #   任务描述符管理 + 生命周期控制
│   │   ├── memory/                        #   内存分层 + 分配
│   │   ├── time/                          #   时间原语
│   │   ├── locking/                       #   锁机制与同步原语
│   │   ├── irq/                           #   中断处理
│   │   └── api/                           #   内核 API 入口
│   ├── superv/                            # Micro-Supervisor 冷酷执法层
│   │   ├── airy_ipc_freeze.c              #   IPC ring 冻结控制
│   │   ├── airy_eventfd.c                 #   eventfd 通知机制
│   │   ├── airy_die_notify.c              #   Agent 故障通知（die notifier）
│   │   └── airy_cap_check.c               #   Capability 校验
│   ├── log/                               # 统一日志系统
│   │   ├── airy_log_kern.c                #   内核日志
│   │   ├── airy_log_persist.c             #   持久化日志
│   │   └── airy_log_ring.c                #   环形日志缓冲区
│   ├── ipc/                               # IPC 子系统
│   │   ├── airy_ipc_syscall.c             #   IPC 系统调用入口
│   │   └── airy_ipc_capability.c          #   IPC capability 管理
│   └── syscalls/                          # 系统调用
│       └── airy_syscalls.c                #   4 核心 + 20 预留 syscall 总入口
│
├── security/
│   └── airy/                              # 纯 C LSM（10 个源文件，编译为 airy.o）
│       ├── airy_lsm.c                     #   LSM 入口，注册 250 个钩子
│       ├── airy_cap_init.c                #   Capability 表初始化
│       ├── airy_cap_array.c               #   静态数组管理
│       ├── airy_cap_derive.c              #   Capability 派生（Copy / Mint）
│       ├── airy_cap_check.c               #   权限校验
│       ├── airy_cap_revoke.c              #   O(1) epoch 撤销
│       ├── airy_cap_rotate.c              #   CNode Rotate 操作
│       ├── airy_ipc_freeze.c              #   IPC ring 冻结
│       ├── airy_die_notify.c              #   Agent 死亡通知
│       └── airy_eventfd.c                #   eventfd 事件通知
│
├── include/
│   ├── uapi/linux/airymax/                # [SC] 共享契约层（10 个头文件，与 agentrt 用户态共享）
│   │   ├── error.h                        #   错误码 + 故障码
│   │   ├── log_types.h                    #   日志类型契约（128B 记录 + 5 级枚举）
│   │   ├── ipc.h                          #   IPC 契约（128B 消息头 + magic 0x41524531 + Badge 偏移）
│   │   ├── sched.h                        #   调度契约（task_desc 12B + vtime Q16.16 + 优先级 + 策略枚举）
│   │   ├── memory_types.h                 #   记忆卷载契约（四层内存分级 + GFP 标志）
│   │   ├── security_types.h               #   安全契约（41 POSIX cap + 250 LSM 钩子 + 7 CNode 操作）
│   │   ├── cognition_types.h              #   认知契约（CoreLoopThree 三阶段 + Thinkdual 双模式）
│   │   ├── syscalls.h                     #   Syscall 编号体系（24 槽位）
│   │   ├── uapi_compat.h                  #   三路类型桥接（__KERNEL__ / __linux__ / #else）
│   │   └── lsm_types.h                    #   纯 C LSM 类型契约
│   │
│   │   # 每个 [SC] 头文件底部含 #ifdef AIRY_SC_FALLBACK 降级块（[DSL] 降级生存层）
│   │   #   — 38 POSIX 错误码 + printk + 最小 128B IPC + EEVDF 默认 + POSIX capability + 统一 Panic
│   │
│   └── airymax/                           # 构建内部类型
│       ├── kconfig_types.h                #   Kconfig 平台检测 + 能力表大小配置
│       └── build_types.h                  #   构建版本号 + CONFIG_AIRY 开关
│
└── configs/
    └── airy_defconfig                     # Agent 优化配置（airy_defconfig + airy_defconfig.base 跨架构基线）
```

---

## 四、配套设计文档

极境内核的完整设计文档位于 `docs/AirymaxOS/`，以下是关键文档索引：

### 架构与原则

| 文档 | 路径 | 说明 |
|------|------|------|
| 总览 | `docs/AirymaxOS/README.md` | AirymaxOS 全部设计思想与子仓概览 |
| 五维正交原则 | `docs/AirymaxOS/10-architecture/02-five-dimensional-principles.md` | 24 条系统/内核/认知/工程/美学原则 |
| 系统架构 | `docs/AirymaxOS/10-architecture/01-system-architecture.md` | 8 子仓架构总览 |
| 微内核策略 | `docs/AirymaxOS/10-architecture/03-microkernel-strategy.md` | seL4 思想借鉴与实践落地（含形式化验证四种注解） |
| 工程基线 | `docs/AirymaxOS/10-architecture/04-engineering-baseline.md` | Linux 6.6 基线 + 五大不可妥协选型 + Linux 7.1 十条前瞻性预留 |
| 架构决策记录 | `docs/AirymaxOS/10-architecture/05-adrs.md` | ADR-001 ~ ADR-017 |

### 内核模块设计

| 文档 | 路径 | 说明 |
|------|------|------|
| 内核设计 | `docs/AirymaxOS/20-modules/01-kernel.md` | **核心文档**——内核子仓完整设计（含 12 daemon 映射表 + [SC] 符号清单） |
| 服务设计 | `docs/AirymaxOS/20-modules/02-services.md` | 12 daemon 服务 + io_uring 消息传递 |
| 安全设计 | `docs/AirymaxOS/20-modules/03-security.md` | Capability + LSM + Landlock + 机密计算 |
| 记忆设计 | `docs/AirymaxOS/20-modules/04-memory.md` | MemoryRovol 内核态 + CXL + PMEM + MGLRU |
| 认知设计 | `docs/AirymaxOS/20-modules/05-cognition.md` | CoreLoopThree kthread + Wasm 3.0 + LLM 感知调度 |
| 8 子仓总览 | `docs/AirymaxOS/20-modules/README.md` | 8 子仓矩阵与同源映射 |

### 接口与数据流

| 文档 | 路径 | 说明 |
|------|------|------|
| 系统调用接口 | `docs/AirymaxOS/30-interfaces/01-syscalls.md` | syscall 分类/编号/C 接口/错误码 |
| IPC 协议 | `docs/AirymaxOS/30-interfaces/02-ipc-protocol.md` | 128B 消息头 + 5 种 payload + io_uring 零拷贝 |
| 调度数据流 | `docs/AirymaxOS/40-dataflows/04-scheduling-flow.md` | EEVDF + sched_tac 调度数据流 |
| IPC 消息流 | `docs/AirymaxOS/40-dataflows/03-ipc-flow.md` | SQ/CQ ring + SQPOLL + DEFER_TASKRUN + MSG_RING |
| 认知数据流 | `docs/AirymaxOS/40-dataflows/01-cognition-flow.md` | System 1/2 双系统 + CoreLoopThree kthread |
| 记忆数据流 | `docs/AirymaxOS/40-dataflows/02-memory-flow.md` | L1→L4 四层递进 + CXL/PMEM/MGLRU |

### 安全

| 文档 | 路径 | 说明 |
|------|------|------|
| LSM 框架详解 | `docs/AirymaxOS/110-security/01-lsm-framework.md` | security_hook_heads 钩子链表 + lsm_blob_sizes |
| Landlock 沙箱 | `docs/AirymaxOS/110-security/02-landlock-sandbox.md` | 用户态可加载沙箱隔离 |
| Capability 模型 | `docs/AirymaxOS/110-security/03-capability-model.md` | seL4 风格 Capability 完整设计 |

### 工程规范

| 文档 | 路径 | 说明 |
|------|------|------|
| 工程标准手册 | `docs/AirymaxOS/50-engineering-standards/00-engineering-standards-handbook.md` | SSoT 规则注册表 + IRON-9 v3 + 禁词清单 |
| 编码规范 | `docs/AirymaxOS/50-engineering-standards/01-coding-standards.md` | C/Rust 编码规范 + 安全编码 |
| 开发流程 | `docs/AirymaxOS/50-engineering-standards/05-development-process.md` | 补丁生命周期 + 审查流程 |
| 治理模型 | `docs/AirymaxOS/50-engineering-standards/07-maintainers-and-governance.md` | 6 层维护者体系 + 工程规范委员会 |

### 契约层

| 文档 | 路径 | 说明 |
|------|------|------|
| 契约总览 | `docs/AirymaxOS/50-engineering-standards/20-contracts/README.md` | [SC]/[SS]/[IND]/[DSL] 四层契约模型 |
| syscall 契约 | `docs/AirymaxOS/50-engineering-standards/20-contracts/syscall_api_contract.md` | 系统调用 API 契约 |
| IPC 协议契约 | `docs/AirymaxOS/50-engineering-standards/20-contracts/ipc_protocol_contract.md` | IPC 协议等级契约 |
| 日志契约 | `docs/AirymaxOS/50-engineering-standards/20-contracts/logging_contract.md` | 日志格式契约 |

### 测试与性能

| 文档 | 路径 | 说明 |
|------|------|------|
| 调度性能 | `docs/AirymaxOS/170-performance/01-scheduling-performance.md` | sched_tac 性能基准（60-150ns）与 P99 < 50μs SLA |
| IPC 性能 | `docs/AirymaxOS/170-performance/03-ipc-performance.md` | io_uring 零拷贝延迟 ≤ 50ns / 吞吐 ≥ 10M msg/s |
| Token 效率 | `docs/AirymaxOS/170-performance/04-token-efficiency.md` | Agent 推理 Token 能效优化 |
| 测试框架 | `docs/AirymaxOS/80-testing/01-kunit-framework.md` | KUnit 内核单元测试 |
| 可观测性 | `docs/AirymaxOS/90-observability/01-ftrace-framework.md` | ftrace 追踪框架 |

### 兼容性

| 文档 | 路径 | 说明 |
|------|------|------|
| ABI 稳定性 | `docs/AirymaxOS/160-compatibility/01-abi-stability.md` | 4 层接口分级 + ABI 审查流程 |
| POSIX 兼容 | `docs/AirymaxOS/160-compatibility/02-posix-compat.md` | POSIX 兼容性矩阵 |
| 上游追踪 | `docs/AirymaxOS/160-compatibility/03-upstream-tracking.md` | Linux 6.6 → 7.1 升级追踪 |

### 开发流程与路线

| 文档 | 路径 | 说明 |
|------|------|------|
| 补丁生命周期 | `docs/AirymaxOS/120-development-process/01-patch-lifecycle.md` | 6 阶段：设计→自测→审查→主线→稳定版→LTS |
| 维护者层级 | `docs/AirymaxOS/120-development-process/02-maintainer-hierarchy.md` | 6 层维护者体系 + 工程规范委员会 |
| 路线图 | `docs/AirymaxOS/130-roadmap/README.md` | 里程碑、时间线、依赖图、风险缓解 |

---

## 五、构建与开发

### 编译

```bash
# 使用 Airymax 专属配置
make airy_defconfig
make -j$(nproc)

# 启用 Airymax 专属配置项
# CONFIG_AIRY_SYSCALL=y         — Airymax 系统调用
# CONFIG_AIRY_COREKERN=y        — 微核心抽象层
# CONFIG_AIRY_LOG=y             — 统一日志
# CONFIG_AIRY_IPC=y             — IPC fabric
# CONFIG_SECURITY_AIRY=y        — 纯 C LSM（airy）
# CONFIG_AIRY_SC_FALLBACK=y     — [DSL] 降级生存层（总开关）
```

### 内核模块

```bash
# 查看 Airymax 专属内核模块
lsmod | grep airy

# 查看启动日志
dmesg | grep "Airymax ALK"
# 输出：Airymax ALK-0.1.1 -- Agent Lifecycle Kernel
```

---

**版本**：0.1.1（文档体系完成）/ 1.0.1（开发）

**设计文档**：[docs/AirymaxOS/](../../docs/AirymaxOS/)

**维护者**：开源极境工程与规范委员会

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

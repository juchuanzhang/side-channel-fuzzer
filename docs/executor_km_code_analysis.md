# Revizor 内核执行器（executor_km）3500行代码深度解析

> 对应论文："Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks" (IEEE S&P 2026)
>
> 论文原文："we decided to implement a custom execution environment from scratch, totaling at over 3'500 lines of code in a kernel module."
>
> 代码位置：`rvzr/executor_km/` 目录

---

## 1. 概述

### 1.1 项目背景

Revizor 是基于模型关系测试（Model-based Relational Testing, MRT）的微架构侧信道漏洞检测工具。本论文的扩展版本引入了 **actor框架**，使其能够跨安全域（虚拟机、内核/用户进程等）检测微架构侧信道信息泄漏。

**内核执行器（executor_km）** 是整个工具的核心执行引擎，作为一个 Linux 内核模块实现。它直接运行在 Ring 0（内核模式），拥有对 CPU 硬件的完全控制权，负责：

- 配置 CPU 的微架构状态（MSR、CR0/CR4、性能计数器等）
- 创建和管理虚拟机（Intel VMX / AMD SVM）及进程的执行环境
- 执行多 actor 测试用例并收集硬件追踪（hardware traces）
- 在测量过程中确保低噪声、高吞吐量的隔离执行环境

### 1.2 为什么需要内核模块？

论文 Section 5.1 明确阐述了两个核心需求：

1. **完全可配置性（Full Configurability）**：需要自由配置所有执行环境参数（页表权限、CPU模式、VM配置等），甚至允许无效的系统配置来触发特定泄漏类型。Linux内核的安全防护机制会阻止这种自由配置。

2. **低开销（Low Overhead）**：MRT技术的有效性取决于每秒可执行的测试用例数量。需要至少100次测量/秒，要求在毫秒级时间内创建VM和页表。Linux内核的VM管理面向完整虚拟机，开销过大。

因此，作者选择从零开始实现自定义执行环境，而非复用 Linux 内核的 VM 和页表管理机制。

### 1.3 代码定位与规模

论文提到的 3500 行内核代码位于 `rvzr/executor_km/` 目录。主要由以下文件组成：

| 分类 | 文件 | 行数 | 核心功能 |
|------|------|------|----------|
| **通用基础设施** | | | |
| | `main.c` | 778 | 模块入口、SysFS接口、初始化/退出流程 |
| | `sandbox_manager.c` | 299 | 沙箱内存分配（代码区/数据区/util区） |
| | `code_loader.c` | 251 | 测试用例代码加载到沙箱 |
| | `data_loader.c` | 103 | 输入数据加载、寄存器初始化 |
| | `input_parser.c` | 203 | 输入数据解析（RCBF格式） |
| | `test_case_parser.c` | 362 | 测试用例解析（RCBF格式） |
| | `macro_expansion.c` | 342 | 宏扩展框架（架构无关部分） |
| | `measurement.c` | 369 | 测量执行流程、CPU环境配置 |
| | `page_tables_host.c` | 485 | 宿主机页表管理（PTE缓存/权限修改） |
| **x86平台特定** | | | |
| | `x86/vmx.c` | 848 | Intel VMX虚拟化管理（VMCS配置/VMLAUNCH） |
| | `x86/svm.c` | 465 | AMD SVM虚拟化管理（VMCB配置/VMRUN） |
| | `x86/macros.c` | 783 | 宏实现（域切换、测量、故障处理） |
| | `x86/page_tables_guest.c` | 672 | 客户机页表(GPT)和扩展页表(EPT/NPT)管理 |
| | `x86/idt.c` | 167 | IDT（中断描述符表）自定义管理 |
| | `x86/special_registers.c` | 317 | MSR/CR0/CR4管理、SSBP补丁、预取器控制 |
| | `x86/perf_counters.c` | 248 | Intel/AMD PMU性能计数器配置 |
| | `x86/fault_handlers.S` | 391 | 故障处理入口（汇编实现） |

x86核心实现代码（`.c` + `.S` 文件）总计约 **3500行**，与论文描述吻合。加上头文件和ARM64支持代码，总规模约6000行。

---

## 2. 整体架构

### 2.1 模块化架构设计

内核执行器采用清晰的模块化架构，各子系统通过明确定义的接口交互：

```
                    ┌─────────────────────────────┐
                    │     用户空间控制层            │
                    │  (Revizor Python CLI/配置)    │
                    └───────────┬─────────────────┘
                                │ SysFS / bin_attribute接口
                    ┌───────────▼─────────────────┐
                    │         main.c               │
                    │  模块入口 + SysFS属性管理      │
                    └───────────┬─────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
   ┌──────▼───────┐    ┌──────▼───────┐    ┌──────▼───────┐
   │ 测试用例管理   │    │  沙箱管理     │    │  测量引擎     │
   │ tc_parser     │    │ sandbox_mgr  │    │ measurement   │
   │ input_parser  │    │ code_loader  │    │ perf_counters │
   └───────────────┘    │ data_loader  │    └───────────────┘
                        └──────┬───────┘           │
                               │                   │
                ┌──────────────┼───────────────────┤
                │              │                   │
         ┌──────▼──────┐ ┌───▼─────────┐ ┌──────▼──────────┐
         │  页表管理     │ │  宏扩展     │ │  CPU状态管理     │
         │ pt_host      │ │ macro_exp   │ │ special_regs    │
         │ pt_guest     │ │ x86/macros  │ │ idt             │
         └──────────────┘ └─────────────┘ │ vmx / svm       │
                                        └───────────────────┘
```

### 2.2 Actor框架

**Actor** 是本文的核心抽象，代表任何安全域（进程、VM或其他隔离执行上下文）。技术上，一个actor包含：

- 一段在特定特权级和CPU模式下执行的代码区域
- 一段具有可配置权限的私有数据内存
- 多个入口和出口点，用于与其他actor交互

Actor类型：

| 类型 | CPU模式 | 特权级 | 域切换方式 |
|------|---------|--------|------------|
| main actor | HOST | KERNEL | 测试用例入口/退出 |
| guest actor | GUEST | KERNEL | VMRESUME/VMRUN ↔ VMCALL/VMMCALL |
| user actor | HOST | USER | SYSCALL ↔ SYSRET |

```c
// include/actor.h - Actor元数据定义
typedef struct {
    uint8_t mode;                    // MODE_HOST 或 MODE_GUEST
    uint8_t pl;                      // PL_KERNEL 或 PL_USER
    uint16_t data_permissions;       // 宿主机PTE权限掩码（可修改的位）
    uint16_t data_ept_properties;    // EPT权限掩码
} actor_metadata_t;
```

### 2.3 沙箱（Sandbox）内存布局

沙箱是所有actor共享的受控执行环境，内存布局如下：

```
沙箱内存布局（sandbox_manager.c管理）：

┌──────────────────────────────────────────────────────────┐
│  util_t（共享工具区，8KB对齐）                            │
│    ├── L1D priming area     [L1D_PRIMING_OFFSET]         │
│    │   （Prime+Probe的缓存填充/探测缓冲区）               │
│    ├── stored_rsp           [STORED_RSP_OFFSET]          │
│    ├── latest_measurement   [MEASUREMENT_OFFSET]         │
│    │   （htrace + pfc_reading + measurement_status）      │
│    └── ...                                                │
├──────────────────────────────────────────────────────────┤
│  actor_data_t[0]（主actor数据，8KB对齐）                  │
│    ├── underflow_pad        （下溢保护，防止越界访问）     │
│    ├── main_area            （主数据区，存放输入数据）     │
│    ├── faulty_area          （可控权限页，用于测试特定泄漏）│
│    ├── reg_init_area        （寄存器初始值区域）          │
│    ├── overflow_pad         （上溢保护）                  │
│    ├── macro_stack[64]      （宏调用栈，保存RSP等）       │
├──────────────────────────────────────────────────────────┤
│  actor_data_t[1..n]（其他actor数据）                     │
├──────────────────────────────────────────────────────────┤
│  actor_code_t[0]（主actor代码）                          │
│    ├── section[]            （代码段）                    │
│    ├── macros[]             （宏实现代码段）              │
├──────────────────────────────────────────────────────────┤
│  actor_code_t[1..n]（其他actor代码）                     │
└──────────────────────────────────────────────────────────┘
```

**关键设计决策**（`sandbox_manager.c`）：

1. **物理连续性**：数据区使用 `alloc_pages() + vmap()`，而非 `kmalloc`（使用大页）或 `vmalloc`（非物理连续）。因为 Prime+Probe 攻击要求连续物理页（PIPT缓存特性）。

2. **4KB页表**：不能使用大页（2MB/1GB），因为执行器需要操作单个PTE来修改权限。

3. **8KB对齐**：数据区对齐到2页边界，确保cache set对齐，使Prime+Probe测量更精确。

4. **代码区**：使用 `vmalloc()`，因为不需要物理连续性，但需要4KB页表（用于PTE操作）和可执行权限（通过 `set_memory_x()`）。

5. **自检验**：`init_sandbox_manager()` 包含一系列ASSERT，验证硬编码偏移量与实际结构体布局一致，防止编译器布局变化导致的错误。

---

## 3. 核心子系统详解

### 3.1 测量执行流程（measurement.c）

这是整个内核模块最关键的文件，实现了论文 Figure 4 中描述的高层算法。

**完整执行流程**：

```
trace_test_case()                              ← 最外层入口
    │
    ├── alloc_measurements()                    ← 分配测量结果数组
    ├── pre_run()                               ← 测量前准备
    │   ├── pfc_configure()                     ← 配置性能计数器
    │   ├── kernel_fpu_begin()                  ← 启用FPU（测试用例可能使用）
    │   ├── get_cpu()                           ← 禁止CPU抢占
    │   ├── raw_local_irq_save()                ← 禁用本地中断
    │
    ├── run_experiment_outer()                  ← 汇编入口（故障安全包装）
    │   └── run_experiment()                    ← 核心测量循环
    │       │
    │       ├── set_sandbox_page_tables()       ← 设置沙箱页表权限
    │       │   ├── store_orig_host_permissions()  ← 保存原始PTE
    │       │   ├── set_user_pages()            ← 为user actor设置U/S位
    │       │
    │       ├── set_execution_environment()     ← 配置CPU执行环境
    │       │   ├── set_special_registers()     ← MSR/CR0/CR4配置
    │       │   │   ├── store_orig_msr_state()  ← 保存原始MSR值
    │       │   │   ├── apply SSBP patch        ← Speculative Store Bypass Disable
    │       │   │   ├── disable prefetchers     ← 禁用硬件预取器
    │       │   │   ├── CR0: 清除CD位（启用缓存）
    │       │   │   ├── CR4: 设置PCE位（启用性能计数器）
    │       │   │   ├── set_msrs_for_user_actors() ← 配置syscall入口
    │       │   │   ├── set_msrs_for_vmx/svm()  ← 启用虚拟化扩展
    │       │   │
    │       │   ├── start_vmx/svm_operation()   ← 启用VMX/SVM操作
    │       │   ├── store_orig_vmcs/vmcb_state() ← 保存原始VM状态
    │       │   ├── set_vmcs/vmcb_state()       ← 配置VM控制结构
    │       │
    │       ├── 初始化Prime+Probe缓冲区
    │       ├── uarch_flush()                   ← 刷新微架构状态（可选）
    │       │   Intel: VERW + L1D_FLUSH_CMD + WBINVD + LFENCE
    │       │   AMD:  WBINVD + LFENCE
    │       │
    │       └── for (i = -warmup; i < n_inputs; i++)
    │           │
    │           ├── load_sandbox_data(i)         ← 加载输入数据到沙箱
    │           ├── set_faulty_page_permissions() ← 设置可控页面权限
    │           ├── set_inner_fault_handlers()   ← 安装自定义IDT
    │           │
    │           ├── 执行测试用例                  ← loaded_test_case_entry(data)
    │           │   （测试用例模板包含：
    │           │     保存RSP → 设置GPR → Prime/Flush →
    │           │     域切换 → 客户机/用户代码 →
    │           │     域返回 → Probe/Reload → 恢复RSP）
    │           │
    │           ├── unset_inner_fault_handlers() ← 恢复bubble IDT
    │           ├── restore_faulty_page_permissions() ← 恢复页面权限
    │           │
    │           ├── 检查测量状态                  ← check_measurement_status()
    │           │   （STATUS_ENDED? SMI计数?）
    │           │
    │           └── 存储测量结果                  ← measurements[i]
    │               （htrace + pfc_reading[5]）
    │
    ├── recover_orig_state()                    ← 恢复所有CPU状态
    │   ├── restore_orig_vmcs/vmcb_state()
    │   ├── stop_vmx/svm_operation()
    │   ├── restore_faulty_page_permissions()
    │   ├── restore_special_registers()
    │   ├── restore_orig_sandbox_page_tables()
    │
    ├── post_run()                              ← 测量后清理
    │   ├── AMD: STGI（启用中断）
    │   ├── raw_local_irq_restore()             ← 恢复中断
    │   ├── put_cpu()                           ← 允许抢占
    │   ├── kernel_fpu_end()                    ← 关闭FPU
```

**关键设计要点**：

1. **双层IDT保护**：使用三层故障处理机制：
   - `outer IDT`（bubble_idt）：捕获所有异常并安全恢复
   - `inner IDT`（test_case_idt）：将指定异常路由到测试用例的故障处理宏
   - NMI/Machine Check：直接路由到自定义恢复处理程序

2. **状态保存/恢复**：所有CPU状态的修改都有对应的保存和恢复操作，确保宿主机Linux内核不受影响：
   - CR0/CR4/MSR → `special_registers.c`
   - VMCS/VMCB → `vmx.c` / `svm.c`
   - PTE权限 → `page_tables_host.c` / `page_tables_guest.c`
   - IDT → `idt.c`

3. **微架构刷新**：`uarch_flush()` 清除所有微架构状态缓冲区：
   - Intel: VERW指令（MDS缓解）刷新存储缓冲区 + L1D_FLUSH_CMD + WBINVD
   - AMD: WBINVD + LFENCE

4. **warmup轮次**：`i = -warmup` 的负数轮次用于稳定微架构状态，不记录测量结果。

### 3.2 宏系统（macro_expansion.c + x86/macros.c）

宏系统实现了论文 Section 4.4 中描述的 **binary patching** 方法。

**工作原理**：

1. 测试用例模板中的宏在编译后变为8字节NOP指令（占位符）
2. 执行器扫描代码中的宏占位符，将其替换为5字节相对跳转（JMP）+ 3字节LFENCE
3. LFENCE防止直线推测（straight-line speculation）干扰微架构测量
4. 跳转目标指向宏实现代码，宏实现代码执行完后跳回原位置

```
原始测试用例代码：
    ...其他指令...
    NOP NOP NOP NOP NOP NOP NOP NOP    ← 宏占位符（8字节）
    ...其他指令...

替换后：
    ...其他指令...
    JMP [macro_impl]                   ← 5字节相对跳转
    LFENCE                             ← 3字节，防直线推测
    ...其他指令...

宏实现代码区域：
    [macro_impl]:
        宏动态配置部分（start函数生成的代码）
        宏静态主体部分（body函数的汇编代码）
        JMP [return_addr]              ← 跳回原位置
        LFENCE                         ← 防直线推测
```

**宏类型一览**：

| 宏类型 | 功能 | Intel实现 | AMD实现 |
|--------|------|-----------|---------|
| `measurement_start` | 开始微架构测量 | Prime/Flush/Evict + PFC_start | 同 |
| `measurement_end` | 结束微架构测量 | Probe/Reload/TSC_end + PFC_end | 同 |
| `switch_h2g` | 宿主机→客户机切换 | VMRESUME | CLGI+VMSAVE+VMRUN+VMLOAD+STGI |
| `switch_g2h` | 客户机→宿主机切换 | VMCALL | VMMCALL |
| `switch_k2u` | 内核→用户切换 | SYSRETQ | 同 |
| `switch_u2k` | 用户→内核切换 | SYSCALL | 同 |
| `switch` | 同域actor间切换 | JMP（相对跳转） | 同 |
| `set_h2g_target` | 设置VM入口地址 | VMPTRLD + VMWRITE(GUEST_RIP) | 直接写VMCB.RIP |
| `set_g2h_target` | 设置VM出口地址 | VMWRITE(HOST_RIP) | 无需（AMD自动返回） |
| `set_k2u_target` | 设置syscall返回地址 | MOV R11, function_addr | 同 |
| `set_u2k_target` | 设置syscall入口地址 | WRMSR(LSTAR) + 保存RSP/FLAGS | 同 |
| `landing_h2g` | VM着陆点 | 更新R14/R15/RSP | 同 + 清除RAX |
| `landing_g2h` | VM返回着陆点 | 更新R14/R15 | 同 |
| `landing_k2u` | SYSRET着陆点 | 更新RSP/R14 | 同 |
| `landing_u2k` | SYSCALL着陆点 | 更新R14（RSP由syscall自动恢复） | 同 |
| `fault_handler` | 异常/故障处理 | 设置RSP/R14/R15 + 嵌套故障检测 | 同 |
| `fault_handler_with_measurement` | 带测量的故障处理 | 同上 + measurement_end | 同 |
| `set_data_permissions` | 动态修改PTE权限 | 直接OR/AND PTE位 | 同 |

**域切换的完整流程**（以Host→Guest为例）：

```
=== 宿主机actor代码执行 ===

1. set_h2g_target.vm_start:
   [Intel]  VMPTRLD [vmcs_hpa]           ← 加载目标VM的VMCS
            VMWRITE GUEST_RIP, r11        ← 设置客户机入口RIP
   [AMD]    MOV r11, [vmcb_hva]
            MOV [r11+VMCB_RIP_OFFSET], function_addr  ← 设置客户机入口RIP

2. switch_h2g:
   [Intel]  VMRESUME                      ← 恢复VM执行，进入客户机
   [AMD]    CLGI                           ← 禁用全局中断
            MOV rax, [rax]                 ← 加载VMCB物理地址
            VMSAVE rax                     ← 保存宿主机状态
            VMRUN rax                      ← 进入客户机执行
            VMLOAD rax                     ← VM退出后恢复宿主机状态
            MOV rax, 0                     ← 清除RAX
            STGI                           ← 启用全局中断

=== 客户机actor代码执行 ===

3. landing_h2g:
   更新R14（数据基址）→ guest_memory->data.main_area
   更新R15（util基址）→ guest_memory->util
   [AMD] 清除RAX

4. measurement_start:
   [Prime+Probe] PRIME(l1d_priming_area) + PFC_start + SET_SR_STARTED
   [Flush+Reload] FLUSH(actor_data) + PFC_start + SET_SR_STARTED

5. random_instructions:
   随机生成的指令序列（测试用例主体）

6. measurement_end:
   [Prime+Probe] PROBE(l1d_priming_area) → HTRACE_REGISTER + PFC_end + SET_SR_ENDED
   [Flush+Reload] RELOAD(actor_data) → HTRACE_REGISTER + PFC_end + SET_SR_ENDED

7. switch_g2h:
   [Intel]  VMCALL                       ← 触发VM退出
   [AMD]    VMMCALL                      ← 触发VM退出

=== 宿主机actor着陆 ===

8. landing_g2h:
   更新R14 → sandbox->data[actor_id].main_area
   更新R15 → sandbox->util
   [AMD] 清除RAX
```

**测量方法实现**：

- **Prime+Probe**：先填充L1D缓存（Prime），执行测试代码，再探测缓存状态（Probe），被evicted的cache set表示客户机访问了该set。结果以bitmask形式存储在HTRACE_REGISTER（R12）中。

- **Flush+Reload**：先刷新共享内存的所有缓存行（Flush），执行测试代码，再重新加载（Reload），快速访问的行表示客户机在执行期间访问了该行。结果最高位设为1标记有效测量。

- **TSC**：使用时间戳计数器测量执行时间差，适合检测总体泄漏而非具体cache set。

### 3.3 Intel VMX虚拟化管理（x86/vmx.c）

VMX文件实现了完整的Intel VMX操作流程，严格遵循Intel SDM（Software Developer's Manual）的步骤。

**VMX操作生命周期**：

```
init_vmx()
    ├── 分配VMXON页（4KB对齐）
    ├── 分配VMCS页
    ├── 分配vmcs_hpas数组
    │
start_vmx_operation()                      ← 进入VMX root操作模式
    ├── 检查CR0/CR4固定位
    ├── 配置IA32_FEATURE_CONTROL MSR
    │   （Lock bit + VMX enabled outside SMX）
    ├── 准备VMXON区域（revision ID）
    ├── VMXON                               ← 进入VMX root模式
    │
set_vmcs_state()                            ← 为每个guest actor配置VMCS
    ├── vmclear(vmcs_hpa)                   ← 初始化VMCS
    ├── vmptrld(vmcs_hpa)                   ← 加载VMCS
    │
    ├── set_vmcs_guest_state()              ← 设置客户机状态
    │   ├── CR0/CR3/CR4                    ← 控制寄存器
    │   ├── DR7                             ← 调试寄存器
    │   ├── RSP/RIP/RFLAGS                  ← 通用寄存器
    │   ├── CS/SS/DS/ES/FS/GS/LDTR/TR      ← 段寄存器
    │   ├── GDTR/IDTR                       ← 描述符表寄存器
    │   ├── SYSENTER_CS/ESP/EIP            ← 系统入口
    │   ├── Activity state = 0             ← 活动状态（Active）
    │   ├── Block NMI                       ← 阻止NMI
    │   ├── VMCS link pointer = -1         ← 无链接VMCS
    │   ├── Preemption timer = 0xFFFF      ← VM超时定时器
    │
    ├── set_vmcs_host_state()               ← 设置宿主机状态
    │   ├── CR0/CR3/CR4                    ← 宿主机控制寄存器
    │   ├── CS/SS/DS/ES/FS/GS/TR selectors ← 宿主机段选择子
    │   ├── FS_BASE/GS_BASE/TR_BASE       ← 宿主机段基址
    │   ├── GDTR_BASE/IDTR_BASE            ← 宿主机描述符表基址
    │   ├── SYSENTER_CS/ESP/EIP            ← 宿主机系统入口
    │   ├── EFER                            ← 宿主机EFER
    │
    ├── set_vmcs_exec_control()             ← 设置VM执行控制
    │   ├── Pin-based controls              ← 中断/NMI控制
    │   ├── Primary processor controls      ← 主要处理器控制
    │   ├── Secondary processor controls    ← 二级处理器控制
    │   ├── Exception bitmap                ← 异常拦截位图
    │   ├── CR0/CR4 guest/host masks        ← CR0/CR4虚拟化
    │   ├── EPT pointer                     ← 扩展页表指针
    │   ├── ENCLS exiting bitmap            ← SGX拦截
    │
    ├── set_vmcs_exit_control()             ← 设置VM退出控制
    │   ├── Exit controls                   ← 退出时的宿主机状态加载
    │
    ├── set_vmcs_entry_control()            ← 设置VM进入控制
    │   ├── Entry controls                  ← 进入时的客户机状态加载
    │
    ├── make_vmcs_launched()                ← VMLAUNCH并检查结果
    │   ├── VMWRITE HOST_RIP/HOST_RSP      ← 设置退出返回地址
    │   ├── VMLAUNCH                         ← 启动VM
    │   ├── 检查退出原因                    ← VMCALL或超时定时器
    │   ├── 更新GUEST_RIP/HOST_RIP/HOST_RSP ← 设置后续VMRESUME参数
    │
stop_vmx_operation()                        ← 退出VMX操作模式
    ├── INVEPT                              ← 刷新EPT TLB
    ├── VMXOFF                              ← 退出VMX root模式
```

**关键设计要点**：

1. **VMLAUNCH vs VMRESUME**：首次VM进入使用VMLAUNCH（启动新VM），后续使用VMRESUME（恢复已启动的VM）。`make_vmcs_launched()` 执行一次VMLAUNCH，使VMCS进入"launched"状态。

2. **HOST_RIP/HOST_RSP**：在VMLAUNCH前通过汇编内联代码设置，因为需要捕获VMLAUNCH后的精确返回地址和栈指针。VM退出后，所有caller-saved寄存器可能被修改，因此clobber列表包含所有caller-saved寄存器。

3. **VM超时定时器**：设置VMX preemption timer = 0xFFFF，防止VM代码无限执行。VM运行超时后自动退出。

4. **EPT指针**：每个guest actor有自己的EPT，通过 `EPT_POINTER` VMCS字段设置。

### 3.4 AMD SVM虚拟化管理（x86/svm.c）

SVM文件实现了AMD的安全虚拟机管理，结构与VMX类似但使用不同的控制结构。

**SVM与VMX的关键差异**：

| 特性 | Intel VMX | AMD SVM |
|------|-----------|---------|
| 控制结构 | VMCS（64位字段，VMREAD/VMWRITE） | VMCB（内存结构体，直接修改字段） |
| VM进入 | VMLAUNCH/VMRESUME | VMRUN |
| VM退出 | VMCALL | VMMCALL |
| 状态保存 | VMCS自动管理 | VMSAVE/VMLOAD（需手动调用） |
| 中断管理 | VMX自动处理 | CLGI/STGI（需手动切换） |
| 二级页表 | EPT（RWX权限位） | NPT（标准PTE格式 + XD位） |
| 宿主机状态保存区 | VMCS Host-state area | Host State Save Area（MSR_VM_HSAVE_PA） |
| ASID | VPID | ASID（直接赋值给VMCB） |

**VMRUN执行流程**：
```
宿主机代码：
    CLGI                    ← 禁用全局中断（防止VMRUN期间中断）
    MOV rax, [vmcb_hpa_ptr] ← 加载VMCB物理地址
    VMSAVE rax              ← 保存宿主机状态到Host SSA
    VMRUN rax               ← 进入客户机
                            ← VM退出后自动返回此处
    VMLOAD rax              ← 恢复宿主机状态
    MOV rax, 0              ← 清除RAX
    STGI                    ← 启用全局中断
```

**VMCB拦截配置**：
`set_vmcb_control()` 设置大量拦截位，确保VM中的特权操作都触发VMEXIT：
- 所有CR/DR读写拦截
- 所有异常拦截（exception bitmap = 0xFFFFFFFF）
- 大量指令拦截（CPUID、HLT、INVD、WBINVD、IOIO、MSR等）
- **不拦截**的指令：PUSHF/POPF/RDTSC/RDPMC/RDTSCP（这些指令的执行痕迹是测量目标）

### 3.5 页表管理

页表管理分为宿主机页表（`page_tables_host.c`）和客户机页表（`x86/page_tables_guest.c`）两部分。

**宿主机页表管理**：

核心函数 `get_pte()` 手动遍历内核页表（5级：PGD→P4D→PUD→PMD→PTE），获取给定虚拟地址的PTE指针。这在Linux内核中不是标准操作，因为：

1. x86_64没有专用内核页表寄存器，CR3同时管理用户和内核地址空间
2. CR3在每次上下文切换时重新加载
3. 不能缓存CR3值，因为对应task可能已退出

解决方案：每次调用时读取CR3获取当前pgd基址。内核保持所有pgd的上半部（内核/vmalloc区域）同步，所以任何活跃的pgd都能正确遍历。

**客户机页表管理**：

为每个guest actor创建完整的4级页表结构：

```
客户机内存映射（guest_memory_t）：

GUEST_V_MEMORY_START（客户机虚拟地址空间）
    ├── util                    ← 共享工具区
    ├── data                    ← actor私有数据区
    │   ├── main_area           ← 主数据
    │   ├── faulty_area         ← 可控权限页
    │   ├── reg_init_area       ← 寄存器初始值
    ├── code                    ← actor代码区
    │   ├── section             ← 代码段
    │   ├── macros              ← 宏实现
    ├── gdt                     ← 客户机GDT
    ├── vmlaunch_page           ← VM启动入口页（VMCALL指令）
    ├── guest_page_tables       ← 客户机自身页表

GUEST_P_MEMORY_START（客户机物理地址空间）
    └── （与虚拟地址空间相同布局）
```

**EPT/NPT设置**：

扩展页表（Intel EPT）或嵌套页表（AMD NPT）将客户机物理地址（GPA）映射到宿主机物理地址（HPA）：

```
EPT/NPT映射层次：

L4(EPML4) → L3(EPDPTE) → L2(EPDTE) → L1(EPTE)
                                        ↓
                                    Host Physical Address

每个actor的EPT映射：
    GPA(util)      → HPA(sandbox->util)       ← 共享
    GPA(data)      → HPA(sandbox->data[id])   ← 私有
    GPA(code)      → HPA(sandbox->code[id])   ← 私有
    GPA(gdt)       → HPA(allocated_gdts[id])  ← 私有
    GPA(vmlaunch)  → HPA(vmlaunch_page)        ← 共享
    GPA(page_tbls) → HPA(allocated_page_tables[id]) ← 私有
```

**HPA-GPA碰撞（内存别名）功能**：

论文 Section 5.2 提到的可选特性，用于最大化推测地址混淆的可能性（类似 Foreshadow-VM 攻击）：

- 所有VM actor的代码和数据页位于相同的客户机虚拟地址
- 客户机物理地址与主actor的宿主机物理地址匹配

```c
// page_tables_guest.c中的实现
if (enable_hpa_gpa_collisions) {
    // 数据区：GPA映射到主actor的HPA而非独立的GPA
    uint64_t aliased_vaddr = ((uint64_t)&sandbox->data[0]) + i;
    paddr = vmalloc_to_phys((void *)aliased_vaddr);
} else {
    paddr = ((uint64_t)&guest_p_memory->data) + i;
}
```

### 3.6 IDT管理（x86/idt.c）

中断描述符表（IDT）管理实现了**三层故障处理机制**：

```
正常Linux IDT
    │
    ↓ set_outer_fault_handlers()
    │
bubble IDT（外层保护）
    ├── NMI → nmi_handler（恢复原始状态后退出执行器）
    ├── Double Fault/Machine Check → 原始Linux处理程序
    ├── 其他所有异常 → bubble_handler（恢复原始状态后退出执行器）
    │
    ↓ set_inner_fault_handlers()
    │
test_case IDT（内层测试）
    ├── NMI → nmi_handler
    ├── Double Fault/Machine Check → 原始Linux处理程序
    ├── handled_faults中的异常 → fault_handler宏（测试用例内部处理）
    ├── 其他所有异常 → test_case_handler[i]（每个向量号独立处理程序）
```

- **bubble IDT**：在 `pre_run()` 中安装，捕获所有意外异常并安全恢复CPU状态
- **test_case IDT**：在每个输入执行前安装，将指定异常路由到测试用例的故障处理宏

**fault_handlers.S** 使用汇编宏生成256个故障处理入口点，每个入口点：
1. 设置 `is_nested_fault` 标志
2. 恢复宿主机IDTR（从bubble_idtr）
3. 恢复宿主机GDTR
4. 恢复宿主机CR3（页表）
5. 调用 `recover_orig_state()`（恢复所有CPU状态）
6. 返回错误代码

### 3.7 特殊寄存器管理（x86/special_registers.c）

管理所有CPU特殊寄存器的保存、配置和恢复：

**保存的原始状态**：
- CR0、CR4（控制寄存器）
- EFER（扩展特性启用寄存器）
- LSTAR（syscall入口MSR）
- FS_BASE、GS_BASE（段基址MSR）
- GDTR（全局描述符表寄存器）
- SPEC_CTRL（SSBP补丁MSR）
- MISC_FEATURE_CONTROL（预取器控制MSR）
- SYSCFG（AMD系统配置MSR）

**配置操作**：
1. **SSBP补丁**：根据CPU型号选择正确的MSR（SPEC_CTRL/VIRT_SPEC_CTRL/LS_CFG）
2. **预取器控制**：禁用硬件预取器以减少测量噪声
   - Intel: MSR_MISC_FEATURE_CONTROL，不同型号掩码不同
   - AMD: MSR_AMD64_DC_CFG 或 0xC0000108（Zen4）
3. **CR0修改**：清除CD位（启用缓存），缓存是侧信道测量的基础
4. **CR4修改**：设置PCE位（启用性能计数器Ring 3访问）
5. **User actor**：设置LSTAR MSR指向fault_handler（syscall入口）
6. **VM actor**：
   - Intel: 设置CR4.VMXE=1，确保CR0/CR4固定位
   - AMD: 设置EFER.SVME=1，检查VM_CR.SVME_DISABLE=0

### 3.8 性能计数器配置（x86/perf_counters.c）

配置5个性能计数器（PFC），用于辅助硬件追踪收集和噪声检测：

| PFC编号 | 功能 | Intel事件 | AMD事件 |
|---------|------|-----------|---------|
| PFC#0 | 硬件追踪辅助 | MEM_LOAD_RETIRED.L1_HIT | DC_FILLS_BY_DATA_SOURCE |
| PFC#1 | 模糊反馈（已发射微操作） | UOPS_ISSUED.ANY | Dispatched ops（Zen2+）或dummy（Zen1） |
| PFC#2 | 模糊反馈（已退休微操作） | UOPS_RETIRED.RETIRE_SLOTS | Retired ops |
| PFC#3 | 模糊反馈（误预测恢复周期） | INT_MISC.CLEAR_RESTEER_CYCLES | Decode redirects |
| PFC#4 | 中断检测 | HW_INTERRUPTS.RECEIVED | — |
| PFC#5 | SMI监控 | — | SMI interrupts |

不同CPU型号的事件编号可能不同（如RaptorCove vs KabyLake），代码通过CPU型号检测选择正确的配置。

---

## 4. 数据流与交互

### 4.1 用户空间↔内核模块交互

内核模块通过 SysFS 接口与用户空间的 Revizor Python CLI 交互：

```
/sys/kernel/rvzr_executor/
    ├── test_case          [RW] ← 加载测试用例（RCBF格式）
    ├── test_case_bin      [R]  ← 读取actor代码元数据
    ├── inputs             [RW] ← 加载输入数据（RCBF格式）
    ├── trace              [R]  ← 读取硬件追踪结果
    ├── warmups            [RW] ← 设置/读取预热轮数
    ├── print_data_base    [R]  ← 读取数据区基址
    ├── print_code_base    [R]  ← 读取代码区基址
    ├── enable_ssbp_patch  [W]  ← 启用/禁用SSBP补丁
    ├── enable_prefetcher  [W]  ← 启用/禁用预取器
    ├── enable_pre_run_flush [W] ← 启用/禁用微架构刷新
    ├── enable_hpa_gpa_collisions [W] ← 启用/禁用内存别名
    ├── measurement_mode   [W]  ← 设置测量模式（P+P/F+R/E+R/TSC）
    ├── enable_quick_and_dirty_mode [W] ← 快速模式
    ├── handled_faults     [RW] ← 设置/读取要处理的故障类型
    ├── enable_dbg_gpr_mode [W] ← 调试GPR模式
    ├── dbg_dump           [R]  ← 调试：转储全局变量
    ├── dbg_guest_page_tables [R] ← 调试：转储客户机页表
```

### 4.2 RCBF二进制格式

测试用例和输入数据通过自定义的RCBF（Revizor Custom Binary Format）格式传输：

```
测试用例RCBF格式：
┌──────────────────────────────────────┐
│ Header (16 bytes)                    │
│   ├── n_actors (8 bytes)             │
│   ├── n_symbols (8 bytes)            │
├──────────────────────────────────────┤
│ Actor Table                          │
│   ├── actor_metadata_t[n_actors]     │
│   │   (mode, pl, data_permissions,   │
│   │    data_ept_properties)          │
├──────────────────────────────────────┤
│ Symbol Table                         │
│   ├── tc_symbol_entry_t[n_symbols]   │
│   │   (id, owner, offset, args)      │
├──────────────────────────────────────┤
│ Section Metadata                     │
│   ├── tc_section_metadata_entry_t[n] │
│   │   (owner, size)                  │
├──────────────────────────────────────┤
│ Section Data                         │
│   ├── code[n_actors]                 │
│   │   （每个actor的ELF代码段）        │
└──────────────────────────────────────┘
```

### 4.3 测量结果格式

每次测量结果包含硬件追踪和性能计数器读数：

```
measurement_t（每个输入一个）：
├── htrace[0]          ← 硬件追踪（cache set bitmask或访问地址集合）
│   最高位=1表示有效测量，最高位=0表示损坏
├── pfc_reading[0]     ← L1 hits
├── pfc_reading[1]     ← Uops issued
├── pfc_reading[2]     ← Uops retired
├── pfc_reading[3]     ← Misprediction recovery cycles
├── pfc_reading[4]     ← HW interrupts / SMI
└── status             ← 测量状态（UNINITIALIZED/STARTED/ENDED）
```

---

## 5. 安全设计考量

### 5.1 故障安全（Fail-Safe）设计

内核模块在多个层面实现故障安全机制，确保即使测试用例导致CPU状态异常，宿主机Linux内核也能正常恢复：

1. **状态保存/恢复**：所有CPU状态修改都有对应的保存和恢复操作
2. **三层IDT保护**：即使内层IDT失效，外层bubble IDT也能安全恢复
3. **`recover_orig_state()`**：以故障安全方式编写，可在故障处理程序中调用
4. **中断禁用**：测量期间禁用所有本地中断，防止OS调度干扰
5. **VM超时**：VMLAUNCH设置preemption timer，防止VM代码无限执行
6. **`unfinished_call`标志**：防止在sysfs调用过程中移除模块

### 5.2 微架构噪声控制

为获得精确的微架构测量，执行器实施多种噪声控制措施：

1. **禁用中断**：`raw_local_irq_save()` 防止OS中断干扰
2. **禁用抢占**：`get_cpu()` 防止CPU迁移
3. **禁用预取器**：减少非确定性缓存访问
4. **SSBP补丁**：防止Speculative Store Bypass引入额外泄漏
5. **微架构刷新**：可选的L1D/存储缓冲区/缓存全面刷新
6. **warmup轮次**：稳定微架构状态后再开始正式测量
7. **SMI检测**：通过性能计数器检测SMI，标记受影响的测量

### 5.3 测量状态验证

`check_measurement_status()` 验证每次测量的完整性：
- 检查测量开始宏是否执行（STATUS_STARTED → STATUS_ENDED）
- 检查SMI计数是否为零
- 有效测量标记最高位为1，损坏测量保持最高位为0
- 损坏测量不设置 `err`（因为SMI导致的损坏是预期中的偶发事件）

---

## 6. 总结

### 6.1 代码量分布

| 模块 | 核心代码行数 | 占比 | 论文对应章节 |
|------|-------------|------|-------------|
| VM管理（VMX+SVM） | 1313 | 37% | Section 5.2 "VM Actor Configuration" |
| 页表管理（Host+Guest） | 1157 | 33% | Section 5.2 "CPU Configuration" |
| 宏系统（扩展+实现） | 1125 | 32% | Section 4.4 "Implementation of Macros" |
| 测量引擎 | 369 | — | Section 5.2 "Measurement loop" |
| 其他支撑 | ~500 | — | SysFS、解析、加载 |
| **x86核心总计** | **~3500** | **100%** | — |

### 6.2 设计哲学

这3500行代码体现的核心设计哲学是：

1. **最小化依赖**：不依赖Linux内核的VM/页表管理机制，从零实现，确保完全控制
2. **故障安全优先**：所有状态修改都可逆，即使异常发生也能安全恢复
3. **低开销优先**：使用直接的汇编指令和二进制补丁而非内核API，减少测量噪声
4. **平台适配**：同时支持Intel VMX和AMD SVM，通过条件编译处理差异
5. **可配置性**：通过SysFS接口暴露所有配置选项，支持不同的测试场景

### 6.3 与论文的对应关系

| 代码模块 | 论文章节 | 论文描述 |
|----------|----------|----------|
| `measurement.c` + 模板 | Section 5.2, Figure 4 | "High-level algorithm of setting up the execution environment" |
| `vmx.c` / `svm.c` | Section 5.2 | "VM Actor Configuration" |
| `page_tables_host.c` | Section 5.2 | "User Actor Configuration" |
| `page_tables_guest.c` | Section 5.2 | "Memory Aliasing" |
| `special_registers.c` | Section 5.2 | "CPU Configuration" / "State Preservation" |
| `idt.c` + fault_handlers.S | Section 5.2 | "State Preservation and Fault Isolation" |
| `x86/macros.c` | Section 4.4 | "Implementation of Macros" (binary patching) |
| `macro_expansion.c` | Section 4.4 | "In the executor, macros are implemented via binary patching" |
| `sandbox_manager.c` | Section 5.2 | 内存分配约束（物理连续、4KB PTE、8KB对齐） |
| `perf_counters.c` | Section 7 | 性能计数器用于噪声检测和测量辅助 |

---

## 附录：文件间依赖关系

```
main.c
    ├── → sandbox_manager.c（沙箱分配）
    ├── → code_loader.c（代码加载）
    ├── → data_loader.c（数据加载）
    ├── → input_parser.c（输入解析）
    ├── → test_case_parser.c（测试用例解析）
    ├── → measurement.c（测量执行）
    ├── → special_registers.c（MSR管理）
    ├── → page_tables_host.c（宿主机页表）
    ├── → perf_counters.c（性能计数器）
    ├── → idt.c（IDT管理）
    ├── → vmx.c / svm.c（VM管理）

measurement.c（测量执行流程）
    ├── → sandbox_manager.c（沙箱操作）
    ├── → code_loader.c（测试用例入口）
    ├── → data_loader.c（数据加载）
    ├── → special_registers.c（CPU配置）
    ├── → page_tables_host.c（页表权限）
    ├── → page_tables_guest.c（EPT权限）
    ├── → perf_counters.c（PFC配置）
    ├── → idt.c（IDT切换）
    ├── → vmx.c / svm.c（VM操作）

code_loader.c
    ├── → macro_expansion.c（宏扩展框架）
    │   └── → x86/macros.c（宏实现）
    │       ├── → vmx.c / svm.c（VM相关宏）
    │       ├── → page_tables_host.c（PTE修改宏）
    │       ├── → page_tables_guest.c（guest地址宏）

page_tables_guest.c
    ├── → sandbox_manager.c（沙箱内存地址）
    ├── → vmx.c / svm.c（EPT指针）
```

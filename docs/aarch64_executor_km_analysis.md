# ARM64 Executor KM 代码深度解析文档

## 目录

1. [架构概述](#1-架构概述)
2. [ARM64与x86的关键差异](#2-arm64与x86的关键差异)
3. [vm.c — ARM64 EL2虚拟化管理](#3-vmc--arm64-el2虚拟化管理)
4. [macros.c — 域切换宏实现](#4-macroc--域切换宏实现)
5. [page_tables_guest.c — Stage-1/Stage-2页表](#5-page_tables_guestc--stage-1stage-2页表)
6. [special_registers.c — 系统寄存器管理](#6-special_registersc--系统寄存器管理)
7. [perf_counters.c — Cortex A72/A76 PMU配置](#7-perf_countersc--cortex-a72a76-pmu配置)
8. [fault_handler.c — 多层异常处理](#8-fault_handlerc--多层异常处理)
9. [exception.S — EL2向量表与汇编处理](#9-exceptions--el2向量表与汇编处理)
10. [通用代码的ARM64适配](#10-通用代码的arm64适配)
11. [关键常量与编码](#11-关键常量与编码)
12. [跨域测试支持矩阵](#12-跨域测试支持矩阵)

---

## 1. 架构概述

ARM64 executor_km是论文"Enter, Exit, Page Fault, Leak"在ARM64平台上的完整实现，支持Cortex A72和A76处理器。

### ARM64异常级别模型

| 异常级别 | 功能 | 对应x86概念 |
|----------|------|------------|
| EL0 | 用户态(User) | Ring 3 |
| EL1 | 内核态(Kernel) | Ring 0 |
| EL2 | Hypervisor | VMX root / SVM host |

### 核心文件清单

| 文件 | 行数 | 功能 | 对应x86文件 |
|------|------|------|------------|
| `arm64/vm.c` | 744 | EL2虚拟化管理 | `x86/vmx.c` + `x86/svm.c` |
| `arm64/macros.c` | ~1160 | 域切换宏(K2U/U2K/H2G/G2H) | `x86/macros.c` |
| `arm64/page_tables_guest.c` | ~600 | S1PT/S2PT页表 | `x86/page_tables_guest.c` |
| `arm64/special_registers.c` | ~1048 | 系统寄存器保存/恢复 | `x86/special_registers.c` |
| `arm64/perf_counters.c` | ~300 | PMU事件配置 | `x86/perf_counters.c` |
| `arm64/fault_handler.c` | ~400 | 多层异常向量表 | `x86/fault_handler.c` |
| `arm64/exception.S` | ~200 | EL2向量表汇编 | `x86/fault_handler.S` |
| `include/vm.h` | 180 | VM管理接口定义 | `include/vmx.h` + `include/svm.h` |
| `include/vm_constants.h` | 638 | ARM64 VM常量定义 | `include/vmx_config.h` + `include/svm_constants.h` |

---

## 2. ARM64与x86的关键差异

### 虚拟化管理

| x86 | ARM64 |
|-----|-------|
| VMCS(Intel)/VMCB(AMD)内存结构 | 直接使用系统寄存器 |
| VMLAUNCH/VMRUN进入guest | `eret`从EL2返回EL1 |
| VMCS Host-State Area保存host状态 | host状态自动恢复(无需保存区) |
| EPT/NPT嵌套页表 | Stage-2页表(S2PT), VTTBR_EL2指向 |
| VM_EXIT_REASON + EXIT_QUALIFICATION | ESR_EL2.EC + ESR_EL2.ISS |
| GUEST_LINEAR_ADDRESS/GUEST_PHYSICAL_ADDRESS | FAR_EL2/HPFAR_EL2 |
| VMXON/VMXOFF启用/关闭 | HCR_EL2.VM位启用/关闭 |

### 页表描述符

| x86 EPT | ARM64 S2PT |
|---------|-----------|
| Bit[0]: Read | Bit[1]: Read |
| Bit[1]: Write | Bit[2]: Write |
| Bit[2]: Execute | Bit[3]: Execute |
| Bit[3]: Execute-only | 不支持(需Read+Exec) |
| Bit[6]: Accessed | Bit[10]: AF |
| Bits[51:12]: PA | Bits[47:12]: PA |

### 域切换机制

| x86 | ARM64 |
|-----|-------|
| K2U: SYSCALL + swapgs | K2U: `eret`(EL1→EL0) |
| U2K: SYSRET | U2K: `svc #0`(EL0→EL1) |
| H2G: VMLAUNCH/VMRUN | H2G: `eret`(EL2→EL1 guest) |
| G2H: VMEXIT/VMRUN退出 | G2H: `hvc #0`(EL1→EL2陷阱) |

---

## 3. vm.c — ARM64 EL2虚拟化管理

### 初始化流程

```
init_vm()                    → 分配vm_states/vttbr_hpas数组
vm_check_cpu_compatibility() → 检查EL2/物理地址宽度/Stage-2支持
store_orig_vm_state()        → 保存原始EL2寄存器(HCR_EL2/VTTBR_EL2/VBAR_EL2/MAIR_EL2/TCR_EL2)
start_vm_operation()         → 配置HCR_EL2陷阱位 + MAIR_EL2 + TCR_EL2 + VBAR_EL2
set_vm_state()               → 为每个guest actor填充vm_states(actor_id)
stop_vm_operation()          → 恢复所有EL2寄存器 + TLB刷新
```

### HCR_EL2陷阱位配置

`start_vm_operation()`将HCR_EL2配置为：

```
HCR_EL2 = (current_value | MUST_SET_HCR_EL2) & ~MUST_CLEAR_HCR_EL2 | RW(bit31)
```

关键陷阱位：
- **VM(bit0)**: 启用Stage-2翻译
- **RW(bit31)**: guest使用AArch64
- **IMO(bit4)/FMO(bit3)**: IRQ/FIQ路由到EL2
- **TSC(bit8)**: SVC陷阱到EL2

### VTTBR_EL2配置

每个guest actor使用独立的VTTBR_EL2值：
```
VTTBR_EL2 = (ASID(actor_id) << 48) | (S2PT物理地址 << 12)
```

### TLB刷新策略

`stop_vm_operation()`和`restore_orig_vm_state()`都执行完整TLB刷新：
```asm
dsb ish          // 数据同步屏障(Inner Shareable)
tlbi vmalle1is   // 刷新所有Stage-1 TLB
tlbi alle2is     // 刷新所有Stage-2 TLB
dsb ish          // 再次同步
isb              // 指令同步屏障
```

---

## 4. macros.c — 域切换宏实现

### MSR指令编码机制

ARM64 MSR/MRS指令使用`S3_op0_op1_CRn_CRm_op2`编码格式，fuzzer通过动态生成MSR指令来配置系统寄存器。

编码公式：
```
opcode = 0xD5100000 | (op0<<19) | (op1<<16) | (CRn<<12) | (CRm<<8) | (op2<<5) | src_reg
```

**已修复的关键编码Bug**: 所有EL2寄存器常量原先缺少`op1=4`（即缺少`(4<<16)=0x40000`），导致编码为对应的EL1寄存器而非EL2寄存器。

| 常量 | 修正后值 | 寄存器 | 编码参数 |
|------|---------|--------|---------|
| MSR_SPSR_EL2_ENCODING | 0xD51C4000 | SPSR_EL2 | op0=3, op1=4, CRn=4, CRm=0, op2=0 |
| MSR_ELR_EL2_ENCODING | 0xD51C4020 | ELR_EL2 | op0=3, op1=4, CRn=4, CRm=0, op2=1 |
| MSR_VTTBR_EL2_ENCODING | 0xD51C2020 | VTTBR_EL2 | op0=3, op1=4, CRn=2, CRm=0, op2=1 |
| MSR_VBAR_EL2_ENCODING | 0xD51CC000 | VBAR_EL2 | op0=3, op1=4, CRn=12, CRm=0, op2=0 |

### 四种域切换宏

#### K2U (Kernel → User, EL1 → EL0)

1. 保存EL1寄存器到`special_registers_t`
2. 配置SPSR_EL1：M=EL0t(0x0), D/A/I/F=1(全屏蔽)
3. 配置ELR_EL1：目标用户态函数地址
4. 设置VBAR_EL1指向inner_vector_table
5. 执行`eret`从EL1返回EL0

#### U2K (User → Kernel, EL0 → EL1)

- 用户态执行`svc #0`触发同步异常
- EL1异常向量表(inner_vector_table)捕获SVC
- 从SPSR_EL1恢复EL1状态，从ELR_EL1恢复返回地址

#### H2G (Host → Guest, EL2 → EL1 guest)

1. 配置SPSR_EL2：M=EL1h(0x5), D/A/I/F=1
2. 配置ELR_EL2：guest入口点地址
3. 配置VTTBR_EL2：该actor的S2PT物理地址
4. 执行`eret`从EL2返回EL1(guest模式)

#### G2H (Guest → Host, EL1 guest → EL2)

- Guest执行`hvc #0`触发同步异常
- EL2向量表(outer_vector_table)捕获HVC
- 从ESR_EL2.EC确认退出原因，从SPSR_EL2恢复host状态

### msr_write_to_reg / msr_read_to_reg

这两个函数是ARM64宏系统的核心工具——动态生成MSR/MRS指令序列：

```c
// msr_write_to_reg: 生成 MSR <sysreg>, <src_reg> 指令序列
// 输出: {MSR_opcode | src_reg, ISB, DSB}
uint32_t opcode = sysreg_encoding | src_reg;  // MSR指令
dest[0] = opcode;
dest[1] = ISB_OPCODE;   // 指令同步屏障
dest[2] = DSB_SY_OPCODE; // 数据同步屏障
```

---

## 5. page_tables_guest.c — Stage-1/Stage-2页表

### 双层页表架构

ARM64虚拟化使用两阶段地址翻译：

```
GVA → [Stage-1: TTBR0_EL1/TTBR1_EL1] → IPA
IPA → [Stage-2: VTTBR_EL2] → HPA
```

- **S1PT(Stage-1)**: 将GVA翻译为IPA，等价于x86的guest页表
- **S2PT(Stage-2)**: 将IPA翻译为HPA，等价于x86的EPT/NPT

### S2PT描述符位字段

```
Bit[0]:  Valid    (必须为1)
Bit[1]:  Read     (可读权限)
Bit[2]:  Write    (可写权限)
Bit[3]:  Execute  (可执行权限)
Bit[10]: AF       (访问标志，必须设置)
Bits[47:12]: Output Address (输出物理地址)
```

### S1PT描述符位字段

```
Bit[0]:  Valid
Bit[1]:  Page/Table类型区分
Bits[4:2]: AttrIndx (MAIR属性索引)
Bit[5]:  NS (Non-Secure)
Bits[7:6]: AP (访问权限: RW_EL1/RW_EL01/RO_EL1/RO_EL01)
Bits[9:8]: SH (共享属性)
Bit[10]: AF (访问标志)
Bit[11]: nG (非全局)
Bits[47:12]: Output Address
Bit[53]: PXN (特权执行永不)
Bit[54]: XN (执行永不)
```

### 页表遍历索引（4KB粒度，48位地址）

```
L0_INDEX(addr) = (addr >> 39) & 0x1FF
L1_INDEX(addr) = (addr >> 30) & 0x1FF
L2_INDEX(addr) = (addr >> 21) & 0x1FF
L3_INDEX(addr) = (addr >> 12) & 0x1FF
```

---

## 6. special_registers.c — 系统寄存器管理

### 寄存器保存/恢复流程

```
set_special_registers():
  1. 保存所有EL1/EL2/EL0寄存器到orig_special_registers_state
  2. 禁用硬件预取器(CPUACTLR_EL1)
  3. 启用EL0 PMU访问(PMUSERENR_EL0.EN=1)
  4. (用户actor) → set_msrs_for_user_actors()
  5. (VM actor)   → set_msrs_for_vm_actors()

restore_special_registers():
  1. 恢复所有EL1/EL2/EL0寄存器(if-zero安全检查)
  2. 重新启用预取器
  3. 恢复PMU访问权限
```

### Cortex预取器控制

| CPU | 寄存器 | 禁用L1预取位 | 禁用L2预取位 |
|-----|--------|-------------|-------------|
| A72 | CPUACTLR_EL1 (S3_0_C15_C2_0) | bit[51] | bit[56] |
| A76 | CPUACTLR_EL1 (S3_0_C15_C2_0) | — | bit[56] (L1+L2统一) |

### EL0 PMU访问配置

```c
PMUSERENR_EL0 = EN(bit0) | CR(bit2) | ER(bit3)  // 启用EL0 PMU读写
```

---

## 7. perf_counters.c — Cortex A72/A76 PMU配置

### PMU计数器分配

| 计数器 | 事件 | 用途 |
|--------|------|------|
| PFC#0 | L1D_CACHE_REFILL(0x03) | htrace收集(侧信道信号) |
| PFC#1 | INST_SPEC(0x1B) | 模糊测试反馈(投机指令) |
| PFC#2 | INST_RETIRED(0x08) | 模糊测试反馈(完成指令) |
| PFC#3 | BR_MIS_PRED(0x10) | 投机过滤器(误预测) |
| 周期计数器 | CPU_CYCLES(0x11) | 时间戳 |

### 配置流程

```c
pfc_configure():
  1. 读取MIDR_EL1识别CPU型号(A72/A76)
  2. 检查PMCR_EL0.N字段(可用计数器数量≥4)
  3. 通过PMSELR_EL0选择计数器0-3
  4. 通过PMXEVTYPER_EL0配置事件类型+特权过滤
  5. 通过PMCNTENSET_EL0启用所有计数器+周期计数器
  6. 通过PMCR_EL0全局启用+清零
```

### PMXEVTYPER_EL0特权过滤

```
P=0, U=0 → 所有特权级别计数 (fuzzer需要的配置)
P=1 → 排除EL0
U=1 → 排除EL0(AArch32)
```

---

## 8. fault_handler.c — 多层异常处理

### 三层异常向量表架构

| 向量表 | 寄存器 | 位置 | 捕获事件 |
|--------|--------|------|---------|
| outer_vector_table | VBAR_EL2 | fault_handler.c | HVC/EL2同步异常/IRQ/FIQ |
| inner_vector_table | VBAR_EL1(EL1层) | fault_handler.c | SVC/EL1同步异常/IRQ/FIQ |
| guest_vector_table | VBAR_EL1(guest层) | guest_memory_t | SVC(从EL0 guest) |

### ESR_EL2.EC异常类别过滤

`esr_ec_matches_handled_faults()`根据`handled_faults`位掩码过滤ESR_EL2.EC字段：

```c
uint64_t ec = (esr_value >> 26) & 0x3F;
return (handled_faults >> ec) & 1;
```

默认处理: `EC_AA64_DABORT_EL1(0x24) | EC_AA64_IABORT_EL1(0x20)`

---

## 9. exception.S — EL2向量表与汇编处理

### EL2向量表布局

ARM64异常向量表包含16个入口，每个128字节(32条ARM指令)：

```
偏移0x000: 当前EL SP0同步异常
偏移0x200: 当前EL SPx同步异常
偏移0x400: 低EL AArch64同步异常 ← HVC/SVC捕获入口
偏移0x480: 低EL AArch64 IRQ异常
偏移0x580: 低EL AArch64 SError异常
```

### HVC Handler汇编流程

```asm
hvc_handler:
  1. 保存guest通用寄存器(x0-x30)到EL2栈
  2. 读取ESR_EL2获取EC值
  3. EC=0x16(HVC): 调用C函数处理VM退出
  4. EC=0x24(数据abort): 调用fault_handler处理
  5. 恢复guest寄存器
  6. eret返回guest
```

---

## 10. 通用代码的ARM64适配

### main.c适配

- **vm.h引入**: `#ifdef ARCH_ARM #include "vm.h"`
- **init/free**: `#elif VENDOR_ID == VENDOR_ARM_`分支调用`init_vm()/free_vm()`
- **check_test_case_compat**: ARM64分支调用`vm_check_cpu_compatibility()`
- **get_cpuinfo**: ARM64通过MRS MIDR_EL1读取CPU信息

### measurement.c适配

- **vm.h引入**: ARM64分支引入vm.h
- **uarch_flush**: ARM64使用DC CISW + IC IALLUIS + TLBI + DSB/ISB
- **set_execution_environment**: ARM64分支调用`start_vm_operation()/store_orig_vm_state()/set_vm_state()`
- **recover_orig_state**: ARM64分支调用`restore_orig_vm_state()/stop_vm_operation()`
- **FPU**: ARM64无需kernel_fpu_begin/end（由CPACR_EL1.FPEN控制）

### Makefile适配

```makefile
SRC_ARM64 = arm64/vm.c arm64/fault_handler.c arm64/perf_counters.c arm64/special_registers.c \
    arm64/page_tables_guest.c arm64/macros.c
ASM_ARM64 = arm64/exception.S
```

---

## 11. 关键常量与编码

### 已修复的EC值(vm_constants.h)

**修复前**: 使用AArch32范围值(0x07-0x09, 0x12)
**修复后**: 使用AArch64范围值(0x15-0x17, 0x20)

| 常量 | 修正后值 | 含义 |
|------|---------|------|
| EC_SVC64 | 0x15 | SVC指令(AArch64) |
| EC_HVC64 | 0x16 | HVC指令(AArch64) |
| EC_SMC64 | 0x17 | SMC指令(AArch64) |
| EC_SYSREG_64 | 0x18 | MSR/MRS(AArch64) |
| EC_IABORT_EL1 | 0x20 | 指令abort(低EL) |
| EC_IABORT_EL2 | 0x21 | 指令abort(当前EL) |
| EC_DABORT_EL1 | 0x24 | 数据abort(低EL) |
| EC_DABORT_EL2 | 0x25 | 数据abort(当前EL) |

### SPSR_EL2 M字段编码

| 值 | 模式 | 用途 |
|----|------|------|
| 0x0 | EL0t | K2U: eret到EL0(用户态) |
| 0x5 | EL1h | H2G: eret到EL1(guest) |
| 0x9 | EL2h | 异常前为EL2 |

### 默认HCR_EL2配置(MUST_SET)

```
VM | RW | IMO | FMO | TSC | TWI | TWE | TLB | TVM | TPID
```

---

## 12. 跨域测试支持矩阵

| 测试类型 | 切换机制 | 入口指令 | 退出指令 | 向量表 | ARM64支持状态 |
|----------|---------|---------|---------|--------|-------------|
| U2U | K2U + U2K | eret | svc #0 | VBAR_EL1(inner) | ✅ 已实现 |
| K2U | eret(EL1→EL0) | eret | svc #0 | VBAR_EL1(inner) | ✅ 已实现 |
| H2V | eret(EL2→EL1) | eret | hvc #0 | VBAR_EL2(outer) | ✅ 已实现 |
| V2V | H2V + G2H | eret | hvc #0 | VBAR_EL2(outer) | ✅ 已实现 |
| 异常测试 | 故障触发 | — | — | inner/outer向量表 | ✅ 已实现 |

### PMU在跨域测试中的访问

| 域 | PMU访问 | 配置 |
|----|---------|------|
| EL0(user) | PMXEVCNTR_EL0直接读取 | PMUSERENR_EL0.EN=1 |
| EL1(kernel) | PMXEVCNTR_EL0直接读取 | PMCR_EL0.E=1 |
| EL1(guest) | PMXEVCNTR_EL0直接读取 | HCR_EL2.TPC=0(不陷阱) |
| EL2(hypervisor) | PMXEVCNTR_EL0直接读取 | MDCR_EL2.HPME=1, HPMD=0 |

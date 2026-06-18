# ARM64 Executor KM — 潜在问题与重点测试文档

## 目录

1. [高风险问题](#1-高风险问题)
2. [中风险问题](#2-中风险问题)
3. [低风险问题](#3-低风险问题)
4. [重点测试清单](#4-重点测试清单)
5. [测试环境要求](#5-测试环境要求)

---

## 1. 高风险问题

### 1.1 EL2系统寄存器访问权限

**问题描述**: 当前代码直接使用MRS/MSR指令读写EL2系统寄存器（HCR_EL2、VTTBR_EL2、VBAR_EL2等），但内核模块运行在EL1。在标准Linux内核中，EL1无法直接访问EL2寄存器——除非：
- 系统在VHE(Virtualization Host Extension)模式下运行（host在EL2运行，EL2寄存器可通过`_EL12`别名访问）
- 通过KVM的SMC/HVC调用间接修改
- 通过内核提供的接口（如`kvm_arch_put/hw_vcpu_state`）

**影响**: 所有涉及EL2寄存器操作的代码（vm.c、macros.c中的H2G/G2H宏）在non-VHE系统上将导致Undefined Instruction异常。

**修复方向**:
- VHE模式: 使用`_EL12`别名寄存器（如VBAR_EL12代替VBAR_EL2）
- non-VHE模式: 通过KVM API或SMC调用间接修改EL2寄存器
- 添加运行时VHE检测（ID_AA64MMFR1_EL1.VH字段），根据结果选择不同路径

**测试优先级**: P0 — 必须在真实ARM64硬件上验证

---

### 1.2 SPSR_EL2/ELR_EL2的写入时机

**问题描述**: macros.c中的`start_macro_switch_h2g`在EL1通过动态生成的MSR指令写入SPSR_EL2和ELR_EL2。如果当前运行在EL1（non-VHE模式），这些MSR指令将触发Undefined Instruction异常（EL1无法访问EL2寄存器）。

即使在VHE模式下，MSR SPSR_EL2/ELR_EL2在EL2运行时也需要特殊的屏障处理：
- MSR后必须执行ISB确保写入生效
- eret前必须确保SPSR_EL2/ELR_EL2已更新

**影响**: H2G域切换宏的核心功能可能无法工作。

**测试优先级**: P0

---

### 1.3 HCR_EL2.VM位启用后的系统稳定性

**问题描述**: `start_vm_operation()`设置HCR_EL2.VM=1启用Stage-2翻译。这会导致：
1. 所有EL1/EL0的内存访问经过两阶段翻译（S1PT→S2PT）
2. 如果VTTBR_EL2指向的S2PT不完整或错误，宿主机自身的内存访问会触发Stage-2 Translation Fault
3. 这可能导致宿主机内核崩溃（包括页表遍历、中断处理等关键操作）

**影响**: 模块加载后系统可能立即崩溃，或在某些操作路径上触发不可恢复的故障。

**修复方向**:
- 在启用VM位前，必须确保S2PT映射了宿主机所有需要的物理内存
- 或者使用KVM框架的VM进入机制（不直接修改HCR_EL2）

**测试优先级**: P0 — 需在隔离环境（QEMU/KVM虚拟机）中测试

---

### 1.4 VTTBR_EL2的BADDR字段对齐

**问题描述**: `set_vm_state()`中VTTBR_EL2的BADDR计算为：
```c
.baddr = vttbr_hpas[actor_id] >> VTTBR_EL2_BADDR_SHIFT
```
ARM64要求VTTBR_EL2.BADDR对齐到页表粒度大小（4KB页表要求16KB对齐=4页）。如果S2PT根页的物理地址不满足此对齐要求，CPU会触发Address Size Fault。

**影响**: guest actor无法正确进入——eret后立即触发Stage-2 Translation Fault Level 0。

**测试优先级**: P0

---

### 1.5 异常向量表对齐要求

**问题描述**: ARM64要求VBAR_EL1和VBAR_EL2必须满足特定对齐：
- VBAR_EL1: 必须2KB对齐（向量表大小=2KB）
- VBAR_EL2: 必须2KB对齐（向量表大小=2KB）

`set_inner_fault_handlers()`和`set_el2_fault_handlers()`使用`fault_handler`全局指针设置VBAR，但`fault_handler`指向的是单个处理函数而非完整向量表。代码中注释也提到此问题：
> "fault_handler指向的是单个处理函数，不是完整的向量表"

**影响**: 如果VBAR设置不正确（对齐不满足或指向错误地址），异常发生时CPU跳转到错误位置，导致系统崩溃。

**测试优先级**: P0

---

### 1.6 outer_vector_table和inner_vector_table的物理存在

**问题描述**: vm.c中引用了`outer_vector_table`：
```c
extern void outer_vector_table;
write_msr("vbar_el2", (uint64_t)&outer_vector_table);
```
但`outer_vector_table`是在fault_handler.c中通过`vector_table_t`结构定义的，且仅在ARM64架构下存在。如果fault_handler.c的初始化流程有问题（如内存分配失败、地址未正确设置），`outer_vector_table`可能指向无效内存。

类似问题存在于inner_vector_table——K2U宏中设置VBAR_EL1指向inner_vector_table，但inner_vector_table的分配和设置需要通过`set_inner_fault_handlers()`完成。

**影响**: 异常发生时跳转到无效地址，导致系统崩溃。

**测试优先级**: P0

---

## 2. 中风险问题

### 2.1 MSR指令编码的正确性验证

**问题描述**: macros.c中的MSR指令编码使用硬编码的32位常量（如`MSR_SPSR_EL2_ENCODING = 0xD51C4000`）。这些编码已经从原始的bug修复（添加了op1=4），但需要验证：
1. 编码公式`0xD5100000 | (op0<<19) | (op1<<16) | (CRn<<12) | (CRm<<8) | (op2<<5)`与ARM Architecture Reference Manual的MSR指令编码格式完全一致
2. MSR指令中的Rt字段（bits[4:0]）正确设置为源寄存器编号
3. ISB/DSB屏障指令的编码（0xD5033FDF/0xD5033F9F）正确

**验证方法**: 在QEMU+GDB环境中，单步跟踪动态生成的MSR指令，确认其确实写入正确的系统寄存器。

**测试优先级**: P1

---

### 2.2 PMUSERENR_EL0.EN位的持久性

**问题描述**: `set_special_registers()`设置PMUSERENR_EL0.EN=1使EL0可以读取PMU寄存器。但：
1. PMUSERENR_EL0是否在上下文切换时被内核恢复为0？Linux内核可能不保留此位的修改
2. 在K2U切换后（EL0执行），如果PMUSERENR_EL0.EN被意外清除，EL0的PMU读取将触发Undefined Instruction异常

**影响**: 测试用例在EL0执行时无法读取PMC值，导致htrace收集失败。

**测试优先级**: P1

---

### 2.3 CPUACTLR_EL1预取器控制的实现定义性

**问题描述**: CPUACTLR_EL1是IMPLEMENTATION DEFINED寄存器——不同Cortex型号的编码和位定义不同：
- Cortex A72: S3_0_C15_C2_0, bit[51]=L1预取禁用, bit[56]=L2预取禁用
- Cortex A76: S3_0_C15_C2_0, bit[56]=L1+L2预取禁用（统一）
- 其他型号: 编码可能完全不同

**影响**: 在非A72/A76的CPU上，预取器控制可能写入错误寄存器或错误位，导致不可预测的行为。

**测试优先级**: P1

---

### 2.4 Stage-2页表(S2PT)的完整性

**问题描述**: `page_tables_guest.c`中的S2PT构建需要映射guest所有需要的IPA→HPA翻译：
1. guest的代码区、数据区、util区必须全部映射
2. S2PT必须映射guest的异常向量表页面
3. S2PT必须映射guest的S1PT页面（guest需要能访问自己的页表）

如果S2PT映射不完整，guest在执行过程中会触发Stage-2 Translation Fault，这可能不是预期的测试行为。

**影响**: guest actor无法正常执行——随机触发Stage-2 Translation Fault。

**测试优先级**: P1

---

### 2.5 Stage-1页表(S1PT)的TTBR0_EL1切换

**问题描述**: K2U宏需要修改TTBR0_EL1指向用户actor的页表。这涉及：
1. 保存当前TTBR0_EL1（指向内核页表）
2. 设置TTBAR0_EL1指向用户actor的S1PT
3. 执行TLB刷新（TLBI VMALLE1IS）
4. eret到EL0

U2K宏需要恢复TTBR0_EL1为原始内核页表值。如果恢复不正确，宿主机内核的内存访问将使用错误的页表。

**影响**: K2U切换后内核不稳定，或U2K恢复后系统崩溃。

**测试优先级**: P1

---

### 2.6 ESR_EL2.ISS的FSC解码完整性

**问题描述**: `print_vm_exit_info()`解码ESR_EL2.ISS中的FSC(Fault Status Code)值，但只覆盖了部分FSC值（Translation Fault L0-L3、Permission Fault、SEA等）。ARM Architecture Reference Manual定义了更多FSC值（如Access Flag Fault、SLAB等），未覆盖的值将显示为"Unknown FSC"。

**影响**: 调试困难——某些VM退出原因无法被正确解码。

**测试优先级**: P2

---

## 3. 低风险问题

### 3.1 vm_state_t结构与实际EL2寄存器的匹配

**问题描述**: vm_state_t包含12个字段，但实际EL2虚拟化涉及更多寄存器（如CPACR_EL2、VTCR_EL2、AFSR_EL2等）。如果这些寄存器在start_vm_operation()中被意外修改且未恢复，宿主机状态可能受损。

**影响**: 低概率——KVM通常会管理这些寄存器。

**测试优先级**: P3

---

### 3.2 guest_memory_t中的异常向量表对齐

**问题描述**: `guest_memory_t`中的`exception_vectors[PAGE_SIZE]`使用PAGE_SIZE(4KB)分配，但ARM64向量表只需2KB。4KB对齐满足2KB对齐要求，但浪费了2KB空间。

**影响**: 无功能影响，仅内存浪费。

**测试优先级**: P3

---

### 3.3 ARM64 NOP占位符大小与宏展开的兼容性

**问题描述**: ARM64的宏占位符使用3条NOP指令（12字节），而x86使用8字节。这导致：
- `MACRO_PLACEHOLDER_SIZE`在ARM64上为12，x86上为8
- `code_loader.c`中的游标计算需要考虑不同的占位符大小
- `insert_relative_jmp_n_fence`在ARM64上生成B+ISB+DSB(12字节)

如果占位符大小不一致，宏展开可能覆盖相邻代码或留有空隙。

**影响**: 已在macro_expansion.c中处理（ARM64分支生成12字节补丁），但需要验证实际编译结果。

**测试优先级**: P3

---

### 3.4 ARM64汇编中B指令的偏移量范围限制

**问题描述**: ARM64的B指令使用26位有符号偏移量，范围±128MB。在宏展开中，`insert_relative_jmp_n_fence`检查偏移量范围：
```c
ASSERT(target < 0x02000000 && target >= -0x02000000, "insert_relative_jmp_n_fence");
```
但如果宏代码区(macros)与代码区(section)之间的偏移超过128MB（极端情况），B指令将无法正确跳转。

**影响**: 低概率——正常沙箱布局中偏移远小于128MB。

**测试优先级**: P3

---

## 4. 重点测试清单

### P0级测试（必须通过）

| # | 测试项 | 测试方法 | 预期结果 | 失败症状 |
|---|--------|---------|---------|---------|
| 1 | EL2寄存器访问权限 | 在non-VHE和VHE系统上分别运行vm.c | MRS/MSR不触发Undefined Instruction | 系统崩溃/挂死 |
| 2 | HCR_EL2.VM=1启用 | start_vm_operation()后系统稳定性 | 系统正常运行5分钟 | 内核panic/挂死 |
| 3 | VTTBR_EL2对齐 | 检查vttbr_hpas的物理地址对齐 | 16KB对齐(4页边界) | Stage-2 L0 Translation Fault |
| 4 | VBAR_EL1/EL2对齐 | 检查outer/inner_vector_table地址 | 2KB对齐 | 异常跳转到错误地址 |
| 5 | eret到EL0 | K2U宏后CPU在EL0执行 | CurrentEL=0 | 系统崩溃 |
| 6 | eret到EL1 guest | H2G宏后CPU在EL1 guest执行 | CurrentEL=1, HCR_EL2.VM=1 | 系统崩溃 |
| 7 | SVC from EL0 | actor2执行svc后回到EL1 | 正常切换，无异常 | Undefined Instruction或系统崩溃 |
| 8 | HVC from EL1 guest | actor2执行hvc后回到EL2 | ESR_EL2.EC=0x16 | 系统崩溃 |

### P1级测试（应该通过）

| # | 测试项 | 测试方法 | 预期结果 | 失败症状 |
|---|--------|---------|---------|---------|
| 9 | MSR编码验证 | GDB单步跟踪MSR指令 | SPSR_EL2/ELR_EL2/VTTBR_EL2/VBAR_EL2正确写入 | 写入错误寄存器 |
| 10 | PMU EL0访问 | K2U后EL0读取PMXEVCNTR_EL0 | 返回PMC计数值 | Undefined Instruction |
| 11 | 预取器控制 | 设置CPUACTLR_EL1后测量噪声 | 噪声显著减少 | 无变化或异常 |
| 12 | S2PT完整性 | guest执行完整代码段 | 无Stage-2 Translation Fault | 随机故障 |
| 13 | TTBR0_EL1切换 | K2U后U2K恢复 | 内核稳定运行 | 内核崩溃 |
| 14 | 测量宏正确性 | Prime+Probe在ARM64上 | htrace非零且可重复 | htrace全零 |

### P2级测试（建议通过）

| # | 测试项 | 测试方法 | 预期结果 | 失败症状 |
|---|--------|---------|---------|---------|
| 15 | 异常恢复完整性 | 触发Data Abort后恢复 | 测量正常结束 | 测量状态损坏 |
| 16 | 多次域切换 | 两次K2U+U2K循环 | 第二次切换正常 | 第二次切换失败 |
| 17 | SET_DATA_PERMISSIONS | 修改PTE后访问 | 触发预期的故障 | 不触发或系统崩溃 |
| 18 | Spectre V1检测 | spectre_v1_extended.asm | htrace显示缓存泄漏 | htrace无变化 |

---

## 5. 测试环境要求

### 5.1 必要硬件

| 环境 | 用途 | 获取方式 |
|------|------|---------|
| Cortex A72 (如RPi 3B+) | EL2测试(non-VHE) | Raspberry Pi 3B+ |
| Cortex A76 (如RPi 4) | EL2测试(VHE支持) | Raspberry Pi 4 |
| QEMU aarch64 | 初步验证(可控环境) | qemu-system-aarch64 -M virt |

### 5.2 软件环境

| 软件 | 版本要求 | 用途 |
|------|---------|------|
| Linux内核 | ≥5.10 (ARM64 KVM稳定版) | 内核模块运行环境 |
| KVM | 启用CONFIG_KVM | EL2寄存器间接访问 |
| GCC交叉编译器 | aarch64-linux-gnu-gcc ≥10 | 编译内核模块 |
| GDB + QEMU | aarch64-multiarch gdb | MSR编码调试 |

### 5.3 安全测试策略

**严禁在物理服务器上直接测试**——以下测试可能导致系统不可恢复的崩溃：

1. HCR_EL2.VM=1启用测试 → 必须在QEMU虚拟机中测试
2. VTTBR_EL2修改测试 → 必须在QEMU虚拟机中测试
3. eret到EL0/EL1 guest测试 → 必须在QEMU虚拟机中测试
4. 异常向量表覆盖测试 → 必须在QEMU虚拟机中测试

**推荐测试顺序**:
1. QEMU aarch64基本功能验证（模块加载、单actor测量）
2. QEMU K2U/U2K切换验证
3. QEMU H2G/G2H切换验证（需要启用QEMU的EL2支持）
4. 物理硬件上的PMU验证（A72/A76）
5. 物理硬件上的域切换验证（仅在确认QEMU测试通过后）

### 5.4 QEMU测试启动命令

```bash
# 基本ARM64虚拟机（不支持EL2）
qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 1 -m 1G \
    -kernel linux-image -append "console=ttyAMA0 root=/dev/vda" \
    -drive file=disk.img,format=raw -nographic

# 支持EL2的ARM64虚拟机（用于H2G/G2H测试）
qemu-system-aarch64 -M virt -cpu cortex-a57 -smp 1 -m 1G \
    -machine virtualization=on \
    -kernel linux-image -append "console=ttyAMA0 root=/dev/vda" \
    -drive file=disk.img,format=raw -nographic

# GDB调试模式
qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 1 -m 1G \
    -gdb tcp::1234 -S \
    -kernel linux-image -nographic
# 然后在另一个终端:
gdb-multiarch -ex "target remote :1234" -ex "set architecture aarch64"
```

---

## 附录A: 已修复的Bug清单

| Bug | 修复前 | 修复后 | 影响 |
|-----|--------|--------|------|
| MSR_SPSR_EL2编码 | 0xD5184000 (写SPSR_EL1) | 0xD51C4000 (写SPSR_EL2) | K2U/H2G无法正确设置guest返回状态 |
| MSR_ELR_EL2编码 | 0xD5184020 (写ELR_EL1) | 0xD51C4020 (写ELR_EL2) | eret跳转到错误地址 |
| MSR_VTTBR_EL2编码 | 0xD5184120 (写未知EL1寄存器) | 0xD51C2020 (写VTTBR_EL2) | guest内存映射完全错误 |
| MSR_VBAR_EL2编码 | 0xD518C000 (写VBAR_EL1) | 0xD51CC000 (写VBAR_EL2) | HVC异常不被EL2捕获 |
| EC值(AArch32范围) | 0x07-0x09, 0x12 | 0x15-0x17, 0x20 | ESR解码错误，异常处理混乱 |
| VTTBR_EL2注释 | CRm=1 | CRm=0 | 文档误导 |
| static/extern不匹配 | static set_msrs_for_* | extern可见 | 编译或链接可能失败 |

## 附录B: ARM64与x86行为差异导致的潜在问题

| 行为差异 | ARM64 | x86 | 潜在问题 |
|----------|-------|-----|---------|
| VM进入机制 | eret(需预先配置SPSR/ELR) | VMLAUNCH/VMRUN(自动从VMCS/VMCB加载) | ARM64需要更多手动配置步骤 |
| VM退出机制 | HVC(SVC/SMC/陷阱)自动保存ESR/FAR | VMEXIT自动保存退出信息到VMCS | ARM64退出信息分散在多个寄存器 |
| VM状态保存 | 无VMCS/VMCB，需手动保存每个EL2寄存器 | VMCS/VMCB自动保存 | ARM64遗漏寄存器将导致状态丢失 |
| TLB刷新 | TLBI指令+DSB+ISB | INVEPT/INVVPID | ARM64刷新更复杂(需区分Stage-1/2) |
| 页表权限 | RWX分离位(非Execute-only) | RWX位(支持Execute-only) | ARM64不支持Execute-only页 |
| 预取器控制 | CPUACTLR_EL1(实现定义) | MSR_IA32_PREFETCH控制 | ARM64不同CPU型号编码不同 |
| FPU | CPACR_EL1.FPEN控制 | CR0.TS+kernel_fpu_begin | ARM64无需手动save/restore FPU |
| 系统调用 | SVC(EL0→EL1) + HVC(EL1→EL2) | SYSCALL(兼容模式) | ARM64两级系统调用机制不同 |

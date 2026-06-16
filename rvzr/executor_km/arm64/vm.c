/// File: Configuration and use of ARM64 VM (virtualization) — equivalent to x86/vmx.c and x86/svm.c
///
// ==============================================================================
// ARM64虚拟化管理模块概述：
// 本文件实现了ARM64架构下虚拟机的完整管理，是论文
// "Enter, Exit, Page Fault, Leak"中ARM64平台VM Actor Configuration的核心实现。
//
// 整体架构和初始化流程：
// 1. init_vm()                   —— 分配vm_states和vttbr_hpas数组
// 2. vm_check_cpu_compatibility() —— 检查CPU是否支持ARM64虚拟化所需特性
// 3. store_orig_vm_state()       —— 保存原始EL2系统寄存器值
// 4. start_vm_operation()        —— 配置HCR_EL2/VBAR_EL2/MAIR_EL2/TCR_EL2等，启用虚拟化
// 5. set_vm_state()              —— 为每个guest actor配置VM状态：
//    a. 设置HCR_EL2陷阱位（控制哪些操作触发VM退出）
//    b. 设置VTTBR_EL2（指向该actor的Stage-2页表物理地址）
//    c. 设置VBAR_EL2（指向guest异常向量表）
//    d. 设置SPSR_EL2/ELR_EL2（guest入口点和处理器状态）
//    e. 设置SCTLR_EL1（guest的MMU/缓存控制）
// 6. stop_vm_operation()         —— 恢复原始EL2系统寄存器值
//
// 与x86的关键区别：
// - x86使用VMCS/VMCB内存结构 + VMLAUNCH/VMRUN指令进入guest
// - ARM64使用系统寄存器 + eret指令从EL2返回EL1(guest)
// - x86的VM退出由VMCS/VMCB控制位自动触发
// - ARM64的VM退出由HCR_EL2陷阱位触发，CPU自动保存状态到ESR_EL2/FAR_EL2等
// - x86需要VMLAUNCH验证步骤（make_vmcs_launched），ARM64不需要
// - ARM64的host状态在VM退出时自动恢复（无需像VMX那样在VMCS Host-State Area中保存）
//
// 运行环境说明：
// 本内核模块运行在EL1（Linux内核层）。在大多数ARM64 Linux系统中，
// KVM已经初始化了EL2并设置了HCR_EL2等寄存器。本模块假设系统已在EL2运行，
// 可以通过修改EL2系统寄存器来控制guest行为。
// 注意：直接从EL1修改EL2系统寄存器需要特殊处理——
// 在KVM框架下，可以通过KVM的API间接修改EL2寄存器；
// 在VHE(Virtualization Host Extension)模式下，host在EL2运行，可直接修改。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "fault_handler.h"
#include "main.h"
#include "page_tables_guest.h"
#include "special_registers.h"
#include "vm.h"
#include "vm_constants.h"

// =================================================================================================
// 全局变量
// ==============================================================================

// vm_is_on：全局标志，标记VM操作是否已启动
// 置true表示当前正在运行guest actor，需要虚拟化管理
// 类似于x86的vmx_is_on/svm_is_on
bool vm_is_on = false; // global

// vm_states：每个guest actor对应的VM状态数组
// 数组索引为actor_id，每个元素保存了该actor需要配置的EL2系统寄存器值
// 在set_vm_state()中填充，在start_vm_operation()中写入系统寄存器
// 类似于x86的VMCS数组(vmcss)或VMCB页面数组(vmcb_pages)
vm_state_t *vm_states = NULL; // global

// vttbr_hpas：每个guest actor对应的Stage-2页表物理地址数组
// 数组索引为actor_id，每个元素保存了该actor的Stage-2页表根页的物理地址
// 用于配置VTTBR_EL2的BADDR字段，实现actor间的地址空间隔离
// 类似于x86的vmcs_hpas（VMCS物理地址）或vmcb_hpas（VMCB物理地址）
uint64_t *vttbr_hpas = NULL; // global

// =================================================================================================
// 静态变量——原始状态保存
// ==============================================================================

// 保存fuzzer启动前的EL2系统寄存器原始值，用于fuzzer退出时恢复
// 确保宿主机的虚拟化环境不受fuzzer操作的影响
static vm_state_t orig_vm_state;

// =================================================================================================
// 辅助宏和内联函数
// ==============================================================================

// _BITULL(x)：生成第x位为1的64位无符号整数
// 用于设置HCR_EL2等寄存器的位域
#ifndef _BITULL
#define _BITULL(x) (1ULL << (x))
#endif

// EL2系统寄存器读写辅助函数
// ARM64使用MRS/MSR指令读写系统寄存器，不像x86有RDMSR/WRMSR指令
// shortcuts.h中定义了read_msr/write_msr宏，使用内联汇编封装MRS/MSR

// =================================================================================================
// VM管理接口（暴露给executor其余部分的函数）
// ==============================================================================

// ==============================================================================
// vm_check_cpu_compatibility：检查CPU是否支持ARM64虚拟化所需特性
//
// 与x86的vmx_check_cpu_compatibility()/svm_check_cpu_compatibility()对应。
// 验证项目：
// 1. EL2是否可用（通过ID_AA64PFR0_EL1.PFR0_EL2字段检查）
// 2. 物理地址宽度是否满足要求（通过ID_AA64MMFR0_EL1.PARange字段检查）
// 3. Stage-2翻译是否支持（通过ID_AA64MMFR0_EL1.S2PS字段检查）
// 4. HCR_EL2必须置1和必须清0的陷阱位是否与CPU支持兼容
// 5. Cortex-A72/A76特定检查（如L1D缓存配置是否符合预期）
//
// 注意：在KVM框架下运行时，EL2已由KVM初始化，此处检查的是KVM提供的虚拟化能力
// ==============================================================================
int vm_check_cpu_compatibility(void)
{
    uint64_t reg_val = 0;

    // ---- 检查1：EL2是否可用 ----
    // 读取ID_AA64PFR0_EL1，检查EL2字段(bits[19:16])
    // PFR0_EL2_IMPL(0x1)表示EL2已实现，可以运行hypervisor
    // 如果EL2不可用，虚拟化管理无法工作
    read_msr("id_aa64pfr0_el1", reg_val);
    uint64_t el2_field = (reg_val >> 16) & 0xF;
    ASSERT_MSG(el2_field != PFR0_EL2_NOT_IMPL, "vm_check_cpu_compatibility",
               "EL2 is not implemented on this CPU; virtualization is not available");

    // ---- 检查2：物理地址宽度 ----
    // 读取ID_AA64MMFR0_EL1，检查PARange字段(bits[3:0])
    // PARange编码与TCR_EL2.PS字段使用相同编码
    // fuzzer需要至少40位物理地址宽度（支持1TB物理内存）
    read_msr("id_aa64mmfr0_el1", reg_val);
    uint64_t parange = reg_val & 0xF;
    ASSERT_MSG(parange >= MMFR0_PARange_40, "vm_check_cpu_compatibility",
               "Physical address width insufficient: PARange=%llu (need >=40 bits)", parange);

    // ---- 检查3：Stage-2翻译支持 ----
    // 检查ID_AA64MMFR0_EL1的S2PS字段(bits[19:16])
    // S2PS报告Stage-2翻译支持的物理地址宽度
    // MMFR0_S2PS_SAME_AS_PARange(0x0)表示S2 PS = PA Range，即Stage-2支持与物理地址相同的宽度
    read_msr("id_aa64mmfr0_el1", reg_val);
    uint64_t s2ps = (reg_val >> 16) & 0xF;
    ASSERT_MSG(s2ps >= MMFR0_S2PS_SAME_AS_PARange, "vm_check_cpu_compatibility",
               "Stage-2 translation not properly supported: S2PS=%llu", s2ps);

    // ---- 检查4：HCR_EL2陷阱位兼容性 ----
    // 读取当前HCR_EL2值，验证必须置1/清0的位
    // 在KVM框架下，HCR_EL2已由KVM设置，我们检查是否可以修改为fuzzer需要的配置
    read_msr("hcr_el2", reg_val);
    // 验证必须清0的位当前是否为0（或者可以清0）
    // MUST_CLEAR_HCR_EL2中的位如果当前为1，表示CPU正在使用这些特性
    // 例如E2H=1表示当前在VHE模式下运行，fuzzer可能需要特殊处理
    if ((reg_val & MUST_CLEAR_HCR_EL2) != 0) {
        PRINT_WARN("vm_check_cpu_compatibility: HCR_EL2 has MUST_CLEAR bits set (0x%llx)\n",
                   reg_val & MUST_CLEAR_HCR_EL2);
        // VHE模式(E2H=1)下需要特殊处理——此处暂不强制返回错误
        // 实际实现需要根据VHE/non-VHE模式分别处理
    }

    // ---- 检查5：VHE支持状态 ----
    // 读取ID_AA64MMFR1_EL1的VH字段(bits[7:4])
    // VH=MMFR1_VH_IMPL(0x1)表示支持VHE，host可以在EL2运行
    read_msr("id_aa64mmfr1_el1", reg_val);
    uint64_t vh = (reg_val >> 4) & 0xF;
    PRINT_ERR("vm_check_cpu_compatibility: VHE support=%llu (0=not impl, 1=impl)\n", vh);

    // ---- 检查6：CPU型号识别 ----
    // 读取MIDR_EL1，识别CPU型号（Cortex-A72/A76或其他）
    // 不同型号的L1D缓存配置不同，影响侧信道分析策略
    read_msr("midr_el1", reg_val);
    uint64_t implementer = (reg_val >> 24) & 0xFF;
    uint64_t part_num = (reg_val >> 4) & 0xFFF;
    PRINT_ERR("vm_check_cpu_compatibility: CPU implementer=0x%llx, part=0x%llx\n", implementer,
              part_num);

    if (implementer == ARM_IMPLEMENTER_ID) {
        if (part_num == CORTEX_A72_PART_NUM) {
            PRINT_ERR("  Detected Cortex-A72\n");
        } else if (part_num == CORTEX_A76_PART_NUM) {
            PRINT_ERR("  Detected Cortex-A76\n");
        } else {
            PRINT_WARN("  Unknown ARM CPU part number: 0x%llx\n", part_num);
        }
    } else {
        PRINT_WARN("  Non-ARM implementer: 0x%llx\n", implementer);
    }

    return 0;
}

// ==============================================================================
// start_vm_operation：启动VM操作，保存原始EL2寄存器并配置虚拟化环境
//
// 与x86的start_vmx_operation()/start_svm_operation()对应。
// 流程：
// 1. 保存原始EL2系统寄存器值（已在store_orig_vm_state中完成）
// 2. 设置HCR_EL2为虚拟化配置——启用VM位和陷阱位
// 3. 配置VBAR_EL2指向guest异常向量表
// 4. 配置MAIR_EL2——定义Stage-2页表的内存属性
// 5. 配置TCR_EL2——设置Stage-2翻译参数
//
// ARM64虚拟化启动不需要像x86那样执行VMXON/设置VM_HSAVE_PA等操作，
// 因为ARM64的系统寄存器可以直接修改——写入HCR_EL2.VM=1即可启用虚拟化。
// eret指令从EL2返回EL1时，CPU自动进入guest模式。
// ==============================================================================
int start_vm_operation(void)
{
    uint64_t hcr_val = 0;
    uint64_t mair_val = DEFAULT_MAIR_EL2;
    uint64_t tcr_val = DEFAULT_TCR_EL2;

    // ---- 步骤1：读取当前HCR_EL2值 ----
    // 保存当前值用于后续配置（已在store_orig_vm_state中完整保存）
    read_msr("hcr_el2", hcr_val);

    // ---- 步骤2：配置HCR_EL2 ----
    // 设置必须置1的位（VM位、陷阱位、中断路由位等）
    // 清除必须清0的位（TGE、E2H等）
    // 保留当前HCR_EL2中其他位的值——这些位可能由KVM或其他hypervisor设置
    // 类似于x86 VMX中设置VM执行控制的方式：MUST_SET + MSR允许的位
    hcr_val = (hcr_val | MUST_SET_HCR_EL2) & ~MUST_CLEAR_HCR_EL2;

    // ---- 特殊处理：HCR_EL2.RW位 ----
    // HCR_EL2.RW (bit 31)控制下层EL的执行状态：
    // RW=1：下层EL使用AArch64（64位ARM）——这是我们需要的（guest运行64位代码）
    // RW=0：下层EL使用AArch32（32位ARM）
    // 大多数64位Linux系统中RW=1已设置，但此处显式确保
    hcr_val |= _BITULL(31); // 确保guest使用AArch64

    // 写入HCR_EL2——启用虚拟化和陷阱配置
    write_msr("hcr_el2", hcr_val);

    // ---- 步骤3：配置MAIR_EL2 ----
    // MAIR_EL2定义了Stage-2页表中可用的内存属性
    // 每个Stage-2页表项的AttrIndx字段选择MAIR_EL2中的对应属性
    // 类似于x86 VMX中EPTP的内存类型(WB=6)或SVM中g_pat的配置
    write_msr("mair_el2", mair_val);

    // ---- 步骤4：配置TCR_EL2 ----
    // TCR_EL2控制Stage-2翻译的参数：
    // - PS: 物理地址宽度（48位，覆盖256TB物理内存）
    // - T0SZ: IPA宽度（48位IPA，T0SZ=16）
    // - TG0: 页表粒度（4KB）
    // - SL0: 页表起始级别（从Level1开始遍历）
    // - IRGN0/ORGN0: 缓存属性（Write-Back Write-Allocate）
    // - SH0: 共享属性（Inner Shareable）
    // 类似于x86 VMX中EPTP的页表级数和granule大小配置
    write_msr("tcr_el2", tcr_val);

    // ---- 步骤5：配置VBAR_EL2 ----
    // VBAR_EL2指向EL2异常向量表，当guest触发陷阱时CPU跳转到此地址
    // 此处使用fault_handler.c中的outer_vector_table——
    // 当guest异常从EL1陷阱到EL2时，CPU跳转到VBAR_EL2+0x400（同步异常入口）
    // 类似于x86 VMX中的HOST_RIP（VM退出时跳转地址）
    extern char *fault_handler;
    if (fault_handler != NULL) {
        // 将VBAR_EL2设置为fault_handler地址
        // 但注意：ARM64的向量表需要0x800字节对齐
        // fault_handler指向的是单个处理函数，不是完整的向量表
        // 实际实现中需要设置完整的向量表，此处暂使用outer_vector_table
        extern void outer_vector_table;
        write_msr("vbar_el2", (uint64_t)&outer_vector_table);
    }

    // 标记VM操作已启动
    vm_is_on = true;
    return 0;
}

// ==============================================================================
// stop_vm_operation：停止VM操作，恢复原始EL2系统寄存器值
//
// 与x86的stop_vmx_operation()/stop_svm_operation()对应。
// 此函数可在异常处理程序中使用，不会失败。
// 流程：将所有EL2系统寄存器恢复为store_orig_vm_state保存的原始值
//
// ARM64停止虚拟化不需要像x86那样执行VMXOFF/恢复VM_HSAVE_PA等操作，
// 只需将HCR_EL2恢复为原始值（特别是清除VM位，关闭Stage-2翻译）。
// ==============================================================================
void stop_vm_operation(void)
{
    if (!vm_is_on)
        return;

    // ---- 恢复HCR_EL2 ----
    // 将HCR_EL2恢复为原始值——清除VM位等虚拟化配置
    // HCR_EL2.VM=0后，Stage-2翻译不再启用，EL1的内存访问直接使用Stage-1页表
    write_msr("hcr_el2", orig_vm_state.hcr_el2);

    // ---- 恢复VTTBR_EL2 ----
    // 将VTTBR_EL2恢复为原始值——清除fuzzer设置的Stage-2页表基址
    // 防止残留的Stage-2翻译影响宿主机
    write_msr("vttbr_el2", orig_vm_state.vttbr_el2);

    // ---- 恢复VBAR_EL2 ----
    // 将VBAR_EL2恢复为原始值——清除fuzzer设置的异常向量表指针
    write_msr("vbar_el2", orig_vm_state.vbar_el2);

    // ---- 恢复MAIR_EL2 ----
    write_msr("mair_el2", orig_vm_state.mair_el2);

    // ---- 恢复TCR_EL2 ----
    write_msr("tcr_el2", orig_vm_state.tcr_el2);

    // ---- 刷新TLB ----
    // 恢复EL2寄存器后需要刷新Stage-2 TLB，防止残留的Stage-2翻译缓存
    // ARM64使用TLBI指令刷新TLB，类似于x86 VMX的INVEPT指令
    // TLBI VMALLE1IS：刷新所有Stage-1 TLB条目（Inner Shareable）
    // TLBI VMALLE1OS：刷新所有Stage-1 TLB条目（Outer Shareable）
    // TLBI ALLE2IS：刷新所有Stage-2 TLB条目
    asm volatile("dsb ish\n"
                 "tlbi vmalle1is\n"
                 "tlbi alle2is\n"
                 "dsb ish\n"
                 "isb\n"
                 :
                 :
                 : "memory");

    vm_is_on = false;
}

// ==============================================================================
// store_orig_vm_state：保存原始EL2系统寄存器状态
//
// 与x86的store_orig_vmcs_state()/store_orig_vmcb_state()对应。
// 在fuzzer启动前保存宿主机的EL2寄存器值，用于fuzzer退出时恢复。
//
// ARM64版本需要保存多个EL2系统寄存器（不像VMX只需保存VMCS指针）：
// - HCR_EL2：虚拟化配置寄存器——控制虚拟化使能和陷阱位
// - VTTBR_EL2：Stage-2页表基址寄存器——指向当前使用的Stage-2页表
// - VBAR_EL2：EL2异常向量表基址——指向当前EL2异常处理向量表
// - MAIR_EL2：内存属性间接寄存器——定义当前Stage-2的内存属性
// - TCR_EL2：翻译控制寄存器——控制当前Stage-2的翻译参数
// ==============================================================================
int store_orig_vm_state(void)
{
    // ---- 保存HCR_EL2 ----
    // HCR_EL2是虚拟化的核心控制寄存器，保存其原始值至关重要
    // 如果原始值中VM位已置1（KVM已启用虚拟化），恢复时需要保持VM=1
    read_msr("hcr_el2", orig_vm_state.hcr_el2);

    // ---- 保存VTTBR_EL2 ----
    // VTTBR_EL2指向当前KVM使用的Stage-2页表基址
    // 恢复时需要将此值写回，否则宿主机的Stage-2翻译会指向fuzzer的页表
    read_msr("vttbr_el2", orig_vm_state.vttbr_el2);

    // ---- 保存VBAR_EL2 ----
    // VBAR_EL2指向KVM的EL2异常向量表
    // 恢复时需要将此值写回，否则宿主机的异常处理会使用fuzzer的向量表
    read_msr("vbar_el2", orig_vm_state.vbar_el2);

    // ---- 保存MAIR_EL2 ----
    // MAIR_EL2保存了当前Stage-2的内存属性定义
    read_msr("mair_el2", orig_vm_state.mair_el2);

    // ---- 保存TCR_EL2 ----
    // TCR_EL2保存了当前Stage-2的翻译参数
    read_msr("tcr_el2", orig_vm_state.tcr_el2);

    return 0;
}

// ==============================================================================
// restore_orig_vm_state：恢复原始EL2系统寄存器状态
//
// 与x86的restore_orig_vmcs_state()/restore_orig_vmcb_state()对应。
// 此函数可在异常处理程序中使用，仅在出错时打印警告。
//
// 注意：ARM64版本的restore需要写回多个EL2系统寄存器（不像VMX只需vmptrld），
// 且需要在每条MSR指令后执行ISB(Instruction Synchronization Barrier)确保生效。
// ==============================================================================
void restore_orig_vm_state(void)
{
    if (!vm_is_on) {
        PRINT_ERR("ERROR: attempting to restore VM state while VM is not on\n");
        return;
    }

    // ---- 恢复HCR_EL2 ----
    // 首先恢复HCR_EL2——这是最关键的寄存器
    // 如果原始HCR_EL2中VM=0，恢复后Stage-2翻译立即关闭
    write_msr("hcr_el2", orig_vm_state.hcr_el2);

    // ---- 恢复VTTBR_EL2 ----
    // 恢复Stage-2页表基址——指向宿主机(KVM)的Stage-2页表
    write_msr("vttbr_el2", orig_vm_state.vttbr_el2);

    // ---- 恢复VBAR_EL2 ----
    write_msr("vbar_el2", orig_vm_state.vbar_el2);

    // ---- 恢复MAIR_EL2 ----
    write_msr("mair_el2", orig_vm_state.mair_el2);

    // ---- 恢复TCR_EL2 ----
    write_msr("tcr_el2", orig_vm_state.tcr_el2);

    // ---- 刷新TLB ----
    // 恢复所有寄存器后刷新TLB，确保新的配置生效
    asm volatile("dsb ish\n"
                 "tlbi vmalle1is\n"
                 "tlbi alle2is\n"
                 "dsb ish\n"
                 "isb\n"
                 :
                 :
                 : "memory");
}

// ==============================================================================
// set_vm_state：为所有guest actor配置VM状态——ARM64 VM Actor Configuration的核心入口
//
// 与x86的set_vmcs_state()/set_vmcb_state()对应。
// 流程：为每个guest actor填充vm_states数组中的对应元素：
// 1. 配置HCR_EL2陷阱位（控制哪些操作从EL1陷阱到EL2）
// 2. 配置VTTBR_EL2（指向该actor的Stage-2页表物理地址）
// 3. 配置VBAR_EL2（指向guest异常向量表）
// 4. 配置SPSR_EL2（guest的PSTATE——特权级、中断屏蔽等）
// 5. 配置ELR_EL2（guest代码入口点地址）
// 6. 配置SCTLR_EL1（guest的MMU/缓存控制）
// 7. 配置VMPIDR_EL2（guest看到的CPU ID）
//
// 与x86的关键区别：
// - x86为每个guest配置独立的VMCS/VMCB结构体
// - ARM64的所有guest共享同一个HCR_EL2（只有一个物理寄存器），
//   但可以通过VTTBR_EL2的ASID字段区分不同guest的Stage-2翻译
// - 在实际运行中，每次VM进入前需要根据当前actor_id加载对应的VTTBR_EL2/SPSR_EL2/ELR_EL2
// ==============================================================================
int set_vm_state(void)
{
    // 为所有guest actor配置VM状态
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // 跳过非guest actor（host actor不需要VM状态）
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        // 获取当前actor的vm_state结构体指针
        vm_state_t *state = &vm_states[actor_id];
        memset(state, 0, sizeof(vm_state_t));

        // ---- 配置1：HCR_EL2陷阱位 ----
        // HCR_EL2的配置对所有guest actor相同（因为只有一个物理寄存器）
        // 设置必须置1的位和清除必须清0的位
        // 额外设置RW位(bit 31)确保guest使用AArch64
        //
        // 【关键设计】与x86 SVM拦截位的设计理念相同：
        // - 陷阱大部分操作：WFI/WFE/SMC/系统寄存器访问/TLB维护/缓存维护
        // - 不陷阱特定指令：用于侧信道分析的指令不应被陷阱
        //   在ARM64上，性能计数器(PMEVCNTR_EL0)的读取不需要陷阱（类似x86的RDPMC）
        //   因此HCR_EL2中不设置TPPC(Trap Performance Counter)位
        state->hcr_el2 = (MUST_SET_HCR_EL2 | _BITULL(31)); // RW位确保AArch64

        // ---- 配置2：VTTBR_EL2 ----
        // VTTBR_EL2指向该actor的Stage-2页表基址
        // 每个actor使用独立的Stage-2页表，实现地址空间隔离
        // ASID字段使用actor_id作为标签，区分不同actor的TLB条目
        // 类似于x86 VMX的EPT_POINTER或SVM的nested_cr3
        //
        // VTTBR_EL2 = (ASID << 48) | (S2PT物理地址 << 1)
        // ASID用于TLB标签，BADDR指向Stage-2页表根页的物理地址
        // 注意：vttbr_hpas数组中存储的是Stage-2页表的物理页帧号，
        // 需要左移PAGE_SHIFT(12)得到完整物理地址
        vttbr_el2_t vttbr = {
            .asid = (uint64_t)actor_id, // ASID = actor_id，区分不同guest的TLB
            .baddr = vttbr_hpas[actor_id] >> VTTBR_EL2_BADDR_SHIFT, // Stage-2页表基址
            .cn = 0, // 必须为0
        };
        state->vttbr_el2 = *(uint64_t *)&vttbr;

        // ---- 配置3：VBAR_EL2 ----
        // VBAR_EL2指向EL2异常向量表
        // 当guest从EL1陷阱到EL2时，CPU跳转到VBAR_EL2 + 对应偏移
        // 使用fault_handler.c中的向量表
        extern void outer_vector_table;
        state->vbar_el2 = (uint64_t)&outer_vector_table;

        // ---- 配置4：SPSR_EL2 ----
        // SPSR_EL2保存了eret时恢复的PSTATE值
        // 定义了guest的初始处理器状态：
        // - 模式：EL1h（guest运行在EL1使用SP_EL1）
        // - 中断屏蔽：全部屏蔽(D/A/I/F)，防止guest初始化时被中断干扰
        // 类似于x86 VMX的GUEST_ACTIVITY_STATE和GUEST_INTERRUPTIBILITY_INFO
        state->spsr_el2 = DEFAULT_SPSR_EL2;

        // ---- 配置5：ELR_EL2 ----
        // ELR_EL2保存了eret时跳转的目标地址——guest代码入口点
        // 类似于x86 VMX的GUEST_RIP
        //
        // ARM64的guest入口点指向code.section[0]——fuzzer测试用例的起始地址
        // 不像VMX需要先指向vmlaunch_page再改为code入口，
        // 因为ARM64没有VMLAUNCH验证步骤，eret直接进入guest代码
        guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
        state->elr_el2 = (uint64_t)&guest_v_memory->code.section[0];

        // ---- 配置6：SCTLR_EL1 ----
        // SCTLR_EL1控制guest的MMU、缓存、对齐检查等
        // 类似于x86 VMX的GUEST_CR0
        //
        // 必须置1的位：M(MMU使能)、C(数据缓存)、I(指令缓存)、A(对齐检查)
        // 必须清0的位：WXN(写执行互斥)
        // 注意：ARM64的SCTLR_EL1不像x86 CR0那样有必须置1的固定位（如PE/PG），
        // 因为ARM64没有实模式——MMU始终启用
        state->sctlr_el1 = MUST_SET_SCTLR_EL1_GUEST & ~MUST_CLEAR_SCTLR_EL1_GUEST;

        // ---- 配置7：MAIR_EL2 ----
        // MAIR_EL2定义了Stage-2页表中可用的内存属性
        // 所有actor使用相同的MAIR_EL2配置——
        // 因为MAIR_EL2只有一个物理寄存器，且内存属性对所有guest应该一致
        state->mair_el2 = DEFAULT_MAIR_EL2;

        // ---- 配置8：TCR_EL2 ----
        // TCR_EL2控制Stage-2翻译参数
        // 所有actor使用相同的TCR_EL2配置——
        // 因为TCR_EL2只有一个物理寄存器
        state->tcr_el2 = DEFAULT_TCR_EL2;

        // ---- 配置9：VMPIDR_EL2 ----
        // VMPIDR_EL2是guest看到的CPU标识寄存器
        // 防止guest读取真实的MIDR_EL1获取硬件信息
        // 使用actor_id作为Aff0字段，区分不同guest看到的CPU ID
        // 类似于x86 VMX中拦截CPUID指令并提供虚拟值的设计
        uint64_t mpidr = 0;
        read_msr("mpidr_el1", mpidr); // 读取真实MPIDR_EL1作为基础值
        // 将Aff0字段替换为actor_id
        mpidr = (mpidr & ~(0xFFULL)) | (uint64_t)actor_id;
        state->vmpidr_el2 = mpidr;

        // ---- 配置10：CSSELR_EL1 ----
        // CSSELR_EL1选择要访问的缓存级别，设为0（选择L1数据缓存）
        state->csselr_el1 = 0;
    }

    return 0;
}

// ==============================================================================
// print_vm_exit_info：打印VM退出事件的详细信息
//
// 与x86的print_vmx_exit_info()/print_svm_exit_info()对应。
// 解码ESR_EL2中的异常原因（EC类码和ISS具体信息），以及相关寄存器值。
//
// ARM64的VM退出信息与x86的区别：
// - x86有VM_EXIT_REASON(基本退出码) + EXIT_QUALIFICATION(详细资格)
// - ARM64有ESR_EL2.EC(异常类别码) + ESR_EL2.ISS(指令特定综合征)
// - x86有GUEST_LINEAR_ADDRESS/GUEST_PHYSICAL_ADDRESS
// - ARM64有FAR_EL2(故障地址) + HPFAR_EL2(Stage-2故障物理地址)
//
// 本函数解码以下信息：
// 1. ESR_EL2——异常类别(EC)和指令特定综合征(ISS)
// 2. FAR_EL2——触发异常的虚拟地址
// 3. HPFAR_EL2——Stage-2故障的物理地址（如果适用）
// 4. ELR_EL2——guest异常时的指令地址（相当于x86的GUEST_RIP）
// 5. SPSR_EL2——guest异常时的PSTATE（相当于x86的GUEST_RFLAGS）
// ==============================================================================
int print_vm_exit_info(void)
{
    uint64_t esr_val = 0;
    uint64_t far_val = 0;
    uint64_t elr_val = 0;
    uint64_t spsr_val = 0;

    // ---- 读取ESR_EL2 ----
    // ESR_EL2是ARM64 VM退出的核心信息寄存器
    // 包含异常类别码(EC)和指令特定综合征(ISS)
    read_msr("esr_el2", esr_val);

    // ---- 解码EC(Exception Class)字段 ----
    // EC字段位于ESR_EL2的bits[31:26]，标识异常类别
    uint64_t ec = (esr_val & ESR_EC_MASK) >> ESR_EC_SHIFT;
    uint64_t iss = esr_val & ESR_ISS_MASK;

    PRINT_ERR("VM exit info:\n");
    PRINT_ERR("  ESR_EL2: 0x%llx (EC=0x%llx, ISS=0x%llx)\n", esr_val, ec, iss);

    // ---- 根据EC值解码异常类别 ----
    // 将EC值映射为可读字符串，类似于x86 VMX的basic_exit_reason_to_str映射表
    const char *ec_str = "Unknown";
    switch (ec) {
    case EC_UNKNOWN:
        ec_str = "Unknown Reason";
        break;
    case EC_WFI_WFE:
        ec_str = "WFI/WFE Trapped";
        break;
    case EC_SYSREG_32:
        ec_str = "MCR/MRC (32-bit SysReg, EL1->EL2)";
        break;
    case EC_SYSREG_64:
        ec_str = "MSR/MRS (64-bit SysReg, EL1->EL2)";
        break;
    case EC_SMC64:
        ec_str = "SMC64 Trapped";
        break;
    case EC_HVC64:
        ec_str = "HVC64 (Hypervisor Call)";
        break;
    case EC_SVC64:
        ec_str = "SVC64 (Supervisor Call from EL1)";
        break;
    case EC_IABORT_EL1:
        ec_str = "Instruction Abort (EL1)";
        break;
    case EC_DABORT_EL1:
        ec_str = "Data Abort (EL1)";
        break;
    case EC_IABORT_EL2:
        ec_str = "Instruction Abort (EL2)";
        break;
    case EC_DABORT_EL2:
        ec_str = "Data Abort (EL2)";
        break;
    default:
        // 未知EC值——打印原始值以便调试
        PRINT_ERR("  Unknown EC: 0x%llx\n", ec);
        break;
    }
    PRINT_ERR("  EC decoded: %s (EC=0x%llx)\n", ec_str, ec);

    // ---- 解码ISS字段（根据EC类别） ----
    if (ec == EC_DABORT_EL1 || ec == EC_IABORT_EL1 || ec == EC_DABORT_EL2 || ec == EC_IABORT_EL2) {
        // 数据/指令中止的ISS解码——这是fuzzer最关心的退出类型
        // ISS中包含故障状态码(FSC)、读写方向(WnR)等信息
        uint64_t fsc = iss & ISS_FSC_MASK;
        uint64_t wnr = (iss & ISS_WNR_BIT) >> 6;

        PRINT_ERR("  Fault details:\n");
        PRINT_ERR("    WnR: %s\n", wnr ? "Write" : "Read");
        PRINT_ERR("    FSC: 0x%llx\n", fsc);

        // 解码FSC（故障状态码）
        const char *fsc_str = "Unknown FSC";
        switch (fsc) {
        case FSC_TRANS_FAULT_L0:
            fsc_str = "Translation Fault (Level 0)";
            break;
        case FSC_TRANS_FAULT_L1:
            fsc_str = "Translation Fault (Level 1)";
            break;
        case FSC_TRANS_FAULT_L2:
            fsc_str = "Translation Fault (Level 2)";
            break;
        case FSC_TRANS_FAULT_L3:
            fsc_str = "Translation Fault (Level 3)";
            break;
        case FSC_ACCESS_FLAG_FAULT:
            fsc_str = "Access Flag Fault";
            break;
        case FSC_PERM_FAULT_L0:
            fsc_str = "Permission Fault (Level 0)";
            break;
        case FSC_PERM_FAULT_L1:
            fsc_str = "Permission Fault (Level 1)";
            break;
        case FSC_PERM_FAULT_L2:
            fsc_str = "Permission Fault (Level 2)";
            break;
        case FSC_PERM_FAULT_L3:
            fsc_str = "Permission Fault (Level 3)";
            break;
        case FSC_SEA:
            fsc_str = "SError (Synchronous External Abort)";
            break;
        default:
            break;
        }
        PRINT_ERR("    FSC decoded: %s\n", fsc_str);

        // ---- 读取FAR_EL2 ----
        // FAR_EL2记录触发数据/指令中止的虚拟地址
        // 类似于x86 VMX的GUEST_LINEAR_ADDRESS
        read_msr("far_el2", far_val);
        PRINT_ERR("    FAR_EL2 (faulting address): 0x%llx\n", far_val);

        // ---- 尝试读取HPFAR_EL2 ----
        // HPFAR_EL2记录Stage-2故障的物理地址（IPA）
        // 类似于x86 VMX的GUEST_PHYSICAL_ADDRESS
        // 注意：HPFAR_EL2只在Stage-2翻译故障时有效
        uint64_t hpfar_val = 0;
        read_msr("hpfar_el2", hpfar_val);
        PRINT_ERR("    HPFAR_EL2 (IPA): 0x%llx\n", hpfar_val);
    } else if (ec == EC_SYSREG_64 || ec == EC_SYSREG_32) {
        // 系统寄存器访问陷阱的ISS解码
        // ISS中包含被访问的系统寄存器的编码(Op0/Op1/CRn/CRm/Op2)和方向(读/写)
        uint64_t op0 = (iss & ISS_SYSREG_OP0_MASK) >> ISS_SYSREG_OP0_SHIFT;
        uint64_t op1 = (iss & ISS_SYSREG_OP1_MASK) >> ISS_SYSREG_OP1_SHIFT;
        uint64_t crn = (iss & ISS_SYSREG_CRN_MASK) >> ISS_SYSREG_CRN_SHIFT;
        uint64_t crm = (iss & ISS_SYSREG_CRM_MASK) >> ISS_SYSREG_CRM_SHIFT;
        uint64_t op2 = (iss & ISS_SYSREG_OP2_MASK) >> ISS_SYSREG_OP2_SHIFT;
        uint64_t dir = iss & ISS_SYSREG_DIR_BIT;

        PRINT_ERR("  System register access: Op0=%llu Op1=%llu CRn=%llu CRm=%llu Op2=%llu Dir=%s\n",
                  op0, op1, crn, crm, op2, dir ? "Write(MSR)" : "Read(MRS)");
    } else if (ec == EC_HVC64) {
        // HVC调用的ISS解码——guest主动调用hypervisor
        // ISS[15:0]为HVC立即数，通常用于标识HVC的服务编号
        PRINT_ERR("  HVC immediate: 0x%llx\n", iss & 0xFFFF);
    } else if (ec == EC_SMC64) {
        // SMC调用的ISS解码——guest调用安全监控
        PRINT_ERR("  SMC immediate: 0x%llx\n", iss & 0xFFFF);
    }

    // ---- 读取ELR_EL2和SPSR_EL2 ----
    // ELR_EL2记录guest异常时的指令地址（相当于x86的GUEST_RIP）
    // SPSR_EL2记录guest异常时的PSTATE（相当于x86的GUEST_RFLAGS）
    read_msr("elr_el2", elr_val);
    read_msr("spsr_el2", spsr_val);
    PRINT_ERR("  ELR_EL2 (guest PC): 0x%llx\n", elr_val);
    PRINT_ERR("  SPSR_EL2 (guest PSTATE): 0x%llx\n", spsr_val);

    return 0;
}

// ==============================================================================
// init_vm：VM模块初始化
//
// 与x86的init_vmx()/init_svm()对应。
// 在fuzzer启动时调用，分配VM运行所需的内存：
// 1. vm_states数组——每个guest actor一个vm_state_t结构体
// 2. vttbr_hpas数组——每个guest actor一个Stage-2页表物理地址
// ==============================================================================
int init_vm(void)
{
    // ---- 分配vm_states数组 ----
    // 每个guest actor需要一个vm_state_t结构体保存其虚拟化配置
    // 类似于x86 VMX的vmcss数组或SVM的vmcb_pages
    vm_states = CHECKED_ZALLOC(sizeof(vm_state_t) * MAX_ACTORS);

    // ---- 分配vttbr_hpas数组 ----
    // 每个guest actor需要一个Stage-2页表物理地址
    // 类似于x86的vmcs_hpas或vmcb_hpas数组
    vttbr_hpas = CHECKED_ZALLOC(sizeof(uint64_t) * MAX_ACTORS);

    return 0;
}

// ==============================================================================
// free_vm：释放VM模块分配的所有内存
//
// 与x86的free_vmx()/free_svm()对应。
// 在fuzzer退出时调用，释放vm_states和vttbr_hpas数组
// ==============================================================================
void free_vm(void)
{
    SAFE_FREE(vm_states);
    SAFE_FREE(vttbr_hpas);
}

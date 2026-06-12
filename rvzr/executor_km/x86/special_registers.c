/// File:
///  - Management of model-specific registers (MSRs)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>

#include "fault_handler.h"
#include "main.h"
#include "shortcuts.h"
#include "special_registers.h"
#include "test_case_parser.h"

// 全局原始特殊寄存器状态，用于保存和恢复CPU控制寄存器/MSR
// 测试执行前保存原始值，执行后恢复，确保系统稳定性
special_registers_t *orig_special_registers_state = NULL; // global

// =================================================================================================
// 读写特殊寄存器的本地快捷函数
// =================================================================================================
// 注意：故意不使用内核的native_read/write_cr0/4函数，因为其签名可能随内核版本变化
// 直接使用内联汇编确保长期稳定性

static inline unsigned long _read_cr0(void)
{
    unsigned long val = 0;
    asm volatile("mov %%cr0, %0\n" : "=r"(val));
    return val;
}

static inline void _write_cr0(unsigned long val) { asm volatile("mov %0, %%cr0\n" : : "r"(val)); }

static inline unsigned long _read_cr4(void)
{
    unsigned long val = 0;
    asm volatile("mov %%cr4, %0\n" : "=r"(val));
    return val;
}

static inline void _write_cr4(unsigned long val) { asm volatile("mov %0, %%cr4\n" : : "r"(val)); }

// =================================================================================================
// 特殊寄存器管理的私有实现
// =================================================================================================

static int store_orig_msr_state(void);

// 为用户态actor配置MSR
// 如果定义了FORCE_SMAP_OFF，禁用SMAP/SMEP（允许内核访问用户态内存和执行用户态代码）
// 这对于测试跨权限级别的侧信道攻击是必要的
static int set_msrs_for_user_actors(void)
{
#ifdef FORCE_SMAP_OFF
    // 禁用SMAP(Supervisor Mode Access Prevention)和SMEP(Supervisor Mode Execution Prevention)
    // SMAP阻止内核态访问用户态内存，SMEP阻止内核态执行用户态代码
    // 禁用它们是为了让测试用例能够在内核态中访问/执行用户态区域的代码
    uint64_t cr4 = _read_cr4();
    cr4 &= ~(X86_CR4_SMAP | X86_CR4_SMEP);
    asm volatile("mov %0, %%cr4" : : "r"(cr4)); // 使用asm绕过内核的CR4写保护检查
#endif
    // 设置syscall入口点为fault_handler
    // 当用户态actor执行syscall指令时，跳转到fault_handler处理
    wrmsr64(MSR_LSTAR, (uint64_t)fault_handler);

    return 0;
}

/// @brief 配置MSR以启用VMX操作（Intel虚拟化）
/// VMX操作需要满足CR0/CR4的固定比特约束，并设置CR4.VMXE位
/// @return 0表示成功，-1表示失败
static int set_msrs_for_vmx(void)
{
    uint64_t cr4 = _read_cr4();
    uint64_t cr0 = _read_cr0();

    // 确保CR0和CR4的比特满足VMX操作的固定比特约束：
    // - _FIXED0中为1的比特：在CRx中必须为1（固定为1）
    // - _FIXED1中为0的比特：在CRx中必须为0（固定为0）
    // (来源：Intel SDM, 24.8 "restrictions on VMX operation")
    cr0 &= rdmsr64(MSR_IA32_VMX_CR0_FIXED1);
    cr0 |= rdmsr64(MSR_IA32_VMX_CR0_FIXED0);
    cr4 &= rdmsr64(MSR_IA32_VMX_CR4_FIXED1);
    cr4 |= rdmsr64(MSR_IA32_VMX_CR4_FIXED0);
    _write_cr0(cr0);

    // 启用VMX操作：设置CR4.VMXE位(Virtual Machine Extensions Enable)
    // (来源：Intel SDM, 24.7 "Enabling and entering VMX operation")
    cr4 |= X86_CR4_VMXE;
    _write_cr4(cr4);

    return 0;
}

/// @brief 配置MSR以启用SVM操作（AMD虚拟化）
/// 验证BIOS未禁用SVM，然后设置EFER.SVME位启用SVM
/// @return 0表示成功，-1表示失败
static int set_msrs_for_svm(void)
{
    // 检查BIOS是否禁用了SVM（VM_CR.MSRbit 4 = SVM Disable Lock）
    // 如果此位为1，SVM被BIOS锁定禁用，无法启用
    uint64_t vm_cr = rdmsr64(MSR_VM_CR);
    ASSERT((vm_cr & (1 << 4)) == 0, "set_msrs_for_svm");

    // 启用SVM操作：设置EFER.SVME位(Secure Virtual Machine Enable)
    uint64_t efer = rdmsr64(MSR_EFER);
    if (!(efer & EFER_SVME)) {
        efer |= EFER_SVME;
        wrmsr64(MSR_EFER, efer);
    }

    return 0;
}

// 获取SSBP(Speculative Store Bypass)补丁的MSR ID和掩码
// SSBP补丁用于控制投机存储绕过漏洞(CVE-2018-3639)
// 不同CPU型号使用不同的MSR和掩码位：
//   Intel: MSR_IA32_SPEC_CTRL, SPEC_CTRL_SSBD位
//   AMD VIRT_SSBD: MSR_AMD64_VIRT_SPEC_CTRL
//   AMD LS_CFG: MSR_AMD64_LS_CFG，不同型号的掩码位不同
static int get_ssbp_patch_msr_ctrls(uint64_t *msr_id, uint64_t *msr_mask)
{
    if (cpu_has(cpuinfo, X86_FEATURE_MSR_SPEC_CTRL)) {
        *msr_id = MSR_IA32_SPEC_CTRL;
        *msr_mask = SPEC_CTRL_SSBD;
    } else if (cpu_has(cpuinfo, X86_FEATURE_VIRT_SSBD)) {
        *msr_id = MSR_AMD64_VIRT_SPEC_CTRL;
        *msr_mask = SPEC_CTRL_SSBD;
    } else if (cpu_has(cpuinfo, X86_FEATURE_LS_CFG_SSBD)) {
        *msr_id = MSR_AMD64_LS_CFG;
        switch (cpuinfo->x86) {
        case 0x15:
            *msr_mask = 1ULL << 54;
            break;
        case 0x16:
            *msr_mask = 1ULL << 33;
            break;
        case 0x17:
            *msr_mask = 1ULL << 10;
            break;
        default:
            PRINT_ERR("ERROR: Unable to patch SSBD on this CPU; unexpected CPU model\n");
            return -1;
        }
    } else {
        PRINT_ERR("ERROR: Unable to patch SSBD on this CPU; no known patch\n");
        return -1;
    }
    return 0;
}

// 获取预取器(prefetcher)控制的MSR ID和掩码
// 预取器控制用于禁用/启用硬件预取器，减少测量噪声
// 禁用预取器确保侧信道测量结果不受预取器干扰
// Intel: MSR_MISC_FEATURE_CONTROL，不同型号掩码不同
// AMD: 0xc0000108或MSR_AMD64_DC_CFG，不同family掩码不同
static int get_prefetcher_msr_ctrls(uint64_t *msr_id, uint64_t *msr_mask)
{
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        *msr_id = MSR_MISC_FEATURE_CONTROL;
        switch (cpuinfo->x86_model) {
        case 0x97:
        case 0x9a:
        case 0xba:
        case 0xb7:
        case 0xbf:
            *msr_mask = 0b101111;
            break;
        default:
            *msr_mask = 0b1111;
            break;
        }
    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        switch (cpuinfo->x86) {
        case 0x19:
            *msr_id = 0xc0000108;
            *msr_mask = 0b101111;
            break;
        default:
            *msr_id = MSR_AMD64_DC_CFG;
            *msr_mask = (1 << 13) | (1 << 15);
            break;
        }
    }
    return 0;
}

// 应用MSR掩码：根据enable参数设置或清除指定MSR的掩码位
// 设置后验证MSR值是否确实改变（某些MSR可能不可写）
static int apply_msr_mask(uint64_t msr_id, uint64_t msr_mask, bool enable)
{
    uint64_t msr_value = rdmsr64(msr_id);
    if (enable) {
        msr_value |= msr_mask;
    } else {
        msr_value &= ~msr_mask;
    }
    wrmsr64(msr_id, msr_value);
    if (rdmsr64(msr_id) != msr_value) {
        PRINT_ERR("ERROR: Not able to set MSR 0x%llx\n", msr_id);
        return -1;
    }
    return 0;
}

// =================================================================================================
// 特殊寄存器管理的公共接口
// =================================================================================================

// 设置特殊寄存器：保存原始状态，然后根据测试用例需求修改
// 配置顺序：保存原始状态 -> SSBP补丁 -> 预取器控制 -> CR0 -> CR4 -> 用户态MSR -> VM MSR
int set_special_registers(void)
{
    int err = 0;
    uint64_t msr_id = 0, msr_mask = 0;

    err = store_orig_msr_state();
    CHECK_ERR("store_orig_msr_state");

#ifndef VMBUILD
    // 投机存储绕过(SSBP)补丁控制
    // 启用SSBP补丁可以减少投机存储绕过带来的侧信道噪声
    err = get_ssbp_patch_msr_ctrls(&msr_id, &msr_mask);
    // 保存原始SPEC_CTRL值，用于后续恢复
    orig_special_registers_state->spec_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_enable_ssbp_patch");
    // 根据配置启用或禁用SSBP补丁
    err = apply_msr_mask(msr_id, msr_mask, enable_ssbp_patch);
    CHECK_ERR("set_enable_ssbp_patch");

    // 硬件预取器控制
    // 禁用预取器可以减少L1/L2缓存预取带来的测量噪声
    // 注意：apply_msr_mask的enable参数使用!enable_prefetchers，
    // 即enable_prefetchers=true时禁用预取器（掩码应用于禁用方向）
    err = get_prefetcher_msr_ctrls(&msr_id, &msr_mask);
    orig_special_registers_state->prefetcher_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_disable_prefetchers");
    err = apply_msr_mask(msr_id, msr_mask, !enable_prefetchers);
    CHECK_ERR("set_disable_prefetchers");
#endif

    // CR0配置
    // 清除CR0.CD(Cache Disable)位，确保缓存启用
    // 缓存必须启用才能收集基于缓存的侧信道追踪(htrace)
    uint64_t cr0 = _read_cr0();
    cr0 &= ~X86_CR0_CD;
    _write_cr0(cr0);

    // CR4配置
    // 设置CR4.PCE(Performance Counter Enable)位，允许在任意权限级别执行RDPMC指令
    // 这使得测试用例可以直接读取性能计数器而不需要系统调用
    uint64_t cr4 = _read_cr4();
    cr4 |= X86_CR4_PCE;
    _write_cr4(cr4);

    // 如果测试用例包含用户态actor，配置相关MSR
    // 包括SMAP/SMEP控制和syscall入口点设置
    if (test_case->features.includes_user_actors) {
        err = set_msrs_for_user_actors();
        CHECK_ERR("set_msrs_for_user_actors");
    }

    // 如果测试用例包含虚拟机(VM) actor，启用虚拟化支持
    // Intel CPU启用VMX，AMD CPU启用SVM
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = set_msrs_for_vmx();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = set_msrs_for_svm();
        }
        CHECK_ERR("set_msrs_for_vm_actors");
    }

    return 0;
}

// 保存原始MSR状态：在修改之前记录所有关键寄存器的值
// 这些值在测试执行完毕后用于恢复系统状态
static int store_orig_msr_state(void)
{
    // 保存CR0和CR4控制寄存器
    orig_special_registers_state->cr0 = _read_cr0();
    orig_special_registers_state->cr4 = _read_cr4();
    // 保存LSTAR(syscall入口点MSR)
    orig_special_registers_state->lstar = rdmsr64(MSR_LSTAR);
    // 保存EFER(Extended Feature Enable Register)
    orig_special_registers_state->efer = rdmsr64(MSR_EFER);
    // 保存FS和GS段基址MSR
    orig_special_registers_state->fs_base = rdmsr64(MSR_FS_BASE);
    orig_special_registers_state->gs_base = rdmsr64(MSR_GS_BASE);

    // 保存GDTR(全局描述符表寄存器)
    struct desc_ptr gdtr;
    asm volatile("sgdt %0" : "=m"(gdtr));
    orig_special_registers_state->gdtr_base = gdtr.address;
    orig_special_registers_state->gdtr_limit = gdtr.size;

#if VENDOR_ID == VENDOR_AMD_ // AMD平台额外保存SYSCFG MSR
    orig_special_registers_state->syscfg = rdmsr64(MSR_SYSCFG);
#endif
    return 0;
}

// 恢复特殊寄存器：将所有修改过的寄存器恢复到原始值
// 注意：if-zero检查是必要的，因为MSR初始化可能中途失败
// 此时MSR状态只有部分被初始化，恢复操作需要跳过未初始化的部分
void restore_special_registers(void)
{
    uint64_t msr_id = 0, msr_mask = 0;

    // note: the if-zero statements are necessary because the MSR initialization might have failed
    // midway through the process, in which case the MSR state was only partially initialized

    if (orig_special_registers_state->cr0 != 0)
        _write_cr0(orig_special_registers_state->cr0);

    if (orig_special_registers_state->cr4 != 0)
        _write_cr4(orig_special_registers_state->cr4);

    if (orig_special_registers_state->efer != 0)
        wrmsr64(MSR_EFER, orig_special_registers_state->efer);

    if (orig_special_registers_state->lstar != 0)
        wrmsr64(MSR_LSTAR, orig_special_registers_state->lstar);

    // 恢复SSBP补丁MSR到原始值
    if (orig_special_registers_state->spec_ctrl != 0) {
        get_ssbp_patch_msr_ctrls(&msr_id, &msr_mask);
        wrmsr64(msr_id, orig_special_registers_state->spec_ctrl);
    }

    // 恢复预取器控制MSR到原始值
    if (orig_special_registers_state->prefetcher_ctrl != 0) {
        get_prefetcher_msr_ctrls(&msr_id, &msr_mask);
        wrmsr64(msr_id, orig_special_registers_state->prefetcher_ctrl);
    }

    // 恢复FS和GS段基址
    if (orig_special_registers_state->fs_base != 0) {
        wrmsr64(MSR_FS_BASE, orig_special_registers_state->fs_base);
    }

    if (orig_special_registers_state->gs_base != 0) {
        wrmsr64(MSR_GS_BASE, orig_special_registers_state->gs_base);
    }

    // 恢复GDTR(全局描述符表寄存器)
    if (orig_special_registers_state->gdtr_base != 0) {
        struct desc_ptr gdtr = {.address = orig_special_registers_state->gdtr_base,
                                .size = orig_special_registers_state->gdtr_limit};
        asm volatile("lgdt %0" : : "m"(gdtr));
    }

#if VENDOR_ID == VENDOR_AMD_ // AMD平台恢复SYSCFG MSR
    if (orig_special_registers_state->syscfg != 0)
        wrmsr64(MSR_SYSCFG, orig_special_registers_state->syscfg);
#endif

    // 清零保存的状态结构，标记所有寄存器已恢复完毕
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

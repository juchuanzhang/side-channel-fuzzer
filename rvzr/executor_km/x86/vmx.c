/// File: Configuration and use of Intel VMX
///
// ==============================================================================
// VMX模块概述：
// 本文件实现了Intel VMX（Virtual Machine Extensions）的完整管理，是论文
// "Enter, Exit, Page Fault, Leak"中VM Actor Configuration的核心实现。
//
// 整体架构和初始化流程：
// 1. init_vmx()          —— 分配VMXON区域和VMCS内存
// 2. vmx_check_cpu_compatibility() —— 检查CPU是否支持VMX及所需控制位
// 3. start_vmx_operation()         —— 设置CR4.VMXE、配置IA32_FEATURE_CONTROL、执行VMXON进入VMX根模式
// 4. set_vmcs_state()              —— 为每个guest actor初始化VMCS：
//    a. vmclear + vmptrld 加载VMCS
//    b. set_vmcs_guest_state()  —— 设置客户机状态(CR0/CR3/CR4、段寄存器、RSP/RIP等)
//    c. set_vmcs_host_state()   —— 设置宿主机状态(CR0/CR3/CR4、段选择子、GDTR/IDTR等)
//    d. set_vmcs_exec_control() —— 配置VM执行控制(引脚控制、主/次处理器控制、EPT等)
//    e. set_vmcs_exit_control()  —— 配置VM退出控制
//    f. set_vmcs_entry_control() —— 配置VM进入控制
//    g. make_vmcs_launched()     —— 执行VMLAUNCH，完成首次VM进入/退出循环
// 5. stop_vmx_operation()          —— 执行VMXOFF退出VMX根模式
//
// 状态保存和恢复机制：
// - store_orig_vmcs_state()  —— 保存原始VMCS指针(vmptrst)
// - restore_orig_vmcs_state() —— 恢复原始VMCS指针(vmptrld)
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/tlbflush.h>
#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "fault_handler.h"
#include "main.h"
#include "page_tables_guest.h"
#include "special_registers.h"
#include "vmx.h"
#include "vmx_config.h"

// NOLINTBEGIN(readability-function-size)
// NOLINTBEGIN(readability-function-cognitive-complexity)
// Justification: these functions directly follow VMX implementation steps as per Intel SDM;
// therefore, they are allowed to be complex

#define CHECK_VMFAIL(src)                                                                          \
    ASSERT(err_inv == 0, src);                                                                     \
    ASSERT(err_val == 0, src);

// 全局状态标志，标记VMX是否已启用（VMXON已执行）
bool vmx_is_on = false;     // global
// 每个actor对应的VMCS物理地址数组，用于vmptrld/vmclear等指令操作
uint64_t *vmcs_hpas = NULL; // global

// 保存原始VMXON状态，用于判断在fuzzer启动前VMX是否已被启用
static bool orig_vmxon_state = false;
// 保存原始VMCS指针，用于在fuzzer退出时恢复宿主机原有的VMCS状态
static uint64_t orig_vmcs_ptr = 0;

// VMXON区域的虚拟地址和物理地址，VMXON指令要求传入4KB对齐的物理地址
static void *vmxon_page_hva = NULL;
static uint64_t vmxon_page_hpa = 0;

// VMCS结构体数组，每个guest actor拥有一个独立的VMCS
static vmcs_t *vmcss = NULL;

// CPU支持的VMX控制位掩码，从MSR中读取，用于验证VMCS控制字段配置的合法性
static uint64_t supported_vmcs_pin_ctrl = 0;
static uint64_t supported_vmcs_primary_ctrl = 0;
static uint64_t supported_vmcs_secondary_ctrl = 0;

static int set_vmcs_guest_state(void);
static int set_vmcs_host_state(void);
static int set_vmcs_exec_control(int actor_id);
static int set_vmcs_exit_control(void);
static int set_vmcs_entry_control(void);
static int make_vmcs_launched(int actor_id);
static void print_vmlaunch_error_info(int err_inv, int err_val, int actor_id);

// =================================================================================================
// Error decoding
// =================================================================================================
// VMX指令错误码到字符串的映射表，用于调试和错误诊断
static const char *vmx_instruction_error_to_str[] = {
    "Unknown error: 0",
    "VMXERR_VMCALL_IN_VMX_ROOT_OPERATION",
    "VMXERR_VMCLEAR_INVALID_ADDRESS",
    "VMXERR_VMCLEAR_VMXON_POINTER",
    "VMXERR_VMLAUNCH_NONCLEAR_VMCS",
    "VMXERR_VMRESUME_NONLAUNCHED_VMCS",
    "VMXERR_VMRESUME_AFTER_VMXOFF",
    "VMXERR_ENTRY_INVALID_CONTROL_FIELD",
    "VMXERR_ENTRY_INVALID_HOST_STATE_FIELD",
    "VMXERR_VMPTRLD_INVALID_ADDRESS",
    "VMXERR_VMPTRLD_VMXON_POINTER",
    "VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID",
    "VMXERR_UNSUPPORTED_VMCS_COMPONENT",
    "VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT",
    "VMXERR_VMXON_IN_VMX_ROOT_OPERATION",
    "VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS_POINTER",
    "VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EXECUTIVE_VMCS_POINTER_NOT_VMXON_POINTER",
    "VMXERR_VMCALL_NONCLEAR_VMCS",
    "VMXERR_VMCALL_INVALID_VM_EXIT_CONTROL_FIELDS",
    "VMXERR_VMCALL_INCORRECT_MSEG_REVISION_ID",
    "VMXERR_VMXOFF_UNDER_DUAL_MONITOR_TREATMENT_OF_SMIS_AND_SMM",
    "VMXERR_VMCALL_INVALID_SMM_MONITOR_FEATURES",
    "VMXERR_ENTRY_INVALID_VM_EXECUTION_CONTROL_FIELDS_IN_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS",
    "VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID",
    NULL};

// VM退出原因到字符串的映射结构体，用于解码VM退出事件
typedef struct {
    uint16_t basic_exit_reason;
    const char *str;
} vmx_basic_exit_reason_t;

static vmx_basic_exit_reason_t vmx_basic_exit_reason_to_str[] = {VMX_EXIT_REASONS, {0, NULL}};

// =================================================================================================
// VMX指令辅助函数
// 这些函数封装了VMX指令的执行，并捕获VMfailInvalid和VMfailValid两种错误状态。
// 每个指令通过内联汇编执行对应的VMX指令，使用setc/setz捕获CF/ZF标志来判断失败类型：
//   - VMfailInvalid: VMX操作因无效状态失败(CF=1)，无法提供更详细的错误信息
//   - VMfailValid:   VMX操作因有效错误失败(ZF=1)，可通过VM_INSTRUCTION_ERROR读取错误码
// =================================================================================================
// VMXON指令：进入VMX根操作模式
// 参数phys为VMXON区域的物理地址（必须4KB对齐，且首4字节为VMCS修订ID）
// 成功后CPU进入VMX根模式，可以执行VMX管理指令(vmclear/vmptrld/vmwrite等)
static inline void vmxon(uint64_t phys, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmxon %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(phys)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

// VMXOFF指令：退出VMX根操作模式
// 执行后CPU离开VMX根模式，不再支持VMX管理指令
static inline void vmxoff(uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmxoff; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

// VMPTRST指令：读取当前VMCS指针
// 将当前加载的VMCS的物理地址存储到dest中，用于保存VMX操作前的VMCS状态
static inline void vmptrst(uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint64_t tmp = 0;
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmptrst %[tmp]; setc %[inval]; setz %[val]\n"
                         : [tmp] "=m"(tmp), [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *dest = tmp;
    *err_inv = inv;
    *err_val = val;
}

// VMPTRLD指令：加载指定VMCS为当前VMCS
// 参数vmcs_hpa为目标VMCS的物理地址，加载后vmwrite/vmread操作针对该VMCS
static inline void vmptrld(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmptrld %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

// VMCLEAR指令：清除指定VMCS的状态
// 将VMCS标记为"clear"状态（VMLAUNCH要求VMCS处于clear状态），并确保其数据写入内存
static inline void vmclear(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmclear %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

// VMREAD指令：读取当前VMCS中指定字段的值
// 参数field为VMCS字段编码，dest存储读取的值
static inline void vmread(uint64_t field, uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    uint64_t dest_local = 0;
    __asm__ __volatile__("vmread %[field], %[dest]; setc %[inval]; setz %[val]\n"
                         : [dest] "=rm"(dest_local), [val] "=rm"(val), [inval] "=rm"(inv)
                         : [field] "r"(field)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
    *dest = dest_local;
}

// VMWRITE指令：向当前VMCS的指定字段写入值
// 参数field为VMCS字段编码，value为要写入的值
// 这是配置VMCS最核心的指令，所有VMCS字段设置都通过此指令完成
static inline void vmwrite(uint64_t field, uint64_t value, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, valid = 0;
    __asm__ __volatile__("vmwrite %[value], %[field]; setc %[inval]; setz %[valid]\n"
                         : [valid] "=rm"(valid), [inval] "=rm"(inv)
                         : [field] "r"(field), [value] "rm"(value)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = valid;
}
// CHECKED_VMWRITE宏：执行vmwrite并检查是否发生VMfail错误
// 所有VMCS字段的写入都应使用此宏，确保写入成功
#define CHECKED_VMWRITE(field, value)                                                              \
    {                                                                                              \
        vmwrite(field, value, &err_inv, &err_val);                                                 \
        CHECK_VMFAIL("CHECKED_VMWRITE");                                                           \
    }

// 验证VMX控制字段配置是否与CPU支持的MSR掩码兼容
// MSR的低32位为必须置1的位（must-be-1），高32位为允许置1的位（may-be-1）
// 如果配置中有必须置1但未置1的位，或置了不允许置1的位，则返回错误
static int check_vmx_controls(uint32_t options, uint32_t msr)
{
    uint64_t msr_value = rdmsr64(msr);
    uint32_t mask_low = msr_value & 0xFFFFFFFF; // 1 low bits indicate must-one
    uint32_t mask_high = msr_value >> 32;       // zero high bits indicate must-zero

    if ((~options & mask_low) || (options & ~mask_high)) {
        PRINT_ERR("VMX MSR 0x%x: bits not supported (value 0x%x, mask l-0x%x h-0x%x)\n", msr,
                  options, mask_low, mask_high);
        return -1;
    }

    return 0;
}

// VMWRITE_GUEST_SEGMENT宏：一次性写入客户机段寄存器的四个VMCS字段
// 包括选择子(selector)、基址(base)、界限(limit)和访问权限(ar)
#define VMWRITE_GUEST_SEGMENT(segment, selector, base, limit, ar)                                  \
    {                                                                                              \
        CHECKED_VMWRITE(GUEST_##segment##_SELECTOR, selector);                                     \
        CHECKED_VMWRITE(GUEST_##segment##_BASE, base);                                             \
        CHECKED_VMWRITE(GUEST_##segment##_LIMIT, limit);                                           \
        CHECKED_VMWRITE(GUEST_##segment##_AR_BYTES, ar);                                           \
    }

// =================================================================================================
// VMX管理接口（暴露给executor其余部分的函数）
// =================================================================================================

// 检查目标CPU是否与VMX管理实现兼容
// 验证：VMX支持、控制寄存器要求(CR0.PE/PG, CR4.PAE, EFER.LME/LMA)、
// True Controls可用性、引脚/处理器/退出/进入控制位的必须清零位是否满足要求
int vmx_check_cpu_compatibility(void)
{
    uint64_t msr_value = 0;

    // Check if VMX is supported
    ASSERT_MSG(cpu_has(cpuinfo, X86_FEATURE_VMX), "vmx_check_cpu_compatibility",
               "VMX is not supported on this CPU");

    // Control registers
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    uint64_t efer = rdmsr64(MSR_EFER);
    ASSERT((cr0 & X86_CR0_PE) != 0, "set_vmcs_guest_state");
    ASSERT((cr0 & X86_CR0_PG) != 0, "set_vmcs_guest_state");
    ASSERT((cr4 & X86_CR4_PAE) != 0, "set_vmcs_guest_state");
    ASSERT((efer & EFER_LME) != 0, "set_vmcs_guest_state");
    ASSERT((efer & EFER_LMA) != 0, "set_vmcs_guest_state");

    // True controls are usable
    msr_value = rdmsr64(MSR_IA32_VMX_BASIC);
    ASSERT((msr_value & VMX_BASIC_TRUE_CTLS) != 0, "vmx_check_cpu_compatibility");

    // Pin-based controls
    supported_vmcs_pin_ctrl = rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    ASSERT((supported_vmcs_pin_ctrl & MUST_CLEAR_PIN_BASED_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Primary processor-based controls
    supported_vmcs_primary_ctrl = rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    ASSERT((supported_vmcs_primary_ctrl & MUST_CLEAR_PRIMARY_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Secondary
    supported_vmcs_secondary_ctrl = rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
    ASSERT((supported_vmcs_secondary_ctrl & MUST_CLEAR_SECONDARY_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Exit/entry
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_EXIT_CTLS);
    ASSERT((msr_value & MUST_CLEAR_EXIT_CTRL) == 0, "vmx_check_cpu_compatibility");
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    ASSERT((msr_value & MUST_CLEAR_ENTRY_CTRL) == 0, "vmx_check_cpu_compatibility");

    return 0;
}

// 启用VMX操作并执行VMXON进入VMX根模式
// 流程：保存原始VMXON状态 → 检查CR0/CR4限制 → 配置IA32_FEATURE_CONTROL MSR
//       → 初始化VMXON区域(写入修订ID) → 执行VMXON指令
int start_vmx_operation(void)
{
    uint8_t err_inv = 0, err_val = 0;

    orig_vmxon_state = ((orig_special_registers_state->cr4 & X86_CR4_VMXE) != 0);
    unsigned long cr4 = __read_cr4();
    unsigned long cr0 = read_cr0();

    if (!orig_vmxon_state) {
        // Note: registers are already configured in special_registers.c:set_msrs_for_vmx

        // Check SDM 24.8 "restrictions on VMX operation" and 24.7 "Enabling and entering VMX"
        ASSERT(((cr0 & rdmsr64(MSR_IA32_VMX_CR0_FIXED1)) | rdmsr64(MSR_IA32_VMX_CR0_FIXED0)) == cr0,
               "start_vmx_operation");
        ASSERT((cr4 | X86_CR4_VMXE) == cr4, "start_vmx_operation");

        // Configure IA32_FEATURE_CONTROL MSR to allow VMXON
        //   Bit 0: Lock bit. If clear, VMXON causes a #GP.
        //   Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
        //          outside of SMX causes a #GP.
        uint64_t feature_control = rdmsr64(MSR_FEATURE_CONTROL);
        uint64_t required = FEATURE_VMX_ENABLED_OUTSIDE_SMX | FEATURE_CTL_LOCKED;
        if ((feature_control & required) != required)
            wrmsr64(MSR_FEATURE_CONTROL, feature_control | required);

        // Prepare VMXON region:
        // (source: SDM, 25.11.5 VMXON Region)
        // - Write the revision identifier into bits 30:0, and clear bit 31
        memset(vmxon_page_hva, 0, VMXON_SIZE);
        ((vmxon_region_t *)vmxon_page_hva)->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        ((vmxon_region_t *)vmxon_page_hva)->reserved_31 = 0;

        // Run VMXON
        vmxon(vmxon_page_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("vmx_start_operation");
    }

    vmx_is_on = true;
    return 0;
}

// 禁用VMX操作并执行VMXOFF退出VMX根模式
// 在VMXOFF之前先执行INVEPT刷新EPT TLB，防止残留的EPT转换导致问题
// 此函数可在异常处理程序中使用，因此不会失败，仅在出错时打印警告
void stop_vmx_operation(void)
{
    // PRINT_ERR("Stopping VMX operation\n");
    uint8_t err_inv = 0, err_val = 0;

    // Run VMXOFF
    if (vmx_is_on && !orig_vmxon_state) {
        // Flush all EPT TLB entries before vmxoff to ensure no stale EPT translations remain
        uint64_t invept_desc[2] = {0, 0};
        asm volatile("invept %0, %1" : : "m"(invept_desc), "r"(2ULL) : "cc", "memory");

        vmxoff(&err_inv, &err_val);
        orig_vmxon_state = false;
    }

    vmx_is_on = false;
    if (err_inv || err_val)
        PRINT_ERRS("stop_vmx_operation", "Exited with VMfailInvalid=%d, VMfailValid=%d\n", err_inv,
                   err_val);
}

// 保存原始VMCS状态（状态保存机制）
// 如果在fuzzer启动前VMX已在运行（如Hyper-V），使用vmptrst保存当前VMCS指针
// 以便fuzzer退出时能恢复原有状态，不影响宿主机的虚拟化环境
int store_orig_vmcs_state(void)
{
    if (!orig_vmxon_state)
        return 0; // VMX was not in use when we started; nothing to store

    uint8_t err_inv = 0, err_val = 0;
    vmptrst(&orig_vmcs_ptr, &err_inv, &err_val);
    CHECK_VMFAIL("store_orig_vmcs_state");
    return 0;
}

// 恢复原始VMCS状态（状态恢复机制）
// 使用vmptrld重新加载之前保存的VMCS指针，恢复宿主机原有的虚拟化状态
// 此函数可在异常处理程序中使用，仅在出错时打印警告
void restore_orig_vmcs_state(void)
{
    uint8_t err_inv = 0, err_val = 0;
    if (!orig_vmxon_state || orig_vmcs_ptr == 0xFFFFFFFFFFFFFFFF)
        return;

    if (!vmx_is_on) {
        PRINT_ERR("ERROR: attempting to restore VMX state while VMX is not on\n");
        return;
    }

    if (!orig_vmcs_ptr) {
        PRINT_ERR("ERROR: attempting to restore VMX state but no state was stored\n");
        return;
    }

    vmptrld(orig_vmcs_ptr, &err_inv, &err_val);
    if (err_inv || err_val)
        PRINT_ERRS("restore_orig_vmcs_state", "Exited with VMfailInvalid=%d, VMfailValid=%d\n",
                   err_inv, err_val);
}

// 为所有guest actor配置VMCS状态——VM Actor Configuration的核心入口
// 流程：为每个guest actor分配/初始化VMCS → vmclear+vmptrld加载 → 依次设置六大VMCS区域
int set_vmcs_state(void)
{
    int err = 0;
    uint8_t err_inv = 0, err_val = 0;

    // if necessary, allocate additional memory for VMCSs
    ASSERT(n_actors <= MAX_ACTORS, "set_vmcs_state:n_actors exceeds MAX_ACTORS");
    static unsigned old_n_actors = 0;
    if (n_actors > old_n_actors) {
        SAFE_VFREE(vmcss);
        vmcss = CHECKED_VMALLOC(n_actors * VMCS_SIZE);
    }
    old_n_actors = n_actors;

    // 为所有guest actor初始化VMCS
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // 跳过非guest actor（host actor不需要VMCS）
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        vmcs_t *vmcs_hva = &vmcss[actor_id];
        uint64_t vmcs_hpa = vmalloc_to_phys(vmcs_hva);
        ASSERT(vmcs_hpa != 0, "set_vmcs_state:vmalloc_to_phys");
        vmcs_hpas[actor_id] = vmcs_hpa;

        // 初始化VMCS修订标识符——VMCS首4字节必须与MSR_IA32_VMX_BASIC中的修订ID匹配
        memset(vmcs_hva, 0, VMCS_SIZE);
        vmcs_hva->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        vmcs_hva->abort_indicator = 0;

        // 加载VMCS：先vmclear确保VMCS处于clear状态，再vmptrld使其成为当前VMCS
        vmclear(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmclear");

        vmptrld(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmptrld");

        // 设置VMCS六大区域（按照Intel SDM规定的顺序）
        // 1. 客户机状态区域(Guest-State Area)：CR0/CR3/CR4、段寄存器、RSP/RIP/RFLAGS等
        err = set_vmcs_guest_state();
        CHECK_ERR("set_vmcs_guest_state");

        // 2. 宿主机状态区域(Host-State Area)：VM退出后恢复的宿主机状态
        err = set_vmcs_host_state();
        CHECK_ERR("set_vmcs_host_state");

        // 3. VM执行控制区域(VM-Execution Controls)：引脚控制、处理器控制、EPT等
        err = set_vmcs_exec_control(actor_id);
        CHECK_ERR("set_vmcs_exec_control");

        // 4. VM退出控制区域(VM-Exit Controls)：控制VM退出时的行为
        err = set_vmcs_exit_control();
        CHECK_ERR("set_vmcs_exit_control");

        // 5. VM进入控制区域(VM-Entry Controls)：控制VM进入时的行为
        err = set_vmcs_entry_control();
        CHECK_ERR("set_vmcs_entry_control");

        // 6. 执行VMLAUNCH完成首次VM进入/退出，验证VMCS配置的正确性
        err = make_vmcs_launched(actor_id);
        CHECK_ERR("set_vmcs_state:make_vmcs_launched");
    }

    return 0;
}

// ==============================================================================
// set_vmcs_guest_state：设置客户机状态区域(Guest-State Area)
// 
// 这是VMCS配置中最关键的函数之一，定义了guest actor在VM进入后看到的完整CPU状态。
// 包括：
// - 控制寄存器：CR0(含PE/PG等保护模式位)、CR3(客户机页表基址)、CR4(含PAE等)
// - 调试寄存器：DR7
// - 核心寄存器：RSP(指向客户机栈)、RIP(指向VMLAUNCH入口页)、RFLAGS(仅固定位)
// - 段寄存器：CS/SS/DS/ES/FS/GS/LDTR/TR(选择子、基址、界限、访问权限)
//   注意：DS/ES/FS/GS/LDTR设置为不可访问(属性0x10000)，客户机访问会触发VM退出
// - GDTR/IDTR：GDTR指向客户机GDT，IDTR设为空(中断使用会导致VM退出)
// - MSR：SYSENTER相关寄存器
// - 非寄存器状态：活动状态=Active、中断屏蔽=block NMI、VMCS链接指针=-1
// ==============================================================================
static int set_vmcs_guest_state(void)
{
    uint8_t err_inv = 0, err_val = 0;
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    // ---- 控制寄存器 ----
    // CR0：保留宿主机的PE/PG位，同时设置VMX guest要求的必须置1/清0位
    // CR3：指向客户机物理内存中的页表L4层(GUEST_P_MEMORY_START)
    // CR4：保留宿主机的PAE等位，同时设置VMX guest要求的必须置1/清0位
    uint64_t cr0 = (read_cr0() | MUST_SET_BITS_CR0_VMX_GUEST) & ~MUST_CLEAR_BITS_CR0_VMX_GUEST;
    uint64_t cr4 = (__read_cr4() | MUST_SET_BITS_CR4_VMX_GUEST) & ~MUST_CLEAR_BITS_CR4_VMX_GUEST;
    CHECKED_VMWRITE(GUEST_CR0, cr0);
    CHECKED_VMWRITE(GUEST_CR3, (uint64_t)&guest_p_memory->guest_page_tables.l4[0]);
    CHECKED_VMWRITE(GUEST_CR4, cr4);

    // ---- 调试寄存器 ----
    // DR7设为0x400，禁用调试断点但允许单步调试功能
    CHECKED_VMWRITE(GUEST_DR7, 0x400);

    // ---- 核心寄存器：RSP、RIP、RFLAGS ----
    // RSP：指向客户机虚拟内存中的栈区域（用于guest actor的局部变量存储）
    // RIP：指向vmlaunch_page（VMLAUNCH时的入口点，不是真正的代码入口）
    // RFLAGS：仅设置固定位(EFLAGS_FIXED=0x2)，其他标志位清零
    // (see also make_vmcs_launched)
    CHECKED_VMWRITE(GUEST_RSP, (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_RIP, (uint64_t)&guest_v_memory->vmlaunch_page[0]);
    CHECKED_VMWRITE(GUEST_RFLAGS, (X86_EFLAGS_FIXED));

    // ---- 段寄存器 ----
    // CS: 代码段，选择子0x10，实模式风格(属性0xa09B: 存在/读写/16位)
    // SS: 栈段，选择子0x20，属性0xc093: 存在/读写/32位/粒度4KB
    // DS/ES/FS/GS: 数据段，选择子0，属性0x10000表示不可用(客户机访问会触发#GP或VM退出)
    // LDTR: 局部描述符表，属性0x10000不可用
    // TR: 任务寄存器，属性0x8b: 32位TSS/存在/忙
    VMWRITE_GUEST_SEGMENT(CS, 0x10, 0, 0xFFFF, 0xa09B);
    VMWRITE_GUEST_SEGMENT(SS, 0x20, 0, 0xFFFF, 0xc093);
    VMWRITE_GUEST_SEGMENT(DS, 0, 0, 0xFFFF, 0x10000); // 0xc093
    VMWRITE_GUEST_SEGMENT(ES, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(FS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(GS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(LDTR, 0, 0, 0xFFFF, 0x10000); // 0xc082);
    VMWRITE_GUEST_SEGMENT(TR, 0, 0, 0xFFFF, 0x8b);

    // ---- GDTR和IDTR ----
    // GDTR指向客户机虚拟内存中的GDT表，IDTR基址设为0
    // IDTR的界限设为0xFFFF，但基址为0意味着客户机使用中断会触发VM退出
    CHECKED_VMWRITE(GUEST_GDTR_BASE, (uint64_t)&guest_v_memory->gdt);
    CHECKED_VMWRITE(GUEST_GDTR_LIMIT, 0xFFFF);
    CHECKED_VMWRITE(GUEST_IDTR_BASE, 0);
    CHECKED_VMWRITE(GUEST_IDTR_LIMIT, 0xFFFF);

    // ---- MSR ----
    // SYSENTER_CS/ESP/EIP：配置SYSENTER/SYSEXIT指令的入口，指向客户机代码段和栈
    CHECKED_VMWRITE(GUEST_IA32_DEBUGCTL, 0);
    CHECKED_VMWRITE(GUEST_SYSENTER_CS, 0x10);
    CHECKED_VMWRITE(GUEST_SYSENTER_ESP,
                    (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_SYSENTER_EIP, (uint64_t)&guest_v_memory->code.section[0]);

    // ---- 验证VM进入控制中的必须清零位 ----
    // 确认PERF_GLOBAL_CTRL、PAT、EFER的加载位在进入控制中是必须清零的
    // 这意味着我们不需要在VM进入时加载这些MSR
    ASSERT((VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL & MUST_CLEAR_ENTRY_CTRL) != 0,
           "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_PAT & MUST_CLEAR_ENTRY_CTRL) != 0, "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_EFER & MUST_CLEAR_ENTRY_CTRL) != 0, "set_vmcs_guest_state");

    // ---- 客户机非寄存器状态 (SDM 25.4.2) ----
    // 活动状态=0(Active)：客户机处于正常活动状态
    // 中断屏蔽信息=0b1000：屏蔽NMI（防止VMLAUNCH期间NMI干扰）
    // VMCS链接指针=-1：不使用SMM双重监控处理
    // VMX抢占定时器=0xFFFF：设置超时值，防止guest无限运行
    CHECKED_VMWRITE(GUEST_ACTIVITY_STATE, 0);
    CHECKED_VMWRITE(GUEST_INTERRUPTIBILITY_INFO, 0b1000); // block NMI
    CHECKED_VMWRITE(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    CHECKED_VMWRITE(VMCS_LINK_POINTER, -1LL);
    CHECKED_VMWRITE(VMX_PREEMPTION_TIMER_VALUE, 0xFFFF); // FIXME: make configurable

    return 0;
}

// ==============================================================================
// set_vmcs_host_state：设置宿主机状态区域(Host-State Area)
// 
// 定义了VM退出后宿主机CPU需要恢复的状态。VM退出时，CPU从guest状态切换回host状态，
// 这些字段决定了宿主机恢复运行时的寄存器值。关键设计：
// - 控制寄存器直接使用宿主机当前值，确保VM退出后能正常运行
// - HOST_RIP和HOST_RSP在make_vmcs_launched中动态设置（必须在汇编中设置以捕获正确地址）
// - GDTR使用宿主机当前的GDT，IDTR使用test_case_idtr（自定义中断描述符表）
// - 段选择子使用内核常量(__KERNEL_CS/__KERNEL_DS)
// - TR的基址需要从GDT中手动解码（因为STR指令只返回选择子，不返回基址）
// ==============================================================================
static int set_vmcs_host_state(void)
{
    uint8_t err_inv = 0, err_val = 0;

    // 获取TR/GDTR/IDTR/LDTR的当前值——这些信息在后续宿主机状态设置中会用到
    // 特别注意：TR的基址需要从GDT中手动解析，因为x86只提供STR(读选择子)指令
    uint64_t tr = 0, ldtr = 0;
    struct desc_ptr gdtr, idtr;
    asm volatile("str %[tr]\n"
                 "sgdt %[gdtr]\n"
                 "sidt %[idtr]\n"
                 "sldt %[ldtr]\n"
                 : [tr] "=r"(tr), [gdtr] "=m"(gdtr), [idtr] "=m"(idtr), [ldtr] "=r"(ldtr)
                 :
                 : "memory");
    // 从GDT中解码TR的基址——GDT中的TSS描述符包含base0/base1/base2/base3四个字段
    // 需要将它们拼合为完整的64位基址
    struct ldttss_desc *tr_register = (struct ldttss_desc *)(gdtr.address + tr);
    uint64_t tr_base = ((uint64_t)tr_register->base0 | ((tr_register->base1) << 16) |
                        ((tr_register->base2) << 24) | ((uint64_t)tr_register->base3 << 32));

    // ---- 宿主机控制寄存器 ----
    // 直接使用宿主机当前值，VM退出后恢复到与VM进入前相同的控制寄存器状态
    CHECKED_VMWRITE(HOST_CR0, read_cr0());
    CHECKED_VMWRITE(HOST_CR3, __read_cr3());
    CHECKED_VMWRITE(HOST_CR4, __read_cr4());

    // ---- RSP和RIP ----
    // 在此处不设置（将在make_vmcs_launched中动态设置）
    // 因为HOST_RIP必须指向VMLAUNCH后的返回点，HOST_RSP指向宿主机栈顶

    // ---- 段选择子 ----
    // CS使用内核代码段(__KERNEL_CS)，SS使用内核数据段(__KERNEL_DS)
    // DS/ES/FS/GS设为0（在64位模式下，数据段选择子通常为0）
    // TR使用当前任务寄存器选择子
    CHECKED_VMWRITE(HOST_CS_SELECTOR, __KERNEL_CS);
    CHECKED_VMWRITE(HOST_SS_SELECTOR, __KERNEL_DS);
    CHECKED_VMWRITE(HOST_DS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_ES_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_FS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_GS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_TR_SELECTOR, tr);

    // ---- 段基址 ----
    // FS/GS基址从MSR读取（内核使用FS/GS基址存储per-CPU数据等）
    // TR基址使用前面从GDT解码出的值
    // GDTR基址使用宿主机当前的GDT地址
    // IDTR基址使用test_case_idtr（自定义的IDT，用于fuzzer的故障处理）
    CHECKED_VMWRITE(HOST_FS_BASE, rdmsr64(MSR_FS_BASE));
    CHECKED_VMWRITE(HOST_GS_BASE, rdmsr64(MSR_GS_BASE));
    CHECKED_VMWRITE(HOST_TR_BASE, tr_base);
    CHECKED_VMWRITE(HOST_GDTR_BASE, gdtr.address);
    CHECKED_VMWRITE(HOST_IDTR_BASE, test_case_idtr.address);

    // ---- MSR ----
    // SYSENTER相关MSR从宿主机读取，EFER从宿主机MSR读取
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));
    CHECKED_VMWRITE(HOST_IA32_EFER, rdmsr64(MSR_EFER));

    ASSERT((VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL & MUST_CLEAR_EXIT_CTRL) != 0, "set_vmcs_host_state");
    ASSERT((VM_EXIT_LOAD_IA32_PAT & MUST_CLEAR_EXIT_CTRL) != 0, "set_vmcs_host_state");
    return 0;
}

// ==============================================================================
// set_vmcs_exec_control：配置VM执行控制区域(VM-Execution Controls)
// 
// 这是VMCS配置中最复杂的部分，决定了guest运行时哪些事件会触发VM退出。
// 论文中VM Actor的设计理念是：guest actor应尽可能自由地执行代码，仅在特定事件时退出。
// 配置包括：
// - 引脚控制(25.6.1)：外部中断/NMI等事件的处理
// - 主处理器控制(25.6.2)：TSC偏移/MSR位图/IO位图等核心执行控制
// - 次处理器控制(25.6.2)：EPT/VPID/ENCLS退出等高级特性
// - 异常位图(25.6.3)：哪些异常触发VM退出（DEFAULT_EXCEPTION_BITMAP）
// - CR0/CR4掩码(25.6.6)：客户机对控制寄存器的访问控制
// - EPT指针(25.6.11)：嵌套页表(EPT/NPT)的物理地址，每个actor独立的地址空间
// ==============================================================================
static int set_vmcs_exec_control(int actor_id)
{
    // int err = 0;
    uint8_t err_inv = 0, err_val = 0;

    // ---- 引脚控制(25.6.1) ----
    // 设置必须置1的位，其余位取MSR允许置1的位（通常不设置额外位）
    // 引脚控制主要处理外部中断、NMI和虚拟NMI的行为
    uint32_t pin_based_vm_exec_control = MUST_SET_PIN_BASED_VM_EXEC_CONTROL |
                                         (rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(pin_based_vm_exec_control, MSR_IA32_VMX_TRUE_PINBASED_CTLS))
        return -1;
    CHECKED_VMWRITE(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control);

    // ---- 主处理器控制(25.6.2) ----
    // 设置必须置1的位（如CR3加载/存储、INVEPT等），其余取MSR允许的位
    // - primary
    uint32_t primary_vm_exec_control = MUST_SET_PRIMARY_VM_EXEC_CONTROL |
                                       (rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(primary_vm_exec_control, MSR_IA32_VMX_TRUE_PROCBASED_CTLS))
        return -1;
    CHECKED_VMWRITE(CPU_BASED_VM_EXEC_CONTROL, primary_vm_exec_control);

    // ---- 次处理器控制(25.6.2) ----
    // 次处理器控制启用EPT(Extended Page Table)等高级特性
    // EPT是实现guest独立地址空间的关键——每个actor有自己的嵌套页表
    uint32_t secondary_vm_exec_control = MUST_SET_SECONDARY_VM_EXEC_CONTROL |
                                         (rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS2) & 0xFFFFFFFFULL);
    if (check_vmx_controls(secondary_vm_exec_control, MSR_IA32_VMX_PROCBASED_CTLS2))
        return -1;
    CHECKED_VMWRITE(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control);

    // ---- 异常位图(25.6.3) ----
    // 设置哪些CPU异常会触发VM退出；DEFAULT_EXCEPTION_BITMAP定义了fuzzer需要拦截的异常
    CHECKED_VMWRITE(EXCEPTION_BITMAP, DEFAULT_EXCEPTION_BITMAP);

    // SDM 25.6.4 I/O-Bitmap Addresses
    ASSERT((CPU_BASED_USE_IO_BITMAPS & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.5 Time-Stamp Counter Offset and Multiplier
    ASSERT((CPU_BASED_USE_TSC_OFFSETTING & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // ---- CR0/CR4客户机/宿主机掩码(25.6.6) ----
    // 宿主机掩码：哪些位由宿主机控制（客户机试图修改被掩码的位会触发VM退出）
    // 读影子寄存器：客户机读取被掩码的位时，返回影子值而非真实值
    // 这里将宿主机当前值设为掩码，意味着guest对CR0/CR4的任何修改都会触发VM退出
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    CHECKED_VMWRITE(CR0_GUEST_HOST_MASK, cr0);
    CHECKED_VMWRITE(CR4_GUEST_HOST_MASK, cr4);
    CHECKED_VMWRITE(CR0_READ_SHADOW, cr0);
    CHECKED_VMWRITE(CR4_READ_SHADOW, cr4);

    // SDM 25.6.7 CR3-Target Controls
    CHECKED_VMWRITE(CR3_TARGET_COUNT, 0);

    // SDM 25.6.8 Controls for APIC Virtualization
    ASSERT((SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES & secondary_vm_exec_control) == 0,
           "set_vmcs_exec_control");

    // SDM 25.6.9 MSR-Bitmap Address
    ASSERT((CPU_BASED_USE_MSR_BITMAPS & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.10 Executive-VMCS Pointer
    // (no idea, leaving it blank for the time being)

    // ---- EPT指针(25.6.11) ----
    // 这是论文Section 5.2的核心——嵌套页表(NPT/EPT)指针
    // 每个guest actor使用独立的EPT，实现actor间的地址空间隔离
    // EPT将客户机物理地址映射到真实物理地址，是侧信道模糊化的基础
    CHECKED_VMWRITE(EPT_POINTER, ((uint64_t *)ept_ptr)[actor_id]);

    // SDM 25.6.12 Virtual-Processor Identifier (VPID)
    ASSERT((SECONDARY_EXEC_ENABLE_VPID & secondary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.13 Controls for PAUSE-Loop Exiting
    // not implemented

    // SDM 25.6.14 VM-Functions
    ASSERT((SECONDARY_EXEC_ENABLE_VMFUNC & secondary_vm_exec_control) == 0,
           "set_vmcs_exec_control");

    // SDM 25.6.15 VMCS Shadowing Bitmap Addresses
    ASSERT((SECONDARY_EXEC_SHADOW_VMCS & secondary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // ---- ENCLS退出位图(25.6.16) ----
    // Intel SGX的ENCLS指令拦截——如果CPU支持此特性，拦截所有SGX相关指令
    // 防止guest actor干扰SGX安全机制
    if (supported_vmcs_secondary_ctrl & SECONDARY_EXEC_ENCLS_EXITING) {
        ASSERT((SECONDARY_EXEC_ENCLS_EXITING & secondary_vm_exec_control) != 0,
               "set_vmcs_exec_control");
        CHECKED_VMWRITE(ENCLS_EXITING_BITMAP, 0x0FFFFFFFFFFFFFFFULL);
    }

    // Misc. features (25.6.14--23) are disabled
    return 0;
}

// ==============================================================================
// set_vmcs_exit_control：配置VM退出控制(VM-Exit Controls)
// 
// 定义了VM退出时的行为：加载哪些宿主机MSR、保存哪些客户机MSR等。
// 这里配置了MUST_SET_EXIT_CTRL中的必须置1位（如主机地址空间大小、加载IA32_EFER等）
// 以及MSR允许的额外位。MSR存储/加载计数设为0，表示不需要在VM退出时自动处理MSR。
// ==============================================================================
static int set_vmcs_exit_control(void)
{
    uint8_t err_inv = 0, err_val = 0;

    uint64_t exit_ctls =
        MUST_SET_EXIT_CTRL | (rdmsr64(MSR_IA32_VMX_TRUE_EXIT_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(exit_ctls, MSR_IA32_VMX_TRUE_EXIT_CTLS))
        return -1;
    CHECKED_VMWRITE(VM_EXIT_CONTROLS, exit_ctls);

    // SDM 25.7.2 VM-Exit Controls for MSRs
    CHECKED_VMWRITE(VM_EXIT_MSR_STORE_COUNT, 0);
    CHECKED_VMWRITE(VM_EXIT_MSR_LOAD_COUNT, 0);
    return 0;
}

// ==============================================================================
// set_vmcs_entry_control：配置VM进入控制(VM-Entry Controls)
// 
// 定义了VM进入(guest恢复执行)时的行为：加载哪些客户机MSR、是否注入事件等。
// 这里配置了MUST_SET_ENTRY_CTRL中的必须置1位（如IA32e模式guest等）
// MSR加载计数设为0，事件注入字段设为0（不注入任何中断/异常）。
// ==============================================================================
static int set_vmcs_entry_control(void)
{
    uint8_t err_inv = 0, err_val = 0;

    uint64_t entry_ctls =
        MUST_SET_ENTRY_CTRL | (rdmsr64(MSR_IA32_VMX_TRUE_ENTRY_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(entry_ctls, MSR_IA32_VMX_TRUE_ENTRY_CTLS))
        return -1;
    CHECKED_VMWRITE(VM_ENTRY_CONTROLS, entry_ctls);

    // SDM 25.8.2 VM-Entry Controls for MSRs
    CHECKED_VMWRITE(VM_ENTRY_MSR_LOAD_COUNT, 0);

    // SDM 25.8.3 VM-Entry Controls for Event Injection
    CHECKED_VMWRITE(VM_ENTRY_INTR_INFO_FIELD, 0);

    return 0;
}

// ==============================================================================
// make_vmcs_launched：执行VMLAUNCH完成首次VM进入/退出
// 
// 这是VMCS初始化的最后一步，也是最关键的一步。流程如下：
// 1. 加载VMCS（vmptrld）
// 2. 在内联汇编中动态设置HOST_RIP和HOST_RSP（必须用汇编设置，因为需要捕获
//    VMLAUNCH后的精确返回地址和栈指针，C语言无法做到这一点）
// 3. 执行VMLAUNCH指令：
//    - 如果成功，CPU进入guest模式，执行vmlaunch_page中的代码
//    - guest执行VMCALL或定时器超时后，VM退出，CPU跳转到HOST_RIP
//    - 如果失败，setc/setz捕获错误标志
// 4. 检查VMLAUNCH结果：错误信息、中止指示器、退出原因
// 5. 更新VMCS字段：
//    - GUEST_RIP改为真正的代码入口(code.section[0])而非vmlaunch_page
//    - GUEST_RSP改为正常的栈指针
//    - HOST_RIP改为fault_handler（后续VM退出都由故障处理程序接管）
//    - HOST_RSP改为sandbox的栈区域
// ==============================================================================
static int make_vmcs_launched(int actor_id)
{
    uint8_t err_inv = 0, err_val = 0;

    // 1. Load VMCS
    uint64_t vmcs_hpa = vmcs_hpas[actor_id];
    vmptrld(vmcs_hpa, &err_inv, &err_val);
    CHECK_VMFAIL("make_vmcs_launched:vmptrld");

    // ---- 步骤2：执行VMLAUNCH ----
    //
    // 关键设计说明：
    // - HOST_RIP必须在汇编中设置：lea 1f(%%rip)获取VMLAUNCH失败后的返回地址，
    //   并通过vmwrite写入HOST_RIP字段。VMLAUNCH成功时此地址不会立即使用，
    //   但VM退出时CPU会跳转到此地址。
    // - HOST_RSP必须在汇编中设置：mov %%rsp获取当前栈指针，确保VM退出后有正确的宿主机栈。
    // - VMLAUNCH成功：CPU进入guest模式，setc/setz指令被跳过，VM退出时返回到"1:"标签
    //   且err_inv=0, err_val=0
    // - VMLAUNCH失败：setc/setz执行，设置错误标志，直接跳到"1:"标签处理错误
    // - clobber列表包含所有caller-saved寄存器，因为VM退出后guest可能修改了这些寄存器
    asm volatile(""
                 "xor %[inval], %[inval]\n"
                 "xor %[val], %[val]\n"
                 "lea 1f(%%rip), %%rax\n"
                 "mov %[host_rip], %%rcx\n"
                 "vmwrite %%rax, %%rcx\n"
                 "mov %%rsp, %%rax\n"
                 "mov %[host_rsp], %%rcx\n"
                 "vmwrite %%rax, %%rcx\n"
                 "vmlaunch\n"
                 "setc %[inval]\n"
                 "setz %[val]\n"
                 "1:\n"
                 : [val] "+rm"(err_val), [inval] "+rm"(err_inv)
                 : [host_rip] "i"((uint64_t)HOST_RIP), [host_rsp] "i"((uint64_t)HOST_RSP)
                 : "cc", "memory", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");

    // ---- 步骤3：检查VMLAUNCH是否失败 ----
    // 如果VMLAUNCH失败，打印详细的错误信息（VM指令错误码、中止指示器）
    if (err_inv || err_val) {
        print_vmlaunch_error_info(err_inv, err_val, actor_id);
    }
    CHECK_VMFAIL("make_vmcs_launched:vmlaunch");

    // ---- 步骤4：验证VM进入是否成功 ----
    // 检查VMCS中止指示器（非零表示发生了VMX中止）
    // 读取VM退出原因，预期是VMCALL（guest主动退出）或抢占定时器超时
    ASSERT(vmcss[actor_id].abort_indicator == 0, "make_vmcs_launched:abort_indicator");
    uint64_t exit_reason = 0;
    vmread(VM_EXIT_REASON, &exit_reason, &err_inv, &err_val);
    CHECK_VMFAIL("make_vmcs_launched:VM_EXIT_REASON");
    // Expected exit reasons after initial vmlaunch: VMCALL (guest code) or timeout
    ASSERT((exit_reason == EXIT_REASON_VMCALL || exit_reason == EXIT_REASON_PREEMPTION_TIMER),
           "make_vmcs_launched:unexpected exit reason");

    // ---- 步骤5：更新VMCS字段，为后续VMRESUME做准备 ----
    // GUEST_RIP改为真正的代码入口(code.section[0])——这是fuzzer测试用例的起始地址
    // GUEST_RSP改为正常的栈指针
    // HOST_RIP改为fault_handler——后续所有VM退出都由故障处理程序接管
    // HOST_RSP改为sandbox栈区域——宿主机使用独立的栈空间处理VM退出
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    CHECKED_VMWRITE(GUEST_RIP, (uint64_t)&guest_v_memory->code.section[0]);
    CHECKED_VMWRITE(GUEST_RSP, (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(HOST_RIP, (uint64_t)fault_handler);
    CHECKED_VMWRITE(HOST_RSP, (uint64_t)&sandbox->data[0].main_area[LOCAL_RSP_OFFSET]);

    return 0;
}

// 打印VMLAUNCH失败的详细错误信息：VMfailInvalid/VMfailValid标志、
// VM指令错误码及其解码字符串、VMCS中止指示器
static void print_vmlaunch_error_info(int err_inv, int err_val, int actor_id)
{
    PRINT_ERR("vmlaunch failed: VMfailInvalid=%d, VMfailValid=%d\n", err_inv, err_val);
    if (err_val) {
        uint64_t instr_error = 0;
        uint8_t tmp_inv = 0, tmp_val = 0;
        vmread(VM_INSTRUCTION_ERROR, &instr_error, &tmp_inv, &tmp_val);
        PRINT_ERR("VM_INSTRUCTION_ERROR: %llu\n", instr_error);
        if (instr_error > 0 && instr_error < 26)
            PRINT_ERR("  decoded: %s\n", vmx_instruction_error_to_str[instr_error]);
    }
    PRINT_ERR("VMCS abort indicator: %d\n", vmcss[actor_id].abort_indicator);
}

// ==============================================================================
// print_vmx_exit_info：打印VM退出事件的详细信息
// 用于调试和错误诊断，包括：
// - 每个actor的VMCS中止指示器
// - VM退出原因（从退出原因码解码为字符串）
// - 退出资格(Exit Qualification)、客户机线性地址、客户机物理地址
// - VM退出中断信息、IDT向量化信息
// - VM退出指令长度和指令信息
// - VM指令错误码及其解码
// ==============================================================================
int print_vmx_exit_info(void)
{
    uint8_t err_inv = 0, err_val = 0;
    uint64_t value = 0;

    // Abort reasons
    PRINT_ERR("VMX Abort indicators:\n");
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        if (actors[actor_id].mode == MODE_GUEST)
            PRINT_ERR("  actor 0x%x: %d\n", actor_id, vmcss[actor_id].abort_indicator);
    }

    // VM exit reason
    PRINT_ERR("VMXC exit info:\n");
    vmread(VM_EXIT_REASON, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_REASON");
    PRINT_ERR("  VM exit reason: 0x%llx\n", value);
    if (value != 0) {
        uint16_t basic_reason = value & 0xFFFF;
        char *exit_type = NULL;
        if (value & (1ULL << 31))
            exit_type = "entry";
        else
            exit_type = "exit";

        for (int i = 0; vmx_basic_exit_reason_to_str[i].str != NULL; i++) {
            if (basic_reason == vmx_basic_exit_reason_to_str[i].basic_exit_reason) {
                PRINT_ERR("    decoded: %s [%s]\n", vmx_basic_exit_reason_to_str[i].str, exit_type);
                break;
            }
        }
    }

    vmread(EXIT_QUALIFICATION, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:EXIT_QUALIFICATION");
    PRINT_ERR("  Exit qualification: 0x%llx\n", value);

    vmread(GUEST_LINEAR_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_LINEAR_ADDRESS");
    PRINT_ERR("  Guest linear address: 0x%llx\n", value);

    vmread(GUEST_PHYSICAL_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_PHYSICAL_ADDRESS");
    PRINT_ERR("  Guest physical address: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_INFO");
    PRINT_ERR("  VM exit interrupt info: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_ERROR_CODE");
    PRINT_ERR("  VM exit interrupt error code: 0x%llx\n", value);

    vmread(IDT_VECTORING_INFO_FIELD, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_INFO_FIELD");
    PRINT_ERR("  IDT vectoring info field: 0x%llx\n", value);

    vmread(IDT_VECTORING_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_ERROR_CODE");
    PRINT_ERR("  IDT vectoring error code: 0x%llx\n", value);

    vmread(VM_EXIT_INSTRUCTION_LEN, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INSTRUCTION_LEN");
    PRINT_ERR("  VM exit instruction length: 0x%llx\n", value);

    vmread(VMX_INSTRUCTION_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VMX_INSTRUCTION_INFO");
    PRINT_ERR("  VM exit instruction info: 0x%llx\n", value);

    vmread(VM_INSTRUCTION_ERROR, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_INSTRUCTION_ERROR");
    PRINT_ERR("  VM exit instruction error: 0x%llx\n", value);
    if (value > 0 && value < 22)
        PRINT_ERR("    decoded: %s\n", vmx_instruction_error_to_str[value]);

    return 0;
}

// =================================================================================================
// ==============================================================================
// init_vmx：VMX模块初始化
// 
// 在fuzzer启动时调用，分配VMX运行所需的内存：
// 1. 检查VMXON区域大小是否与预定义常量匹配
// 2. 分配VMXON区域（4KB对齐的物理内存，VMXON指令要求）
// 3. 分配VMCS内存和物理地址数组
// ==============================================================================
int init_vmx(void)
{
    int err = 0;

    // check that the hw-specific region sizes match our constants
    size_t vmxon_size = (rdmsr64(MSR_IA32_VMX_BASIC) >> 32) & 0xFFF;
    ASSERT(vmxon_size <= VMXON_SIZE, "init_vmx");

    // VMX host data structures
    vmxon_page_hva = CHECKED_ZALLOC(VMXON_SIZE);
    vmxon_page_hpa = virt_to_phys(vmxon_page_hva);
    ASSERT((vmxon_page_hpa & 0xFFF) == 0, "init_vmx"); // VMXON region must be 4KB-aligned

    // VMCS
    vmcss = CHECKED_VMALLOC(VMCS_SIZE);
    vmcs_hpas = CHECKED_ZALLOC(sizeof(uint64_t) * MAX_ACTORS);

    return err;
}

// ==============================================================================
// free_vmx：释放VMX模块分配的所有内存
// 在fuzzer退出时调用，释放VMXON区域、VMCS区域和物理地址数组
// ==============================================================================
void free_vmx(void)
{
    SAFE_FREE(vmxon_page_hva);
    SAFE_VFREE(vmcss);
    SAFE_FREE(vmcs_hpas);
}

// NOLINTEND(readability-function-cognitive-complexity)
// NOLINTEND(readability-function-size)

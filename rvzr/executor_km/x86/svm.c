/// File: Configuration and use of AMD SVM
///
// ==============================================================================
// SVM模块概述：
// 本文件实现了AMD SVM（Secure Virtual Machine）的完整管理，是论文
// "Enter, Exit, Page Fault, Leak"中AMD平台VM Actor Configuration的核心实现。
//
// 整体架构和初始化流程：
// 1. init_svm()                —— 分配VMCB页面、Host SSA、IOPM和MSRPM
// 2. svm_check_cpu_compatibility() —— 检查CPU是否支持SVM及所需特性
// 3. start_svm_operation()     —— 配置VM_HSAVE_PA MSR，启用SVM操作
// 4. set_vmcb_state()          —— 为每个guest actor初始化VMCB：
//    a. set_vmcb_guest_state() —— 设置客户机保存状态区(CR0/CR3/CR4/EFER、段寄存器、RSP/RIP等)
//    b. set_vmcb_control()     —— 配置VMCB控制区(拦截位、NPT、ASID、IOPM/MSRPM等)
// 5. stop_svm_operation()      —— 恢复原始VM_HSAVE_PA，关闭SVM操作
//
// 与VMX的关键区别：
// - SVM使用VMCB(Virtual Machine Control Block)而非VMCS来管理虚拟机状态
// - SVM的拦截(intercept)机制更直接：通过位图设置哪些操作触发#VMEXIT
// - SVM的嵌套页表称为NPT(Nested Page Table)，通过nested_cr3字段配置
// - SVM使用ASID(Address Space Identifier)而非VPID来区分不同guest的TLB条目
// - SVM的Host SSA(State Save Area)用于保存宿主机状态，对应VMX的Host-State Area
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "fault_handler.h"
#include "hardware_desc.h"
#include "main.h"
#include "page_tables_guest.h"
#include "special_registers.h"
#include "svm.h"
#include "svm_constants.h"

// 全局状态标志，标记SVM是否已启用（EFER.SVME已设置且VM_HSAVE_PA已配置）
bool svm_is_on = false; // global
// 每个actor对应的VMCB物理地址数组，VMRUN指令需要VMCB的物理地址
uint64_t *vmcb_hpas;    // global
// 每个actor对应的VMCB虚拟地址数组，用于直接读写VMCB字段
uint64_t *vmcb_hvas;    // global

// Host状态保存区域(SSA)——SVM在#VMEXIT时将宿主机状态保存到此区域
// 保存原始HSAVE_PA以便fuzzer退出时恢复，防止影响宿主机的SVM环境
static struct page *host_ssa_page = NULL;
static char *host_ssa_hva = NULL;
static uint64_t orig_host_ssa_hpa = 0;

// VMCB页面数组——每个guest actor拥有一个独立的4KB对齐的VMCB页面
static struct page *vmcb_pages = NULL;

// IOPM(I/O Permission Map)——控制guest的I/O端口访问权限
// 大小为4页(16KB)，所有位设为1表示拦截所有I/O端口访问（guest任何IN/OUT都会触发#VMEXIT）
static void *iopm_hva = NULL;
static uint64_t iopm_hpa = 0;

// MSRPM(MSR Permission Map)——控制guest的MSR访问权限
// 大小为2页(8KB)，所有位设为1表示拦截所有MSR读写（guest任何RDMSR/WRMSR都会触发#VMEXIT）
static void *msrpm_hva = NULL;
static uint64_t msrpm_hpa = 0;

static int set_vmcb_guest_state(vmcb_t *vmcb_hva);
static int set_vmcb_control(vmcb_t *vmcb_hva, uint64_t actor_id);

// =================================================================================================
// SVM辅助函数
// =================================================================================================
#define _BITU(x) (1U << (x))

// init_seg：初始化SVM段寄存器结构体
// SVM的段寄存器使用seg_t结构体，包含selector/attrib/limit/base四个字段
// 与VMX不同，SVM直接在VMCB中存储段寄存器的完整信息，无需通过vmwrite逐字段设置
/// @param seg The segment to initialize
inline static void init_seg(seg_t *seg, uint16_t selector, uint64_t base, uint32_t limit,
                            uint16_t attrib)
{
    seg->selector = selector;
    seg->attrib = attrib;
    seg->limit = limit;
    seg->base = base;
}

// init_sys_seg：初始化SVM系统段寄存器(LDTR/TR)
// 系统段的属性只设置存在位(P_MASK)和类型字段，选择子/基址/界限使用默认值
/// @param seg The segment to initialize
/// @param type Segment attributes
static void init_sys_seg(seg_t *seg, uint32_t type)
{
    seg->selector = 0;
    seg->attrib = SVM_SELECTOR_P_MASK | type;
    seg->limit = 0xffff;
    seg->base = 0;
}

// =================================================================================================
// SVM管理接口（暴露给executor其余部分的函数）
// =================================================================================================

// 检查目标CPU是否与SVM管理实现兼容
// 验证：SVM支持、控制寄存器要求(CR0.PE/PG, CR4.PAE, EFER.LME/LMA)、
// SNP未启用（SNP安全虚拟化与fuzzer的设计不兼容）
int svm_check_cpu_compatibility(void)
{
    ASSERT_MSG(cpu_has(cpuinfo, X86_FEATURE_SVM), "svm_check_cpu_compatibility",
               "SVM is not supported on this CPU");

    // Control registers
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    uint64_t efer = rdmsr64(MSR_EFER);
    ASSERT((cr0 & X86_CR0_CD) == 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_NW) == 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_PE) != 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_PG) != 0, "set_vmcb_guest_state");
    ASSERT((cr4 & X86_CR4_PAE) != 0, "set_vmcb_guest_state");
    ASSERT((efer & EFER_LME) != 0, "set_vmcb_guest_state");
    ASSERT((efer & EFER_LMA) != 0, "set_vmcb_guest_state");

    // SNP is not supported
    uint64_t syscfg = rdmsr64(MSR_SYSCFG);
    ASSERT((syscfg & _BITULL(24)) == 0, "set_vmcb_guest_state");

    return 0;
}

// 启用SVM操作——配置Host状态保存区域
// 流程：保存原始VM_HSAVE_PA → 清零新SSA → 设置VM_HSAVE_PA指向新SSA页面
// 注意：EFER.SVME已在special_registers.c中设置，此处只配置HSAVE_PA
int start_svm_operation(void)
{
    // Note that EFER.SVME is already set in special_registers.c

    // Store the original Host State Save Area
    orig_host_ssa_hpa = rdmsr64(MSR_VM_HSAVE_PA);

    // Prepare Host State Save Area
    memset(host_ssa_hva, 0, PAGE_SIZE);
    wrmsr64(MSR_VM_HSAVE_PA, page_to_pfn(host_ssa_page) << PAGE_SHIFT);
    ((uint64_t *)host_ssa_hva)[0] = 0x42;

    svm_is_on = true;

    return 0;
}

// 禁用SVM操作——恢复原始Host状态保存区域（状态恢复机制）
// 将VM_HSAVE_PA恢复为fuzzer启动前的值，确保宿主机SVM环境不受影响
// 此函数可在异常处理程序中使用，不会失败
void stop_svm_operation(void)
{
    // Restore the original Host State Save Area
    wrmsr64(MSR_VM_HSAVE_PA, orig_host_ssa_hpa);

    svm_is_on = false;
}

// 保存原始VMCB状态（状态保存机制）——SVM版本为空操作
// SVM不像VMX有vmptrst/vmptrld这样的VMCS指针管理，因此无需保存/恢复原始VMCB
int store_orig_vmcb_state(void) { return 0; }

// 恢复原始VMCB状态（状态恢复机制）——SVM版本为空操作
void restore_orig_vmcb_state(void) {}

// ==============================================================================
// set_vmcb_state：为所有guest actor配置VMCB状态——SVM VM Actor Configuration的核心入口
// 
// 流程：为每个guest actor分配VMCB页面 → 获取物理/虚拟地址 → memset清零 →
// 设置guest保存状态区 → 设置VMCB控制区
// 与VMX的set_vmcs_state()功能对应，但SVM不需要VMLAUNCH验证步骤
// ==============================================================================
int set_vmcb_state(void)
{
    int err = 0;

    // 为所有guest actor初始化VMCB
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // 跳过非guest actor（host actor不需要VMCB）
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        // 获取VMCB页面的虚拟地址和物理地址
        // SVM要求VMCB物理地址4KB对齐（vmcb_hpas & 0xFFF == 0）
        struct page *vmcb_page = &vmcb_pages[actor_id];
        vmcb_t *vmcb_hva = page_address(vmcb_page);
        vmcb_hvas[actor_id] = (uint64_t)vmcb_hva;
        vmcb_hpas[actor_id] = page_to_pfn(vmcb_page) << PAGE_SHIFT;

        ASSERT(vmcb_hpas[actor_id] != 0, "set_vmcb_state");
        ASSERT((vmcb_hpas[actor_id] & 0xFFF) == 0, "set_vmcb_state");

        // 清零VMCB——SVM不像VMX需要设置修订ID，直接memset即可
        memset(vmcb_hva, 0, VMCB_SIZE);

        // 设置VMCB的两大区域：
        // 1. 保存状态区(Save State Area)：guest的CPU寄存器状态
        // 2. 控制区(Control Area)：拦截配置、NPT指针、ASID等
        err = set_vmcb_guest_state(vmcb_hva);
        CHECK_ERR("set_vmcb_state");

        err = set_vmcb_control(vmcb_hva, actor_id);
        CHECK_ERR("set_vmcb_state");
    }

    return 0;
}

// ==============================================================================
// set_vmcb_guest_state：设置VMCB客户机保存状态区(Save State Area)
// 
// 这是SVM配置中定义guest actor初始CPU状态的函数，与VMX的set_vmcs_guest_state()对应。
// SVM的save区直接包含所有寄存器值，不像VMX需要通过vmwrite逐字段设置。
// 包括：
// - 控制寄存器：CR0(含PE/PG/CD/NW等位)、CR3(客户机页表基址)、CR4(含PAE等)、EFER(含LME/LMA/SVME)
// - 调试寄存器：DR6/DR7
// - 核心寄存器：RIP/RSP/RFLAGS/RAX
// - 段寄存器：CS/SS/DS/ES/FS/GS/LDTR/TR
// - GDTR/IDTR
// - MSR：SYSENTER/SYSCALL相关、性能计数器、PAT
// ==============================================================================
static int set_vmcb_guest_state(vmcb_t *vmcb_hva)
{
    int err = 0;
    // vmcb_save_t结构体是VMCB的保存状态区，直接包含所有guest寄存器
    vmcb_save_t *save = &vmcb_hva->save;
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    // ---- 控制寄存器 ----
    // CR0：保留宿主机PE/PG位，设置SVM guest要求的必须置1/清0位
    // CR3：指向客户机物理内存中的页表L4层(GUEST_P_MEMORY_START)
    // CR4：保留宿主机PAE等位，设置SVM guest要求的必须置1/清0位
    // EFER：保留LME/LMA，设置SVME位（guest也需要看到SVM已启用），清除不允许的位
    save->cr0 = (read_cr0() | MUST_SET_BITS_CR0_SVM_GUEST) & ~MUST_CLEAR_BITS_CR0_SVM_GUEST;
    save->cr3 = (uint64_t)&guest_p_memory->guest_page_tables.l4[0];
    save->cr4 = (__read_cr4() | MUST_SET_BITS_CR4_SVM_GUEST) & ~MUST_CLEAR_BITS_CR4_SVM_GUEST;
    save->efer =
        (rdmsr64(MSR_EFER) | MUST_SET_BITS_EFER_SVM_GUEST) & ~MUST_CLEAR_BITS_EFER_SVM_GUEST;

    // ---- 调试寄存器 ----
    // DR7=0x400：禁用调试断点但保留单步调试能力；DR6=0：无调试异常挂起
    save->dr7 = 0x400;
    save->dr6 = 0;

    // ---- 核心寄存器(GPR) ----
    // RIP：直接指向客户机代码入口(code.section[0])，与VMX不同（VMX先指向vmlaunch_page）
    // RSP：指向客户机栈区域
    // RFLAGS：仅固定位(0x2)
    // RAX=0
    save->rip = (uint64_t)&guest_v_memory->code.section[0];
    save->rsp = (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET];
    save->rflags = X86_EFLAGS_FIXED;
    save->rax = 0;

    // ---- 段寄存器 ----
    // CS: 选择子0x10，属性MUST_SET_BITS_CS_SVM_GUEST
    // SS: 选择子0x20，属性MUST_SET_BITS_SS_SVM_GUEST
    // DS: 选择子0，属性MUST_SET_BITS_DS_SVM_GUEST
    // ES/FS/GS: 选择子0，属性0（不可用）
    // LDTR/TR: 系统段，使用init_sys_seg初始化
    init_seg(&save->cs, 0x10, 0, 0xffffffff, MUST_SET_BITS_CS_SVM_GUEST);
    init_seg(&save->ss, 0x20, 0, 0xffffffff, MUST_SET_BITS_SS_SVM_GUEST);
    init_seg(&save->ds, 0, 0, 0xffffffff, MUST_SET_BITS_DS_SVM_GUEST);
    init_seg(&save->es, 0, 0, 0xffffffff, 0);
    init_seg(&save->fs, 0, 0, 0xffffffff, 0);
    init_seg(&save->gs, 0, 0, 0xffffffff, 0);

    init_sys_seg(&save->ldtr, 2);
    init_sys_seg(&save->tr, 3);

    // ---- GDTR/IDTR ----
    // GDTR指向客户机GDT，IDTR基址设为0（与VMX相同，中断使用会触发#VMEXIT）
    save->gdtr.base = (uint64_t)&guest_v_memory->gdt;
    save->gdtr.limit = 0xffff;
    save->idtr.base = 0;
    save->idtr.limit = 0xffff;

    // ---- MSR ----
    // SYSENTER：CS=0x10，ESP/EIP指向客户机栈和代码入口
    // SYSCALL：从宿主机MSR复制STAR/LSTAR/CSTAR/SFMASK，确保guest能正确执行syscall
    // kernel_gs_base：从宿主机MSR复制
    save->dbgctl = 0;
    save->sysenter_cs = 0x10;
    // save->sysenter_cs = rdmsr64(MSR_IA32_SYSENTER_CS);
    save->sysenter_esp = (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET];
    // save->sysenter_esp = rdmsr64(MSR_IA32_SYSENTER_ESP);
    save->sysenter_eip = (uint64_t)&guest_v_memory->code.section[0];
    // save->sysenter_eip = rdmsr64(MSR_IA32_SYSENTER_EIP);

    save->kernel_gs_base = rdmsr64(MSR_KERNEL_GS_BASE);
    save->star = rdmsr64(MSR_STAR);
    save->lstar = rdmsr64(MSR_LSTAR);
    save->cstar = rdmsr64(MSR_CSTAR);
    save->sfmask = rdmsr64(MSR_SYSCALL_MASK);

    // ---- 性能计数器 ----
    // 从宿主机MSR读取性能控制和计数寄存器，用于侧信道分析
    // PERF_CTL/CTR 0-3：AMD F15H系列的4组性能监控寄存器
    save->perf_ctl0 = rdmsr64(MSR_F15H_PERF_CTL0);
    save->perf_ctr0 = rdmsr64(MSR_F15H_PERF_CTR0);
    save->perf_ctl1 = rdmsr64(MSR_F15H_PERF_CTL1);
    save->perf_ctr1 = rdmsr64(MSR_F15H_PERF_CTR1);
    save->perf_ctl2 = rdmsr64(MSR_F15H_PERF_CTL2);
    save->perf_ctr2 = rdmsr64(MSR_F15H_PERF_CTR2);
    save->perf_ctl3 = rdmsr64(MSR_F15H_PERF_CTL3);
    save->perf_ctr3 = rdmsr64(MSR_F15H_PERF_CTR3);

    // ---- 特权级 ----
    // CPL=0：客户机以0特权级（内核级）运行，这是论文设计中guest actor的特点
    save->cpl = 0;

    // ---- PAT(Page Attribute Table) ----
    // 设置所有8个PAT项为类型06(Write Back)，简化guest的内存类型管理
    save->cpl = 0;

    // PAT
    uint64_t pat = 0;
    for (int i = 0; i < 8; i++) {
        pat |= (uint64_t)0x06 << (i * 8);
    }
    save->g_pat = pat;
    return err;
}

// ==============================================================================
// set_vmcb_control：配置VMCB控制区(Control Area)
// 
// 这是SVM配置中最复杂的部分，定义了guest运行时哪些操作会触发#VMEXIT。
// 与VMX的set_vmcs_exec_control()对应。SVM使用拦截(intercept)位图机制，
// 每种操作对应一个位，置1则拦截该操作（触发#VMEXIT）。
// 配置包括：
// - CR拦截(8读+8写)：拦截所有CR0/CR3/CR4/CR8的读写
// - DR拦截(8读+8写)：拦截所有DR0-DR7的读写
// - 异常拦截：拦截所有异常(0xFFFFFFFF)
// - 指令拦截：拦截大部分指令，但故意不拦截PUSHF/POPF/RDTSC/RDPMC/RDTSCP
//   这些不拦截的指令是htrace(硬件迹)收集所必需的——论文的核心机制
// - 扩展拦截：INVPCID/MCOMMIT/TLBSYNC/BUS_LOCK等
// - NPT指针(nested_cr3)：每个actor独立的嵌套页表，实现地址空间隔离
// - ASID(actor_id)：区分不同guest的TLB条目
// ==============================================================================
static int set_vmcb_control(vmcb_t *vmcb_hva, uint64_t actor_id)
{
    int err = 0;
    // vmcb_control_t结构体是VMCB的控制区，包含拦截位图、NPT指针、ASID等
    vmcb_control_t *ctrl = &vmcb_hva->control;

    // ---- CR拦截位 ----
    // 拦截所有CR0/CR3/CR4/CR8的读和写操作
    // guest对这些控制寄存器的任何访问都会触发#VMEXIT，由宿主机处理
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR0_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR3_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR4_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR8_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR0_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR3_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR4_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR8_WRITE);

    // ---- DR拦截位 ----
    // 拦截所有DR0-DR7的读和写操作，防止guest修改调试寄存器
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR0_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR1_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR2_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR3_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR4_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR5_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR6_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR7_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR0_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR1_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR2_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR3_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR4_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR5_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR6_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR7_WRITE);

    // ---- 异常拦截 ----
    // 拦截所有CPU异常(0xFFFFFFFF)，guest发生任何异常都会触发#VMEXIT
    ctrl->intercept_exceptions = 0XFFFFFFFF;

    // ---- 指令拦截 ----
    // 拦截大部分指令：中断/NMI/SMI/INIT/VINTR/选择性CR0/SIDT/SGDT/SLDT/STR/
    // LIDT/LGDT/LLDT/LTR/CPUID/RSM/IRET/INTn/INVD/PAUSE/HLT/INVLPG/INVLPGA/
    // I/O保护/MSR保护/任务切换/FERR冻结/关机/VMRUN/VMMCALL/VMLOAD/VMSAVE/
    // STGI/CLGI/SKINIT/ICEBP/WBINVD/MONITOR/MWAIT/XSETBV/RDPRU/EFER写入
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_NMI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SMI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VINTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SELECTIVE_CR0);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_IDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_GDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_LDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_TR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_IDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_GDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_LDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_TR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_CPUID);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RSM);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_IRET);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INTn);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_PAUSE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_HLT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVLPG);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVLPGA);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_IOIO_PROT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MSR_PROT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_TASK_SWITCH);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_FERR_FREEZE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SHUTDOWN);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMRUN);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMMCALL);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMLOAD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMSAVE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STGI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_CLGI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SKINIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_ICEBP);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_WBINVD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MONITOR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MWAIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MWAIT_COND);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_XSETBV);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDPRU);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_EFER_WRITE);
    // 【关键设计】以下拦截位故意不设置！这些是htrace收集所必需的指令
    // PUSHF/POPF：修改RFLAGS的指令，htrace通过观察RFLAGS变化来推断执行路径
    // RDTSC/RDPMC/RDTSCP：时间戳和性能计数器指令，用于测量执行时间差异（侧信道核心）
    // 不拦截这些指令意味着guest可以自由执行它们，fuzzer通过htrace观测结果
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_PUSHF);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_POPF);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDTSC);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDPMC);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDTSCP);

    // ---- 扩展拦截位 ----
    // 拦截INVLPGB/INVPCID/MCOMMIT/TLBSYNC/BUS_LOCK等较新的指令
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_ALL_INVLPGB);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_INVPCID);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_MCOMMIT);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_TLBSYNC);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_BUS_LOCK);

    // ---- PAUSE过滤阈值 ----
    // 设为0，不使用PAUSE-loop退出机制
    ctrl->pause_filter_count = 0;
    ctrl->pause_filter_thresh = 0;

    // ---- IOPM和MSRPM物理地址 ----
    // IOPM(4页，全1)：拦截所有I/O端口访问
    // MSRPM(2页，全1)：拦截所有MSR读写
    ctrl->iopm_base_pa = iopm_hpa;
    ASSERT(ctrl->iopm_base_pa < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    ctrl->msrpm_base_pa = msrpm_hpa;
    ASSERT(ctrl->msrpm_base_pa < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    // ---- TSC偏移 ----
    // 设为0，guest的TSC值与宿主机相同（不偏移时间戳计数器）
    ctrl->tsc_offset = 0;

    // ---- ASID(Address Space Identifier) ----
    // 使用actor_id作为ASID，确保不同guest的TLB条目不会混淆
    // 这是SVM区分不同guest虚拟地址空间的关键机制
    ctrl->asid = (uint32_t)actor_id;

    // ---- TLB控制 ----
    // tlb_ctl=0：不刷新TLB
    // int_ctl=V_INTR_MASKING_MASK：启用虚拟中断屏蔽，防止guest修改真实中断屏蔽状态
    // int_vector=0, int_state=0：不注入虚拟中断
    ctrl->tlb_ctl = 0;
    ctrl->int_ctl = V_INTR_MASKING_MASK;
    ctrl->int_vector = 0;
    ctrl->int_state = 0;

    // ---- 嵌套分页(Nested Paging)配置 ----
    // 这是论文Section 5.2的核心——SVM的NPT(Nested Page Table)配置
    // SVM_NESTED_CTL_NP_ENABLE：启用嵌套分页，客户机物理地址通过NPT映射到真实物理地址
    // bit 6：启用只读客户机页表（guest页表被标记为只读，写操作触发#VMEXIT用于追踪）
    ctrl->nested_ctl |= SVM_NESTED_CTL_NP_ENABLE;
    ctrl->nested_ctl |= _BITULL(6);

    // ---- NPT页表基址(nested_cr3) ----
    // 每个actor使用独立的NPT，实现actor间的地址空间隔离
    // nested_cr3指向NPT的L4层页表，与VMX的EPT_POINTER功能相同
    // ept_ptr[actor_id].paddr是NPT的物理页帧号，左移12位得到物理地址
    ctrl->nested_cr3 = (((uint64_t)ept_ptr[actor_id].paddr) << 12);
    ASSERT(ctrl->nested_cr3 < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    // ---- 退出码和清洁位 ----
    // exit_code=0x42：设置一个非零初始值作为"哨兵值"，用于检测VMCB是否已被使用
    //   如果VMRUN后exit_code仍然是0x42，说明guest未正常退出
    // clean=0：标记VMCB为"不干净"，意味着所有VMCB字段都需要重新加载（不使用缓存优化）
    ctrl->exit_code = 0x42;

    ctrl->clean = 0;

    return err;
}

// ==============================================================================
// print_svm_exit_info：打印#VMEXIT事件的详细信息
// 用于调试和错误诊断，包括每个guest actor的：
// - 退出码(exit_code)：标识退出原因
// - 退出信息1/2(exit_info_1/2)：退出相关的详细信息
// - 退出中断信息(exit_int_info)：退出时的中断状态
// - 指令长度和指令字节：触发退出的指令信息
// ==============================================================================
int print_svm_exit_info(void)
{
    int err = 0;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        struct page *vmcb_page = &vmcb_pages[actor_id];
        vmcb_t *vmcb_hva = page_address(vmcb_page);

        uint64_t exitcode = vmcb_hva->control.exit_code;
        uint64_t exitinfo1 = vmcb_hva->control.exit_info_1;
        uint64_t exitinfo2 = vmcb_hva->control.exit_info_2;
        uint64_t exitintinfo = vmcb_hva->control.exit_int_info;

        // print exit information
        printk(
            KERN_ERR
            "VMCB[%d]: exitcode=0x%llx, exitinfo1=0x%llx, exitinfo2=0x%llx, exitintinfo=0x%llx\n",
            actor_id, exitcode, exitinfo1, exitinfo2, exitintinfo);
        printk(KERN_ERR "insn_len=0x%x, insn_bytes=0x%llx\n", vmcb_hva->control.insn_len,
               *(uint64_t *)(&vmcb_hva->control.insn_bytes[0]));
    }

    return err;
}

// =================================================================================================
// ==============================================================================
// init_svm：SVM模块初始化
// 
// 在fuzzer启动时调用，分配SVM运行所需的内存：
// 1. VMCB页面——每个guest actor一个4KB的VMCB页面(SVM_MAX_NUM_GUESTS个)
// 2. vmcb_hpas/vmcb_hvas数组——存储每个VMCB的物理/虚拟地址
// 3. Host SSA页面——宿主机状态保存区域(1页)
// 4. IOPM页面——I/O权限位图(4页)，全部置1(拦截所有I/O)
// 5. MSRPM页面——MSR权限位图(2页)，全部置1(拦截所有MSR)
// ==============================================================================
int init_svm(void)
{
    int err = 0;

    // VMCBs
    vmcb_pages = CHECKED_ALLOC_PAGES(SVM_MAX_NUM_GUESTS * VMCB_SIZE);
    vmcb_hpas = CHECKED_ZALLOC(SVM_MAX_NUM_GUESTS * sizeof(uint64_t));
    vmcb_hvas = CHECKED_ZALLOC(SVM_MAX_NUM_GUESTS * sizeof(uint64_t));

    // host state save area
    host_ssa_page = alloc_page(GFP_KERNEL);
    if (!host_ssa_page)
        return -ENOMEM;
    host_ssa_hva = page_address(host_ssa_page);

    // IOPM
    struct page *iopm_pages = alloc_pages(GFP_KERNEL, 2);
    if (!iopm_pages)
        return -ENOMEM;
    iopm_hva = page_address(iopm_pages);
    memset(iopm_hva, 0xff, PAGE_SIZE * 4);
    iopm_hpa = page_to_pfn(iopm_pages) << PAGE_SHIFT;

    // MSRPM
    struct page *msrpm_pages = alloc_pages(GFP_KERNEL, 1);
    if (!msrpm_pages)
        return -ENOMEM;
    msrpm_hva = page_address(msrpm_pages);
    memset(msrpm_hva, 0xff, PAGE_SIZE * 2);
    msrpm_hpa = page_to_pfn(msrpm_pages) << PAGE_SHIFT;

    return err;
}

// ==============================================================================
// free_svm：释放SVM模块分配的所有内存
// 在fuzzer退出时调用，释放VMCB页面、地址数组、Host SSA、IOPM和MSRPM
// ==============================================================================
void free_svm(void)
{
    SAFE_PAGES_FREE(vmcb_pages, SVM_MAX_NUM_GUESTS * VMCB_SIZE);
    SAFE_FREE(vmcb_hpas);
    SAFE_FREE(vmcb_hvas);

    if (host_ssa_page) {
        __free_page(host_ssa_page);
        host_ssa_page = NULL;
        host_ssa_hva = NULL;
    }

    if (iopm_hva) {
        __free_pages(virt_to_page(iopm_hva), 2);
        iopm_hva = NULL;
        iopm_hpa = 0;
    }

    if (msrpm_hva) {
        __free_pages(virt_to_page(msrpm_hva), 1);
        msrpm_hva = NULL;
        msrpm_hpa = 0;
    }
}

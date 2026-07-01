/// File: Configuration constants for VMX
///
// ==============================================================================
// VMX配置常量头文件概述：
// 本文件定义了Intel VMX虚拟化技术的配置常量，是VMCS字段配置的基础。
//
// VMCS(Virtual Machine Control Structure)包含6类控制字段：
//   1. Pin-Based VM-Execution Controls——基于引脚的执行控制
//      控制外部中断、NMI、虚拟中断等如何触发VM退出
//   2. Primary Processor-Based VM-Execution Controls——主处理器执行控制
//      控制CR访问、I/O访问、HLT、MWAIT等是否触发VM退出
//   3. Secondary Processor-Based VM-Execution Controls——次处理器执行控制
//      控制EPT、VPID、RDRAND、RDSEED等高级特性
//   4. VM-Exit Controls——VM退出控制
//      控制VM退出时Host的CPU状态保存行为
//   5. VM-Entry Controls——VM进入控制
//      控制VM进入时Guest的CPU状态加载行为
//   6. Guest/Host-State Areas——状态区域
//      保存Guest和Host的完整CPU状态
//
// Intel VMX的控制字段遵循"默认1"原则：
//   - MUST_SET位：必须为1，否则VMLAUNCH失败
//   - MUST_CLEAR位：必须为0，否则VMLAUNCH失败
//   - 允许为0或1的位：根据测试需求灵活配置
//
// 侧信道测试的关键配置：
//   - 启用EPT(SECONDARY_EXEC_ENABLE_EPT)：Guest使用嵌套页表，
//     控制Guest的内存访问权限——这是跨虚拟化侧信道泄露的基础
//   - 禁用TSC偏移(CPU_BASED_USE_TSC_OFFSETTING)：保持Guest和Host的TSC同步，
//     便于时间测量对比
//   - 禁用RDTSC退出(CPU_BASED_RDTSC_EXITING)：Guest可以自由读取TSC，
//     便于测量代码执行时间
//   - 禁用RDPMC退出(CPU_BASED_RDPMC_EXITING)：Guest可以自由读取PMC，
//     便于性能计数器测量
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _VMX_CONFIG_H_
#define _VMX_CONFIG_H_

#include <asm/vmx.h>

/// VMX最大Guest数量——64个Guest Actor足以覆盖所有测试场景
/// 此值受VMCS和EPT内存限制，不要随意增加
#define VMX_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// =================================================================================================
// 内核缺失常量补充——不同Linux内核版本缺失或不一致的VMX常量定义

/// 三级处理器执行控制启用位——控制Tertiary VM-Execution Controls字段
/// 某些旧内核版本未定义此常量
#ifndef CPU_BASED_ACTIVATE_TERTIARY_CONTROLS
#define CPU_BASED_ACTIVATE_TERTIARY_CONTROLS (1ULL << 17)
#endif
/// RDTSCP退出控制——旧内核版本可能缺失此定义
#ifndef SECONDARY_EXEC_RDTSCP
#define SECONDARY_EXEC_RDTSCP (1ULL << 3)
#endif
/// EPT违规引发#VE——EPT违规时触发虚拟化异常而非VM退出
/// 用于优化EPT权限变更的处理路径
#define SECONDARY_EXEC_EPT_VIOLATION_CAUSES_VE (1ULL << 18)
/// PASID翻译——处理器地址空间ID翻译启用
#define SECONDARY_EXEC_PASID_TRANSLATION       (1ULL << 21)
/// 子页写权限控制——启用EPT子页级别的写权限管理
#define SECONDARY_EXEC_SUBPAGE_WRITE_PERM      (1ULL << 23)
/// PCONFIG启用退出——PCONFIG指令触发VM退出
#define SECONDARY_EXEC_ENABLE_PCONFIG          (1ULL << 27)
/// ENCLV退出启用——ENCLV指令(SGX相关)触发VM退出
#define SECONDARY_EXEC_ENABLE_ENCLV_EXITING    (1ULL << 28)

/// VM退出UINV位——用户中断通知向量
#define VM_EXIT_UINV               (1ULL << 19)
/// VM进入CET位——控制流强制技术启用
#define VM_ENTRY_CET               (1ULL << 20)
/// VM进入加载LBR控制——加载最后分支记录控制MSR
#define VM_ENTRY_LOAD_IA32_LBR_CTL (1ULL << 21)
/// VM进入加载PKRS——加载保护键权限寄存器
#define VM_ENTRY_LOAD_IA32_PKRS    (1ULL << 22)

// ----------------------------------------------------------------------------------------------
// Guest控制寄存器配置——VMX硬件对Guest CR的强制要求

/// CR0必须设置的位——VMX Guest必须启用这些CR0特性
/// 与SVM Guest的CR0要求基本一致（PE, PG, NE, WP, AM, ET）
#define MUST_SET_BITS_CR0_VMX_GUEST                                                                    \
    (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_ET)
/// CR0必须清除的位——VMX Guest必须禁用NW和CD（缓存必须启用）
#define MUST_CLEAR_BITS_CR0_VMX_GUEST (X86_CR0_NW | X86_CR0_CD)

/// CR4必须设置的位——VMX Guest必须启用这些CR4特性
/// 与SVM相比，VMX额外要求：VMXE(VMX启用)和PCIDE(PCID启用)
#define MUST_SET_BITS_CR4_VMX_GUEST                                                                    \
    (X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR |        \
     X86_CR4_OSXMMEXCPT | X86_CR4_VMXE | X86_CR4_PCIDE)
/// CR4必须清除的位——VMX Guest必须禁用这些CR4特性
/// 包括VME, PVI, TSD, UMIP, SMXE, FSGSBASE, OSXSAVE等
/// 注意：OSXSAVE必须禁用，因为侧信道测试需要手动控制XSAVE状态
#define MUST_CLEAR_BITS_CR4_VMX_GUEST                                                                  \
    (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_UMIP | X86_CR4_SMXE | X86_CR4_FSGSBASE |    \
     X86_CR4_OSXSAVE)

// ----------------------------------------------------------------------------------------------
// VMCS控制字段配置——定义VM-Execution/Exit/Entry Controls的必须设置和清除位

/// ================================================================================
/// 基于引脚的VM执行控制(SDM Table 25-5)——控制中断相关的VM退出行为
/// 重要：不能同时启用PIN_BASED_EXT_INTR_MASK和VM_EXIT_ACK_INTR_ON_EXIT，
/// 否则中断会导致系统崩溃！这是VMX配置的关键安全约束。
#define MUST_SET_PIN_BASED_VM_EXEC_CONTROL                                                         \
    (PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS | PIN_BASED_VMX_PREEMPTION_TIMER)
/// 必须清除的引脚控制——禁用外部中断屏蔽和Posted Interrupt
#define MUST_CLEAR_PIN_BASED_VM_EXEC_CONTROL (PIN_BASED_EXT_INTR_MASK | PIN_BASED_POSTED_INTR)

/// ================================================================================
/// 主处理器VM执行控制(SDM Table 25-6)——控制Guest指令是否触发VM退出
/// 关键配置决策：
///   - 禁用TSC偏移：保持Guest/Host TSC同步，便于时间测量
///   - 禁用RDTSC/RDPMC退出：Guest自由读取时间戳和PMC，便于侧信道测量
///   - 禁用MSR位图：不拦截MSR访问，减少VM退出开销
///   - 启用CR3加载/存储退出：监控Guest页表切换，防止恶意页表操作
///   - 启用CR8加载/存储退出：控制Guest的APIC任务优先级
///   - 启用IO无条件退出：禁止Guest直接访问I/O端口
///   - 启用HLT/MWAIT/PAUSE退出：防止Guest长时间占用CPU
#define MUST_SET_PRIMARY_VM_EXEC_CONTROL                                                           \
    (CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |            \
     CPU_BASED_MWAIT_EXITING | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |          \
     CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING | CPU_BASED_MOV_DR_EXITING |         \
     CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_MONITOR_EXITING | CPU_BASED_PAUSE_EXITING |           \
     CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_NMI_WINDOW_EXITING)
#define MUST_CLEAR_PRIMARY_VM_EXEC_CONTROL                                                         \
    (CPU_BASED_USE_TSC_OFFSETTING | CPU_BASED_RDPMC_EXITING | CPU_BASED_RDTSC_EXITING |            \
     CPU_BASED_ACTIVATE_TERTIARY_CONTROLS | CPU_BASED_TPR_SHADOW | CPU_BASED_USE_IO_BITMAPS |      \
     CPU_BASED_MONITOR_TRAP_FLAG | CPU_BASED_USE_MSR_BITMAPS)

/// ================================================================================
/// 次处理器VM执行控制(SDM Table 25-7)——控制高级VMX特性的启用/禁用
/// 核心配置：
///   - 启用EPT(SECONDARY_EXEC_ENABLE_EPT)：Guest使用嵌套页表——侧信道测试基础
///   - 启用DESC退出：VM退出时处理GDTR/LDTR/IDTR/TR的加载
///   - 启用WBINVD退出：防止Guest冲刷缓存（保持缓存状态用于测量）
///   - 启用INVPCID：支持按PCID使TLB无效
///   - 启用RDRAND/RDSEED退出：防止Guest获取硬件随机数（避免干扰测量）
///   - 禁用VPID：不使用虚拟处理器ID（简化TLB管理）
///   - 禁用Unrestricted Guest：Guest必须启用CR0.PE和CR0.PG（确保64位模式）
///   - 禁用XSAVES：不启用XSAVE/XRSTOR管理（手动控制XSAVE状态）
#define MUST_SET_SECONDARY_VM_EXEC_CONTROL                                                         \
    (SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_DESC | SECONDARY_EXEC_WBINVD_EXITING |             \
     SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_RDRAND_EXITING |                               \
     SECONDARY_EXEC_RDSEED_EXITING)
#define MUST_CLEAR_SECONDARY_VM_EXEC_CONTROL                                                       \
    (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES | SECONDARY_EXEC_RDTSCP |                             \
     SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE | SECONDARY_EXEC_ENABLE_VPID |                          \
     SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_APIC_REGISTER_VIRT |                       \
     SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY | SECONDARY_EXEC_ENABLE_VMFUNC |                         \
     SECONDARY_EXEC_ENCLS_EXITING | SECONDARY_EXEC_ENABLE_PML |                                    \
     SECONDARY_EXEC_EPT_VIOLATION_CAUSES_VE | SECONDARY_EXEC_PT_CONCEAL_VMX |                      \
     SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_PASID_TRANSLATION |                                    \
     SECONDARY_EXEC_MODE_BASED_EPT_EXEC | SECONDARY_EXEC_SUBPAGE_WRITE_PERM |                      \
     SECONDARY_EXEC_PT_USE_GPA | SECONDARY_EXEC_TSC_SCALING |                                      \
     SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE | SECONDARY_EXEC_ENABLE_PCONFIG |                        \
     SECONDARY_EXEC_ENABLE_ENCLV_EXITING | SECONDARY_EXEC_SHADOW_VMCS)

/// VMBUILD模式下的次处理器控制——减少必须启用的控制位
/// VMBUILD模式下仅保留最基本的控制（EPT, DESC, WBINVD, RDRAND, RDSEED）
#ifdef VMBUILD
#undef MUST_SET_SECONDARY_VM_EXEC_CONTROL
#define MUST_SET_SECONDARY_VM_EXEC_CONTROL                                                         \
    (SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_DESC | SECONDARY_EXEC_WBINVD_EXITING |             \
     SECONDARY_EXEC_RDRAND_EXITING | SECONDARY_EXEC_RDSEED_EXITING)
#endif

/// 异常位图默认值——所有异常都重定向到Host
/// 0xFFFFFFFF确保任何Guest异常都会触发VM退出，
/// Host可以在exit处理函数中决定是否恢复Guest或终止测试
#define DEFAULT_EXCEPTION_BITMAP 0xFFFFFFFF // all exceptions are redirected to host

/// ================================================================================
/// VM退出控制(SDM Table 25-8)——控制VM退出时Host的状态恢复
/// 必须设置：保存调试控制和64位Host模式
/// 必须清除：大部分MSR自动加载/保存功能（减少VM退出开销）
#define MUST_SET_EXIT_CTRL (VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_HOST_ADDR_SPACE_SIZE)
#define MUST_CLEAR_EXIT_CTRL                                                                       \
    (VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL | VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT |          \
     VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_VMX_PREEMPTION_TIMER |         \
     VM_EXIT_CLEAR_BNDCFGS | VM_EXIT_PT_CONCEAL_PIP | VM_EXIT_CLEAR_IA32_RTIT_CTL |                \
     VM_EXIT_ACK_INTR_ON_EXIT)

/// ================================================================================
/// VM进入控制(SDM Table 25-9)——控制VM进入时Guest的状态加载
/// 必须设置：加载调试控制和64位Guest模式(IA-32e)
/// 必须清除：大部分MSR自动加载功能（减少VM进入开销）
#define MUST_SET_ENTRY_CTRL (VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE)
#define MUST_CLEAR_ENTRY_CTRL                                                                      \
    (VM_ENTRY_SMM | VM_ENTRY_DEACT_DUAL_MONITOR | VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |            \
     VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER | VM_ENTRY_LOAD_BNDCFGS |                    \
     VM_ENTRY_PT_CONCEAL_PIP | VM_ENTRY_LOAD_IA32_RTIT_CTL | VM_EXIT_UINV | VM_ENTRY_CET |         \
     VM_ENTRY_LOAD_IA32_LBR_CTL | VM_ENTRY_LOAD_IA32_PKRS)

#endif // _VMX_CONFIG_H_

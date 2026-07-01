/// File: Definitions of constants used by AMD SVM (Secure Virtual Machine) technology
///
// ==============================================================================
// AMD SVM常量定义头文件概述：
// 本文件定义了AMD SVM虚拟化技术使用的常量，包括：
//   1. Guest控制寄存器的必须设置/清除位——确保Guest的CR0/CR4/EFER配置合法
//      SVM硬件对某些CR位有强制要求：必须为1或必须为0，否则VMRUN失败
//   2. 段寄存器属性的必须设置位——确保Guest的CS/DS/SS段描述符合法
//   3. VMCB拦截位定义——控制哪些CR/DR/异常/指令触发VM退出
//   4. 内核兼容性定义——不同Linux内核版本间不一致的常量定义
//
// 与Intel VMX的区别：
//   - SVM使用拦截位图(intercept bitmap)而非VMCS的执行控制字段
//   - SVM的CR/DR拦截使用简单的位索引(0-7对应CR0-CR7/DR0-DR7)
//   - SVM的指令拦截使用枚举值而非位号
//
// 这些常量直接影响Guest Actor的行为边界——
// 哪些操作在Guest中合法执行，哪些触发VM退出回到Host处理。
// 侧信道测试中，合理的拦截配置确保Guest可以执行被测代码，
// 同时Host可以在关键事件(如页故障)时介入测量。
// ==============================================================================

#include <asm/msr-index.h>

// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_SVM_CONSTANTS_H_
#define _RVZR_EXECUTOR_SVM_CONSTANTS_H_

// =================================================================================================
// 默认配置值——VMCB字段和Guest寄存器的初始设置

/// SVM最大Guest数量——64个Guest Actor足以覆盖所有测试场景
/// 此值受VMCB和IOPM/MSRPM内存限制，不要随意增加
#define SVM_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// -------------------------------------------------------------------------------------------------
// Guest控制寄存器配置——SVM硬件对Guest CR的强制要求
// 这些位必须正确设置，否则VMRUN指令会失败(#GP异常)

/// CR0必须设置的位——SVM Guest必须启用这些CR0特性
/// PE(Protection Enable)：必须启用保护模式
/// PG(Paging)：必须启用分页
/// NE(Numeric Error)：必须启用内置x87错误报告
/// WP(Write Protect)：必须启用写保护（Ring0不能写入只读页）
/// AM(Alignment Mask)：必须启用对齐检查
/// ET(Extension Type)：必须设置（表示387DX样式FPU）
#define MUST_SET_BITS_CR0_SVM_GUEST                                                                \
    (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_ET)
/// CR0必须清除的位——SVM Guest必须禁用这些CR0特性
/// NW(Not Write-through)：清除以启用直写缓存
/// CD(Cache Disable)：清除以启用缓存（侧信道测试需要缓存活跃）
#define MUST_CLEAR_BITS_CR0_SVM_GUEST (X86_CR0_NW | X86_CR0_CD)

/// CR4必须设置的位——SVM Guest必须启用这些CR4特性
/// PSE(Page Size Extension)：支持4MB大页
/// PAE(Physical Address Extension)：支持36位物理地址（64位模式必须）
/// MCE(Machine Check Exception)：启用机器检查异常
/// PGE(Page Global Enable)：启用全局页（TLB优化）
/// PCE(Performance Counter Enable)：启用Ring3访问性能计数器（侧信道测量必须）
/// OSFXSR(OS FXSAVE/XRSTOR Support)：启用FXSAVE/XRSTOR指令
/// OSXMMEXCPT(OS XMM Exception Support)：启用SIMD浮点异常处理
#define MUST_SET_BITS_CR4_SVM_GUEST                                                                \
    (X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR |        \
     X86_CR4_OSXMMEXCPT)
/// CR4必须清除的位
/// VME(Virtual Mode Extension)：禁用虚拟8086模式扩展
#define MUST_CLEAR_BITS_CR4_SVM_GUEST (X86_CR4_VME)

/// EFER必须设置的位——SVM Guest必须启用这些EFER特性
/// SCE(Syscall Enable)：启用SYSCALL/SYSRET指令
/// LME(Long Mode Enable)：启用长模式（64位模式）
/// LMA(Long Mode Active)：标记长模式已激活
/// NX(No Execute)：启用NX位（禁止从某些页执行代码）
/// SVME(SVM Enable)：启用SVM虚拟化（Guest需要此位才能嵌套虚拟化）
#define MUST_SET_BITS_EFER_SVM_GUEST   (EFER_SCE | EFER_LME | EFER_LMA | EFER_NX | EFER_SVME)
/// EFER必须清除的位
/// LMSLE(Lock Mode Seal Enable)：禁用锁定模式密封（避免限制Guest行为）
#define MUST_CLEAR_BITS_EFER_SVM_GUEST (EFER_LMSLE)

// -------------------------------------------------------------------------------------------------
// 段寄存器属性——SVM Guest的段描述符必须设置位

/// CS段必须设置的属性——代码段必须是：Present + Long mode + Writable
#define MUST_SET_BITS_CS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)
/// DS段必须设置的属性——数据段必须是：Present + Long mode + Writable
#define MUST_SET_BITS_DS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)
/// SS段必须设置的属性——栈段必须是：Present + Long mode + Writable
#define MUST_SET_BITS_SS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)

// -------------------------------------------------------------------------------------------------
// VMCB控制字段——拦截配置的基础

// =================================================================================================
// 内核兼容性常量——不同Linux内核版本间不一致或缺失的VMCB位定义
// 我们在此重新定义VMCB拦截位，因为内核中的定义在不同版本间不稳定

/// CR寄存器拦截位索引——读取拦截
/// 当Guest读取对应的CR寄存器时，触发VM退出
#define VMCB_INTERCEPT_CR0_READ  0   // 拦截CR0读取
#define VMCB_INTERCEPT_CR3_READ  3   // 拦截CR3读取（页表基址——侧信道关键寄存器）
#define VMCB_INTERCEPT_CR4_READ  4   // 拦截CR4读取
#define VMCB_INTERCEPT_CR8_READ  8   // 拦截CR8读取（APIC任务优先级）
/// CR寄存器拦截位索引——写入拦截
/// intercept_cr的[16:23]为写入拦截位，[0:7]为读取拦截位
#define VMCB_INTERCEPT_CR0_WRITE (16 + 0)  // 拦截CR0写入
#define VMCB_INTERCEPT_CR3_WRITE (16 + 3)  // 拦截CR3写入——用于控制页表切换
#define VMCB_INTERCEPT_CR4_WRITE (16 + 4)  // 拦截CR4写入
#define VMCB_INTERCEPT_CR8_WRITE (16 + 8)  // 拦截CR8写入

/// DR寄存器拦截位索引——读取拦截
/// 当Guest读取对应的DR寄存器时，触发VM退出
#define VMCB_INTERCEPT_DR0_READ  0
#define VMCB_INTERCEPT_DR1_READ  1
#define VMCB_INTERCEPT_DR2_READ  2
#define VMCB_INTERCEPT_DR3_READ  3   // 拦截DR3读取——调试断点地址
#define VMCB_INTERCEPT_DR4_READ  4
#define VMCB_INTERCEPT_DR5_READ  5
#define VMCB_INTERCEPT_DR6_READ  6   // 拦截DR6读取——调试状态
#define VMCB_INTERCEPT_DR7_READ  7   // 拦截DR7读取——调试控制
/// DR寄存器拦截位索引——写入拦截
#define VMCB_INTERCEPT_DR0_WRITE (16 + 0)
#define VMCB_INTERCEPT_DR1_WRITE (16 + 1)
#define VMCB_INTERCEPT_DR2_WRITE (16 + 2)
#define VMCB_INTERCEPT_DR3_WRITE (16 + 3)
#define VMCB_INTERCEPT_DR4_WRITE (16 + 4)
#define VMCB_INTERCEPT_DR5_WRITE (16 + 5)
#define VMCB_INTERCEPT_DR6_WRITE (16 + 6)
#define VMCB_INTERCEPT_DR7_WRITE (16 + 7)

/// 指令拦截枚举——当Guest执行对应的指令时，触发VM退出
/// intercept位图的第N位对应枚举中的第N个值
/// 侧信道测试中通常不拦截大部分指令，让Guest自由执行被测代码
/// 仅在特定测试场景中启用某些拦截（如RDTSC拦截用于时间测量控制）
enum {
    VMCB_INTERCEPT_INTR,              // 拦截硬件中断
    VMCB_INTERCEPT_NMI,              // 拦截非屏蔽中断
    VMCB_INTERCEPT_SMI,              // 拦截系统管理中断
    VMCB_INTERCEPT_INIT,             // 拦截INIT信号
    VMCB_INTERCEPT_VINTR,            // 拦截虚拟中断——SVM的虚拟中断注入机制
    VMCB_INTERCEPT_SELECTIVE_CR0,    // 拦截选择性CR0修改——仅拦截特定CR0位的写入
    VMCB_INTERCEPT_STORE_IDTR,       // 拦截SIDT指令——存储IDTR
    VMCB_INTERCEPT_STORE_GDTR,       // 拦截SGDT指令——存储GDTR
    VMCB_INTERCEPT_STORE_LDTR,       // 拦截SLDT指令——存储LDTR
    VMCB_INTERCEPT_STORE_TR,         // 拦截STR指令——存储TR
    VMCB_INTERCEPT_LOAD_IDTR,        // 拦截LIDT指令——加载IDTR
    VMCB_INTERCEPT_LOAD_GDTR,        // 拦截LGDT指令——加载GDTR
    VMCB_INTERCEPT_LOAD_LDTR,        // 拦截LLDT指令——加载LDTR
    VMCB_INTERCEPT_LOAD_TR,          // 拦截LTR指令——加载TR
    VMCB_INTERCEPT_RDTSC,            // 拦截RDTSC指令——读取时间戳计数器
    VMCB_INTERCEPT_RDPMC,            // 拦截RDPMC指令——读取性能计数器
    VMCB_INTERCEPT_PUSHF,            // 拦截PUSHF指令——压入标志寄存器
    VMCB_INTERCEPT_POPF,             // 拦截POPF指令——弹出标志寄存器
    VMCB_INTERCEPT_CPUID,            // 拦截CPUID指令——CPU特征查询
    VMCB_INTERCEPT_RSM,              // 拦截RSM指令——从SMI模式恢复
    VMCB_INTERCEPT_IRET,             // 拦截IRET指令——中断返回
    VMCB_INTERCEPT_INTn,             // 拦截INTn指令——软件中断
    VMCB_INTERCEPT_INVD,             // 拦截INVD指令——使缓存无效（不回写）
    VMCB_INTERCEPT_PAUSE,            // 拦截PAUSE指令——用于Pause过滤
    VMCB_INTERCEPT_HLT,              // 拦截HLT指令——停止处理器
    VMCB_INTERCEPT_INVLPG,           // 拦截INVLPG指令——使TLB条目无效
    VMCB_INTERCEPT_INVLPGA,          // 拦截INVLPGA指令——使ASID关联的TLB条目无效
    VMCB_INTERCEPT_IOIO_PROT,        // 拦截I/O端口访问——IOPM位图控制
    VMCB_INTERCEPT_MSR_PROT,         // 拦截MSR访问——MSRPM位图控制
    VMCB_INTERCEPT_TASK_SWITCH,      // 拦截任务切换
    VMCB_INTERCEPT_FERR_FREEZE,      // 拦截FERR冻结——浮点错误冻结处理器
    VMCB_INTERCEPT_SHUTDOWN,         // 拦截关机——Guest尝试关机
    VMCB_INTERCEPT_VMRUN,            // 拦截VMRUN指令——防止嵌套虚拟化
    VMCB_INTERCEPT_VMMCALL,          // 拦截VMMCALL指令——Guest→Host通信
    VMCB_INTERCEPT_VMLOAD,           // 拦截VMLOAD指令——从VMCB加载状态
    VMCB_INTERCEPT_VMSAVE,           // 拦截VMSAVE指令——保存状态到VMCB
    VMCB_INTERCEPT_STGI,             // 拦截STGI指令——设置全局中断标志
    VMCB_INTERCEPT_CLGI,             // 拦截CLGI指令——清除全局中断标志
    VMCB_INTERCEPT_SKINIT,           // 拦截SKINIT指令——安全内核初始化
    VMCB_INTERCEPT_RDTSCP,           // 拦截RDTSCP指令——读取TSC和处理器ID
    VMCB_INTERCEPT_ICEBP,            // 拦截ICEBP指令——调试断点
    VMCB_INTERCEPT_WBINVD,           // 拦截WBINVD指令——使缓存无效并回写
    VMCB_INTERCEPT_MONITOR,          // 拦截MONITOR指令——设置监视区域
    VMCB_INTERCEPT_MWAIT,            // 拦截MWAIT指令——等待监视事件
    VMCB_INTERCEPT_MWAIT_COND,       // 拦截MWAIT条件等待
    VMCB_INTERCEPT_XSETBV,          // 拦截XSETBV指令——设置扩展控制寄存器
    VMCB_INTERCEPT_RDPRU,            // 拦截RDPRU指令——读取处理器利用率
    VMCB_INTERCEPT_EFER_WRITE,       // 拦截EFER写入——控制EFER修改
};

/// 扩展指令拦截枚举——SVM扩展拦截功能
/// 这些拦截位用于控制较新的CPU特性
enum {
    VMCB_INTERCEPT_ALL_INVLPGB,      // 拦截所有INVLPGB指令——全局TLB无效化广播
    VMCB_INTERCEPT_INVALID_INVLPGB,  // 拦截无效的INVLPGB指令
    VMCB_INTERCEPT_INVPCID,          // 拦截INVPCID指令——按进程上下文ID使TLB无效
    VMCB_INTERCEPT_MCOMMIT,          // 拦截MCOMMIT指令——内存提交
    VMCB_INTERCEPT_TLBSYNC,          // 拦截TLBSYNC指令——TLB同步
    VMCB_INTERCEPT_BUS_LOCK,         // 拦截总线锁——阻止跨核心的原子操作锁定总线
    VMCB_INTERCEPT_HLT_IF_NOT_VINTR, // 拦截HLT（无虚拟中断时）——阻止无中断的HLT
};

#endif // _RVZR_EXECUTOR_SVM_CONSTANTS_H_

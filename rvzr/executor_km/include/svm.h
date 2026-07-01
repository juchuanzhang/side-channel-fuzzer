/// File: Header for svm.c
///
// ==============================================================================
// AMD SVM（安全虚拟机）头文件概述：
// 本文件定义了AMD SVM虚拟化技术的核心数据结构和接口函数，
// 是AMD平台侧信道模糊测试中Guest Actor配置的基础。
//
// SVM(Secure Virtual Machine)是AMD的硬件虚拟化技术，
// 通过VMCB(Virtual Machine Control Block)管理Guest虚拟机的状态。
// 与Intel VMX的关键区别：
//   - Intel使用VMCS(Virtual Machine Control Structure) + vmwrite/vmread指令
//   - AMD使用VMCB(Virtual Machine Control Block) + 直接内存访问
//   - Intel VM进入通过VMLAUNCH/VMRESUME指令
//   - AMD VM进入通过VMRUN指令
//   - Intel VM退出信息存储在VMCS的exit字段中
//   - AMD VM退出信息存储在VMCB的control区域中
//
// VMCB分为两个区域：
//   1. vmcb_control_t：控制区域——定义拦截(intercept)规则和VM退出信息
//      包括CR/DR拦截、异常拦截、指令拦截、退出代码等
//   2. vmcb_save_t：状态保存区域——保存Guest的完整CPU状态
//      包括所有段寄存器、控制寄存器、RIP/RSP/RFLAGS等
//
// 本文件中的VMCB结构体字段与AMD64 Architecture Programmer's Manual Volume 2
// 第15章"Secure Virtual Machine"的VMCB格式定义一致。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_SVM_H_
#define _RVZR_EXECUTOR_SVM_H_

#include <asm/svm.h>
#include <linux/types.h>

#include "svm_constants.h"

// =================================================================================================
// 虚拟机控制块(VMCB)定义——AMD SVM虚拟化的核心数据结构
// VMCB大小为1页(4KB)，包含control和save两个区域
#define VMCB_SIZE PAGE_SIZE

/// VMCB控制区域结构体——定义Guest行为的拦截规则和VM退出信息
/// 拦截(intercept)机制是SVM虚拟化的核心：当Guest执行被拦截的操作时，
/// CPU自动退出VM模式回到Host，Host可以在exit处理函数中决定如何响应。
/// 这对侧信道测试至关重要：通过配置拦截规则控制Guest的行为边界。
typedef struct {
    uint32_t intercept_cr;              // CR寄存器拦截位图——哪些CR读/写触发VM退出
    uint32_t intercept_dr;              // DR寄存器拦截位图——哪些DR读/写触发VM退出
    uint32_t intercept_exceptions;      // 异常拦截位图——哪些异常触发VM退出
    uint64_t intercept;                 // 指令拦截位图——哪些指令触发VM退出
    uint32_t intercept_ext;             // 扩展指令拦截位图——更多指令的拦截控制
    uint8_t reserved_1[36];             // 保留区域
    uint16_t pause_filter_thresh;       // PAUSE指令过滤阈值——PAUSE次数超过此值触发退出
    uint16_t pause_filter_count;        // PAUSE指令过滤计数——当前PAUSE累计次数
    uint64_t iopm_base_pa;              // I/O权限位图物理地址——控制I/O端口访问拦截
    uint64_t msrpm_base_pa;             // MSR权限位图物理地址——控制MSR访问拦截
    uint64_t tsc_offset;                // TSC偏移值——Guest的TSC = Host_TSC + tsc_offset
    uint32_t asid;                      // 地址空间标识符——TLB标签，区分不同Guest的翻译
    uint8_t tlb_ctl;                    // TLB控制——控制TLB刷新策略
    uint8_t reserved_2[3];              // 保留区域
    uint32_t int_ctl;                   // 中断控制——虚拟中断注入等
    uint8_t int_vector;                 // 注入中断向量号
    uint8_t reserved_3[3];              // 保留区域
    uint8_t int_state;                  // 中断状态
    uint8_t reserved_4[7];              // 保留区域
    uint64_t exit_code;                 // VM退出代码——标识退出原因(如#PF, #GP, VMRUN等)
    uint64_t exit_info_1;               // VM退出信息1——退出的附加信息(如故障地址)
    uint64_t exit_info_2;               // VM退出信息2——退出的更多附加信息
    uint64_t exit_int_info;             // VM退出时的中断信息——嵌套中断的向量号和类型
    uint64_t nested_ctl;                // 嵌套虚拟化控制——启用嵌套SVM
    uint64_t avic_vapic_bar;            // AVIC虚拟APIC基址——虚拟中断控制器
    uint8_t reserved_5[8];              // 保留区域
    uint32_t event_inj;                 // 事件注入——向Guest注入异常/中断
    uint32_t event_inj_err;             // 事件注入错误码
    uint64_t nested_cr3;                // 嵌套虚拟化的CR3——嵌套Guest的页表基址
    uint64_t virt_ext;                  // 虚拟化扩展控制
    uint32_t clean;                     // VMCB清洁位——标记哪些区域未被修改，避免不必要的加载
    uint32_t reserved_6;                // 保留区域
    uint64_t next_rip;                  // 下一条指令的RIP——VM退出后Guest恢复执行的地址
    uint8_t insn_len;                   // 导致VM退出的指令长度
    uint8_t insn_bytes[15];             // 导致VM退出的指令字节——最多15字节(x86指令最大长度)
    uint64_t avic_backing_page;         // AVIC backing页物理地址
    uint8_t reserved_7[8];              // 保留区域
    uint64_t avic_logical_id;           // AVIC逻辑ID表物理地址
    uint64_t avic_physical_id;          // AVIC物理ID表物理地址
    uint8_t reserved_8[768];            // 保留区域——填充到VMCB总大小4KB
} __attribute__((__packed__)) vmcb_control_t;

/// 段寄存器描述符结构体——描述一个x86段寄存器的完整信息
/// 包括selector(段选择子)、attrib(段属性)、limit(段限长)、base(段基址)
typedef struct {
    uint16_t selector;                  // 段选择子——索引GDT/LDT中的描述符
    uint16_t attrib;                    // 段属性——类型、DPL、Present等
    uint32_t limit;                     // 段限长——段的最大偏移量
    uint64_t base;                      // 段基址——段的起始线性地址
} __attribute__((__packed__)) seg_t;

/// VMCB状态保存区域结构体——保存Guest的完整CPU状态
/// VMRUN执行前，Host将Guest的目标状态写入此区域；
/// VM退出后，CPU将Guest的当前状态更新到此区域。
typedef struct {
    seg_t es;                           // ES段寄存器——附加数据段
    seg_t cs;                           // CS段寄存器——代码段
    seg_t ss;                           // SS段寄存器——栈段
    seg_t ds;                           // DS段寄存器——数据段
    seg_t fs;                           // FS段寄存器——附加段1
    seg_t gs;                           // GS段寄存器——附加段2
    seg_t gdtr;                         // GDTR——全局描述符表寄存器
    seg_t ldtr;                         // LDTR——局部描述符表寄存器
    seg_t idtr;                         // IDTR——中断描述符表寄存器
    seg_t tr;                           // TR——任务寄存器
    uint8_t reserved_1[43];             // 保留区域
    uint8_t cpl;                        // 当前特权级(CPL)——Ring0或Ring3
    uint8_t reserved_2[4];              // 保留区域
    uint64_t efer;                      // EFER——扩展功能启用寄存器(SCE, LME, LMA, NX, SVME)
    uint64_t reserved_2a;               // 保留区域
    uint64_t perf_ctl0;                 // 性能计数器控制0——PMC0的事件选择
    uint64_t perf_ctr0;                 // 性能计数器值0——PMC0的计数值
    uint64_t perf_ctl1;                 // 性能计数器控制1
    uint64_t perf_ctr1;                 // 性能计数器值1
    uint64_t perf_ctl2;                 // 性能计数器控制2
    uint64_t perf_ctr2;                 // 性能计数器值2
    uint64_t perf_ctl3;                 // 性能计数器控制3
    uint64_t perf_ctr3;                 // 性能计数器值3
    uint64_t perf_ctl4;                 // 性能计数器控制4
    uint64_t perf_ctr4;                 // 性能计数器值4
    uint64_t perf_ctl5;                 // 性能计数器控制5
    uint64_t perf_ctr5;                 // 性能计数器值5
    uint64_t reserved_3;                // 保留区域
    uint64_t cr4;                       // CR4——控制寄存器4(PAE, PGE, VMXE等)
    uint64_t cr3;                       // CR3——页目录基址寄存器(Guest的页表物理地址)
    uint64_t cr0;                       // CR0——控制寄存器0(PE, PG, WP等)
    uint64_t dr7;                       // DR7——调试控制寄存器
    uint64_t dr6;                       // DR6——调试状态寄存器
    uint64_t rflags;                    // RFLAGS——标志寄存器(CF, ZF, IF等)
    uint64_t rip;                       // RIP——指令指针寄存器(Guest当前执行地址)
    uint8_t reserved_4[88];             // 保留区域
    uint64_t rsp;                       // RSP——栈指针寄存器
    uint8_t reserved_5[24];             // 保留区域
    uint64_t rax;                       // RAX——累加器寄存器
    uint64_t star;                      // STAR——Syscall/Sysret目标地址
    uint64_t lstar;                     // LSTAR——64位Syscall目标地址
    uint64_t cstar;                     // CSTAR——32位兼容模式Syscall目标地址
    uint64_t sfmask;                    // SFMASK——Syscall时RFLAGS的屏蔽位
    uint64_t kernel_gs_base;            // KernelGsBase——SwapGS交换的GS基址
    uint64_t sysenter_cs;               // SYSENTER_CS——Sysenter段选择子
    uint64_t sysenter_esp;              // SYSENTER_ESP——Sysenter栈指针
    uint64_t sysenter_eip;              // SYSENTER_EIP——Sysenter入口地址
    uint64_t cr2;                       // CR2——页故障线性地址(触发#PF的地址)
    uint8_t reserved_6[32];             // 保留区域
    uint64_t g_pat;                     // Guest PAT——页属性表(Guest的缓存属性配置)
    uint64_t dbgctl;                    // 调试控制寄存器——LBR、冻结等控制
    uint64_t br_from;                   // 最后分支来源地址——LBR记录
    uint64_t br_to;                     // 最后分支目标地址——LBR记录
    uint64_t last_excp_from;            // 最后异常来源地址
    uint64_t last_excp_to;              // 最后异常目标地址
} __attribute__((__packed__)) vmcb_save_t;

/// VMCB完整结构体——包含control和save两个区域
/// 每个Guest Actor对应一个VMCB，VMRUN指令加载VMCB并进入Guest
typedef struct {
    vmcb_control_t control;             // 控制区域——拦截规则和退出信息
    vmcb_save_t save;                   // 状态保存区域——Guest CPU状态
} __attribute__((packed)) vmcb_t;


// =================================================================================================
// 模块接口——SVM虚拟化的管理函数
/// VMCB中RIP字段的偏移量——用于汇编中直接访问VMCB.save.rip
#define VMCB_RIP_OFFSET offsetof(vmcb_t, save.rip)

/// SVM操作状态标志——为true表示当前正在运行Guest Actor
extern bool svm_is_on;

/// VMCB物理地址数组——每个Guest Actor对应的VMCB页的物理地址
/// 用于配置嵌套页表(NPT)——NPT需要物理地址而非虚拟地址
extern uint64_t *vmcb_hpas;

/// VMCB虚拟地址数组——每个Guest Actor对应的VMCB页的虚拟地址
/// 用于直接修改VMCB字段（如设置RIP、CR0、拦截位图等）
extern uint64_t *vmcb_hvas;

/// 检查CPU是否支持AMD SVM虚拟化——验证必要的CPU特性
/// 包括：SVM支持(CPUID)、NRIP_Save、FlushByAsid等
/// @return 0表示支持，负数表示不支持
int svm_check_cpu_compatibility(void);

/// 启动SVM操作——保存原始CPU状态并配置虚拟化环境
/// 包括：设置EFER.SVME、配置VMCB、启用SVM
/// @return 0表示成功，负数表示错误码
int start_svm_operation(void);

/// 停止SVM操作——恢复原始CPU状态
/// 此函数可在异常处理程序中使用，不会失败
void stop_svm_operation(void);

/// 保存原始VMCB状态——记录当前VMCB字段值用于后续恢复
/// @return 0表示成功，负数表示错误码
int store_orig_vmcb_state(void);

/// 恢复原始VMCB状态——将VMCB恢复为测试前的配置
void restore_orig_vmcb_state(void);

/// 设置VMCB状态——为所有Guest Actor配置VMCB字段
/// 包括：设置拦截位图、CR寄存器、段寄存器、RIP等
/// @return 0表示成功，负数表示错误码
int set_vmcb_state(void);

/// 打印SVM退出信息——解码VMCB中的exit_code和exit_info
/// 用于调试和诊断Guest VM退出事件
/// @return 0表示成功，负数表示错误码
int print_svm_exit_info(void);

/// 初始化SVM模块——分配VMCB和辅助数据结构的内存
/// @return 0表示成功，负数表示错误码
int init_svm(void);

/// 释放SVM模块分配的所有内存
void free_svm(void);

#endif // _RVZR_EXECUTOR_SVM_H_

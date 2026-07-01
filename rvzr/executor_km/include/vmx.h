/// File: Header for vmx.c
///
// ==============================================================================
// Intel VMX（虚拟机扩展）头文件概述：
// 本文件定义了Intel VMX虚拟化技术的核心数据结构和接口函数，
// 是Intel平台侧信道模糊测试中Guest Actor配置的基础。
//
// VMX(Virtual Machine Extensions)是Intel的硬件虚拟化技术，
// 通过VMCS(Virtual Machine Control Structure)管理Guest虚拟机的状态。
// 与AMD SVM的关键区别：
//   - Intel使用VMCS + vmwrite/vmread/vmlaunch/vmresume指令管理虚拟化
//   - AMD使用VMCB(Virtual Machine Control Block) + 直接内存访问 + vmrun指令
//   - Intel VM进入通过VMLAUNCH/VMRESUME指令（从VMCS加载状态）
//   - AMD VM进入通过VMRUN指令（从VMCB加载状态）
//   - Intel VM退出信息存储在VMCS的read-only字段中
//   - AMD VM退出信息存储在VMCB的control区域中
//
// VMXON区域：4KB对齐的特殊内存区域，VMXON指令使用此区域初始化VMX操作。
// VMCS区域：4KB对齐的特殊内存区域，存储一个Guest虚拟机的完整配置和状态。
// 每个VMCS包含6个区域：Guest-state, Host-state, VM-Execution Controls,
// VM-Exit Controls, VM-Entry Controls, VM-Exit Information。
//
// 本文件还处理不同Linux内核版本间的VMX常量命名差异。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_VMX_H_
#define _RVZR_EXECUTOR_VMX_H_

#include <asm/vmx.h>
#include <linux/types.h>

// =================================================================================================
// 内核兼容性处理——不同Linux内核版本间VMX常量命名不一致
// =================================================================================================
/// VMX功能启用位——不同内核版本使用不同的命名：
/// 5.x+使用FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
/// 旧版本使用FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#ifdef FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#define FEATURE_VMX_ENABLED_OUTSIDE_SMX FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#elif defined(FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
#define FEATURE_VMX_ENABLED_OUTSIDE_SMX FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#else
#error "FEATURE_VMX_ENABLED_OUTSIDE_SMX not defined"
#endif

/// Feature Control锁定位——不同内核版本的命名差异
#ifdef FEAT_CTL_LOCKED
#define FEATURE_CTL_LOCKED FEAT_CTL_LOCKED
#elif defined(FEATURE_CONTROL_LOCKED)
#define FEATURE_CTL_LOCKED FEATURE_CONTROL_LOCKED
#else
#error "FEATURE_CTL_LOCKED not defined"
#endif

/// Feature Control MSR地址——不同内核版本的命名差异
#ifdef MSR_IA32_FEAT_CTL
#define MSR_FEATURE_CONTROL MSR_IA32_FEAT_CTL
#elif defined(MSR_IA32_FEATURE_CONTROL)
#define MSR_FEATURE_CONTROL MSR_IA32_FEATURE_CONTROL
#else
#error "MSR_FEATURE_CONTROL not defined"
#endif

/// XSAVES启用位——不同内核版本间命名不一致的兼容处理
#ifndef SECONDARY_EXEC_XSAVES
#define SECONDARY_EXEC_XSAVES SECONDARY_EXEC_ENABLE_XSAVES
#endif

// =================================================================================================
// Host VMX数据结构——VMXON和VMCS区域的定义
// =================================================================================================
/// VMXON区域大小——4KB，Intel SDM要求VMXON区域必须为4KB对齐
#define VMXON_SIZE 4096 // 4KB, as defined in SDM "Enabling and Entering VMX Operation"
/// VMCS区域大小——4KB，Intel SDM要求VMCS区域必须为4KB对齐
#define VMCS_SIZE  4096 // 4KB, as defined in SDM "Format of the VMCS Region"

/// VMXON区域结构体——VMX操作初始化时使用的特殊内存区域
/// 包含revision_id(VMCS版本号，CPU写入)和data(VMXON状态，CPU内部使用)
/// 此区域必须4KB对齐，物理连续
typedef struct {
    uint32_t revision_id : 30;          // VMCS版本号——CPU支持的VMCS格式版本
    uint32_t reserved_31 : 1;           // 保留位31
    uint8_t data[VMXON_SIZE - 4];       // VMXON操作数据——CPU内部使用，软件不应修改
} __attribute__((packed)) vmxon_region_t;

/// VMCS区域结构体——存储一个Guest虚拟机的完整配置和状态
/// 包含revision_id(VMCS版本号)、abort_indicator(VMCS中止标志)和data(VMCS字段)
/// VMWRITE/VMREAD指令通过VMCS区域读写Guest/Host配置
typedef struct {
    uint32_t revision_id : 30;          // VMCS版本号——必须与CPU支持的版本匹配
    uint32_t reserved_31 : 1;           // 保留位31
    uint32_t abort_indicator;           // VMCS中止标志——VMLAUNCH/VMRESUME失败时CPU设置此字段
    uint8_t data[VMCS_SIZE - 8];        // VMCS数据区域——包含6个区域的全部字段
} __attribute__((packed)) vmcs_t;

// =================================================================================================
// 模块接口——VMX虚拟化的管理函数
/// VMX操作状态标志——为true表示当前正在运行Guest Actor
extern bool vmx_is_on;

/// VMCS物理地址数组——每个Guest Actor对应的VMCS页的物理地址
/// 用于配置EPT——EPT需要物理地址而非虚拟地址
extern uint64_t *vmcs_hpas;

/// 检查CPU是否支持Intel VMX虚拟化——验证必要的CPU特性
/// 包括：VMX支持(CPUID)、EPT支持、VPID、NRIP_Save等
/// @return 0表示支持，负数表示不支持
int vmx_check_cpu_compatibility(void);

/// 启动VMX操作——保存原始CPU状态并配置虚拟化环境
/// 包括：执行VMXON、配置VMCS、执行VMLAUNCH进入Guest
/// @return 0表示成功，负数表示错误码
int start_vmx_operation(void);

/// 停止VMX操作——恢复原始CPU状态并执行VMXOFF
/// 此函数可在异常处理程序中使用，不会失败
void stop_vmx_operation(void);

/// 保存原始VMCS状态——记录当前VMCS字段值用于后续恢复
/// @return 0表示成功，负数表示错误码
int store_orig_vmcs_state(void);

/// 恢复原始VMCS状态——将VMCS恢复为测试前的配置
void restore_orig_vmcs_state(void);

/// 设置VMCS状态——为所有Guest Actor配置VMCS字段
/// 包括：设置VM-Execution Controls、VM-Exit/Entry Controls、
/// Guest/Host-state字段、EPT指针等
/// @return 0表示成功，负数表示错误码
int set_vmcs_state(void);

/// 打印VMX退出信息——解码VMCS中的exit_reason和exit_qualification
/// 用于调试和诊断Guest VM退出事件
/// @return 0表示成功，负数表示错误码
int print_vmx_exit_info(void);

/// 初始化VMX模块——分配VMXON、VMCS和辅助数据结构的内存
/// @return 0表示成功，负数表示错误码
int init_vmx(void);

/// 释放VMX模块分配的所有内存
void free_vmx(void);

#endif // _RVZR_EXECUTOR_VMX_H_

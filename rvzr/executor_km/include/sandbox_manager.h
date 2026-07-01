/// File: Header for sandbox management
///       See docs/sandbox.md for the description of the sandboxing mechanism.
///
// ==============================================================================
// 沙箱管理器头文件概述：
// 本文件定义了沙箱(sandbox)的完整数据布局和管理接口。
//
// 沙箱是侧信道模糊测试的核心执行环境，提供了：
//   1. 内存隔离：测试代码在独立的沙箱区域执行，不干扰宿主机内核
//   2. 权限控制：通过PTE/EPT权限位精确控制每个内存页的访问权限
//   3. 故障注入：通过修改faulty_area的权限位触发页故障，模拟Meltdown类攻击场景
//   4. 测量支持：提供L1D priming area和measurement结构体，支持缓存侧信道测量
//
// 沙箱内存布局（每个Actor）：
//   [util_t]          ← r15指向此基址（工具数据）
//     L1D priming area ← Prime+Probe的缓存填充区域
//     util_vars_t      ← 测试用例与执行器的通信变量
//
//   [actor_data_t]    ← r14指向main_area基址（Actor数据）
//     macro_stack      ← 宏调用时的寄存器保存栈
//     underflow_pad    ← 栈下溢保护（零填充）
//     main_area        ← 主输入页（不触发故障）
//     faulty_area      ← 故障输入页（可触发故障）
//     reg_init_area    ← 寄存器初始化区域
//     overflow_pad     ← 栈上溢保护（零填充）
//
//   [actor_code_t]    ← 测试代码区域
//     section          ← 展开后的测试代码
//     macros           ← 展开后的宏代码
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SANDBOX_MANAGER_H_
#define _SANDBOX_MANAGER_H_

#include <linux/types.h>

#include "sandbox_constants.h"

#include "hardware_desc.h" // L1D_ASSOCIATIVITY
#include "measurement.h"   // measurement_t

// =================================================================================================
// 沙箱数据布局——定义沙箱内存中各区域的结构体
// =================================================================================================
/// @brief 测试用例全局变量区域——用于与执行器通信和存储中间结果
///        这些变量在汇编中通过r15(util基址)+常量偏移访问
typedef struct {
    uint64_t stored_rsp;              // 保存测试前的栈指针——宏调用后恢复原始栈
    measurement_t latest_measurement; // 最新测量结果——MACRO_MEASUREMENT_END写入此字段
    uint64_t unused1;                 // 未使用字段（预留）
#ifdef ARCH_X86_64
    /// x86_64的K2U/U2K目标地址通过PTE权限控制，不需要存储在util_vars中
    uint8_t unused[UTIL_VARS_MAX - sizeof(measurement_t) - (2 * sizeof(uint64_t))];
#elif defined(ARCH_ARM)
    uint64_t k2u_target_address; // K2U切换目标地址——ARM64需要显式存储切换目标
    uint64_t u2k_target_address; // U2K切换目标地址——ARM64需要显式存储切换目标
    uint8_t unused[UTIL_VARS_MAX - sizeof(measurement_t) - (4 * sizeof(uint64_t))];
#endif // ARCH_ARM
} util_vars_t;

/// @brief 工具数据结构体——各种测试原语使用的辅助数据
///        必须严格分配在main actor数据之前，因为测试代码通过
///        常量偏移(r15基址)访问此结构体的字段
typedef struct {
    uint8_t l1d_priming_area[L1D_PRIMING_AREA_SIZE]; // L1D缓存填充区域——Prime+Probe第一步
    util_vars_t vars;                                // 测试用例通信变量
} __attribute__((packed)) util_t;

/// @brief Actor数据结构体——Actor代码可访问的全部内存区域
///        每个Actor有独立的actor_data_t，包含输入数据和寄存器初始值
typedef struct {
    uint8_t macro_stack[MACRO_STACK_SIZE];     // 宏调用寄存器保存栈
    uint8_t underflow_pad[UNDERFLOW_PAD_SIZE]; // 栈下溢保护区域（零填充）
    uint8_t main_area[MAIN_AREA_SIZE];         // 主输入页——不触发页故障
    uint8_t faulty_area[FAULTY_AREA_SIZE];     // 故障输入页——可触发页故障（侧信道测试核心）
    uint8_t reg_init_area[REG_INIT_AREA_SIZE]; // 寄存器初始化区域——测试前加载CPU寄存器值
    uint8_t overflow_pad[OVERFLOW_PAD_SIZE];   // 栈上溢保护区域（零填充）
} __attribute__((packed)) actor_data_t;

// =================================================================================================
// 沙箱代码布局——Actor代码区域的结构体定义
// =================================================================================================
/// Actor代码结构体——每个Actor的测试代码和宏展开代码
typedef struct {
    uint8_t section[MAX_EXPANDED_SECTION_SIZE]; // 展开后的测试代码段（最多8KB）
    uint8_t macros[MAX_EXPANDED_MACROS_SIZE];   // 展开后的宏代码区域（最多4KB）
} __attribute__((packed)) actor_code_t;

// =================================================================================================
// sandbox_t——沙箱的顶层结构体，包含所有Actor的数据和代码指针
// =================================================================================================
/// 沙箱顶层结构体——指向所有Actor的数据、代码和工具区域
/// 每个Actor在data/code/util数组中有对应的条目
typedef struct {
    actor_data_t *data;  // 所有Actor的数据区域数组
    actor_code_t *code;  // 所有Actor的代码区域数组
    util_t *util;        // 所有Actor的工具数据数组
} sandbox_t;

// =================================================================================================
// 沙箱管理器接口——沙箱的分配、配置和释放函数
// =================================================================================================
/// 全局沙箱实例——包含所有Actor的数据和代码指针
extern sandbox_t *sandbox;

/// 获取沙箱总大小（以页为单位）——计算所有Actor的数据+代码+工具区域总页数
/// @return 沙箱占用的总页数
int get_sandbox_size_pages(void);

/// 设置沙箱页表——为所有Actor的数据/代码/工具区域配置正确的EPT/PTE权限
/// 包括为Guest Actor设置嵌套页表(EPT/NPT/Stage-2)
/// @return 0表示成功，负数表示错误码
int set_sandbox_page_tables(void);

/// 恢复沙箱页表为原始权限——测试完成后恢复所有修改的权限位
void restore_orig_sandbox_page_tables(void);

/// 设置faulty_area的权限为故障触发配置——移除权限位使其触发页故障
void set_faulty_page_permissions(void);

/// 恢复faulty_area的权限为正常配置
void restore_faulty_page_permissions(void);

/// 分配沙箱内存——为所有Actor分配数据、代码和工具区域
/// 使用alloc_pages确保物理连续内存（避免跨页边界影响缓存行为）
/// @return 0表示成功，负数表示错误码
int allocate_sandbox(void);

/// 重置代码区域——清零所有Actor的代码区域，准备加载新的测试用例
void reset_code_area(void);

/// 初始化沙箱管理器——分配沙箱结构和所有Actor的内存
/// @return 0表示成功，负数表示错误码
int init_sandbox_manager(void);

/// 释放沙箱管理器分配的所有内存
void free_sandbox_manager(void);

#endif // _SANDBOX_MANAGER_H_

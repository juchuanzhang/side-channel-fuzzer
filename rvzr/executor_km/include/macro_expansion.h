/// File: Header for test case macro loader
///
// ==============================================================================
// 宏展开头文件概述：
// 本文件定义了测试用例中宏(macro)的展开机制，是侧信道测试用例的核心组件。
//
// 宏(Macro)是测试用例中的特殊标记，代表预定义的代码序列。
// 在测试用例加载时，宏被展开为对应的汇编代码序列，插入到测试代码中。
//
// 宏的类型和功能：
//   1. 测量宏：开始/结束侧信道测量（Prime+Probe, Flush+Reload, TSC等）
//   2. 故障处理宏：处理测试中触发的异常（页故障、一般保护故障等）
//   3. 特权级切换宏：模拟跨特权级攻击场景
//      - K2U（Kernel→User）：模拟从内核态到用户态的切换
//      - U2K（User→Kernel）：模拟从用户态到内核态的切换
//      - H2G（Host→Guest）：模拟从宿主机到虚拟机的切换
//      - G2H（Guest→Host）：模拟从虚拟机到宿主机的切换
//   4. Landing宏：切换后的着陆点代码
//   5. 数据权限设置宏：动态修改数据区域的页表权限
//
// 宏展开流程：
//   1. test_case_parser识别测试代码中的宏标记（MACRO_START/END token）
//   2. expand_macro根据宏名称和参数，调用对应的宏描述符(macro_descr_t)
//   3. 宏描述符的start函数生成宏的入口代码，body函数包含宏的主体逻辑
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_MACRO_LOADER_H_
#define _RVZR_MACRO_LOADER_H_

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "test_case_parser.h"
#include <linux/types.h>

// =================================================================================================
// 宏名称枚举——标识所有可能的宏类型
// =================================================================================================
/// 宏名称枚举——每个值对应一种预定义的测试用例宏
typedef enum {
    NONMACRO_FUNCTION = 0,              // 非宏函数——普通代码段
    MACRO_MEASUREMENT_START = 1,        // 测量开始宏——启动侧信道测量
    MACRO_MEASUREMENT_END = 2,          // 测量结束宏——停止侧信道测量并收集结果
    MACRO_FAULT_HANDLER = 3,            // 故障处理宏——捕获并处理异常
    MACRO_SWITCH = 4,                   // 通用切换宏——执行特权级/模式切换
    MACRO_SET_K2U_TARGET = 5,          // 设置K2U切换目标地址
    MACRO_SWITCH_K2U = 6,              // 执行Kernel→User切换
    MACRO_SET_U2K_TARGET = 7,          // 设置U2K切换目标地址
    MACRO_SWITCH_U2K = 8,              // 执行User→Kernel切换
    MACRO_SET_H2G_TARGET = 9,          // 设置H2G切换目标地址
    MACRO_SWITCH_H2G = 10,             // 执行Host→Guest切换
    MACRO_SET_G2H_TARGET = 11,         // 设置G2H切换目标地址
    MACRO_SWITCH_G2H = 12,             // 执行Guest→Host切换
    MACRO_LANDING_K2U = 13,            // K2U切换着陆点——切换后在User态执行的代码
    MACRO_LANDING_U2K = 14,            // U2K切换着陆点——切换后在Kernel态执行的代码
    MACRO_LANDING_H2G = 15,            // H2G切换着陆点——切换后在Guest态执行的代码
    MACRO_LANDING_G2H = 16,            // G2H切换着陆点——切换后在Host态执行的代码
    MACRO_FAULT_HANDLER_WITH_MEASUREMENT = 17, // 带测量的故障处理宏——在故障处理期间继续测量
    MACRO_SET_DATA_PERMISSIONS = 18,    // 数据权限设置宏——动态修改数据区域的EPT/PTE权限
} macro_name_e;

// =================================================================================================
// 宏子类型枚举——标识宏的具体实现变体
// =================================================================================================
/// 宏子类型枚举——每种宏可能有多种实现方式
/// 例如：测量宏可以有Prime+Probe、Flush+Reload、TSC等多种实现
typedef enum {
    TYPE_UNDEFINED,                     // 未定义类型
    TYPE_PRIME,                         // Prime阶段——填充缓存（Prime+Probe攻击的第一步）
    TYPE_FAST_PRIME,                    // 快速Prime——优化版本的Prime，使用更快的缓存填充方式
    TYPE_PARTIAL_PRIME,                 // 部分Prime——仅填充部分缓存集（减少测量噪声）
    TYPE_FAST_PARTIAL_PRIME,            // 快速部分Prime——优化版本的部分Prime
    TYPE_PROBE,                         // Probe阶段——检测缓存状态（Prime+Probe攻击的第二步）
    TYPE_FLUSH,                         // Flush阶段——刷新特定缓存行（Flush+Reload攻击的第一步）
    TYPE_EVICT,                         // Evict阶段——通过缓存冲突驱逐特定行（Evict+Reload攻击）
    TYPE_RELOAD,                        // Reload阶段——重新加载并测量访问时间（Flush/Evict+Reload第二步）
    TYPE_TSC_START,                     // TSC测量开始——记录时间戳计数器起始值
    TYPE_TSC_END,                       // TSC测量结束——记录时间戳计数器结束值
    TYPE_FAULT_HANDLER,                 // 故障处理——捕获异常后继续执行
    TYPE_FAULT_AND_PROBE,               // 故障处理+Probe——在故障处理期间执行Probe
    TYPE_FAULT_AND_RELOAD,              // 故障处理+Reload——在故障处理期间执行Reload
    TYPE_FAULT_AND_TSC_END,             // 故障处理+TSC结束——在故障处理期间记录TSC
    TYPE_SWITCH,                        // 通用切换——执行特权级/模式切换
    TYPE_SET_K2U_TARGET,                // 设置K2U目标地址
    TYPE_SWITCH_K2U,                    // 执行K2U切换
    TYPE_SET_U2K_TARGET,                // 设置U2K目标地址
    TYPE_SWITCH_U2K,                    // 执行U2K切换
    TYPE_SET_H2G_TARGET,                // 设置H2G目标地址
    TYPE_SWITCH_H2G,                    // 执行H2G切换
    TYPE_SET_G2H_TARGET,                // 设置G2H目标地址
    TYPE_SWITCH_G2H,                    // 执行G2H切换
    TYPE_LANDING_K2U,                   // K2U着陆点
    TYPE_LANDING_U2K,                   // U2K着陆点
    TYPE_LANDING_H2G,                   // H2G着陆点
    TYPE_LANDING_G2H,                   // G2H着陆点
    TYPE_SET_DATA_PERMISSIONS,          // 设置数据权限
} macro_subtype_e;

// =================================================================================================
// 宏描述符——定义宏的展开逻辑
// =================================================================================================
/// 宏参数结构体——传递给宏展开函数的参数
/// 每个宏最多接受4个16位参数(arg1-arg4)和1个64位owner字段
typedef struct {
    uint16_t arg1;          // 宏参数1
    uint16_t arg2;          // 宏参数2
    uint16_t arg3;          // 宏参数3
    uint16_t arg4;          // 宏参数4
    uint64_t owner;         // 宏所属的Actor ID
} macro_args_t;

/// 宏描述符结构体——定义一种宏的展开逻辑
/// 每种宏类型对应一个描述符，包含两个函数指针：
///   - start：生成宏的入口代码，将汇编指令写入目标缓冲区，返回代码大小
///   - body：宏的主体逻辑（通常在汇编中直接实现，不需要C函数）
typedef struct {
    size_t (*start)(macro_args_t args, uint8_t *dest); // 宏入口代码生成函数
    void (*body)(void);                                // 宏主体逻辑函数
} macro_descr_t;

/// 宏描述符数组——索引为macro_name_e枚举值
/// 每个元素对应一种宏类型的展开逻辑
extern macro_descr_t macro_descriptors[];

// =================================================================================================
// 宏解析的常量定义——用于识别测试代码中的宏标记
// =================================================================================================
/// 宏起始标记——8字节特殊值，标记测试代码中宏的开始位置
/// 由模糊测试引擎在生成测试用例时插入
#define MACRO_START              0x0fff379000000000
/// 宏结束标记——8字节特殊值，标记测试代码中宏的结束位置
#define MACRO_END                0x0fff2f9000000000
/// 宏起始标记长度——8字节
#define MACRO_START_TOKEN_LENGTH 8
/// 宏结束标记长度——8字节
#define MACRO_END_TOKEN_LENGTH   8

/// 宏占位符大小——宏标记在代码中被替换时占用的空间
/// x86_64：8字节（一个指令的典型长度）
/// ARM64：12字节（AArch64指令可能需要更多空间）
#if defined(ARCH_X86_64)
#define MACRO_PLACEHOLDER_SIZE 8
#elif defined(ARCH_ARM)
#define MACRO_PLACEHOLDER_SIZE 12
#endif

// =================================================================================================
// 公共接口
// =================================================================================================
/// 展开测试用例中的宏——将宏标记替换为对应的汇编代码序列
/// @param macro 符号表中的宏条目（包含宏名称、参数和偏移量）
/// @param dest 宏代码的目标缓冲区地址
/// @param macro_dest 宏展开结果的目标地址
/// @param macro_size 输出参数，宏展开后的代码大小
/// @return 0表示成功，负数表示错误码
int expand_macro(tc_symbol_entry_t *macro, uint8_t *dest, uint8_t *macro_dest, size_t *macro_size);

/// 设置主程序前导码（prologue）的大小
/// 前导码是测试代码入口前的初始化代码，用于设置寄存器和测量状态
void set_main_prologue_size(size_t size);

/// 获取主程序前导码的大小
size_t get_main_prologue_size(void);

#endif // _RVZR_MACRO_LOADER_H_

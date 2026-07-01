/// File: Collection of constants that define the layout of the sandbox;
///       This file is intentionally separate from sandbox_manager.h so that
///       it can be included in assembly files as well.
///
// ==============================================================================
// 沙箱常量定义头文件概述：
// 本文件定义了沙箱(sandbox)内存布局的所有常量，是侧信道测试框架的基础配置。
//
// 沙箱是测试用例执行的隔离环境，包含：
//   1. util_t：工具数据区域
//      - L1D priming area：缓存填充区域（Prime+Probe攻击的第一步）
//      - util_vars_t：测试用例与执行器通信的变量区域
//        （stored_rsp, measurement, k2u/u2k_target等）
//
//   2. actor_data_t：Actor数据区域（每个Actor一份）
//      - macro_stack：宏调用时的寄存器保存栈
//      - underflow_pad：栈下溢保护区域（零填充，防止越界写）
//      - main_area：主输入页（4KB，不触发页故障）
//      - faulty_area：故障输入页（4KB，可触发页故障——Meltdown类测试核心）
//      - reg_init_area：寄存器初始化区域（测试前加载CPU寄存器初始值）
//      - overflow_pad：栈上溢保护区域
//
//   3. actor_code_t：Actor代码区域（每个Actor一份）
//      - section：展开后的测试代码段（最多8KB）
//      - macros：展开后的宏代码区域（最多4KB）
//
// 本文件刻意与sandbox_manager.h分离，以便汇编文件也能包含这些常量。
// 汇编代码通过r14（main_area基址）和r15（util基址）+常量偏移访问各区域。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SANDBOX_CONSTANTS_H_
#define _SANDBOX_CONSTANTS_H_

#include "hardware_desc.h"

/// uint64_t的大小——8字节，用于计算偏移量
#define SIZE_UINT64 (8)

// =================================================================================================
// util_t布局常量——工具数据区域的内存布局
// =================================================================================================
/// 工具变量区域最大大小——4KB，包含stored_rsp、measurement等
#define UTIL_VARS_MAX         4096
/// L1D缓存填充区域大小——等于L1D缓存总大小
/// Prime+Probe攻击需要填充整个L1D缓存以驱逐所有目标缓存集
#define L1D_PRIMING_AREA_SIZE (L1D_SIZE_KB * 1024ULL)
/// 保存的RSP大小——8字节，存储测试前的栈指针
#define STORED_RSP_SIZE       SIZE_UINT64
/// 测量结果大小——56字节（见measurement.h的measurement_t结构体）
/// 包含htrace(8B) + pfc_reading(40B) + status(8B) = 56B
#define MEASUREMENT_SIZE      56ULL // see measurement.h
/// 嵌套故障标志大小——8字节，标记是否发生了嵌套故障
#define NESTED_FAULT_SIZE     SIZE_UINT64

// =================================================================================================
// actor_data_t布局常量——Actor数据区域的内存布局
// =================================================================================================
/// 宏调用栈大小——64字节，用于保存调用宏时的寄存器状态
/// 宏调用时需要保存/恢复所有通用寄存器，64字节足够存储8个64位寄存器
#define MACRO_STACK_SIZE   64
/// 栈下溢保护区域大小——填充零字节，防止macro_stack下溢时破坏其他数据
#define UNDERFLOW_PAD_SIZE (4096 - MACRO_STACK_SIZE)
/// 主输入区域大小——4KB，映射到沙箱的main_area页
/// main_area的PTE权限设置为正常可访问（不触发页故障）
#define MAIN_AREA_SIZE     4096
/// 故障输入区域大小——4KB，映射到沙箱的faulty_area页
/// faulty_area的PTE权限可配置为触发页故障（Meltdown类测试的核心配置）
#define FAULTY_AREA_SIZE   4096
/// 寄存器初始化区域大小——320字节
/// 包含8个64位GPR初始值(8*8=64B) + 8个256位YMM初始值(8*32=256B) = 320B
#define REG_INIT_AREA_SIZE 320 // 8 64-bit GPRs + 8 256-bit YMMs
/// 栈上溢保护区域大小——填充零字节，防止reg_init_area上溢
#define OVERFLOW_PAD_SIZE  (4096 - REG_INIT_AREA_SIZE)

// =================================================================================================
// 代码段大小常量——Actor代码区域的布局
// =================================================================================================
/// 最大展开代码段大小——8KB（2页）
/// 包含宏展开后的所有测试代码
#define MAX_EXPANDED_SECTION_SIZE (0x1000ULL * 2)
/// 最大展开宏区域大小——4KB（1页）
/// 包含所有宏的展开代码
#define MAX_EXPANDED_MACROS_SIZE  (0x1000ULL)

// =================================================================================================
// util_t偏移量常量——相对于util_t基址(r15)的偏移量
// =================================================================================================
/// L1D填充区域偏移——util_t起始位置（偏移0）
#define L1D_PRIMING_OFFSET (0)
/// 工具变量区域偏移——紧跟在L1D填充区域之后
#define UTIL_VARS_OFFSET   (L1D_PRIMING_OFFSET + L1D_PRIMING_AREA_SIZE)
/// 保存的RSP偏移——util_vars_t内的偏移0
#define STORED_RSP_OFFSET  (UTIL_VARS_OFFSET + 0)
/// 测量结果偏移——util_vars_t内，紧跟stored_rsp之后
#define MEASUREMENT_OFFSET (STORED_RSP_OFFSET + STORED_RSP_SIZE)
/// 未使用区域偏移——紧跟measurement之后
#define UNUSED1_OFFSET     (MEASUREMENT_OFFSET + MEASUREMENT_SIZE)
/// K2U切换目标地址偏移——存储Kernel→User切换的目标地址
#define K2U_TARGET_OFFSET  (UNUSED1_OFFSET + NESTED_FAULT_SIZE)
/// U2K切换目标地址偏移——存储User→Kernel切换的目标地址
#define U2K_TARGET_OFFSET  (K2U_TARGET_OFFSET + SIZE_UINT64)

/// util_t相对于main_actor的main_area基址的偏移量
/// 计算公式：L1D填充区 + 工具变量区 + 下溢保护 + 宏栈
#define UTIL_REL_TO_MAIN                                                                           \
    (L1D_PRIMING_AREA_SIZE + UTIL_VARS_MAX + UNDERFLOW_PAD_SIZE + MACRO_STACK_SIZE)

// =================================================================================================
// actor_data_t偏移量常量——相对于main_area基址(r14)的偏移量
// =================================================================================================
/// 宏栈顶部偏移——等于下溢保护区域大小（栈从高地址向低地址增长）
#define MACRO_STACK_TOP_OFFSET (UNDERFLOW_PAD_SIZE)
/// main_area偏移——从actor_data_t起始处偏移0
#define MAIN_AREA_OFFSET       (0)
/// faulty_area偏移——紧跟在main_area之后（4KB）
#define FAULTY_AREA_OFFSET     (MAIN_AREA_SIZE)
/// 寄存器初始化区域偏移——紧跟在faulty_area之后（4KB）
#define REG_INIT_OFFSET        (FAULTY_AREA_OFFSET + FAULTY_AREA_SIZE)
/// 上溢保护区域偏移——紧跟在reg_init_area之后
#define OVERFLOW_PAD_OFFSET    (REG_INIT_OFFSET + REG_INIT_AREA_SIZE)
/// 局部RSP存储偏移——faulty_area前8字节，用于保存测试期间的栈指针
#define LOCAL_RSP_OFFSET       (FAULTY_AREA_OFFSET - 8)

// =================================================================================================
// 页ID常量——各区域在沙箱内存中的页编号（用于PTE指针缓存索引）
// =================================================================================================
/// main_area页ID——宏栈+下溢保护 = 1页，之后是main_area
#define MAIN_PAGE_ID   ((MACRO_STACK_SIZE + UNDERFLOW_PAD_SIZE) / 4096)
/// faulty_area页ID——宏栈+下溢保护+main_area = 2页，之后是faulty_area
#define FAULTY_PAGE_ID ((MACRO_STACK_SIZE + UNDERFLOW_PAD_SIZE + MAIN_AREA_SIZE) / 4096)

// =================================================================================================
// 页数常量——各组件所需的页数
// =================================================================================================
/// 工具区域页数——util_t结构体占用的4KB页数
#define N_UTIL_PAGES           (sizeof(util_t) / 4096)
/// 每个Actor的数据区域页数——actor_data_t结构体占用的4KB页数
#define N_DATA_PAGES_PER_ACTOR (sizeof(actor_data_t) / 4096)
/// 每个Actor的代码区域页数——actor_code_t结构体占用的4KB页数
#define N_CODE_PAGES_PER_ACTOR (sizeof(actor_code_t) / 4096)

#endif // _SANDBOX_CONSTANTS_H_

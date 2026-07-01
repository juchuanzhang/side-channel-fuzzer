/// File: Header for hardware configuration
///
// ==============================================================================
// 硬件描述头文件概述：
// 本文件定义了目标CPU的硬件配置参数，是整个模糊测试框架的基础配置文件。
//
// 硬件描述决定了：
//   1. CPU厂商和架构类型（Intel x86_64 / AMD x86_64 / ARM64）
//      → 影响虚拟化方案选择（VMX/SVM/ARM VM）、汇编片段、页表结构等
//   2. 物理地址宽度（PHYSICAL_WIDTH）
//      → 影响页表条目中物理地址字段的位宽和最大可寻址内存
//   3. L1数据缓存参数（L1D_ASSOCIATIVITY, L1D_SIZE_KB）
//      → 影响Prime+Probe/Evict+Reload等缓存侧信道测试的参数配置
//
// 这些参数由Makefile在编译时通过-D选项传入，确保与目标平台一致。
// 错误的硬件描述会导致测试结果不准确或内核崩溃。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _HARDWARE_DESC_H_
#define _HARDWARE_DESC_H_

#include <linux/types.h>

/// CPU厂商ID——必须在编译时由Makefile定义，否则触发编译错误
/// 可能的值：1(Intel), 2(AMD), 3(ARM)
#ifndef VENDOR_ID
#error "Undefined VENDOR_ID"
#define VENDOR_ID 0
#endif

/// 验证VENDOR_ID是否为支持的值
/// 不支持或损坏的VENDOR_ID会导致运行时行为不正确
#if VENDOR_ID != 1 && VENDOR_ID != 2 && VENDOR_ID != 3
#error "Unsupported/corrupted VENDOR_ID"
#endif

/// CPU厂商标识——Intel
#define VENDOR_INTEL_ 1
/// CPU厂商标识——AMD
#define VENDOR_AMD_   2
/// CPU厂商标识——ARM
#define VENDOR_ARM_   3
// 清除可能由其他头文件定义的同名宏，避免冲突
#undef VENDOR_INTEL
#undef VENDOR_AMD
#undef VENDOR_ARM

/// 根据VENDOR_ID定义架构宏
/// Intel和AMD均使用x86_64架构，ARM使用AArch64架构
/// 这些宏控制整个代码库中架构特定代码的选择
#if VENDOR_ID == VENDOR_INTEL_
#define ARCH_X86_64
#elif VENDOR_ID == VENDOR_AMD_
#define ARCH_X86_64
#elif VENDOR_ID == VENDOR_ARM_
#define ARCH_ARM
#endif

// =================================================================================================
// CPU识别信息
// =================================================================================================
/// CPU信息结构体类型定义——根据架构选择不同的内部结构
/// x86_64使用内核提供的cpuinfo_x86结构体（包含CPU型号、缓存信息等）
/// ARM64使用自定义结构体（包含implementer、variant、architecture、part、revision）
#ifndef __ASSEMBLER__
#if defined(ARCH_X86_64)
typedef struct cpuinfo_x86 cpuinfo_t;
#elif defined(ARCH_ARM)
typedef struct {
    int implementer;    // 实现者标识（如0x41=ARM Limited）
    int variant;        // 变体号（主要版本）
    int architecture;   // 架构版本
    int part;           // 部件编号（核心型号，如Cortex-A72的0xD08）
    int revision;       // 修订号（次要版本）
} cpuinfo_t;
#endif
#endif // __ASSEMBLER__

// =================================================================================================
// 内存配置
// =================================================================================================
/// 物理地址宽度——必须在编译时由Makefile定义
/// 决定了页表条目中paddr字段的位宽，以及最大可寻址物理地址
/// 例如：51位→最大物理地址2^51=2PB，48位→256TB
#ifndef PHYSICAL_WIDTH
#define PHYSICAL_WIDTH 51 // 仅用于语法高亮，实际编译时会触发错误
#error "PHYSICAL_WIDTH must be defined by the makefile"
#endif

/// 最大物理地址——所有可寻址物理地址的上界
/// 页表条目的paddr字段必须小于此值
#define MAX_PHYSICAL_ADDRESS ((1ULL << PHYSICAL_WIDTH) - 1)

// =================================================================================================
// 缓存配置
// =================================================================================================
/// L1数据缓存关联度——必须在编译时由Makefile定义
/// 决定了Prime+Probe攻击中需要多少个缓存行才能驱逐同一缓存集的所有条目
/// 支持的值：12(Intel Skylake等), 8(Intel Core等), 4(某些低功耗CPU), 2(极小缓存)
#ifndef L1D_ASSOCIATIVITY
#error "Undefined L1D_ASSOCIATIVITY"
#define L1D_ASSOCIATIVITY 0
#elif L1D_ASSOCIATIVITY != 12 && L1D_ASSOCIATIVITY != 8 && L1D_ASSOCIATIVITY != 4 &&               \
    L1D_ASSOCIATIVITY != 2
#warning "Unsupported/corrupted L1D associativity. Falling back to 8-way"
#define L1D_ASSOCIATIVITY 8
#endif

/// L1数据缓存大小(KB)——必须在编译时由Makefile定义
/// 与关联度一起决定了缓存冲突距离(L1D_CONFLICT_DISTANCE)
/// 典型值：32KB（大多数现代CPU）
#ifndef L1D_SIZE_KB
#error "Undefined L1D_SIZE"
#define L1D_SIZE_KB 32 // 仅用于语法高亮
#else
#endif

/// L1数据缓存冲突距离(B)——同一缓存集的行之间的字节距离
/// 计算公式：L1D_SIZE / L1D_ASSOCIATIVITY
/// 例如：32KB / 8-way = 4KB，即每隔4KB的地址映射到同一缓存集
/// Prime+Probe攻击使用此值构造驱逐集(eviction set)
#define L1D_CONFLICT_DISTANCE (L1D_SIZE_KB * 1024 / L1D_ASSOCIATIVITY)

// =================================================================================================
// 杂项定义
// =================================================================================================

/// MSR_SYSCFG——AMD系统配置MSR，内核头文件中可能缺少此定义
/// 地址0xc0010010，用于配置SVM相关功能（如VM启用、嵌套虚拟化等）
#define MSR_SYSCFG 0xc0010010

#endif // _HARDWARE_DESC_H_

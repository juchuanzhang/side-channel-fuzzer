/// File: Main Header
///
// ==============================================================================
// 主配置头文件概述：
// 本文件定义了侧信道模糊测试执行器(executor)的核心配置接口，
// 是整个内核模块的全局配置中心。
//
// 主要配置项：
//   1. 测量模式(measurement_mode_e)：选择侧信道测量的方法
//      - PRIME_PROBE：经典Prime+Probe攻击，通过缓存驱逐/重填测量
//      - PARTIAL_PRIME_PROBE：部分Prime+Probe，减少噪声
//      - FAST_PRIME_PROBE：快速Prime+Probe，优化缓存填充速度
//      - FAST_PARTIAL_PRIME_PROBE：快速部分Prime+Probe
//      - FLUSH_RELOAD：Flush+Reload攻击，通过clflush+时间测量
//      - EVICT_RELOAD：Evict+Reload攻击，通过缓存冲突驱逐
//      - TSC：时间戳计数器测量，直接记录执行时间差
//
//   2. 其他运行时配置：
//      - quick_and_dirty_mode：快速模式，牺牲准确性换取速度
//      - uarch_reset_rounds：微架构重置轮数，控制流水线冲刷强度
//      - enable_ssbp_patch：SSBP修补，防止Store Buffer侧信道
//      - enable_prefetchers：预取器启用，影响缓存行为的真实性
//      - pre_run_flush：每次运行前的缓存冲刷策略
//      - enable_hpa_gpa_collisions：HPA-GPA碰撞，模拟物理地址冲突
//      - dbg_gpr_mode：调试GPR模式，记录通用寄存器变化
//
//   3. 内核兼容性：处理不同Linux内核版本之间的API差异
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_MAIN_H_
#define _RVZR_EXECUTOR_MAIN_H_

#include <asm/cpu.h>
#include <linux/types.h>
#include <linux/version.h>

#include "hardware_desc.h"

/// 测量模式枚举——定义侧信道攻击的具体测量方法
typedef enum {
    PRIME_PROBE,              // Prime+Probe——填充缓存后探测缓存状态变化
    PARTIAL_PRIME_PROBE,      // 部分Prime+Probe——仅填充部分缓存集以减少噪声
    FAST_PRIME_PROBE,         // 快速Prime+Probe——优化缓存填充速度
    FAST_PARTIAL_PRIME_PROBE, // 快速部分Prime+Probe——速度和噪声的折衷
    FLUSH_RELOAD,             // Flush+Reload——clflush刷新后测量重新加载时间
    EVICT_RELOAD,             // Evict+Reload——通过缓存冲突驱逐后测量重新加载时间
    TSC,                      // TSC测量——使用时间戳计数器直接记录时间差
} measurement_mode_e;

/// 调试模式开关——0为正常模式，1为详细调试输出
#define EXECUTOR_DEBUG 0

// =================================================================================================
// 执行器配置接口——所有配置项可通过sysfs在运行时修改
// =================================================================================================
/// 快速模式开关——为true时跳过部分初始化步骤，提高执行速度但可能降低准确性
extern bool quick_and_dirty_mode;
/// 当前测量模式——决定每次测试使用哪种侧信道测量方法
extern measurement_mode_e measurement_mode;
/// 测量模式默认值：PRIME_PROBE（最通用的侧信道测量方法）
#define MEASUREMENT_MODE_DEFAULT PRIME_PROBE
/// 微架构重置轮数——每次测量前冲刷流水线的轮数，越高则测量越干净但越慢
extern long uarch_reset_rounds;
/// 微架构重置轮数默认值：1轮（最快的冲刷策略）
#define UARCH_RESET_ROUNDS_DEFAULT 1
/// SSBP修补开关——防止Store Buffer成为侧信道泄露源
extern bool enable_ssbp_patch;
/// SSBP修补默认值：启用
#define SSBP_PATCH_DEFAULT true
/// 预取器启用开关——为true时保持CPU预取器活跃，增加缓存噪声的真实性
extern bool enable_prefetchers;
/// 预取器默认值：禁用（减少缓存噪声，提高测量精度）
#define PREFETCHER_DEFAULT false
/// 每次运行前的缓存冲刷策略：
/// 0=不冲刷, 1=冲刷全部L1D缓存, 2=冲刷特定缓存行
extern char pre_run_flush;
/// 缓存冲刷默认值：1（冲刷全部L1D缓存）
#define PRE_RUN_FLUSH_DEFAULT 1
/// HPA-GPA碰撞开关——模拟宿主机物理地址与Guest物理地址的冲突
/// 用于测试跨虚拟化边界的缓存侧信道泄露
extern bool enable_hpa_gpa_collisions;
/// HPA-GPA碰撞默认值：禁用
#define HPA_GPA_COLLISIONS_DEFAULT false
/// 调试GPR模式开关——为true时记录每次测试前后通用寄存器的变化
extern bool dbg_gpr_mode;
/// 调试GPR模式默认值：禁用
#define DBG_GPR_MODE_DEFAULT false

// =================================================================================================
// Linux内核兼容性处理——不同内核版本的set_memory_x/nx API差异
// =================================================================================================
/// Linux 5.4+版本将set_memory_x/nx移入kallsyms导出符号，
/// 需要动态查找函数地址；旧版本可直接使用头文件声明
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
extern int (*set_memory_x)(unsigned long, int);  // 设置内存页为可执行
extern int (*set_memory_nx)(unsigned long, int); // 设置内存页为不可执行
#else
#include <linux/set_memory.h>
#endif

/// 缓存的CPU信息——CPU 0的cpu_data查询结果
/// 避免每次测试都查询CPU信息，提高性能
extern cpuinfo_t *cpuinfo;

#endif // _RVZR_EXECUTOR_MAIN_H_

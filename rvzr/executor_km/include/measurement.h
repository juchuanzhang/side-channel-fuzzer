/// File: Header for the measurement manager
///
// ==============================================================================
// 测量管理器头文件概述：
// 本文件定义了侧信道测量的数据结构和接口，是模糊测试结果收集的核心。
//
// 测量(masurement)是侧信道模糊测试的核心产出，包含：
//   1. 硬件追踪(htrace)：缓存侧信道观测结果
//      - Prime+Probe模式：htrace记录哪些缓存集被重填（1bit/集）
//      - Flush+Reload模式：htrace记录哪些共享页被重新加载
//   2. 性能计数器读数(PFC)：微架构事件的精确计数
//      - L1D缓存重填次数、投机指令数、已完成指令数、分支误预测数等
//   3. 测量状态(status)：当前测量的进度和系统干扰信息
//      - SMI计数：记录系统管理中断的发生次数（SMI会干扰测量精度）
//
// 测量流程：
//   1. 测试代码执行MACRO_MEASUREMENT_START开始测量
//   2. 执行测试主体（被测代码段）
//   3. 执行MACRO_MEASUREMENT_END结束测量，收集htrace和PFC数据
//   4. 结果存储在measurements数组中，每条输入对应一个measurement_t
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MEASUREMENT_H_
#define _MEASUREMENT_H_

#include <linux/types.h>
#include <linux/version.h>

/// 硬件追踪宽度——htrace数组的元素数量
/// 目前为1（单元素htrace），存储整个测量期间的综合缓存观测结果
#define HTRACE_WIDTH 1
/// 性能计数器数量——同时追踪的PMU事件数量
/// 5个计数器：L1D缓存重填、投机指令、已完成指令、分支误预测、周期数
#define NUM_PFC      5

/// 测量状态常量——标记当前测量所处的阶段
#define STATUS_UNINITIALIZED 0 // 未初始化——测量尚未开始
#define STATUS_STARTED       1 // 已开始——正在执行测量
#define STATUS_ENDED         2 // 已结束——测量完成，数据已收集

/// 测量状态结构体——记录测量的进度和系统干扰信息
/// packed属性确保结构体布局与测试代码中的汇编访问一致
typedef struct measurement_status {
    uint8_t measurement_state;  // 测量状态（UNINITIALIZED/STARTED/ENDED）
    uint8_t reserved[3];        // 保留字段——对齐到4字节
    uint32_t smi_count;         // SMI中断计数——SMI会冲刷缓存，干扰测量精度
} __attribute__((packed)) measurement_status_t;

/// 测量结果结构体——一条完整的侧信道测量数据
/// 每次测试执行产生一个measurement_t，存储在measurements数组中
/// packed属性确保结构体布局与汇编代码中的偏移量访问一致
/// fields说明：
///   - htrace：硬件追踪结果——缓存侧信道观测值（如缓存集重填位图）
///   - pfc_reading：性能计数器读数——各PMU事件的精确计数
///   - status：测量状态和干扰信息
typedef struct Measurement {
    uint64_t htrace[HTRACE_WIDTH];      // 硬件追踪结果——缓存侧信道观测值
    uint64_t pfc_reading[NUM_PFC];      // 性能计数器读数——5个PMU事件计数
    measurement_status_t status;        // 测量状态和SMI干扰计数
} __attribute__((packed)) measurement_t;

/// 测量结果数组——存储所有输入的测量数据
/// 数组大小等于n_inputs，每条输入对应一个measurement_t
extern measurement_t *measurements;

/// 执行单条测试用例的测量——运行测试代码并收集侧信道数据
/// 流程：设置沙箱→加载输入→执行测试→收集测量→恢复状态
/// @return 0表示成功，负数表示错误码
int trace_test_case(void);

/// 运行完整实验——对所有输入执行测量并汇总结果
/// @return 0表示成功，负数表示错误码
int run_experiment(void);

/// 恢复原始系统状态——测试执行后恢复被修改的CPU状态
/// 包括页表权限、MSR值、缓存状态等
void recover_orig_state(void);

/// 分配测量结果数组内存
/// @return 0表示成功，负数表示错误码
int alloc_measurements(void);

/// 初始化测量管理器——配置PMU计数器和测量参数
/// @return 0表示成功，负数表示错误码
int init_measurements(void);

/// 释放测量管理器分配的所有内存
void free_measurements(void);

#endif // _MEASUREMENT_H_

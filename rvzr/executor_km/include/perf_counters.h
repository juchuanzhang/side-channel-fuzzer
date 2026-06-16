/// 文件：性能计数器配置与管理的头文件
/// 定义ARM64/x86_64 PMU事件选择和计数器配置的接口与常量
///
/// 性能监控单元(PMU)是侧信道模糊测试工具的核心测量基础设施。
/// PMU提供硬件级的事件计数功能，可以精确追踪微架构行为：
///   - 缓存访问/未命中次数(L1D_CACHE_REFILL) → 硬件追踪(htrace)
///   - 投机执行指令数(INST_SPEC) → 模糊测试反馈
///   - 已完成指令数(INST_RETIRED) → 模糊测试反馈
///   - 分支误预测次数(BR_MIS_PRED) → 投机过滤器
///
/// ARM64 PMU与x86 PMU的差异：
///   - ARM64使用PMSELR_EL0/PMXEVTYPER_EL0选择和配置计数器
///   - x86使用MSR_P6_EVNTSEL(Intel)或MSR_F15H_PERF_CTL(AMD)
///   - ARM64的事件编码是简单的evtCount编号(11位)
///   - x86使用evt_num+umask组合编码
///   - ARM64 PMU计数器数量由PMCR_EL0.N字段指定(通常6个)
///   - x86 PMU通常有4个通用计数器+3个固定计数器(Intel)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PERF_COUNTERS_H_
#define _PERF_COUNTERS_H_

#include "hardware_desc.h"

/// @brief 配置性能计数器：设置PMU事件选择器和计数器控制
/// 根据CPU型号选择正确的PMU事件编码，配置所有计数器
/// @return 0表示成功，负数表示错误码
int pfc_configure(void);

/// @brief 初始化性能计数器管理器
/// @return 0表示成功
int init_perf_counters(void);

/// @brief 释放性能计数器管理器资源
void free_perf_counters(void);

// =====================================================================
// ARM64 PMU架构特定定义
// =====================================================================
#ifdef ARCH_ARM

// -----------------------------------------------------------------
// Cortex CPU型号识别常量
// 通过MIDR_EL1寄存器的Part字段识别具体的Cortex核心型号
// MIDR_EL1格式：
//   [31:24] Implementer - 实现者标识(0x41=ARM Limited)
//   [23:20] Variant     - 变体号(主要版本)
//   [19:16] Architecture - 架构版本(0xF=ARMv8-A系列)
//   [15:4]  Part        - 部件编号(核心型号标识)
//   [3:0]   Revision    - 修订号(次要版本)
// -----------------------------------------------------------------

/// ARM实现者标识 - MIDR_EL1[31:24]字段
/// 0x41表示ARM Limited（ARM公司自研核心）
/// 其他值：0x42=Broadcom, 0x43=Cavium, 0x44=DEC, 0x46=Fujitsu,
///          0x48=HiSilicon, 0x49=Infineon, 0x4D=Motorola, 0x4E=NVIDIA,
///          0x50=APM, 0x51=Qualcomm, 0x53=Samsung, 0x56=Marvell,
///          0x61=Ampere, 0x63=Intel
#define ARM_IMPLEMENTER_ID 0x41

/// Cortex A72部件编号 - MIDR_EL1[15:4]字段
/// Cortex A72是ARMv8.0-A实现，3发射顺序流水线，
/// 广泛用于服务器和嵌入式平台（如Raspberry Pi 3B+）
#define CORTEX_A72_PART 0xD08

/// Cortex A76部件编号 - MIDR_EL1[15:4]字段
/// Cortex A76是ARMv8.2-A实现，4发射顺序流水线，
/// 支持更多PMU事件（L2缓存、前端/后端停顿等）
#define CORTEX_A76_PART 0xD0B

/// Cortex A73部件编号 - 用于兼容性检测
#define CORTEX_A73_PART 0xD09

/// Cortex A75部件编号 - 用于兼容性检测
#define CORTEX_A75_PART 0xD0A

/// Cortex A77部件编号 - 用于兼容性检测
#define CORTEX_A77_PART 0xD0C

// -----------------------------------------------------------------
// ARM64 PMU事件编号定义
// ARMv8-A架构定义的PMU事件编号(evtCount)是11位字段，
// 写入PMXEVTYPER_EL0[10:0]来选择要计数的事件。
//
// 不同Cortex型号支持的事件集不同：
//   - 所有ARMv8-A处理器必须支持CPU_CYCLES(0x11)和INST_RETIRED(0x08)
//   - 架构定义事件(如L1D_CACHE_REFILL)是推荐实现但非强制
//   - 实现特定事件因处理器型号而异
// -----------------------------------------------------------------

// === 通用ARMv8-A PMU事件 ===
/// L1D_CACHE_REFILL: L1数据缓存重填事件(0x03)
/// 当L1数据缓存行从外部(L2/主存)加载时计数。
/// 这是侧信道追踪(htrace)收集的核心指标：
///   - Prime+Probe: 重填次数反映缓存行的驱逐/重载
///   - Flush+Reload: 重填次数反映共享内存的重新加载
/// 在Cortex A72和A76上均可用
#define EVENT_L1D_CACHE_REFILL 0x03

/// L1D_CACHE: L1数据缓存访问事件(0x04)
/// 每次L1数据缓存被访问时计数（无论命中或未命中）。
/// 可用于计算L1缓存命中率 = (L1D_CACHE - L1D_CACHE_REFILL) / L1D_CACHE
#define EVENT_L1D_CACHE 0x04

/// INST_RETIRED: 已完成指令计数事件(0x08)
/// 计数架构上已完成的指令数量。
/// 与INST_SPEC对比可以衡量投机执行的程度：
///   投机执行量 = INST_SPEC - INST_RETIRED
///   这是因为投机执行的指令可能最终被放弃(不完成retire)
/// 所有ARMv8-A处理器必须实现此事件
#define EVENT_INST_RETIRED 0x08

/// BR_MIS_PRED: 分支误预测事件(0x10)
/// 当分支预测器预测错误时计数。
/// 分支误预测会导致流水线冲刷和恢复，这是投机执行漏洞的关键指标：
///   - Spectre类漏洞利用误预测后的投机执行路径
///   - 误预测率高的代码区域可能包含可利用的投机窗口
/// 在Cortex A72和A76上均可用
#define EVENT_BR_MIS_PRED 0x10

/// CPU_CYCLES: CPU周期计数事件(0x11)
/// 计数处理器运行的时钟周期数。
/// 所有ARMv8-A处理器必须实现此事件。
/// ARM64使用周期计数器PMCCNTR_EL0单独计数周期，
/// 此事件编号也可分配给可编程计数器
#define EVENT_CPU_CYCLES 0x11

/// BR_PRED: 分支预测事件(0x12)
/// 当分支预测器做出预测时计数（无论正确或错误）。
/// 分支预测率 = BR_PRED / (BR_PRED + BR_MIS_PRED)
/// 高预测率表示分支预测器对代码路径非常"熟悉"
#define EVENT_BR_PRED 0x12

/// INST_SPEC: 投机执行指令计数事件(0x1B)
/// 计数投机执行的指令数量（包括最终被放弃的指令）。
/// 这是模糊测试反馈的关键指标之一：
///   - 与INST_RETIRED对比：INST_SPEC > INST_RETIRED表示发生了投机执行
///   - 投机执行的指令数量反映代码路径对流水线的影响
///   - 在Spectre类漏洞检测中：高投机执行量可能暗示漏洞利用窗口
/// 在Cortex A72和A76上均可用
#define EVENT_INST_SPEC 0x1B

// === Cortex A76扩展PMU事件 ===
/// L2D_CACHE: L2数据缓存访问事件(0x16)
/// 每次L2数据缓存被访问时计数（无论命中或未命中）。
/// 仅Cortex A76及以上型号支持（ARMv8.2-A）。
/// Cortex A72不支持此事件（A72的L2缓存是共享缓存而非私有L2）
#define EVENT_L2D_CACHE 0x16

/// L2D_CACHE_REFILL: L2数据缓存重填事件(0x17)
/// 当L2数据缓存行从外部(主存/其他缓存)加载时计数。
/// 仅Cortex A76及以上型号支持。
/// 可用于检测跨核心的缓存干扰（侧信道噪声来源之一）
#define EVENT_L2D_CACHE_REFILL 0x17

/// STALL_FRONTEND: 前端停顿事件(0x23)
/// 由于前端问题（取指/解码）导致没有操作发射的周期数。
/// 仅Cortex A76及以上型号支持（ARMv8.2-A）。
/// 前端停顿可能由以下原因引起：
///   - ITLB未命中 → 指令地址翻译延迟
///   - ICache未命中 → 指令缓存未命中需从L2/主存取指
///   - 分支误预测恢复 → 前端需要从正确路径重新取指
#define EVENT_STALL_FRONTEND 0x23

/// STALL_BACKEND: 后端停顿事件(0x24)
/// 由于后端问题（执行/内存访问）导致没有操作发射的周期数。
/// 仅Cortex A76及以上型号支持（ARMv8.2-A）。
/// 后端停顿可能由以下原因引起：
///   - DTLB未命中 → 数据地址翻译延迟
///   - L1D缓存未命中 → 数据加载延迟
///   - 数据依赖 → 等待前序指令结果
///   - 资源冲突 → 保留站/执行单元占用
#define EVENT_STALL_BACKEND 0x24

// -----------------------------------------------------------------
// ARM64 PMU计数器分配方案
//
// ARM64 PMU有N个可编程计数器(PMEVCNTR<n>_EL0)和1个周期计数器
// (PMCCNTR_EL0)，N由PMCR_EL0[11:7]指定(典型值N=6)。
//
// 测试用例使用的计数器通过PMSELR_EL0选择，然后通过
// PMXEVCNTR_EL0读取(这是当前选中计数器的视图寄存器)。
//
// 汇编层使用的PFC寄存器别名（见arm64/registers.h）：
//   PFC0 = x10 → 用于存储PMC计数差值(Read PFC Start/End)
//   PFC1 = x9  → 用于存储PMC计数差值(Read PFC Start/End)
//   PFC2 = x8  → 用于存储PMC计数差值(Read PFC Start/End)
//   PFC3 = x7  → 需要在registers.h中新增，用于PFC#3
//
// 注意：READ_ONE_PFC宏通过PMSELR_EL0选择计数器编号，
// 然后通过PMXEVCNTR_EL0读取计数值，不依赖PFC寄存器别名。
// PFC寄存器别名仅用于在汇编中存储计数差值。
// -----------------------------------------------------------------

/// PMU计数器#0: L1D_CACHE_REFILL - 硬件追踪(htrace)收集
/// 这是侧信道泄露的直接信号：
///   - Prime+Probe：重填次数反映缓存集的驱逐状态
///   - Flush+Reload：重填次数反映共享页的重新加载
///   - 测试用例通过READ_ONE_PFC("0")在探测阶段读取此计数器
#define PFC0_EVENT L1D_CACHE_REFILL

/// PMU计数器#1: INST_SPEC - 模糊测试反馈(投机指令)
/// 投机执行的指令数反映代码对流水线的影响：
///   - 高投机执行量 = 分支误预测后的投机窗口大
///   - 低投机执行量 = 代码路径稳定，投机风险小
#define PFC1_EVENT INST_SPEC

/// PMU计数器#2: INST_RETIRED - 模糊测试反馈(已完成指令)
/// 与INST_SPEC对比衡量投机执行程度：
///   投机执行量 = INST_SPEC - INST_RETIRED
///   完成指令数反映代码的实际执行路径长度
#define PFC2_EVENT INST_RETIRED

/// PMU计数器#3: BR_MIS_PRED - 投机过滤器(分支误预测)
/// 分支误预测是投机执行漏洞的核心指标：
///   - Spectre-V1(Bounds Check Bypass)：误预测条件分支
///   - Spectre-V2(Branch Target Injection)：误预测间接分支
///   - 高误预测率 → 可能存在可利用的投机窗口
#define PFC3_EVENT BR_MIS_PRED

/// ARM64需要的最小可编程计数器数量
/// 我们使用4个可编程计数器(PFC#0-3)，周期计数器单独使用
#define REQUIRED_N_COUNTERS_ARM 4

// -----------------------------------------------------------------
// ARM64 PMU寄存器控制位定义
// 这些位定义用于配置PMCR_EL0、PMCNTENSET_EL0、PMXEVTYPER_EL0等
// -----------------------------------------------------------------

/// PMCR_EL0控制位
/// [0] E - 启用所有计数器(全局启用位)
///         设置后所有配置的计数器和周期计数器开始计数
#define PMCR_ENABLE           BIT_(0)
/// [1] P - 重置事件计数器
///         写1后所有可编程事件计数器(PMEVCNTR<n>)清零
///         此位是自清除位(写1后自动归零)
#define PMCR_EVENT_CNTR_RESET BIT_(1)
/// [2] C - 重置周期计数器
///         写1后周期计数器(PMCCNTR_EL0)清零
///         此位是自清除位
#define PMCR_CYCLE_CNTR_RESET BIT_(2)
/// [3] D - 周期计数器时钟分频器
///         设置后周期计数器每64个时钟周期计数一次
#define PMCR_DP               BIT_(5)
/// PMCR_EL0[11:7] - 可用计数器数量N的起始位位置
#define PMCR_N_COUNTER_START  11
/// PMCR_EL0[15:11] - 可用计数器数量N的掩码(5位)
#define PMCR_N_COUNTER_MASK   0b11111

/// MDCR_EL2控制位
/// [7] HPME - 硬件性能监控事件启用
///            设置后允许PMU事件计数器在EL1/EL0级别计数
///            必须设置为1才能使PMU正常工作
#define MDCR_HPME             BIT_(7)
/// [14] HPMD - 硬件性能监控事件禁用
///              设置后PMU事件被陷阱到EL2(不允许直接计数)
///              必须设置为0才能使PMU在低EL级别计数
#define MDCR_HPMD             BIT_(17)

/// PMCNTENSET_EL0控制位 - 计数器启用寄存器
/// 每个位对应一个计数器，写1启用对应的计数器
#define PMCNTENSET_P0         BIT_(0)   // 启用PMEVCNTR0_EL0
#define PMCNTENSET_P1         BIT_(1)   // 启用PMEVCNTR1_EL0
#define PMCNTENSET_P2         BIT_(2)   // 启用PMEVCNTR2_EL0
#define PMCNTENSET_P3         BIT_(3)   // 启用PMEVCNTR3_EL0
#define PMCNTENSET_C          BIT_(31)  // 启用PMCCNTR_EL0(周期计数器)

/// PMCCFILTR_EL0控制位 - 周期计数器过滤器
/// [27] NSH - 非安全硬化过滤位
///            设置后周期计数器仅在非安全状态计数
#define PMCCFILTR_NSH         BIT_(27)

/// PMSELR_EL0 - 计数器选择寄存器
/// [4:0] SELECT - 选择要访问的计数器编号
///                0x1F = 选择周期计数器(PMCCNTR_EL0视图)
///                0-5  = 选择可编程计数器PMEVCNTR<n>
#define PMSELR_CYCLE_CNTR     0x1f

/// PMXEVTYPER_EL0事件类型过滤器 - 用于可编程计数器
/// [30] P - EL0特权过滤器(AArch64)
///          设置后排除EL0级别的事件(不计数EL0)
///          P=0,U=0表示在所有特权级别计数(我们需要的配置)
#define PMXEVTYPER_P_BIT      BIT_(30)
/// [29] U - EL0特权过滤器(AArch32)
///          设置后排除EL0级别的事件
#define PMXEVTYPER_U_BIT      BIT_(29)

/// PMUSERENR_EL0控制位 - 性能监控用户使能寄存器
/// [0] EN - 启用EL0对PMU寄存器的访问
///          设置后EL0可以读取PMXEVCNTR_EL0等寄存器
///          这对侧信道测试至关重要：测试用例运行在EL0
#define PMUSERENR_EN          BIT_(0)
/// [2] CR - 启用EL0对周期计数器的访问
#define PMUSERENR_CR          BIT_(2)
/// [3] ER - 启用EL0对事件计数器的访问
#define PMUSERENR_ER          BIT_(3)

#endif // ARCH_ARM

#endif // _PERF_COUNTERS_H_

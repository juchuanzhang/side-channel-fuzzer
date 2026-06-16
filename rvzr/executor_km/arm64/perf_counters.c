/// 文件：ARM64性能计数器(PMU)的配置与管理实现
///
/// 本文件实现了ARM64架构下性能监控单元(PMU)的配置和使用功能。
/// PMU是侧信道模糊测试工具(Revizor)的核心测量基础设施。
///
/// 【ARM64 PMU概述】
/// ARM64 PMU提供硬件级的事件计数功能，可以精确追踪微架构行为：
///   - 缓存访问/未命中次数 → 硬件追踪(htrace)收集
///   - 投机执行指令数 → 模糊测试反馈（推测代码路径影响）
///   - 已完成指令数 → 模糊测试反馈（实际执行路径长度）
///   - 分支误预测次数 → 投机过滤器（Spectre漏洞指标）
///
/// ARM64 PMU与x86 PMU的关键差异：
///   1. 事件编码：ARM64使用简单的evtCount编号(11位，如0x03=L1D_CACHE_REFILL)，
///      x86使用evt_num+umask组合编码(如0xD1+0x01=MEM_LOAD_RETIRED.L1_HIT)
///   2. 计数器选择：ARM64通过PMSELR_EL0选择计数器，然后通过PMXEVTYPER_EL0
///      配置事件类型，通过PMXEVCNTR_EL0读取计数值（视图寄存器模式）
///      x86通过直接MSR地址访问每个计数器(如MSR_IA32_PERFCTR0+id)
///   3. 全局控制：ARM64使用PMCR_EL0全局启用/禁用计数器，
///      x86使用MSR_CORE_PERF_GLOBAL_CTRL(Intel)或MSR_F15H_PERF_CTL(AMD)
///   4. 特权过滤：ARM64使用PMUSERENR_EL0控制EL0访问权限，
///      MDCR_EL2控制EL2陷阱行为；x86使用CR4.PCE位
///   5. 计数器数量：ARM64由PMCR_EL0.N字段指定(典型值N=6)，
///      x86通常有4个通用计数器(Intel)或6个(AMD)
///
/// 【Cortex型号差异】
/// 不同Cortex型号支持的PMU事件集不同：
///   - Cortex A72 (ARMv8.0-A)：支持基本事件(L1D, INST, BR, CPU_CYCLES)
///   - Cortex A76 (ARMv8.2-A)：支持基本事件+扩展事件(L2D, STALL_FRONTEND/BACKEND)
///   本文件根据MIDR_EL1识别的CPU型号动态选择最佳PMU事件配置
///
/// 【计数器分配方案】
///   PFC#0: L1D_CACHE_REFILL → 硬件追踪(htrace)收集（侧信道泄露核心指标）
///   PFC#1: INST_SPEC → 模糊测试反馈（投机执行指令数）
///   PFC#2: INST_RETIRED → 模糊测试反馈（已完成指令数）
///   PFC#3: BR_MIS_PRED → 投机过滤器（分支误预测次数）
///   周期计数器(PMCCNTR_EL0)：单独配置，不占用可编程计数器
///
/// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/types.h>

#include "main.h"
#include "shortcuts.h"

#include "perf_counters.h"
#include "shortcuts.h"

/// ARM64 PMU需要的最小可编程计数器数量
/// 我们使用4个可编程计数器(PFC#0-3)来收集侧信道追踪和模糊测试反馈：
///   PFC#0: L1D_CACHE_REFILL - htrace收集
///   PFC#1: INST_SPEC - 模糊测试反馈(投机指令)
///   PFC#2: INST_RETIRED - 模糊测试反馈(已完成指令)
///   PFC#3: BR_MIS_PRED - 投机过滤器(分支误预测)
/// Cortex A72/A76各有6个可编程计数器(PMCR_EL0.N=6)，满足4个计数器的需求
#define REQUIRED_N_COUNTERS 4

// =====================================================================
// ARM64 PMU事件编号常量
// 这些常量定义了用于配置PMXEVTYPER_EL0[10:0](evtCount字段)的事件编号
// =====================================================================

/// L1D_CACHE_REFILL: L1数据缓存重填事件(0x03)
/// 当L1数据缓存行从外部(L2缓存或主存)加载时计数。
/// 这是侧信道追踪(htrace)收集的核心指标：
///   - Prime+Probe：重填次数反映缓存集的驱逐/重载状态
///     如果Prime阶段占用的缓存行在Probe阶段被重填，
///     说明被测代码访问了相同的缓存集
///   - Flush+Reload：重填次数反映共享内存页的重新加载
///     如果刷新的缓存行在Reload阶段被重填，
///     说明被测代码（或投机执行路径）访问了相同的地址
/// 在Cortex A72和A76上均可用
#define EVENT_L1D_CACHE_REFILL 0x03

/// L1D_CACHE: L1数据缓存访问事件(0x04)
/// 每次L1数据缓存被访问时计数（无论命中或未命中）
#define EVENT_L1D_CACHE 0x04

/// INST_RETIRED: 已完成指令计数事件(0x08)
/// 计数架构上已完成的指令数量。
/// 与INST_SPEC对比可以衡量投机执行的程度：
///   投机执行量 = INST_SPEC - INST_RETIRED
///   高投机执行量表示代码路径对流水线影响大，可能存在漏洞
/// 所有ARMv8-A处理器必须实现此事件
#define EVENT_INST_RETIRED 0x08

/// BR_MIS_PRED: 分支误预测事件(0x10)
/// 当分支预测器预测错误时计数。
/// 分支误预测会导致流水线冲刷和恢复，是投机执行漏洞的关键指标
#define EVENT_BR_MIS_PRED 0x10

/// CPU_CYCLES: CPU周期计数事件(0x11)
/// 计数处理器运行的时钟周期数
#define EVENT_CPU_CYCLES 0x11

/// BR_PRED: 分支预测事件(0x12)
/// 当分支预测器做出预测时计数（无论正确或错误）
#define EVENT_BR_PRED 0x12

/// INST_SPEC: 投机执行指令计数事件(0x1B)
/// 计数投机执行的指令数量（包括最终被放弃的指令）
/// 这是模糊测试反馈的关键指标之一
#define EVENT_INST_SPEC 0x1B

/// L2D_CACHE: L2数据缓存访问事件(0x16)
/// 仅Cortex A76及以上型号支持
#define EVENT_L2D_CACHE 0x16

/// L2D_CACHE_REFILL: L2数据缓存重填事件(0x17)
/// 仅Cortex A76及以上型号支持
#define EVENT_L2D_CACHE_REFILL 0x17

/// STALL_FRONTEND: 前端停顿事件(0x23)
/// 仅Cortex A76及以上型号支持
#define EVENT_STALL_FRONTEND 0x23

/// STALL_BACKEND: 后端停顿事件(0x24)
/// 仅Cortex A76及以上型号支持
#define EVENT_STALL_BACKEND 0x24

// =====================================================================
// ARM64 PMU寄存器控制位定义
// =====================================================================

/// PMCR_EL0控制位
/// [0] E - 启用所有计数器(全局启用位)
#define PMCR_ENABLE           BIT_(0)
/// [1] P - 重置事件计数器(写1清零所有事件计数器)
#define PMCR_EVENT_CNTR_RESET BIT_(1)
/// [2] C - 重置周期计数器(写1清零周期计数器)
#define PMCR_CYCLE_CNTR_RESET BIT_(2)
/// [5] DP - 禁用周期计数器(1=停止周期计数器计数)
#define PMCR_DP               BIT_(5)
/// PMCR_EL0[11:7] - 可用计数器数量N的起始位位置
#define PMCR_N_COUNTER_START  11
/// PMCR_EL0[15:11] - 可用计数器数量N的掩码(5位)
#define PMCR_N_COUNTER_MASK   0b11111

/// MDCR_EL2控制位
/// [7] HPME - 硬件性能监控事件启用(允许PMU计数)
#define MDCR_HPME             BIT_(7)
/// [14] HPMD - 硬件性能监控事件禁用(陷阱PMU事件到EL2)
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
#define PMCCFILTR_NSH         BIT_(27)

/// PMSELR_EL0 - 计数器选择寄存器
/// [4:0] SELECT - 选择要访问的计数器编号
/// 0x1F = 选择周期计数器
#define PMSELR_CYCLE_CNTR     0x1f

// =====================================================================
// Cortex型号检测与PMU事件选择
// =====================================================================

/// @brief 检测ARM64 CPU型号
/// 通过读取MIDR_EL1寄存器获取CPU型号信息，并存储到cpuinfo结构体中。
///
/// MIDR_EL1(Main ID Register)格式：
///   [31:24] Implementer - 实现者标识
///     0x41 = ARM Limited（ARM自研核心，如Cortex系列）
///     0x42 = Broadcom, 0x51 = Qualcomm, 0x53 = Samsung等
///   [23:20] Variant     - 变体号(主要版本)
///   [19:16] Architecture - 架构版本
///     0xF = ARMv8-A系列(包含ARMv8.0-A到ARMv8.5-A)
///   [15:4]  Part        - 部件编号(核心型号标识)
///     0xD08 = Cortex A72 (ARMv8.0-A, 3发射顺序流水线)
///     0xD0B = Cortex A76 (ARMv8.2-A, 4发射顺序流水线)
///     0xD0C = Cortex A77 (ARMv8.2-A, 4发射顺序流水线)
///   [3:0]   Revision    - 修订号(次要版本)
///
/// 本函数在init_perf_counters中调用，为后续的PMU事件选择
/// 和实现特定寄存器配置提供CPU型号信息。
static void detect_cpu_model(void)
{
    uint64_t midr_el1 = 0;
    asm volatile("mrs %0, MIDR_EL1" : "=r"(midr_el1));

    // 从MIDR_EL1中提取各字段
    // cpuinfo结构体已在main.c的get_cpuinfo函数中填充
    // 此处仅打印CPU型号信息用于调试
    int implementer = (midr_el1 >> 24) & 0xFF;
    int part = (midr_el1 >> 4) & 0xFFF;
    int variant = (midr_el1 >> 20) & 0xF;
    int revision = midr_el1 & 0xF;

    PRINT_WARNS("detect_cpu_model",
                "CPU detected: Implementer=0x%x Part=0x%x Variant=%d Revision=%d\n",
                implementer, part, variant, revision);

    if (implementer == ARM_IMPLEMENTER_ID) {
        switch (part) {
        case CORTEX_A72_PART:
            PRINT_WARNS("detect_cpu_model",
                        "Cortex A72 (ARMv8.0-A): 3-issue ordered pipeline, "
                        "6 PMU counters, separate L1/L2 prefetcher control\n");
            break;
        case CORTEX_A76_PART:
            PRINT_WARNS("detect_cpu_model",
                        "Cortex A76 (ARMv8.2-A): 4-issue ordered pipeline, "
                        "6 PMU counters, combined L1+L2 prefetcher control, "
                        "extra events: L2D_CACHE, STALL_FRONTEND, STALL_BACKEND\n");
            break;
        default:
            PRINT_WARNS("detect_cpu_model",
                        "Unknown ARM Cortex part 0x%x; using generic PMU events\n",
                        part);
            break;
        }
    } else {
        PRINT_WARNS("detect_cpu_model",
                    "Non-ARM implementer 0x%x; PMU event selection may be incorrect\n",
                    implementer);
    }
}

/// @brief 根据CPU型号和计数器用途选择最佳的PMU事件编号
///
/// 不同Cortex型号支持的PMU事件集不同，需要根据CPU型号选择：
///   - Cortex A72 (ARMv8.0-A): 仅支持基本事件
///   - Cortex A76 (ARMv8.2-A): 支持基本事件+扩展事件
///   - 其他型号: 使用通用ARMv8-A事件作为安全回退
///
/// 计数器用途与事件选择：
///   PFC#0 (htrace收集): L1D_CACHE_REFILL(0x03) - 所有型号通用
///     这是侧信道追踪的核心指标，所有ARMv8-A处理器都应支持
///   PFC#1 (模糊测试反馈): INST_SPEC(0x1B) - 所有型号通用
///     投机执行指令数是模糊测试反馈的关键指标
///   PFC#2 (模糊测试反馈): INST_RETIRED(0x08) - 所有型号通用
///     已完成指令数用于计算投机执行量
///   PFC#3 (投机过滤器): BR_MIS_PRED(0x10) - 所有型号通用
///     分支误预测是Spectre类漏洞的核心指标
///     Cortex A76可以考虑用STALL_BACKEND替代，但BR_MIS_PRED
///     对侧信道检测更直接有效
///
/// @param counter_id 计数器编号(0-3)
/// @return PMU事件编号(evtCount)，若不支持则返回0xFFFF
static uint64_t select_pmu_event_for_counter(int counter_id)
{
    // 检查CPU实现者是否为ARM
    if (cpuinfo->implementer != ARM_IMPLEMENTER_ID) {
        // 非ARM实现，使用通用ARMv8-A事件作为回退
        // 注意：某些非ARM实现可能不支持所有ARMv8-A事件，
        // 如果PMU事件不工作，需要查看具体CPU的TRM文档
        PRINT_WARNS("select_pmu_event",
                    "Non-ARM implementer; using generic ARMv8-A events\n");
    }

    // 根据计数器用途选择事件
    // 所有4个核心事件在Cortex A72和A76上都可用，
    // 所以不需要按型号分别选择。
    // Cortex A76的额外事件(L2D_CACHE, STALL_FRONTEND, STALL_BACKEND)
    // 可以在将来需要更精细的分析时使用。
    switch (counter_id) {
    case 0:
        // PFC#0: L1D_CACHE_REFILL - 硬件追踪(htrace)收集
        // 这是侧信道泄露的直接信号：
        //   - Prime+Probe：重填次数反映缓存集的驱逐状态
        //   - Flush+Reload：重填次数反映共享页的重新加载
        //   - Evict+Reload：重填次数反映驱逐后的重新加载
        // 在所有Cortex型号上均可用
        return EVENT_L1D_CACHE_REFILL;

    case 1:
        // PFC#1: INST_SPEC - 模糊测试反馈(投机执行指令数)
        // 投机执行的指令数反映代码路径对流水线的影响：
        //   - 高投机执行量 = 分支误预测后的投机窗口大
        //   - 低投机执行量 = 代码路径稳定，投机风险小
        // 与INST_RETIRED对比：INST_SPEC > INST_RETIRED表示发生了投机执行
        // 在所有Cortex型号上均可用
        return EVENT_INST_SPEC;

    case 2:
        // PFC#2: INST_RETIRED - 模糊测试反馈(已完成指令数)
        // 已完成指令数反映代码的实际执行路径长度。
        // 投机执行量 = INST_SPEC - INST_RETIRED
        // 这是ARMv8-A必须实现的事件，所有型号均可用
        return EVENT_INST_RETIRED;

    case 3:
        // PFC#3: BR_MIS_PRED - 投机过滤器(分支误预测次数)
        // 分支误预测是投机执行漏洞的核心指标：
        //   - Spectre-V1(Bounds Check Bypass): 误预测条件分支
        //   - Spectre-V2(Branch Target Injection): 误预测间接分支
        //   - 高误预测率 → 可能存在可利用的投机窗口
        //
        // Cortex A76可以考虑使用以下替代事件：
        //   STALL_BACKEND(0x24) - 后端停顿周期数
        //     后端停顿包括缓存未命中延迟、数据依赖等，
        //     可以更全面地反映微架构性能瓶颈。
        //     但BR_MIS_PRED对侧信道检测更直接有效，
        //     所以我们优先使用BR_MIS_PRED。
        //
        // Cortex A72没有STALL_BACKEND事件，只能使用BR_MIS_PRED
        return EVENT_BR_MIS_PRED;

    default:
        PRINT_ERRS("select_pmu_event",
                   "Invalid counter_id %d (must be 0-3)\n", counter_id);
        return 0xFFFF;
    }
}

// =====================================================================
// 私有模块级函数 - PMU控制
// =====================================================================

/// @brief 获取当前异常级别(EL)
/// ARM64有4个特权级别：EL0(用户态), EL1(内核态), EL2(虚拟化管理器),
/// EL3(安全监控器)。PMU的配置需要根据当前EL级别决定是否需要
/// 修改EL2寄存器(MDCR_EL2等)。
/// CurrentEL寄存器格式：[3:2] = EL级别(0=EL0, 1=EL1, 2=EL2, 3=EL3)
/// @return 当前异常级别(0-3)
static inline int get_current_exception_level(void)
{
    int val = 0;
    read_msr("CurrentEL", val);
    val = (val >> 2) & 0b11;
    return val;
}

/// @brief 在EL2级别启用性能监控单元(PMU)
/// 设置MDCR_EL2寄存器的关键位：
///   - HPME=1(bit[7]): 硬件性能监控事件启用，允许PMU计数器工作
///   - HPMD=0(bit[14]): 硬件性能监控事件禁用位清除，不陷阱PMU事件到EL2
///   - TPMCR=0(bit[28]): 不陷阱PMCR_EL0访问，允许EL0/EL1访问PMU控制寄存器
///
/// 为什么需要EL2配置：
///   ARM64的PMU访问权限由多个寄存器分层控制：
///   1. MDCR_EL2 (EL2级别): 控制PMU事件是否被允许(HPME)和是否陷阱(HPMD/TPMCR)
///   2. PMUSERENR_EL0 (EL0级别): 控制EL0程序是否可以直接访问PMU寄存器
///   3. PMCR_EL0 (全局): 启用/禁用所有计数器
///   如果MDCR_EL2.HPMD=1，所有PMU事件被陷阱到EL2，EL0/EL1无法正常计数。
///   必须先在EL2级别解除陷阱，然后在EL0级别启用访问。
///
/// @return 0表示成功
static inline int pmu_enable_el2(void)
{
    uint64_t mdcr = 0;
    read_msr("MDCR_EL2", mdcr);

    // 设置HPME=1(bit[7]): 启用硬件性能监控事件
    // 这是PMU工作的前提条件，否则所有事件计数器都不计数
    mdcr = mdcr | MDCR_HPME;

    // 清除HPMD=0(bit[14]): 不陷阱PMU事件到EL2
    // HPMD=1时，PMU事件访问会被陷阱到EL2处理，
    // 导致EL0/EL1的PMU读取触发异常而非直接返回计数器值
    // 必须清除此位才能使测试用例直接读取PMC
    mdcr = mdcr & (~MDCR_HPMD);

    // 清除TPMCR=0(bit[28]): 不陷阱PMCR_EL0访问
    // TPMCR=1时，从EL0/EL1对PMCR_EL0和PMXEVTYPER_EL0的访问
    // 会触发陷阱到EL2，导致配置PMU时产生异常
    mdcr &= ~BIT_(28);

    write_msr("MDCR_EL2", mdcr);
    return 0;
}

/// @brief 启用性能监控单元(PMU)
/// 设置PMCR_EL0寄存器启用所有计数器并清除禁用标志：
///   - E=1(bit[0]): 启用所有计数器(全局启用位)
///   - DP=0(bit[5]): 周期计数器不禁用(清除禁用标志)
///
/// PMCR_EL0是PMU的全局控制寄存器：
///   PMCR_EL0.E=0时，所有计数器(包括周期计数器)都不计数，
///   即使PMCNTENSET_EL0中启用了对应的计数器位。
///   PMCR_EL0.DP=1时，周期计数器(PMCCNTR_EL0)停止计数，
///   但事件计数器仍然可以计数。
///   我们需要E=1且DP=0，使所有计数器(包括周期计数器)正常工作。
///
/// @return 0表示成功
static inline int pmu_enable(void)
{
    uint64_t pmcr = 0;
    read_msr("PMCR_EL0", pmcr);
    // E=1: 启用所有计数器
    // DP=0: 周期计数器不禁用(清除DP位)
    write_msr("PMCR_EL0", (pmcr | PMCR_ENABLE) & (~PMCR_DP));
    return 0;
}

/// @brief 重置性能监控单元(PMU)
/// 清零所有事件计数器和周期计数器：
///   - P=1(bit[1]): 重置事件计数器(写1清零所有PMEVCNTR<n>)
///   - C=1(bit[2]): 重置周期计数器(写1清零PMCCNTR_EL0)
///
/// 注意：P和C位是自清除位(RAZ/WI)，写1后自动归零，
/// 不需要手动清除。读回PMCR_EL0时这两个位总是0。
/// 清零计数器确保测试开始前的计数值为0，
/// 使测试结束时的计数值直接反映测试期间的事件数量。
///
/// @return 0表示成功
static inline int pmu_reset(void)
{
    uint64_t pmcr = 0;
    read_msr("PMCR_EL0", pmcr);
    // P=1: 清零所有事件计数器
    // C=1: 清零周期计数器
    write_msr("PMCR_EL0", pmcr | PMCR_EVENT_CNTR_RESET | PMCR_CYCLE_CNTR_RESET);
    return 0;
}

/// @brief 启用所有需要的PMU计数器
/// 首先验证可用计数器数量满足需求(>= REQUIRED_N_COUNTERS=4)，
/// 然后启用计数器P0-P3和周期计数器。
///
/// PMCNTENSET_EL0是计数器启用寄存器，每个位对应一个计数器：
///   bit[0] = P0启用, bit[1] = P1启用, ..., bit[31] = 周期计数器启用
///   写1启用对应的计数器，读1表示对应计数器已启用。
///
/// 验证计数器数量是必要的，因为不同ARM64实现的PMU计数器数量不同：
///   - Cortex A72/A76: PMCR_EL0.N = 6 (6个可编程计数器)
///   - Cortex A53: PMCR_EL0.N = 2 (仅2个可编程计数器)
///   - 某些低端实现: PMCR_EL0.N = 0 (没有可编程计数器)
///   如果可用计数器不足，无法配置所有4个事件，测试结果不完整。
///
/// @return 0表示成功，-EIO表示计数器数量不足
static inline int enable_all_counters(void)
{
    // 读取PMCR_EL0获取可用计数器数量
    // PMCR_EL0[11:7] = N字段，表示可编程计数器数量
    uint64_t pmcr_value = 0;
    read_msr("PMCR_EL0", pmcr_value);
    uint64_t pmcr_n = (pmcr_value >> PMCR_N_COUNTER_START) & PMCR_N_COUNTER_MASK;

    // 验证可用计数器数量
    // 我们需要至少4个可编程计数器(PFC#0-3)
    ASSERT(pmcr_n >= REQUIRED_N_COUNTERS, "pmu_enable");

    // 启用所有需要的计数器
    // P0-P3: 4个事件计数器
    // C(bit[31]): 周期计数器(PMCCNTR_EL0)
    uint64_t enable_all = PMCNTENSET_P0 | PMCNTENSET_P1 | PMCNTENSET_P2
                        | PMCNTENSET_P3 | PMCNTENSET_C;
    write_msr("PMCNTENSET_EL0", enable_all);

    return 0;
}

/// @brief 禁用PMU周期计数器过滤
/// 配置PMCCFILTR_EL0寄存器，设置NSH=1(bit[27])
/// 使周期计数器在非安全状态下计数。
///
/// PMCCFILTR_EL0是周期计数器过滤器寄存器，控制PMCCNTR_EL0的计数条件：
///   [31] RES0
///   [30] RES0
///   [29] H  - Hyp模式过滤(1=仅计数Hyp模式下的周期)
///   [28] SH - 安全硬化过滤
///   [27] NSH - 非安全硬化过滤(1=仅计数非安全状态下的周期)
///   [26:24] RES0
///   ...
///   设置NSH=1使周期计数器在非安全状态下计数，
///   这符合大多数侧信道测试的需求（测试用例运行在非安全状态）。
///   设置H=0, SH=0意味着不限制Hyp和安全状态的计数。
///
/// @return 0表示成功
static inline int disable_filtering(void)
{
    write_msr("PMCCFILTR_EL0", PMCCFILTR_NSH);
    return 0;
}

/// @brief 配置PMU事件类型 - 根据CPU型号选择最佳事件并写入PMXEVTYPER_EL0
///
/// 配置步骤：
///   1. 配置周期计数器(PMCCNTR_EL0)的过滤器(PMCCFILTR_EL0)
///   2. 逐个配置4个可编程计数器(PFC#0-3)的事件类型
///
/// PMXEVTYPER_EL0寄存器格式（当选中可编程计数器时）：
///   [31] RES0
///   [30] P  - EL0 AArch64特权过滤器(1=排除EL0事件)
///   [29] U  - EL0 AArch32特权过滤器(1=排除EL0事件)
///   [28:19] RES0
///   [18:16] TH - 阈值(ARMv8.1+, 不使用)
///   [15] RES0
///   [14] TX - 阈值排除(ARMv8.1+, 不使用)
///   [13] TW - 阈值权重(ARMv8.1+, 不使用)
///   [12] TE - 阈值启用(ARMv8.1+, 不使用)
///   [11] RES0
///   [10:0] evtCount - 事件编号(选择要计数的微架构事件)
///
/// 对于侧信道测试，我们需要P=0, U=0（在所有特权级别计数），
/// evtCount = select_pmu_event_for_counter()返回的事件编号。
///
/// 配置方法：
///   1. 使用PMSELR_EL0选择计数器编号
///   2. 使用PMXEVTYPER_EL0写入事件类型配置
///   PMXEVTYPER_EL0是"视图"寄存器：写入时实际修改的是
///   PMEVTYPER<n>_EL0（当前选中计数器的配置寄存器）
///
/// @return 0表示成功
static inline int configure_events(void)
{
    // 配置周期计数器过滤器
    // 先选择周期计数器(PMSELR_EL0 = 0x1F)
    // 然后配置过滤器(PMCCFILTR_EL0，通过PMXEVTYPER_EL0视图写入)
    // 设置NSH=1(bit[27])使周期计数器在非安全状态下计数
    write_msr("PMSELR_EL0", PMSELR_CYCLE_CNTR);
    write_msr("PMXEVTYPER_EL0", PMCCFILTR_NSH);

    // === PFC#0: L1D_CACHE_REFILL - 硬件追踪(htrace)收集 ===
    // 这是侧信道泄露的核心指标。
    // 在Prime+Probe测量中，READ_ONE_PFC("0")宏在探测阶段
    // 读取此计数器来检测缓存行的驱逐/重载状态。
    write_msr("PMSELR_EL0", 0);
    write_msr("PMXEVTYPER_EL0", select_pmu_event_for_counter(0));

    // === PFC#1: INST_SPEC - 模糊测试反馈(投机执行指令数) ===
    // 投机执行的指令数反映代码对流水线的影响。
    // 在READ_PFC_START/END宏中通过READ_ONE_PFC("1")读取。
    // 与PFC#2(INST_RETIRED)对比计算投机执行量。
    write_msr("PMSELR_EL0", 1);
    write_msr("PMXEVTYPER_EL0", select_pmu_event_for_counter(1));

    // === PFC#2: INST_RETIRED - 模糊测试反馈(已完成指令数) ===
    // 已完成指令数是ARMv8-A必须实现的事件。
    // 在READ_PFC_START/END宏中通过READ_ONE_PFC("2")读取。
    write_msr("PMSELR_EL0", 2);
    write_msr("PMXEVTYPER_EL0", select_pmu_event_for_counter(2));

    // === PFC#3: BR_MIS_PRED - 投机过滤器(分支误预测次数) ===
    // 分支误预测是Spectre类漏洞的核心指标。
    // 需要在arm64/registers.h中添加PFC3="x7"别名，
    // 以及在asm_snippets.h中更新READ_PFC_START/END宏
    // 以支持读取第4个计数器。
    // 目前PFC#3通过READ_ONE_PFC("3")单独读取。
    write_msr("PMSELR_EL0", 3);
    write_msr("PMXEVTYPER_EL0", select_pmu_event_for_counter(3));

    return 0;
}

// =====================================================================
// 公共接口
// =====================================================================

/// @brief 配置ARM64 PMU用于侧信道追踪收集和模糊测试反馈
///
/// 配置顺序（严格按照ARM Architecture Reference Manual Section D13.1）：
///   1. pmu_enable_el2() - 在EL2级别解除PMU陷阱(HPME=1, HPMD=0, TPMCR=0)
///      仅在当前EL>=2时需要执行。如果运行在EL1，EL2寄存器不可访问。
///   2. configure_events() - 选择PMU事件类型并写入PMXEVTYPER_EL0
///      必须在启用计数器之前配置，否则计数器可能计数错误的事件
///   3. pmu_reset() - 清零所有计数器(P=1, C=1)
///      清零确保测试开始前的计数值为0
///   4. disable_filtering() - 配置周期计数器过滤器(PMCCFILTR_EL0.NSH=1)
///   5. enable_all_counters() - 启用计数器P0-P3和周期计数器
///      必须在配置事件类型之后启用，否则可能计数未配置的事件
///   6. pmu_enable() - 全局启用PMU(PMCR_EL0.E=1, DP=0)
///      最后执行，确保所有配置完成后才开始计数
///
/// 注意：VMBUILD宏用于虚拟机构建，此时PMU配置由VM管理器处理，
/// 不需要在此处配置。
///
/// @return 0表示成功，负数表示错误码
int pfc_configure(void)
{
    // NOTE: 下面的实现基于ARM Architecture Reference Manual for A-profile
    // architecture Section "D13.1 About the Performance Monitors"
    // 该章节描述了PMU的正确配置顺序和寄存器访问方法

    int err = 0;

#ifndef VMBUILD
    // 步骤1: 在EL2级别解除PMU陷阱
    // 仅在当前EL>=2时执行（如果运行在EL1，跳过此步骤）
    // MDCR_EL2的陷阱位控制低级别(EL0/EL1)对PMU的访问：
    //   HPME=1: 允许PMU事件计数
    //   HPMD=0: 不陷阱PMU事件到EL2
    //   TPMCR=0: 不陷阱PMCR_EL0访问
    if (get_current_exception_level() >= 2) {
        err = pmu_enable_el2();
        CHECK_ERR("pmu_enable_el2");
    }

    // 步骤2: 配置PMU事件类型
    // 根据CPU型号(Cortex A72/A76)选择最佳事件编号，
    // 并写入PMXEVTYPER_EL0寄存器
    err = configure_events();
    CHECK_ERR("configure_events");

    // 步骤3: 清零所有计数器
    // PMCR_EL0.P=1清零事件计数器，PMCR_EL0.C=1清零周期计数器
    err = pmu_reset();
    CHECK_ERR("pmu_reset");

    // 步骤4: 配置周期计数器过滤器
    // PMCCFILTR_EL0.NSH=1使周期计数器在非安全状态下计数
    err = disable_filtering();
    CHECK_ERR("disable_filtering");

    // 步骤5: 启用所有需要的计数器
    // PMCNTENSET_EL0启用P0-P3和周期计数器
    // 同时验证可用计数器数量>=4
    err = enable_all_counters();
    CHECK_ERR("enable_all_counters");

    // 步骤6: 全局启用PMU
    // PMCR_EL0.E=1启用所有计数器，DP=0启用周期计数器
    err = pmu_enable();
    CHECK_ERR("pmu_enable");

#endif // VMBUILD

    return err;
}

// =====================================================================
// 初始化与释放
// =====================================================================

/// @brief 初始化性能计数器管理器
/// 在模块初始化阶段调用，检测CPU型号并打印PMU配置信息。
/// CPU型号信息用于后续的PMU事件选择和实现特定寄存器配置。
/// @return 0表示成功
int init_perf_counters(void)
{
    detect_cpu_model();
    return 0;
}

/// @brief 释放性能计数器管理器资源
/// ARM64 PMU不需要额外的资源分配，此函数为空实现。
/// PMU寄存器在restore_special_registers()中恢复为原始配置。
void free_perf_counters(void) {}

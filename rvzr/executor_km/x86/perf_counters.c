/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "main.h"
#include "shortcuts.h"

#include "perf_counters.h"

// 性能计数器(PFC)配置结构
// 包含Intel/AMD PMU事件选择器的所有字段
struct pfc_config {
    unsigned long evt_num;  // 事件编号(event number)，标识要计数的微架构事件
    unsigned long umask;    // 单位掩码(unit mask)，进一步细分事件类型
    unsigned long cmask;    // 计数掩码(counter mask)，事件发生cmask次后才计数一次
    unsigned int any;       // AnyThread位，计数所有线程的事件(而非仅当前线程)
    unsigned int edge;      // Edge检测位，计数事件的边沿(上升沿)而非级别
    unsigned int inv;       // Invert位，反转cmask的比较条件
};

// 性能计数器名称枚举
// 每个枚举值对应一个用于侧信道追踪收集或模糊测试反馈的微架构事件
typedef enum {
    L1_HITS = 0,                      // L1数据缓存命中次数，用于硬件追踪(htrace)收集
    UOPS_ISSUED_ANY = 1,              // 发出的微操作数，用于模糊测试的投机过滤器
    UOPS_RETIRED_ANY = 2,             // 完成的微操作数，用于模糊测试反馈
    MISPREDICTION_RECOVERY_CYCLES = 3, // 分支误预测恢复周期数，用于模糊测试反馈
    HW_INTERRUPTS_RECEIVED = 4,       // 硬件中断次数(Intel专用)，用于中断干扰检测
    SMI_INTERRUPTS_RECEIVED = 5,      // SMI中断次数(AMD专用)，用于SMI干扰检测
    DECODE_REDIRECTS = 6              // 解码重定向次数(AMD备用)
} pfc_name_e;

// 根据性能计数器名称获取对应的PFC配置
// 根据CPU厂商(Intel/AMD)和型号选择正确的MSR事件编码
// Intel PMU使用MSR_P6_EVNTSEL系列MSR
// AMD PMU使用MSR_F15H_PERF_CTL系列MSR
static int get_pfc_config_by_name(pfc_name_e pfc_name, struct pfc_config *config)
{
    uint64_t family = cpuinfo->x86;
    uint64_t model = cpuinfo->x86_model;

    // 大多数情况下cmask、any、edge、inv字段为0
    config->cmask = 0;
    config->any = 0;
    config->edge = 0;
    config->inv = 0;

    // Intel PMU配置
    // Intel使用事件编号+单位掩码的组合来选择微架构事件
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        switch (pfc_name) {
        case L1_HITS:
            // MEM_LOAD_RETIRED.L1_HIT: 计数至少有一个微操作命中L1数据缓存的已完成加载指令
            // 包含所有软件预取和锁指令，无论数据来源
            config->evt_num = 0xd1;
            config->umask = 0x01;
            break;
        case UOPS_ISSUED_ANY:
            // UOPS_ISSUED.ANY: 计数RAT(资源分配表)发送到RS(保留站)的微操作数
            // 用于模糊测试的投机过滤器：发出但未完成的微操作表示投机执行
            // 部分Intel型号(如0xBA,0xB7等)使用不同的事件编号0xAE
            if (model == 0xBA || model == 0xB7 || model == 0xBF || model == 0x97 || model == 0x9A) {
                config->evt_num = 0xAE;
                config->umask = 0x01;
            } else {
                config->evt_num = 0x0E;
                config->umask = 0x01;
            }
            break;
        case UOPS_RETIRED_ANY:
            // UOPS_RETIRED.RETIRE_SLOTS: 计数已完成的退休槽位
            // 用于模糊测试反馈：完成的微操作数
            config->evt_num = 0xC2;
            config->umask = 0x02;
            break;
        case MISPREDICTION_RECOVERY_CYCLES:
            // INT_MISC.CLEAR_RESTEER_CYCLES: 分支误预测或机器清除事件后，
            // 发射阶段等待前端从重新定向路径取指的周期数
            // 部分Intel型号(如0xBA,0xB7等)使用不同的事件编号0xAD
            if (model == 0xBA || model == 0xB7 || model == 0xBF || model == 0x97 || model == 0x9A) {
                config->evt_num = 0xAD;
                config->umask = 0x80;
            } else {
                config->evt_num = 0x0D;
                config->umask = 0x01;
            }
            break;
        case HW_INTERRUPTS_RECEIVED:
            // HW_INTERRUPTS.RECEIVED: 计数处理器接收的硬件中断数量
            // 用于检测硬件中断对侧信道测量的干扰
            config->evt_num = 0xCB;
            config->umask = 0x01;
            break;
        default:
            return -1;
        }
        return 0;
    }

    // AMD PMU配置
    // AMD使用不同于Intel的事件编号体系
    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        switch (pfc_name) {
        case L1_HITS:
            // AMD L1缓存命中计数
            // Family 0x1a/0x19(Zen3+): 使用事件0x44(Data Cache Fills)
            // 其他family: 使用事件0x43(Data Cache Fills)
            switch (family) {
            case 0x1a:
            case 0x19:
                // Zen3+: 按数据源分类的任意数据缓存填充
                config->evt_num = 0x44;
                config->umask = 0xff;
                break;
            default:
                config->evt_num = 0x43;
                config->umask = 0xff;
            }
            break;
        case UOPS_ISSUED_ANY:
            // AMD发出的微操作(调度操作)计数
            // Family 0x17(Zen2): 没有可靠的调度操作计数器，
            // 使用dummy计数器(事件0x00)始终返回零，从而禁用投机过滤器
            // 其他family: 使用事件0xAB(Dispatched Ops)
            switch (family) {
            case 0x17:
                // Zen2没有可靠的调度操作计数器
                // 使用dummy计数器(0x00)始终返回零，等效禁用投机过滤器
                config->evt_num = 0x00;
                config->umask = 0x00;
                break;
            default:
                config->evt_num = 0xAB;
                config->umask = 0xff;
            }
            break;
        case UOPS_RETIRED_ANY:
            // AMD完成的微操作(退休操作)计数
            // 事件0xC1，umask=0x00
            config->evt_num = 0xC1;
            config->umask = 0x00;
            break;
        case MISPREDICTION_RECOVERY_CYCLES:
            // AMD解码重定向计数
            // 事件0x91(Decode Redirects)，用于检测分支误预测恢复
            config->evt_num = 0x91;
            config->umask = 0x00;
            break;
        case SMI_INTERRUPTS_RECEIVED:
            // AMD SMI(System Management Interrupt)监控
            // 事件0x2c，用于检测SMI对侧信道测量的干扰
            // SMI是不可屏蔽的系统管理中断，可能导致测量噪声
            config->evt_num = 0x2c;
            config->umask = 0x00;
            break;
        default:
            return -1;
        }
        return 0;
    }

    // unsupported vendor
    return -1;
}

/// @brief 清除可编程性能计数器并将配置写入对应的MSR
/// Intel PMU使用MSR_P6_EVNTSEL系列配置事件选择器
/// AMD PMU使用MSR_F15H_PERF_CTL系列配置事件选择器
/// @param id 计数器编号(0-3或更多)
/// @param config 事件配置结构
/// @param usr 用户态计数位(1=在用户态计数)
/// @param os 内核态计数位(1=在内核态计数)
/// @return 0表示成功，-1表示失败
static int pfc_write(unsigned int id, struct pfc_config *config, unsigned int usr, unsigned int os)
{
    uint64_t perf_configuration = 0;
#if VENDOR_ID == 1 // Intel PMU配置
    // Intel: 先启用全局性能计数器控制(ENnable位0-3和Fixed Counter 0-3)
    uint64_t global_ctrl = native_read_msr(MSR_CORE_PERF_GLOBAL_CTRL);
    global_ctrl |= ((uint64_t)7 << 32) | 15; // 启用Fixed Counter 0-2和PMC0-3
    wrmsr64(MSR_CORE_PERF_GLOBAL_CTRL, global_ctrl);

    // 读取当前事件选择器配置
    perf_configuration = native_read_msr(MSR_P6_EVNTSEL0 + id);

    // 先禁用计数器（清除所有低32位配置字段）
    // 防止在配置过程中产生计数
    perf_configuration &= ~(((uint64_t)1 << 32) - 1);
    wrmsr64(MSR_P6_EVNTSEL0 + id, perf_configuration);

    // 清零计数器值
    wrmsr64(MSR_IA32_PERFCTR0 + id, 0ULL);

    // 组合事件选择器配置字段：
    // [24:31] cmask - 计数掩码
    // [23]    inv   - 反转位
    // [22]    EN    - 启用位(必须设置)
    // [21]    any   - AnyThread位
    // [18]    edge  - 边沿检测位
    // [17]    OS    - 内核态计数位
    // [16]    USR   - 用户态计数位
    // [8:15]  umask - 单位掩码
    // [0:7]   evt_num - 事件编号

    perf_configuration |= ((config->cmask & 0xFF) << 24);
    perf_configuration |= (config->inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config->any << 21);
    perf_configuration |= (config->edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    perf_configuration |= ((config->umask & 0xFF) << 8);
    perf_configuration |= (config->evt_num & 0xFF);
    wrmsr64(MSR_P6_EVNTSEL0 + id, perf_configuration);
#elif VENDOR_ID == 2 // AMD PMU配置
    // AMD: 组合事件选择器配置字段
    // [32:39] evt_num[8:11] - 事件编号高位
    // [0:7]   evt_num[0:7]  - 事件编号低位
    // [8:15]  umask         - 单位掩码
    // [24:30] cmask         - 计数掩码(AMD只有7位vs Intel 8位)
    // [23]    inv           - 反转位
    // [22]    EN            - 启用位(必须设置)
    // [18]    edge          - 边沿检测位
    // [17]    OS            - 内核态计数位
    // [16]    USR           - 用户态计数位
    // AMD使用MSR_F15H_PERF_CTL + 2*id的偏移（每个计数器2个MSR：CTL和CTR）
    perf_configuration |= ((config->evt_num) & 0xF00) << 24;
    perf_configuration |= (config->evt_num) & 0xFF;
    perf_configuration |= ((config->umask) & 0xFF) << 8;
    perf_configuration |= ((config->cmask) & 0x7F) << 24;
    perf_configuration |= (config->inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config->edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    wrmsr64(MSR_F15H_PERF_CTL + 2 * id, perf_configuration);
#endif
    return 0;
}

// 配置所有性能计数器用于侧信道追踪收集和模糊测试反馈
// 计数器分配：
//   #0: L1_HITS - 硬件追踪(htrace)收集，这是侧信道泄露的核心指标
//   #1: UOPS_ISSUED_ANY - 模糊测试反馈(投机过滤器)
//   #2: UOPS_RETIRED_ANY - 模糊测试反馈(完成操作数)
//   #3: MISPREDICTION_RECOVERY - 模糊测试反馈(误预测恢复)
//   #4: HW_INTERRUPTS - 中断干扰检测(Intel)
//   #5: SMI_INTERRUPTS - SMI干扰检测(AMD)
int pfc_configure(void)
{
    int err = 0;
    struct pfc_config config = {0};

    // 配置PMU
    // #0: Htrace收集 - L1缓存命中是侧信道泄露的直接信号
    err |= get_pfc_config_by_name(L1_HITS, &config);
    CHECK_ERR("pfc_configure");
    // usr=1, os=1: 在用户态和内核态都计数
    err |= pfc_write(0, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #1: 模糊测试反馈 - 发出的微操作数用于推测投机执行程度
    err |= get_pfc_config_by_name(UOPS_ISSUED_ANY, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(1, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #2: 模糊测试反馈 - 完成的微操作数与发出的微操作数之差反映投机执行量
    err |= get_pfc_config_by_name(UOPS_RETIRED_ANY, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(2, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #3: 模糊测试反馈 - 误预测恢复周期数反映分支预测器的行为
    err |= get_pfc_config_by_name(MISPREDICTION_RECOVERY_CYCLES, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(3, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #4: 中断干扰检测(Intel专用)
    // 硬件中断会打断测试执行，导致测量结果噪声
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        err |= get_pfc_config_by_name(HW_INTERRUPTS_RECEIVED, &config);
        CHECK_ERR("pfc_configure");
        err |= pfc_write(4, &config, 1, 1);
        CHECK_ERR("pfc_configure");
    }

    // #5: SMI干扰检测(AMD专用)
    // SMI(System Management Interrupt)是不可屏蔽中断，会导致测量噪声
    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        err |= get_pfc_config_by_name(SMI_INTERRUPTS_RECEIVED, &config);
        CHECK_ERR("pfc_configure");
        err |= pfc_write(5, &config, 1, 1);
        CHECK_ERR("pfc_configure");
    }

    return err;
}

// =================================================================================================
int init_perf_counters(void) { return 0; }
void free_perf_counters(void) {}

/// File: Kernel module interface
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// =================================================================================================
// 【模块总体功能与架构说明】
//
// 本文件是 Revizor 侧信道模糊测试工具的内核执行器模块（executor_km）的入口文件。
// Revizor 基于论文 "Enter, Exit, Page Fault, Leak" 的思路，通过在内核模块中构建
// 精确控制的执行沙箱，来检测微架构侧信道漏洞。
//
// 模块架构概述：
//   1. **SysFS 接口层**：通过 /sys/rvzr_executor/ 目录下的虚拟文件，用户空间程序
//      可以加载测试用例（test_case）、输入数据（inputs）、读取硬件追踪结果（trace），
//      以及配置各种执行参数（预热轮数、测量模式、SSBP补丁等）。
//   2. **沙箱管理层（sandbox_manager）**：为测试用例的执行创建隔离的内存沙箱环境，
//      包括代码区、数据区和堆栈区，防止测试用例影响宿主系统。
//   3. **代码/数据加载器（code_loader, data_loader）**：将用户空间传入的测试用例二进制
//      代码和数据加载到沙箱的指定内存区域。
//   4. **测量模块（measurement）**：使用 Prime+Probe、Flush+Reload 等侧信道测量技术，
//      在测试用例执行前后采集微架构状态（如缓存占用、性能计数器），生成硬件追踪。
//   5. **页表管理（page_tables）**：为虚拟机（VM）actor 构建客户页表和 EPT/NPT，
//      实现物理地址碰撞（HPA-GPA collision）等高级侧信道检测特性。
//   6. **故障处理（fault_handler）**：拦截测试用例执行中产生的页故障、通用保护故障等，
//      在沙箱内进行处理而非让整个内核崩溃。
//   7. **虚拟化支持（vmx/svm）**：当测试用例包含 VM actor 时，利用 Intel VT-x（VMX）
//      或 AMD SVM（Secure Virtual Machine）硬件虚拟化扩展来运行客户代码。
//
// 工作流程：
//   用户空间 → SysFS写入test_case → 解析+兼容性检查 → 分配沙箱 → 加载代码
//   用户空间 → SysFS写入inputs   → 解析输入数据
//   用户空间 → SysFS读取trace    → 执行测量（trace_test_case） → 返回硬件追踪结果
//
// =================================================================================================

// 【内核头文件引入】包含内核模块开发所需的基础头文件：内核基础设施、
// 模块初始化/退出宏、SysFS接口、版本检查、内核对象管理、处理器信息
// clang-format off
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/kobject.h>
#include <asm/processor.h>
// clang-format on

#include "hardware_desc.h"

// 【模块内部子模块头文件引入】每个子模块负责一个特定功能：
// actor - actor（执行角色）管理
// code_loader - 测试用例代码加载到沙箱
// data_loader - 输入数据加载到沙箱
// hardware_desc - CPU硬件特性描述
// input_parser - 输入数据解析
// macro_expansion - 宏展开辅助工具
// main.h - 模块全局定义和声明
// measurement - 侧信道测量执行与结果采集
// sandbox_manager - 执行沙箱的分配与管理
// shortcuts - 错误检查与调试的快捷宏
// test_case_parser - 测试用例二进制格式解析
#include "actor.h"

// 【虚拟化与硬件控制子模块头文件】
// fault_handler - 沙箱内的故障拦截和处理（页故障、GP故障等）
// page_tables_* - 页表管理：common（通用）、guest（客户机）、host（宿主机）
// perf_counters - 硬件性能计数器（PMC）的配置与读取
// special_registers - 特殊寄存器（如MSR）的读写控制
#include "fault_handler.h"

// 【ISA架构特定头文件】根据目标CPU架构引入虚拟化支持：
// x86_64架构：svm.h（AMD SVM虚拟化）、vmx.h（Intel VMX虚拟化）
// ARM架构：内核CPU特性检测头文件
#if defined(ARCH_X86_64)

// =================================================================================================
// 【内核版本兼容性处理】
// Linux内核不同版本之间API变化较大，以下代码通过内核版本号（LINUX_VERSION_CODE）
// 动态选择合适的头文件和函数实现，确保模块能在4.12到6.14+等多个内核版本上编译运行。

// 【版本依赖的头文件引入】
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 6)
#ifdef ARCH_X86_64
#include <../arch/x86/include/asm/io.h>
#endif
#endif

// 【kprobe机制】5.7.0及以上内核不再导出kallsyms_lookup_name符号，
// 需通过kprobe技术动态获取该函数地址，以便后续解析其他未导出的内核符号
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 12, 0)
#include <asm/cacheflush.h>
#endif

// 【set_memory_x/nx函数获取】5.4.0及以上内核不再导出set_memory_x和set_memory_nx，
// 需通过kallsyms_lookup_name动态获取其地址；较旧内核可直接从set_memory.h引入
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)

// 【版本依赖的定义】6.14.0及以上内核中bin_attribute变为const类型，
// 通过宏定义bin_attr_t来适配不同版本的类型差异
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)

// =================================================================================================
// 【全局变量定义】以下全局变量控制模块的执行行为，可通过SysFS接口从用户空间动态配置。
//
// quick_and_dirty_mode - 快速模式开关。启用后将Prime+Probe测量切换为Fast Prime+Probe，
//   通过减少重置轮数来加速测试，但可能降低检测精度。
// uarch_reset_rounds - 微架构状态重置轮数。在每次测量前执行多少轮重置操作，
//   以清除微架构状态（如缓存、TLB等），确保测量起点一致。
// enable_ssbp_patch - SSBP（Store Bypass）补丁开关。控制是否启用针对Store Bypass
//   侧信道的防御补丁，影响测量中是否需要特殊处理。
// enable_prefetchers - 硬件预取器开关。控制是否启用CPU的硬件预取器，
//   关闭预取器可减少噪声，使侧信道追踪更精确。
// pre_run_flush - 运行前刷新模式。控制每次测量运行前是否刷新缓存等微架构状态：
//   0=不刷新，1=刷新。影响测量的起始状态。
// enable_hpa_gpa_collisions - HPA-GPA地址碰撞开关。启用后构建特殊的页表映射，
//   使宿主机物理地址（HPA）与客户机物理地址（GPA）发生碰撞，
//   以检测依赖物理地址布局的侧信道泄漏。
// measurement_mode - 测量模式选择。决定使用哪种侧信道测量技术：
//   PRIME_PROBE（填充+探测）、PARTIAL_PRIME_PROBE（部分填充+探测）、
//   FLUSH_RELOAD（刷新+重载）、EVICT_RELOAD（驱逐+重载）、TSC（时间戳计数器）。
// dbg_gpr_mode - 调试GPR（通用寄存器）模式开关。启用后在测量结果中记录
//   测试用例执行后的通用寄存器值，用于调试分析。
// cpuinfo - CPU信息结构体指针。存储目标CPU的厂商、型号、特性等信息，
//   用于兼容性检查和硬件特性适配。
bool quick_and_dirty_mode = false;

// =================================================================================================
// 【局部声明和定义】模块内部使用的变量和宏定义。
//
// SYSFS_DIRNAME - SysFS目录名称，模块将在 /sys/rvzr_executor/ 下创建接口文件
// kobj_interface - 内核对象指针，代表SysFS中的模块目录节点
// inputs_top - 输入数据写入进度计数器，跟踪已接收的输入数据量
// inputs_ready - 输入数据就绪标志，为true时表示所有输入数据已加载完毕
// tc_ready - 测试用例就绪标志，为true时表示测试用例已解析并沙箱已准备好
// unfinished_call - 未完成调用标志，用于安全检测。当SysFS调用正在处理时为true，
//   防止在处理过程中卸载模块导致系统崩溃
#define SYSFS_DIRNAME "rvzr_executor"

// =================================================================================================
// 【SysFS接口定义】
// SysFS是Linux内核与用户空间通信的标准机制。模块通过在 /sys/rvzr_executor/ 目录下
// 创建虚拟文件，使用户空间程序可以通过读写文件来：
//   - 加载测试用例和输入数据
//   - 配置测量参数（预热轮数、测量模式、各种开关）
//   - 读取硬件追踪结果和调试信息
//
// 每个接口文件对应一个 kobj_attribute 或 bin_attribute，定义了读（show）和写（store）
// 回调函数。用户空间写入时调用store函数解析数据，读取时调用show函数返回结果。

// 【权限检查绕过】SysFS默认限制0644权限，但本模块需要0666（所有人可写）权限
// 以便用户空间程序能写入配置。此处通过宏覆盖来绕过内核的权限检查。
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

// 【trace接口】（只读）用户空间读取此文件时触发测量执行。
// 返回格式：每组输入的硬件追踪值(htrace)和5个性能计数器读数(pfc[0-4])，
// 格式为 "htrace,pfc0,pfc1,pfc2,pfc3,pfc4"，每组输入一行，最后以"done"结尾。
/// Reading hardware traces and performance counters

// 【test_case接口】（只写）用户空间将测试用例的原始二进制数据写入此文件。
// 模块会解析数据格式、检查CPU兼容性、分配沙箱内存并加载测试代码。
/// Loading a test case

// 【test_case_bin接口】（二进制只读）用于读取已加载的测试用例代码，
// 每次读取一个页大小的数据块，支持偏移量定位。主要用于调试时验证代码加载是否正确。

// 【inputs接口】（读写）用户空间将侧信道测试的输入数据集写入此文件，
// 写入完成后inputs_ready设为true；读取时返回输入数据是否已就绪的状态。

// 【warmups接口】（读写）设置和读取微架构状态重置的预热轮数（uarch_reset_rounds）。
// 较多的预热轮数可以更彻底地清除微架构状态残留，但会增加测量耗时。

// 【print_data_base接口】（只读）返回沙箱数据区的起始虚拟地址。
// 用户空间需要此地址来构建与沙箱地址布局匹配的输入数据。

// 【print_code_base接口】（只读）返回测试用例代码加载区域的起始虚拟地址。
// 用户空间需要此地址以确保测试用例中的跳转目标地址与实际加载位置一致。

// 【enable_ssbp_patch接口】（只写）控制SSBP（Store Bypass）防御补丁的启用状态。
// Store Bypass是一种微架构侧信道攻击方式，启用补丁可在测量中对此进行特殊处理。

// 【enable_prefetcher接口】（只写）控制CPU硬件预取器的启用状态。
// 禁用预取器可减少测量噪声，使侧信道追踪更精确可控。

// 【enable_pre_run_flush接口】（只写）控制每次测量运行前是否执行缓存刷新。
// 刷新可确保每次测量的起始微架构状态一致，提高测量的可重复性。

// 【enable_hpa_gpa_collisions接口】（只写）控制是否启用宿主机物理地址(HPA)与
// 客户机物理地址(GPA)的碰撞映射。启用后模块会构建特殊的页表，使不同层的物理地址
// 产生碰撞，用于检测依赖物理地址布局的侧信道泄漏（如L1D Eviction-based攻击）。

// 【measurement_mode接口】（只写）选择侧信道测量技术模式。
// 支持的模式：P(Prime+Probe)、P+(带预取的Prime+Probe)、F(Flush+Reload)、
// E(Evict+Reload)、T(TSC时间戳计数器)。写入时同时重置quick_and_dirty模式。

// 【enable_quick_and_dirty_mode接口】（只写）启用/禁用快速测量模式。
// 启用后Prime+Probe自动切换为Fast Prime+Probe（减少重置步骤以加速测量），
// 禁用后恢复为标准模式。这是一种精度与速度的权衡。

// 【handled_faults接口】（读写）设置/读取哪些CPU故障类型应在沙箱内处理。
// 通过位掩码指定，默认包含必要的故障类型（HANDLED_FAULTS_DEFAULT）。
// 这允许测试用例故意触发某些故障（如页故障#PF）来产生微架构变化，
// 这些变化可能构成侧信道信号。

// 【enable_dbg_gpr_mode接口】（只写）启用/禁用调试GPR（通用寄存器）模式。
// 启用后，测量结果中会包含测试用例执行后各通用寄存器的值，
// 用于辅助分析测试用例的执行行为和故障原因。

// 【dbg_dump接口】（只读）调试用接口，读取时输出所有关键全局变量的当前值，
// 包括actor数量、测试用例地址、测量结果地址、输入数据地址、沙箱地址等。
// 用于排查模块状态异常或验证数据加载是否正确。

// 【SysFS属性列表】将所有普通属性（kobj_attribute）汇总为一个数组，
// 在模块初始化时逐个注册到内核对象的SysFS目录下。
static struct attribute *sysfs_attributes[] = {
    &trace_attribute.attr,
    &test_case_attribute.attr,
    &inputs_attribute.attr,
    &warmups_attribute.attr,
    &print_data_base_attribute.attr,
    &print_code_base_attribute.attr,
    &enable_ssbp_patch_attribute.attr,
    &enable_prefetcher_attribute.attr,
    &enable_pre_run_flush_attribute.attr,
    &measurement_mode_attribute.attr,
    &enable_quick_and_dirty_mode_attribute.attr,
    &enable_dbg_gpr_mode_attribute.attr,
    &handled_faults_attribute.attr,
    &dbg_dump_attribute.attr,
    &dbg_guest_page_tables_attribute.attr,
    &enable_hpa_gpa_collisions_attribute.attr,
    NULL, /* need to NULL terminate the list of attributes */
};

// 【SysFS二进制属性列表】二进制属性用于传输大量数据（如测试用例代码），
// 不受页面大小限制，支持按偏移量分块读写。
static struct bin_attribute *bin_sysfs_attributes[] = {
    &test_case_bin_attribute, //
    NULL,                     /* need to NULL terminate the list of attributes */
};

// =================================================================================================
// 【SysFS属性回调函数实现】以下实现了每个SysFS接口文件的读写回调函数，
// 当用户空间程序读写对应的虚拟文件时，内核会调用这些函数。

// next_measurement_id - 追踪当前正在输出的测量结果索引。
// 由于输出缓冲区大小有限（约4KB），可能需要多次读取trace文件才能获取全部结果，
// 此变量记录下次读取应从哪个输入开始输出，-1表示需要启动新的测量。
int next_measurement_id = -1;

// 【trace_show函数】当用户空间读取trace文件时调用。
// 功能：执行侧信道测量并返回结果。流程如下：
//   1. 前置检查：确认测量结果数组、输入数据、测试用例均已就绪
//   2. 设置unfinished_call标志（防止在测量过程中卸载模块）
//   3. 如果next_measurement_id<0（即需要新测量），调用trace_test_case()执行测量
//   4. 按输入索引逆序输出每个测量结果：htrace + 5个性能计数器值
//   5. 由于缓冲区大小限制（~4KB），可能需要多次读取才能获取全部结果，
//      每次读取后更新next_measurement_id，下次读取继续输出剩余结果
//   6. 所有结果输出完毕后，追加"done"标记行
static ssize_t trace_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int count = 0;
    int retval = 0;

    ASSERT(measurements, "trace_show");
    ASSERT(input_parsing_completed(), "trace_show");
    ASSERT(tc_parsing_completed(), "trace_show");

    // start a new measurement?
    unfinished_call = true;
    if (next_measurement_id < 0) {
        int err = trace_test_case();
        if (err)
            return -EIO;

        // start printing the results
        next_measurement_id = n_inputs - 1;
    }
    unfinished_call = false;

    // print the results, but make sure we can continue later if we run out of space in buf
    for (; next_measurement_id >= 0; next_measurement_id--) {
        // check if the output buffer still has space
        if (count >= (4096 - 128))
            return count; // we will continue in the next call of this function

        measurement_t m = measurements[next_measurement_id];
        retval =
            sprintf(&buf[count], "%llu,%llu,%llu,%llu,%llu,%llu\n", m.htrace[0], m.pfc_reading[0],
                    m.pfc_reading[1], m.pfc_reading[2], m.pfc_reading[3], m.pfc_reading[4]);
        if (!retval)
            return -1;
        count += retval;
    }
    count += sprintf(&buf[count], "done\n");
    return count;
}

// 【check_test_case_compat函数】检查解析后的测试用例与当前CPU的兼容性。
// 包括两方面检查：
//   1. 如果测试用例包含user actor，验证SMAP/SMEP是否已关闭
//      （因为user actor需要在内核态执行用户空间代码，SMAP/SMEP会阻止此操作）
//   2. 如果测试用例包含VM actor，根据CPU厂商检查虚拟化扩展兼容性
//      Intel检查VMX兼容性，AMD检查SVM兼容性
/// @brief Check if the parsed test case is compatible with the current CPU
/// @param void
/// @return 0 if the test case is compatible, -1 otherwise
static int check_test_case_compat(void)
{
    int err = 0;

#ifdef ARCH_X86_64
    if (test_case->features.includes_user_actors) {
#ifndef FORCE_SMAP_OFF
        // ensure that SMAP and SMEP are disabled
        uint64_t cr4 = __read_cr4();
        ASSERT(!(__read_cr4() & (X86_CR4_SMAP | X86_CR4_SMEP)), "test_case_store");
#endif
    }
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = vmx_check_cpu_compatibility();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = svm_check_cpu_compatibility();
        }
        CHECK_ERR("vm_check_cpu_compatibility");
    }
#endif

    return err;
}

// 【test_case_store函数】当用户空间写入test_case文件时调用。
// 功能：接收并加载测试用例。流程如下：
//   1. 重置tc_ready标志，表示正在加载新测试用例
//   2. 通过parse_test_case_buffer增量解析二进制数据（支持分多次写入）
//   3. 数据接收完成后，检查测试用例与CPU的兼容性
//   4. 分配沙箱内存空间（allocate_sandbox）
//   5. 将测试用例代码加载到沙箱中（load_sandbox_code）
//   6. 设置tc_ready=true，表示测试用例已就绪可执行测量
static ssize_t test_case_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                                size_t count)
{
    int err = 0;
    tc_ready = false;

    bool finished = false;
    ssize_t consumed_bytes = parse_test_case_buffer(buf, count, &finished);
    if (!finished) {
        return consumed_bytes;
    }

    // check if the given test case can be executed on this CPU
    err = check_test_case_compat();
    CHECK_ERR("check_test_case_compat");

    // prepare sandboxes
    err = allocate_sandbox();
    CHECK_ERR("allocate_sandbox");

    err = load_sandbox_code();
    CHECK_ERR("load_sandbox_code");

    next_measurement_id = -1;
    tc_ready = true;
    return consumed_bytes;
}

// 【test_case_bin_read函数】二进制接口读取回调，用于读取已加载的测试用例代码。
// 支持按偏移量(pos)和大小(count)分块读取，每次读取最多PAGE_SIZE字节，
// 用于调试时验证测试用例代码是否正确加载到内存中。
static ssize_t test_case_bin_read(struct file *file, struct kobject *kobj, bin_attr_t *bin_attr,
                                  char *to, loff_t pos, size_t count)
{
    loff_t max_pos = n_actors * sizeof(actor_code_t);
    if (pos > max_pos)
        return 0;

    loff_t chunk_end = pos + PAGE_SIZE;
    if (chunk_end > max_pos)
        chunk_end = max_pos;
    count = chunk_end - pos;
    memcpy(to, &loaded_test_case_entry[pos], count);
    return count;
}

// 【inputs_store函数】当用户空间写入inputs文件时调用。
// 功能：接收侧信道测试的输入数据集。通过parse_input_buffer增量解析数据，
// 支持分多次写入。数据全部接收完成后设置inputs_ready=true。
static ssize_t inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                            size_t count)
{
    bool finished = false;
    ssize_t consumed_bytes = parse_input_buffer(buf, count, &finished);
    inputs_ready = false;

    if (finished) {
        inputs_ready = true;
    }
    return consumed_bytes;
}

// 【inputs_show函数】当用户空间读取inputs文件时调用。
// 当前仅返回输入数据是否已就绪的状态（0或1），完整实现尚未完成。
static ssize_t inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    // FIXME: not implemented yet. See Flavien's branch for a reference implementation
    return sprintf(buf, "%d\n", inputs_ready);
}

// 【warmups_show/store函数】读写微架构状态重置预热轮数(uarch_reset_rounds)。
// 预热轮数决定了测量前执行多少轮微架构状态重置操作。
static ssize_t warmups_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%ld\n", uarch_reset_rounds);
}

static ssize_t warmups_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                             size_t count)
{
    sscanf(buf, "%ld", &uarch_reset_rounds);
    return count;
}

// 【print_data_base_show函数】返回沙箱数据区的起始虚拟地址。
// 用户空间测试控制器需要此地址来构建与沙箱布局匹配的输入数据结构。
static ssize_t print_data_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llx\n", (long long unsigned)&sandbox->data[0]);
}

// 【print_code_base_show函数】返回测试用例代码加载区域的起始虚拟地址。
// 用户空间需要此地址来确保测试用例中的绝对地址跳转与实际加载位置一致。
static ssize_t print_code_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llx\n", (long long unsigned)loaded_test_case_entry);
}

// 【enable_ssbp_patch_store函数】设置SSBP防御补丁的启用/禁用状态。
// 写入0禁用，写入非0值启用。SSBP补丁影响测量中对Store Bypass侧信道的处理策略。
static ssize_t enable_ssbp_patch_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    enable_ssbp_patch = (value == 0) ? false : true;
    return count;
}

// 【enable_prefetcher_store函数】设置CPU硬件预取器的启用/禁用状态。
// 写入0禁用预取器（减少测量噪声），写入非0值启用预取器。
static ssize_t enable_prefetcher_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    enable_prefetchers = (value == 0) ? false : true;
    return count;
}

// 【enable_pre_run_flush_store函数】设置每次测量运行前的缓存刷新模式。
// 写入0不刷新，写入非0值启用刷新，确保每次测量的微架构起始状态一致。
static ssize_t enable_pre_run_flush_store(struct kobject *kobj, struct kobj_attribute *attr,
                                          const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    pre_run_flush = (value == 0) ? 0 : 1;
    return count;
}

// 【enable_hpa_gpa_collisions_store函数】设置HPA-GPA地址碰撞映射的启用/禁用状态。
// 启用后模块在构建VM actor的页表时，会故意制造宿主机物理地址与客户机物理地址的碰撞，
// 以检测依赖物理地址布局的侧信道泄漏（如L1D Eviction-based攻击）。
static ssize_t enable_hpa_gpa_collisions_store(struct kobject *kobj, struct kobj_attribute *attr,
                                               const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    enable_hpa_gpa_collisions = (value == 0) ? false : true;
    return count;
}

// 【measurement_mode_store函数】设置侧信道测量技术模式。
// 支持的输入字符：'P+'=Prime+Probe（带预取）、'P'=Partial Prime+Probe、
// 'F'=Flush+Reload、'E'=Evict+Reload、'T'=TSC时间戳计数器。
// 切换测量模式时同时重置quick_and_dirty模式，确保测量配置的一致性。
static ssize_t measurement_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    switch (buf[0]) {
    case 'P':
        if (buf[1] == '+')
            measurement_mode = PRIME_PROBE;
        else
            measurement_mode = PARTIAL_PRIME_PROBE;
        break;
    case 'F':
        measurement_mode = FLUSH_RELOAD;
        break;
    case 'E':
        measurement_mode = EVICT_RELOAD;
        break;
    case 'T':
        measurement_mode = TSC;
        break;
    default:
        PRINT_ERRS("measurement_mode_store", "Invalid measurement mode\n");
        return -1;
    }

    quick_and_dirty_mode = false; // updating the measurement mode resets the Q&D mode
    return count;
}

// 【enable_quick_and_dirty_mode函数】启用/禁用快速测量模式。
// 启用(value=1)时：Prime+Probe→Fast Prime+Probe，Partial Prime+Probe→Fast Partial Prime+Probe
// 禁用(value=0)时：Fast模式恢复为标准模式。快速模式通过减少重置步骤加速测量，
// 但可能降低检测精度，是精度与速度的权衡。
static ssize_t enable_quick_and_dirty_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                           const char *buf, size_t count)
{

    unsigned value = 0;
    sscanf(buf, "%u", &value);
    if (value == 1 && quick_and_dirty_mode == false) {
        quick_and_dirty_mode = true;
        switch (measurement_mode) {
        case PRIME_PROBE:
            measurement_mode = FAST_PRIME_PROBE;
            break;
        case PARTIAL_PRIME_PROBE:
            measurement_mode = FAST_PARTIAL_PRIME_PROBE;
            break;
        default:
            break;
        }
    } else if (value == 0 && quick_and_dirty_mode == true) {
        quick_and_dirty_mode = false;
        switch (measurement_mode) {
        case FAST_PRIME_PROBE:
            measurement_mode = PRIME_PROBE;
            break;
        case FAST_PARTIAL_PRIME_PROBE:
            measurement_mode = PARTIAL_PRIME_PROBE;
            break;
        default:
            break;
        }
    }
    return count;
}

// 【enable_dbg_gpr_mode函数】启用/禁用调试通用寄存器模式。
// 启用后在测量结果中记录测试用例执行后各通用寄存器的值，用于调试分析。
static ssize_t enable_dbg_gpr_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    dbg_gpr_mode = (value == 0) ? false : true;
    return count;
}

// 【handled_faults_show/store函数】读取/设置沙箱内处理的CPU故障类型位掩码。
// 位掩码中的每一位对应一种故障类型（如页故障#PF=14、通用保护故障#GP=13等），
// 设置后这些故障将在沙箱内被拦截和处理，不会导致内核崩溃。
// 始终保留HANDLED_FAULTS_DEFAULT中定义的基础故障类型，确保模块自身安全运行。
static ssize_t handled_faults_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "0x%llx\n", (unsigned long long)handled_faults);
}

static ssize_t handled_faults_store(struct kobject *kobj, struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    unsigned long long value;
    if (sscanf(buf, "%lld", &value) != 1)
        return -EINVAL;

    handled_faults = value | HANDLED_FAULTS_DEFAULT;
    return count;
}

// 【dbg_dump_show函数】调试用函数，读取时输出所有关键全局变量的当前值，
// 包括：actor数量、测试用例地址、代码入口点地址、测量结果数组地址、输入数据地址、
// 沙箱地址、故障处理器地址、handled_faults掩码、各种配置开关的状态值等。
// 用于排查模块状态异常或验证数据加载是否正确。
/// Dump all global variables
///
static ssize_t dbg_dump_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int len = 0;
    len += sprintf(&buf[len], "n_actors: %lu\n", n_actors);
    len += sprintf(&buf[len], "test_case: 0x%llx\n", (uint64_t)test_case);
    len += sprintf(&buf[len], "loaded_test_case_entry: 0x%llx\n", (uint64_t)loaded_test_case_entry);
    len += sprintf(&buf[len], "measurements: 0x%llx\n", (uint64_t)measurements);
    len += sprintf(&buf[len], "n_inputs: %lu\n", n_inputs);
    len += sprintf(&buf[len], "inputs: %llx\n", (uint64_t)inputs);
    if (inputs) {
        len += sprintf(&buf[len], "inputs->metadata: %llx\n", (uint64_t)inputs->metadata);
        len += sprintf(&buf[len], "inputs->data: %llx\n", (uint64_t)inputs->data);
    }
    len += sprintf(&buf[len], "sandbox: %llx\n", (uint64_t)sandbox);
    len += sprintf(&buf[len], "fault_handler: %llx\n", (uint64_t)fault_handler);
    len += sprintf(&buf[len], "handled_faults: %u\n", handled_faults);
    len += sprintf(&buf[len], "quick_and_dirty_mode: %d\n", quick_and_dirty_mode);
    len += sprintf(&buf[len], "uarch_reset_rounds: %ld\n", uarch_reset_rounds);
    len += sprintf(&buf[len], "enable_ssbp_patch: %d\n", enable_ssbp_patch);
    len += sprintf(&buf[len], "enable_prefetchers: %d\n", enable_prefetchers);
    len += sprintf(&buf[len], "pre_run_flush: %d\n", pre_run_flush);
    return len;
}

// 【dbg_guest_page_tables接口】（只读）调试用接口，读取时将VM actor的客户页表
// 和EPT（Extended Page Tables）内容输出到内核日志(dmesg)。
// 用于验证页表映射是否按预期构建，特别是HPA-GPA碰撞映射。
/// Dump guest page tables into the kernel log
static ssize_t dbg_guest_page_tables_show(struct kobject *kobj, struct kobj_attribute *attr,
                                           char *buf)
{
    if (n_actors < 2)
        return sprintf(buf, "No actors to print tables for\n");

    int err = dbg_dump_guest_page_tables(1);
    if (err)
        return err;
    err = dbg_dump_ept(1);
    if (err)
        return err;
    return sprintf(buf, "done (see dmesg)\n");
}

// =================================================================================================
// 【模块初始化与内存管理】
// 以下代码实现模块加载（init）和卸载（exit）时的资源分配/释放逻辑，
// 以及必要的内核函数符号解析和CPU兼容性检查。
// =================================================================================================

// 【_get_required_kernel_functions函数】解析未导出的内核函数符号地址。
// 在5.4.0及以上内核版本中，set_memory_x和set_memory_nx不再导出给模块使用，
// 需通过kallsyms_lookup_name获取其地址。而kallsyms_lookup_name本身在5.7.0及以上
// 版本也不再导出，需要先通过kprobe技术获取其地址，再通过它查找其他符号。
// 这些函数用于将测试用例代码所在的内存页设置为可执行（X）或不可执行（NX）。
/// @brief Resolve kernel function symbols that are not exported to modules
///        on recent kernels.
/// @param void
/// @return 0 on success, negative errno on failure
static inline int _get_required_kernel_functions(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name) {
        PRINT_ERR("Failed to resolve kallsyms_lookup_name via kprobe\n");
        return -ENODEV;
    }
#endif // KPROBE_LOOKUP

    set_memory_x = (void *)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void *)kallsyms_lookup_name("set_memory_nx");
    if (!set_memory_x || !set_memory_nx) {
        PRINT_ERR("Failed to resolve required kernel symbols "
                  "(set_memory_x=%p, set_memory_nx=%p)\n",
                  set_memory_x, set_memory_nx);
        return -ENODEV;
    }
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    return 0;
}

// 【get_cpuinfo函数】获取CPU信息结构体。
// x86_64架构：直接使用内核提供的cpu_data(0)获取CPU0的信息（含厂商、型号、特性标志等）
// ARM架构：通过MRS指令读取MIDR_EL1寄存器获取CPU主ID信息，并手动分配cpuinfo结构体
/// @brief Get a description of the CPU
/// @param void
/// @return 0 on success, -1 on failure
static inline cpuinfo_t *get_cpuinfo(void)
{
#if defined(ARCH_X86_64)
    return &cpu_data(0);
#elif defined(ARCH_ARM)
    cpuinfo_t *cpuinfo = kmalloc(sizeof(cpuinfo_t), GFP_KERNEL);
    if (!cpuinfo) {
        return NULL;
    }

    uint64_t midr_el1 = 0;
    asm volatile("MRS %0, MIDR_EL1" : "=r"(midr_el1));
    cpuinfo->implementer = (midr_el1 >> 24) & 0xFF;
    cpuinfo->variant = (midr_el1 >> 20) & 0xF;
    cpuinfo->architecture = (midr_el1 >> 16) & 0xF;
    cpuinfo->part = (midr_el1 >> 4) & 0xFFF;
    cpuinfo->revision = midr_el1 & 0xF;

    return cpuinfo;
#endif
}

// 【check_cpu_compat函数】检查当前CPU是否满足模块运行的最低要求。
// x86_64架构的检查项：
//   1. CPU厂商必须是Intel或AMD（其他厂商的虚拟化扩展尚未实现）
//   2. CPU必须支持AVX和MMX指令集（测试用例可能使用这些指令）
//   3. 物理地址位宽必须与hardware_desc.h中PHYSICAL_WIDTH定义一致
//      （页表管理依赖精确的物理地址宽度，不一致会导致映射错误）
// ARM架构：暂无额外检查要求
/// @brief Check if the CPU supports the required features
/// @param void
/// @return 0 on success, -1 on failure
static int check_cpu_compat(void)
{
#if defined(ARCH_X86_64)
    // Check CPU vendor
    if (cpuinfo->x86_vendor != X86_VENDOR_INTEL && cpuinfo->x86_vendor != X86_VENDOR_AMD) {
        printk(KERN_ERR "ERROR: rvzr_executor: This CPU vendor is not supported\n");
        return -1;
    }

    // Check that the CPU supports the required features
    if (!cpu_has(cpuinfo, X86_FEATURE_AVX) || !cpu_has(cpuinfo, X86_FEATURE_MMX)) {
        printk(KERN_ERR "ERROR: rvzr_executor: Executor KM requires AVX\n");
        return -1;
    }

    // Check memory configuration
    unsigned int phys_addr_width = cpuinfo->x86_phys_bits;
    if (phys_addr_width != PHYSICAL_WIDTH) {
        printk(KERN_ERR "rvzr_executor: ERROR: The width of physical addresses is %d instead of "
                        "expected %d\n",
               phys_addr_width, PHYSICAL_WIDTH);
        return -1;
    }
#elif defined(ARCH_ARM)
    // Nothing so far
#endif
    return 0;
}

// 【executor_init函数】模块初始化入口，当内核加载模块时调用。
// 初始化流程按以下顺序执行：
//   1. 获取CPU信息（get_cpuinfo）→ 存入全局cpuinfo指针
//   2. 检查CPU兼容性（check_cpu_compat）→ 验证厂商、指令集、物理地址宽度
//   3. 解析未导出的内核符号（_get_required_kernel_functions）→ 获取set_memory_x/nx
//   4. 初始化所有子模块（按顺序）：
//      - measurements（测量结果数组分配）
//      - sandbox_manager（沙箱内存池分配）
//      - code_loader（代码加载器初始化）
//      - data_loader（数据加载器初始化）
//      - input_parser（输入解析器初始化）
//      - test_case_parser（测试用例解析器初始化）
//      - fault_handler（故障处理器初始化）
//      - page_table_manager（页表管理器初始化）
//      - perf_counters（性能计数器初始化）
//      - special_register_manager（特殊寄存器管理器初始化）
//      - vmx/svm（根据CPU厂商初始化虚拟化支持）
//   5. 创建SysFS目录 /sys/rvzr_executor/
//   6. 注册所有SysFS属性文件（普通属性和二进制属性）
// 任何步骤失败都会导致模块加载中止并返回错误码。
static int __init executor_init(void)
{
    int err = 0;

    // Get CPU information and store in a global variable for future references
    cpuinfo = get_cpuinfo();
    if (!cpuinfo) {
        printk(KERN_ERR "rvzr_executor: Failed to get CPU information\n");
        return -ENOMEM;
    }

    // Check if the CPU supports the required features
    if (check_cpu_compat() != 0) {
        return -1;
    }

    // Make sure that we have all requirements
    err = _get_required_kernel_functions();
    if (err) {
        return err;
    }

    // Initialize modules
    err |= init_measurements();
    err |= init_sandbox_manager();
    err |= init_code_loader();
    err |= init_data_loader();
    err |= init_input_parser();
    err |= init_test_case_parser();
    err |= init_fault_handler();
    err |= init_page_table_manager();
    err |= init_perf_counters();
    err |= init_special_register_manager();

#if VENDOR_ID == VENDOR_INTEL_
    err |= init_vmx();
#elif VENDOR_ID == VENDOR_AMD_
    err |= init_svm();
#endif
    CHECK_ERR("executor_init");

    // Create a pseudo file system interface
    kobj_interface = kobject_create_and_add(SYSFS_DIRNAME, kernel_kobj->parent);
    if (!kobj_interface) {
        printk(KERN_ERR "rvzr_executor: Failed to create a sysfs directory for x86-executor\n");
        return -ENOMEM;
    }

    // Create the files associated with this kobject
    // int retval = sysfs_create_group(kobj_interface, &attr_group);
    int i = 0;
    struct attribute *attr;
    for (attr = sysfs_attributes[i]; !err; i++) {
        attr = sysfs_attributes[i];
        if (attr == NULL)
            break;

        err = sysfs_create_file(kobj_interface, attr);
    }
    if (err != 0) {
        printk(KERN_ERR "rvzr_executor: Failed to create a sysfs group\n");
        kobject_put(kobj_interface);
        return err;
    }

    // Create binary attributes (used for passing large amounts of data)
    i = 0;
    struct bin_attribute *bin_attr;
    for (bin_attr = bin_sysfs_attributes[i]; !err; i++) {
        bin_attr = bin_sysfs_attributes[i];
        if (bin_attr == NULL)
            break;

        err = sysfs_create_bin_file(kobj_interface, bin_attr);
    }
    if (err != 0) {
        printk(KERN_ERR "rvzr_executor: Failed to create a binary sysfs files\n");
        kobject_put(kobj_interface);
        return err;
    }

    return 0;
}

// 【executor_exit函数】模块卸载入口，当内核移除模块时调用。
// 卸载流程：
//   1. 安全检查：如果unfinished_call为true（说明有SysFS调用正在处理中），
//      打印严重错误警告并拒绝卸载——因为此时卸载可能导致内核崩溃或死锁，
//      用户需要重启系统来安全移除模块。
//   2. 按初始化的逆序释放所有子模块资源：
//      - measurements、sandbox_manager、code_loader、data_loader、
//        input_parser、test_case_parser、fault_handler、
//        page_table_manager、perf_counters、special_register_manager
//      - vmx/svm虚拟化资源释放
//   3. ARM架构下释放手动分配的cpuinfo结构体（x86_64使用内核静态数据无需释放）
//   4. 释放SysFS内核对象（kobject_put）
static void __exit executor_exit(void)
{
    if (unfinished_call) {
        PRINT_ERR("CRITICAL ERROR: executor crashed while handling a sysfs call\n"
                  "Removing the module is no longer safe as it may lead to system blocking\n"
                  "Reboot to remove the module\n");
        return;
    }

    free_measurements();
    free_sandbox_manager();
    free_code_loader();
    free_data_loader();
    free_input_parser();
    free_test_case_parser();
    free_fault_handler();
    free_page_table_manager();
    free_perf_counters();
    free_special_register_manager();

#if VENDOR_ID == VENDOR_INTEL_
    free_vmx();
#elif VENDOR_ID == VENDOR_AMD_
    free_svm();
#endif

#if defined(ARCH_ARM)
    if (cpuinfo)
        kfree(cpuinfo);
#endif

    if (kobj_interface)
        kobject_put(kobj_interface);
}

// 【模块注册宏】向内核注册初始化和退出函数，
// insmod时调用executor_init，rmmod时调用executor_exit
module_init(executor_init);
module_exit(executor_exit);
// 【模块元信息】许可证为Dual MIT/GPL（兼容内核GPL要求），作者为Oleksii Oleksenko
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Oleksii Oleksenko");

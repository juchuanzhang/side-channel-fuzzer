/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"
#include <asm/processor.h>

#include "code_loader.h"
#include "data_loader.h"
#include "input_parser.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"
#include "page_tables_guest.h"
#include "page_tables_host.h"
#include "perf_counters.h"
#include "special_registers.h"

#ifdef ARCH_X86_64
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/spec-ctrl.h>

#include "svm.h"
#include "vmx.h"
#elif defined(ARCH_ARM)

#endif

measurement_t *measurements = NULL; // global

int run_experiment_outer(void); // inline asm label defined in <arch>/fault_handler.c

// =================================================================================================
// Local shortcut functions
// =================================================================================================

// 微架构状态刷新函数：清除CPU微架构层面的残留状态（如L1数据缓存、填充缓冲区、
// 存储缓冲区等），确保每次测量执行前CPU处于一致的初始状态，防止前一次测试的
// 微架构痕迹影响后续测量的硬件追踪结果，从而保证侧信道泄漏观测的可重复性和确定性。
// Intel平台使用VERW指令刷新填充缓冲区、L1D_FLUSH MSR刷新L1数据缓存、WBINVD回写
// 并失效缓存；AMD平台使用WBINVD和LFENCE组合刷新。
/// @brief Flushes the microarchitectural state
/// @param void
/// @return 0 on success, -1 on failure
static inline int uarch_flush(void)
{
#if VENDOR_ID == VENDOR_INTEL_ // Intel
    static const u16 ds = __KERNEL_DS;
    asm volatile("verw %[ds]" : : [ds] "m"(ds) : "cc");
#ifndef VMBUILD
    wrmsr64(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
#endif
    asm volatile("wbinvd\n" : : :);
    asm volatile("lfence\n" : : :);
#elif VENDOR_ID == VENDOR_AMD_ // AMD
    asm volatile("wbinvd\n" : : :);
    asm volatile("lfence\n" : : :);
    // TBD
#endif
    return 0;
}

// 测试执行前的CPU环境准备函数：验证关键数据结构（测试用例入口、输入数据等）的有效性，
// 配置性能计数器(PFC)用于硬件追踪收集，启用FPU以防测试用例使用浮点指令，
// 绑定CPU核心(get_cpu)防止调度迁移，禁用本地中断(raw_local_irq_save)确保测量期间
// 无外部干扰——这些操作为测量创造一个尽可能隔离和确定性的执行环境。
/// @brief Check if entry page of the test case is valid (present and executable)
/// @param void
/// @return 0 if the entry page is valid, -1 otherwise
static int check_test_case_entry(void)
{
    pte_t *tc_pte = get_pte((uint64_t)loaded_test_case_entry);
    if (!tc_pte || !pte_present(*tc_pte)) {
        return -1;
    }
#ifdef ARCH_X86_64
    if (!pte_exec(*tc_pte)) {
        return -1;
    }
#endif

    return 0;
}

/// @brief Checks the measurement status for corruption
/// @param status The measurement status structure to check
/// @return 0 on valid (non-corrupted) measurement, -1 on corrupted measurement
static int check_measurement_status(measurement_status_t *status)
{
    if (status->measurement_state != STATUS_ENDED) {
        switch (status->measurement_state) {
        case STATUS_UNINITIALIZED:
            PRINT_WARNS("run_experiment",
                        "Corrupted measurement: measurement_start macro was not executed, state=%d",
                        status->measurement_state);
            break;
        case STATUS_STARTED:
            PRINT_WARNS("run_experiment",
                        "Corrupted measurement: measurement_end macro was not executed, state=%d",
                        status->measurement_state);
            break;
        default:
            PRINT_WARNS("run_experiment", "Corrupted measurement: unknown state, state=%d",
                        status->measurement_state);
        }
        return -1;
    }

    if (status->smi_count != 0) {
        PRINT_WARNS("run_experiment", "Corrupted measurement: SMI detected, count=%d",
                    status->smi_count);
        return -1;
    }

    return 0;
}

/// @brief Check if the executor is ready to start measurements, and perform the necessary
///        setup of the CPU to ensure that the test case can be executed. Note that this function
///        only partially configures the CPU, and more will be done in set_execution_environment
/// @param irq_flags The flags to store the interrupt state
/// @return 0 on success, -1 on failure
static int pre_run(unsigned long *irq_flags)
{
    int err = 0;

    // check that all main data structures were allocated
    ASSERT(loaded_test_case_entry, "trace_test_case");
    ASSERT(check_test_case_entry() == 0, "trace_test_case");
    ASSERT(inputs, "trace_test_case");
    ASSERT(inputs->metadata, "trace_test_case");
    ASSERT(inputs->data, "trace_test_case");

    // Configure performance counters
    err |= pfc_configure();
    CHECK_ERR("trace_test_case:pfc_configure");

    // Enable FPU - just in case, we might use it within the test case
#ifdef ARCH_X86_64
    kernel_fpu_begin();
#endif

    // Prevent preemption
    get_cpu();

    unsigned long flags;
    raw_local_irq_save(flags);
    *irq_flags = flags;

    return err;
}

// 测试执行后的CPU环境恢复函数：与pre_run配对，恢复被修改的CPU状态——
// AMD平台重新启用全局中断(STGI)，恢复本地中断状态(raw_local_irq_restore)，
// 释放CPU核心绑定(put_cpu)，关闭FPU使用权限(kernel_fpu_end)，
// 确保测量完成后系统回归正常运行状态。
/// @brief Cleanup after the test case execution by undoing the changes made in pre_run
/// @param irq_flags The flags to restore the interrupt state
/// @return void
static inline void post_run(unsigned long *irq_flags)
{
#if VENDOR_ID == VENDOR_AMD_
    asm volatile("stgi\n"); // enable interrupts in case they were disabled
#endif
    unsigned long flags = *irq_flags;
    raw_local_irq_restore(flags);

    put_cpu();

#ifdef ARCH_X86_64
    kernel_fpu_end();
#endif
}

// =================================================================================================
// CPU state management
// =================================================================================================
// 执行环境配置函数（对应论文Figure 4算法步骤）：首先通过set_special_registers
// 配置系统寄存器（如CR3页表基址、CR4控制位等）为测试所需的特殊值；若测试用例
// 涉及虚拟机操作(includes_vm_actors)，则根据CPU厂商(Intel/AMD)启动虚拟化扩展
// (VMX/SVM)，保存宿主机原始虚拟机状态(store_orig_vmcs_state/store_orig_vmcb_state)，
// 并配置虚拟机控制结构(VMCS/VMCB)为测试所需的参数(set_vmcs_state/set_vmcb_state)。
// 这些步骤对应论文中"配置系统寄存器"和"创建虚拟机"两个关键环节。
/// @brief Stores the current state of the CPU and re-configures it for the test case execution
/// @param void
/// @return 0 on success, -1 on failure
static int set_execution_environment(void)
{
    int err = 0;
    err = set_special_registers();
    CHECK_ERR("set_execution_environment:set_special_registers");

    // If necessary, enable VM operation
#ifdef ARCH_X86_64
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = start_vmx_operation();
            CHECK_ERR("set_execution_environment:start_vmx_operation");

            err = store_orig_vmcs_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcs_state");

            err = set_vmcs_state();
            CHECK_ERR("set_execution_environment:set_vmcs_state");
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = start_svm_operation();
            CHECK_ERR("set_execution_environment:start_svm_operation");

            err = store_orig_vmcb_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcb_state");

            err = set_vmcb_state();
            CHECK_ERR("set_execution_environment:set_vmcb_state");
        }
    }
#endif
    return 0;
}

// 原始状态恢复函数（故障安全方式）：该函数以故障安全(fail-safe)方式编写，
// 可在故障处理程序中安全调用，确保即使测试用例触发异常或故障也能完整回滚。
// 恢复顺序：1) 若启用了虚拟化，恢复宿主机原始VMCS/VMCB状态并停止虚拟化操作
// (VMX/SVM)；2) 恢复被修改的故障页权限(restore_faulty_page_permissions)；
// 3) 恢复特殊系统寄存器到原始值(restore_special_registers)；
// 4) 恢复原始沙箱页表(restore_orig_sandbox_page_tables)——
// 防止内核状态因测量执行而永久损坏，是论文中"故障安全恢复"策略的核心实现。
/// @brief Restores the CPU state to the state before the test case execution. This function is
/// written in a fail-safe manner, so that it can be called in fault handlers.
/// @param void
void recover_orig_state(void)
{
    // restore VMX state
#ifdef ARCH_X86_64
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // if (vmx_is_on)
            //     print_vmx_exit_info(); // uncomment to debug VMX exits
            restore_orig_vmcs_state();
            stop_vmx_operation();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            // if (svm_is_on)
            //     print_svm_exit_info(); // uncomment to debug SVM exits
            restore_orig_vmcb_state();
            stop_svm_operation();
        }
    }
#endif

    restore_faulty_page_permissions();
    restore_special_registers();
    restore_orig_sandbox_page_tables();
}

// =================================================================================================
// Measurement loop: trace_test_case -> run_experiment_outer -> run_experiment
// =================================================================================================

// 核心测量循环函数（对应论文中的测量执行流程）：完整执行一次测量实验，步骤如下：
// 1) 创建沙箱页表(set_sandbox_page_tables)——对应论文"创建页表"；
// 2) 配置执行环境(set_execution_environment)——对应论文"配置系统寄存器/创建虚拟机"；
// 3) 初始化Prime+Probe探测区域并可选刷新微架构状态(uarch_flush)——对应论文
//    "刷新缓存和缓冲区"；
// 4) 进入测量循环：对每个输入执行测试用例，包括加载沙箱数据、设置故障页权限、
//    设置故障处理程序、执行测试用例、收集硬件追踪和PFC读数、后处理测量结果
//    （检测SMI干扰等导致的测量损坏，有效测量标记最高位以区分）——对应论文
//    "循环执行测试用例并收集硬件追踪"；
// 5) 清理阶段调用recover_orig_state恢复系统。
// 前uarch_reset_rounds次为预热运行(i<0)，不计入正式测量结果。
/// @brief Run a complete measurement experiment: setup the execution environment and execute
///        the loaded test case for each inputs, storing the resulting hardware traces and PFC
///        readings in the global `measurements` array
/// @param void
/// @return 0 on success, -1 on error
int run_experiment(void)
{
    int err = 0;

    // allocate and map memory for the test case
    err = set_sandbox_page_tables();
    if (err)
        goto cleanup;

    // configure the CPU (and anything else necessary) to prepare for the test case execution
    err = set_execution_environment();
    if (err)
        goto cleanup;

    // Zero-initialize the region of memory used by Prime+Probe
    if (!quick_and_dirty_mode)
        memset(&sandbox->util->l1d_priming_area[0], 0, L1D_PRIMING_AREA_SIZE * sizeof(char));

    // Try to reset the uarch state
    // (we do it here because from this point on the execution is expected to be deterministic
    // and depend solely on the test case and the input to it)
    if (pre_run_flush == 1 && !quick_and_dirty_mode)
        uarch_flush();

    long rounds = (long)n_inputs;
    for (long i = -uarch_reset_rounds; i < rounds; i++) {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;

        // Prepare sandbox
        load_sandbox_data(i_);
        set_faulty_page_permissions();

        // Catch all exceptions
        set_inner_fault_handlers();

        // Execute
        char *main_data = &sandbox->data[0].main_area[0];
        err = ((int (*)(char *))loaded_test_case_entry)(main_data);

        // Restore the original fault handlers and sandbox state
        unset_inner_fault_handlers();
        restore_faulty_page_permissions();
        if (err) // Note: this check HAS to be after IDT/PT reset to avoid corrupting system state
            goto cleanup;

        // Store the measurement
        measurement_t result = sandbox->util->vars.latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        memcpy(measurements[i_].pfc_reading, result.pfc_reading, sizeof(uint64_t) * NUM_PFC);

        // Post-process the measurement
        // (only in normal, non-debug non-warmup runs)
        if (i >= 0 && !dbg_gpr_mode) {
            // Check for measurement corruption
            if (check_measurement_status(&result.status) != 0)
                // Note: we intentionally do not set the `err` variable upon corruption, because
                // corruptions are expected to happen every once in a while because of SMIs,
                // and thus we want to handle them gracefully
                goto cleanup;

            // If the measurement is valid, set the upper bit of htrace
            // to distinguish correct htraces from corrupted ones
            measurements[i_].htrace[0] |= 1ULL << 63;
        }
    }

cleanup:
    if (err)
        measurements[0].htrace[0] = 0; // communicate the error up to executor.py
    recover_orig_state();
    CHECK_ERR("run_experiment:cleanup");
    return err;
}

// 最外层测量入口函数：作为测量的最外层包装，负责：
// 1) 分配测量结果存储空间(alloc_measurements)；
// 2) 调用pre_run准备CPU环境并禁用中断——对应论文"禁用中断/保存宿主机状态"；
// 3) 若有输入数据则调用run_experiment_outer进入测量核心循环；
// 4) 调用post_run恢复CPU状态和中断。
// 该函数与run_experiment_outer（内联汇编定义在<arch>/fault_handler.c中）共同构成了
// 论文Figure 4描述的完整高层算法的入口点。
/// @brief The outermost wrapper for the test case execution. Sets up performance counters,
///        configures the CPU, disables interrupts, and calls enter_unsafe_bubble
/// @param void
/// @return 0 on success, -1 on failure
int trace_test_case(void)
{
    int err = 0;
    unsigned long irq_flags = 0;

    err = alloc_measurements();
    CHECK_ERR("alloc_measurements");

    err = pre_run(&irq_flags);
    CHECK_ERR("trace_test_case:pre_run");

    if (n_inputs) {
        err |= run_experiment_outer();
    }

    post_run(&irq_flags);
    CHECK_ERR("trace_test_case:cleanup");

    return err;
}

// =================================================================================================
// Constructor and destructor + initialization
// =================================================================================================
int alloc_measurements(void)
{
    static int old_n_inputs = 0;
    if (n_inputs <= old_n_inputs)
        return 0;
    old_n_inputs = n_inputs;

    SAFE_VFREE(measurements);
    measurements = CHECKED_VMALLOC(n_inputs * sizeof(measurement_t));
    memset(measurements, 0, n_inputs * sizeof(measurement_t));
    return 0;
}

int init_measurements(void)
{
    measurements = CHECKED_VMALLOC(sizeof(measurement_t));
    return 0;
}

/// Destructor for the measurement module
///
void free_measurements(void) { SAFE_VFREE(measurements); }

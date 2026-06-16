// 文件：ARM64架构底层异常处理汇编代码
//
// 本文件实现了ARM64（AArch64）架构上的完整异常向量表和处理器，支持以下功能：
//   1. EL1级向量表（outer_vector_table / inner_vector_table）- 用于内核态异常捕获
//   2. EL2级向量表（el2_vector_table）- 用于虚拟化场景下的VM异常捕获
//   3. SVC处理器 - 捕获EL0→EL1的SVC异常（K2U/U2K跨域测试）
//   4. HVC处理器 - 捕获EL1→EL2的HVC异常（H2G/G2H跨域测试）
//   5. 增强的fallback_handler - 包含ESR_EL2诊断输出
//
// ARM64异常处理架构概述：
//
//   ARM64使用固定格式的异常向量表（VBAR）来处理不同类型的异常。
//   每个向量表有16个条目，分为4组：
//
//   组0（当前EL使用SP_EL0，即EL1t/EL2t模式）：
//     偏移 +0x000: 同步异常    - 同步异常是最常见的，包括SVC/HVC陷阱、
//     偏移 +0x080: IRQ中断      数据/指令异常、对齐异常等
//     偏移 +0x100: FIQ中断      FIQ是高优先级快速中断
//     偏移 +0x180: SError       SError是异步系统错误
//
//   组1（当前EL使用SP_ELx，即EL1h/EL2h模式）：
//     偏移 +0x200: 同步异常    - ARM64异常通常在EL1h模式下进入，
//     偏移 +0x280: IRQ中断      即使用SP_EL1作为栈指针
//     偏移 +0x300: FIQ中断      大多数Linux内核异常处理使用此组
//     偏移 +0x380: SError
//
//   组2（来自低特权级，AArch64模式，即EL0→EL1或EL1→EL2）：
//     偏移 +0x400: 同步异常    - 这是跨域异常的核心入口：
//     偏移 +0x480: IRQ中断      * EL1向量表中：EL0的SVC/数据异常路由到此
//     偏移 +0x500: FIQ中断      * EL2向量表中：EL1的HVC/数据异常路由到此
//     偏移 +0x580: SError         (VM Exit的主要入口)
//
//   组3（来自低特权级，AArch32模式）：
//     偏移 +0x600: 同步异常    - 32位兼容模式，现代64位系统通常不使用
//     偏移 +0x680: IRQ中断
//     偏移 +0x700: FIQ中断
//     偏移 +0x780: SError
//
//   向量表整体大小 = 16 × 0x80 = 0x800 (2048字节)
//   向量表必须对齐到2048字节边界（.balign 2048）
//
// ESR_EL1 / ESR_EL2 寄存器格式：
//   [31:26] EC字段（异常类别，6位）- 标识异常类型
//   [25]    IL字段（指令长度标志）- 1=32位指令，0=16位指令
//   [24:0]  ISS字段（异常特定信息）- 提供异常的详细参数
//
//   关键EC值与异常对应关系：
//     0x15 (SVC64)   - SVC指令，EL0→EL1系统调用
//     0x16 (HVC64)   - HVC指令，EL1→EL2虚拟化调用
//     0x17 (SMC64)   - SMC指令，安全监控调用
//     0x18 (MRS/MSR) - 系统寄存器访问陷阱
//     0x20 (IABORT_EL1) - 来自低特权级的指令异常
//     0x21 (IABORT_CUR) - 当前特权级的指令异常
//     0x22 (PCALIGN)    - PC对齐异常
//     0x24 (DABORT_EL1) - 来自低特权级的数据异常（Meltdown类漏洞核心）
//     0x25 (DABORT_CUR) - 当前特权级的数据异常
//     0x26 (SPALIGN)    - SP对齐异常
//     0x28 (FP)         - 浮点异常
//     0x2F (SError)     - 系统错误中断
//
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/asm-bug.h>
// #include <asm/exception.h>

#include "sandbox_constants.h"
#include "registers.h"

// =================================================================================================
// 外部符号声明
// =================================================================================================
// C语言函数和全局变量声明，供汇编代码引用

.extern _printk                // 内核打印函数，用于输出诊断信息
.extern set_outer_fault_handlers  // 设置外层向量表（C函数，修改VBAR_EL1）
.extern unset_outer_fault_handlers // 恢复原始向量表（C函数）
.extern run_experiment           // 测试执行主函数（C函数）
.extern orig_vector_table_ptr    // 保存的原始VBAR_EL1向量表指针
.extern loaded_test_case_entry   // 加载的测试用例入口地址

.extern fault_handler            // 自定义异常处理函数地址
                                // 当测试用例注册自定义handler时，此指针指向handler地址
                                // 若为NULL，则使用默认的test_case_handler
.extern is_nested_fault          // 嵌套异常标志（共享变量）
                                // 当异常处理过程中又发生异常时置为1
                                // 防止无限递归进入异常处理代码
.extern handled_faults           // 异常类别(EC)过滤位掩码（共享变量）
                                // 每一位对应一个ESR.EC值，决定是否处理该类异常
.extern esr_ec_matches_handled_faults // C函数：检查EC是否在handled_faults掩码中
.extern orig_vbar_el2_ptr        // 保存的原始VBAR_EL2向量表指针（虚拟化场景）

// =================================================================================================
// 全局变量（数据段）
// =================================================================================================
.data

// recovery_sp：保存run_experiment_outer的栈指针
//   当run_experiment中发生致命bug导致栈损坏时，用此值恢复SP
recovery_sp:
.quad 0

// el2_recovery_sp：保存EL2上下文的栈指针
//   在HVC handler中使用，用于恢复宿主机(Hypervisor)的栈状态
el2_recovery_sp:
.quad 0

// .Lunreachable_msg：不可达代码错误消息
//   用于标记向量表中不应该被执行的条目（如AArch32模式条目）
.Lunreachable_msg:
.asciz	"ERROR: rvzr_executor: unreachable code\n"
.align

// .Lunexpected_fault_msg：fallback_handler的错误消息模板
//   当run_experiment框架层面发生异常时输出此消息
//   包含ESR_EL1（异常综合征）、FAR_EL1（故障地址）和SP值
//   格式说明：\0013是Linux printk的日志级别（KERN_ERR级别）
.Lunexpected_fault_msg:
.asciz	"\0013 ERROR: [fallback_handler] Unexpected fault in run_experiment: \n\
1 [Error Syndrome]:\t0x%llx\n\
2 [Fault Address]:\t0x%llx\n\
  (run_experiment start:\t0x%llx)\n\
3 [SP]:\t0x%llx\n"
.align

// .Lunexpected_el2_fault_msg：EL2级fallback的错误消息模板
//   当EL2层面发生意外异常时输出此消息
//   包含ESR_EL2、ELR_EL2（异常返回地址）和SP_EL2值
.Lunexpected_el2_fault_msg:
.asciz	"\0013 ERROR: [el2_sync_handler] Unexpected fault at EL2: \n\
1 [ESR_EL2]:\t0x%llx\n\
2 [ELR_EL2]:\t0x%llx\n\
3 [SP_EL2]:\t0x%llx\n"
.align

// .Ldefault_fault_msg：test_case_handler的错误消息模板
//   当测试用例中发生未被自定义handler处理的异常时输出此消息
//   包含ESR_EL1、FAR_EL1、测试用例入口地址和SP值
.Ldefault_fault_msg:
.asciz	"\0013 ERROR: [test_case_handler] Unhandled fault in the test case: \n\
1 [Error Syndrome]:\t0x%llx\n\
2 [Fault Address]:\t0x%llx\n\
  (test case start:\t0x%llx)\n\
3 [SP]:\t0x%llx\n"
.align

// .Lsvc_handler_msg：SVC handler的诊断消息
//   当SVC异常被捕获时输出，用于K2U/U2K调试
.Lsvc_handler_msg:
.asciz	"\0013 INFO: [svc_handler] SVC exception from EL0, ESR=0x%llx, ELR=0x%llx\n"
.align

// .Lhvc_handler_msg：HVC handler的诊断消息
//   当HVC异常被捕获时输出，用于H2G/G2H调试
.Lhvc_handler_msg:
.asciz	"\0013 INFO: [hvc_handler] HVC exception from EL1, ESR=0x%llx, ELR=0x%llx\n"
.align

// .Lnested_fault_msg：嵌套异常错误消息
//   当异常处理过程中又发生异常（二次异常）时输出
.Lnested_fault_msg:
.asciz	"\0013 ERROR: Nested fault detected, cannot handle safely\n"
.align


// =================================================================================================
// 宏定义
// =================================================================================================

// unreachable宏：标记不可达代码路径
//   当向量表中的某个条目不应该被执行时使用（如AArch32模式条目）
//   执行此宏会触发内核panic，打印错误消息和链接寄存器(lr)值
.macro unreachable
    adr	x0, .Lunreachable_msg
    mov	x2, lr
    b panic
.endm

// save_el2_state宏：保存EL2级别的关键寄存器状态
//   在EL2异常handler中使用，保存以下寄存器：
//   - ESR_EL2：异常综合征寄存器，包含EC和ISS信息
//   - ELR_EL2：异常链接寄存器，保存异常发生时的返回地址
//   - SPSR_EL2：保存的程序状态寄存器，记录异常前的处理器状态
//   这些值保存在栈上，供后续诊断或恢复使用
.macro save_el2_state
    mrs TMP_REG1_, esr_el2        // 读取ESR_EL2（异常类别和详细信息）
    mrs TMP_REG2_, elr_el2        // 读取ELR_EL2（异常返回地址，即触发异常的指令地址）
    mrs TMP_REG3_, spsr_el2       // 读取SPSR_EL2（异常前的PSTATE状态）
    stp TMP_REG1_, TMP_REG2_, [sp, -16]!  // ESR_EL2和ELR_EL2压栈
    stp TMP_REG3_, x30, [sp, -16]!        // SPSR_EL2和LR压栈
.endm

// restore_el2_state宏：恢复EL2级别的关键寄存器状态
//   在EL2异常处理完毕后，恢复之前保存的寄存器值
.macro restore_el2_state
    ldp TMP_REG3_, x30, [sp], 16          // 恢复SPSR_EL2和LR
    ldp TMP_REG1_, TMP_REG2_, [sp], 16    // 恢复ESR_EL2和ELR_EL2
    msr spsr_el2, TMP_REG3_               // 写回SPSR_EL2
    msr elr_el2, TMP_REG2_                // 写回ELR_EL2
.endm


// =================================================================================================
// EL1级向量表 - 外层（框架保护）
// =================================================================================================
.text

/// @brief outer_vector_table: 外层向量表，用于保护run_experiment框架本身
///
/// 此向量表在run_experiment_outer函数开头通过set_outer_fault_handlers安装。
/// 所有异常条目指向fallback_handler，确保框架层面任何bug都能被捕获并优雅恢复。
///
/// 用途：开发期间的调试保护，正常运行中不应该有异常路由到此表。
/// 如果fallback_handler被触发，说明run_experiment函数内部存在bug，
/// 需要修复而不是忽略。
///
/// 向量表结构说明：
///   组0（EL1t模式，当前EL使用SP_EL0）：偏移+0x000~+0x180
///     - ARM64异常极少在EL1t模式下进入（Linux内核使用SP_EL1）
///     - 但向量表规范要求必须有这些条目
///   组1（EL1h模式，当前EL使用SP_ELx）：偏移+0x200~+0x380
///     - 这是Linux内核异常处理的主入口
///     - 大多数同步异常（数据异常、指令异常等）通过此组进入
///   组2（来自EL0的AArch64异常）：偏移+0x400~+0x580
///     - 用户态(EL0)的异常路由到此组
///     - SVC指令、用户态数据异常等通过此组进入EL1
///   组3（来自EL0的AArch32异常）：偏移+0x600~+0x780
///     - 32位兼容模式，现代64位系统不使用，标记为unreachable

.global outer_vector_table
.balign 2048              // 向量表必须2048字节对齐（ARM64架构规范要求）
outer_vector_table:
    // 组0：当前EL(EL1)异常，使用SP_EL0（EL1t模式）
    // 说明：ARM64异常极少以EL1t模式进入，但向量表规范要求必须有这些条目
    // 偏移+0x000
        b fallback_handler
    .balign 0x80
    // 偏移+0x080 - IRQ中断
        b fallback_handler
    .balign 0x80
    // 偏移+0x100 - FIQ快速中断
        b fallback_handler
    .balign 0x80
    // 偏移+0x180 - SError系统错误
        b fallback_handler
    // 组1：当前EL(EL1)异常，使用SP_ELx（EL1h模式）
    // 说明：这是Linux内核异常处理的主入口，大多数异常通过此组进入
    // 偏移+0x200 - 同步异常（数据异常、指令异常等最常见类型）
    .balign 0x80
        b fallback_handler
    .balign 0x80
    // 偏移+0x280 - IRQ中断
        b fallback_handler
    .balign 0x80
    // 偏移+0x300 - FIQ快速中断
        b fallback_handler
    .balign 0x80
    // 偏移+0x380 - SError系统错误
        b fallback_handler
    // 组2：来自低特权级(EL0)的异常，AArch64模式
    // 说明：用户态异常路由到此组，SVC指令和EL0数据异常通过此组进入EL1
    // 偏移+0x400 - 同步异常（SVC指令、EL0数据/指令异常的主入口）
    .balign 0x80
        b fallback_handler
    .balign 0x80
    // 偏移+0x480 - IRQ中断（来自EL0）
        b fallback_handler
    .balign 0x80
    // 偏移+0x500 - FIQ快速中断（来自EL0）
        b fallback_handler
    .balign 0x80
    // 偏移+0x580 - SError系统错误（来自EL0）
        b fallback_handler
    // 组3：来自低特权级(EL0)的异常，AArch32模式（32位兼容模式）
    // 说明：现代64位系统不使用32位模式，这些条目不应被执行
    // 偏移+0x600 - 同步异常
    .balign 0x80
        unreachable
    .balign 0x80
    // 偏移+0x680 - IRQ中断
        unreachable
    .balign 0x80
    // 偏移+0x700 - FIQ快速中断
        unreachable
    .balign 0x80
    // 偏移+0x780 - SError系统错误
        unreachable


// =================================================================================================
// EL1级向量表 - 内层（测试用例异常捕获）
// =================================================================================================

/// @brief inner_vector_table: 内层向量表，用于捕获测试用例执行期间的异常
///
/// 此向量表在sandbox_manager执行测试用例之前通过set_inner_fault_handlers安装。
/// 与outer_vector_table不同，此表在正常运行中会被频繁触发，特别是：
///   - Meltdown类漏洞测试：访问非法内存地址会触发数据异常(DABORT)
///   - K2U/U2K跨域测试：SVC指令会触发同步异常
///   - 故障注入测试：故意触发各种异常类型
///
/// inner_vector_table的关键设计：
///   组2同步异常（偏移+0x400）指向svc_handler而非test_case_handler，
///   这是因为EL0→EL1的SVC异常需要特殊处理：
///     1. SVC异常需要保存用户态(EL0)的完整上下文
///     2. 需要检查是否为嵌套异常（避免递归）
///     3. 如果有自定义fault_handler注册，优先跳转到fault_handler
///     4. 否则使用默认的test_case_handler处理
///
/// 异常处理流程：
///   1. CPU触发异常 → 跳转到inner_vector_table对应条目
///   2. handler检查is_nested_fault标志
///   3. 若非嵌套异常且有自定义handler → eret到fault_handler
///   4. 若为嵌套异常或无自定义handler → 跳转到recovery代码

.global inner_vector_table
.balign 2048              // 向量表必须2048字节对齐
inner_vector_table:
    // 组0：当前EL(EL1)异常，使用SP_EL0（EL1t模式）
    // 说明：EL1t模式异常极少发生，但仍需提供handler
    // 偏移+0x000 - 同步异常
    .balign 0x80
        b test_case_handler
    .balign 0x80
    // 偏移+0x080 - IRQ中断
        b test_case_handler
    .balign 0x80
    // 偏移+0x100 - FIQ快速中断
        b test_case_handler
    .balign 0x80
    // 偏移+0x180 - SError系统错误
        b test_case_handler
    // 组1：当前EL(EL1)异常，使用SP_ELx（EL1h模式）
    // 说明：这是测试用例异常处理的主入口
    // 偏移+0x200 - 同步异常（最常见的入口，数据异常、指令异常等）
    .balign 0x80
        b test_case_handler
    .balign 0x80
    // 偏移+0x280 - IRQ中断
        b test_case_handler
    .balign 0x80
    // 偏移+0x300 - FIQ快速中断
        b test_case_handler
    .balign 0x80
    // 偏移+0x380 - SError系统错误
        b test_case_handler
    // 组2：来自低特权级(EL0)的异常，AArch64模式
    // 说明：EL0→EL1异常的核心入口，K2U/U2K测试的关键路由点
    // 偏移+0x400 - 同步异常（SVC指令、EL0数据/指令异常）
    //   重要：此条目使用svc_handler而非test_case_handler
    //   SVC异常需要特殊处理流程：保存EL0上下文、检查嵌套、路由到fault_handler
    .balign 0x80
        b svc_handler
    .balign 0x80
    // 偏移+0x480 - IRQ中断（来自EL0）
        b test_case_handler
    .balign 0x80
    // 偏移+0x500 - FIQ快速中断（来自EL0）
        b test_case_handler
    .balign 0x80
    // 偏移+0x580 - SError系统错误（来自EL0）
        b test_case_handler
    // 组3：来自低特权级(EL0)的异常，AArch32模式（32位兼容）
    // 说明：现代64位系统不使用，但保留handler以防止意外触发时系统崩溃
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler


// =================================================================================================
// EL2级向量表 - 虚拟化场景异常处理
// =================================================================================================

/// @brief el2_vector_table: EL2级异常向量表，用于虚拟化场景
///
/// 此向量表在虚拟化测试场景（includes_vm_actors=true）中通过
/// set_el2_fault_handlers安装，将VBAR_EL2指向此表。
///
/// EL2向量表的用途：
///   当客户机VM(EL1)执行过程中触发以下异常时，异常路由到EL2处理：
///     - HVC指令：客户机主动请求Hypervisor服务（VM Exit）
///     - 数据异常：客户机访问映射无效的内存地址
///     - 指令异常：客户机执行非法指令
///     - MRS/MSR陷阱：客户机访问受限系统寄存器
///     - SError：异步系统错误信号
///
/// EL2向量表与EL1向量表的结构完全相同（16个条目，4组），
/// 但handler实现不同：
///   组0/组1（EL2自身异常）：使用el2_sync_handler等EL2专用handler
///   组2（来自EL1/EL0的异常）：使用el2_lower_sync_handler等跨域handler
///
/// H2G/G2H测试的关键路由：
///   - MACRO_SWITCH_H2G：宿主机→客户机切换，使用HVC指令从EL2进入EL1
///   - MACRO_SWITCH_G2H：客户机→宿主机切换，客户机通过HVC触发VM Exit
///   - 客户机VM执行期间的数据异常等也会路由到EL2
///
/// 向量表安装时机：
///   set_inner_fault_handlers()中，当检测到includes_vm_actors=true时，
///   调用set_el2_fault_handlers()安装此向量表

.global el2_vector_table
.balign 2048              // EL2向量表也必须2048字节对齐
el2_vector_table:
    // 组0：当前EL(EL2)异常，使用SP_EL0（EL2t模式）
    // 说明：EL2异常极少以EL2t模式进入，但向量表规范要求这些条目
    // 偏移+0x000 - 同步异常（EL2自身的同步异常，如HVC在EL2执行）
    //   HVC指令在EL2执行时产生的同步异常路由到此
    .balign 0x80
        b el2_sync_handler
    .balign 0x80
    // 偏移+0x080 - IRQ中断
        b el2_irq_handler
    .balign 0x80
    // 偏移+0x100 - FIQ快速中断
        b el2_fiq_handler
    .balign 0x80
    // 偏移+0x180 - SError系统错误
        b el2_serror_handler
    // 组1：当前EL(EL2)异常，使用SP_ELx（EL2h模式）
    // 说明：这是Hypervisor异常处理的主入口
    // 偏移+0x200 - 同步异常（EL2级别的同步异常）
    .balign 0x80
        b el2_sync_handler
    .balign 0x80
    // 偏移+0x280 - IRQ中断
        b el2_irq_handler
    .balign 0x80
    // 偏移+0x300 - FIQ快速中断
        b el2_fiq_handler
    .balign 0x80
    // 偏移+0x380 - SError系统错误
        b el2_serror_handler
    // 组2：来自低特权级(EL1/EL0)的异常，AArch64模式
    // 说明：这是虚拟化场景的核心入口
    //   EL1→EL2的同步异常（HVC指令、数据异常等VM Exit事件）路由到此组
    //   这是H2G/G2H跨域测试的关键路由点
    // 偏移+0x400 - 同步异常（HVC指令、EL1数据/指令异常，VM Exit主入口）
    //   重要：此条目使用el2_lower_sync_handler处理来自EL1的同步异常
    //   该handler检查ESR_EL2.EC字段确定异常类型：
    //     EC=0x16(HVC) → HVC handler，恢复宿主机上下文
    //     EC=0x24(DABORT_EL1) → 数据异常处理
    //     其他EC值 → 默认EL2异常恢复
    .balign 0x80
        b el2_lower_sync_handler
    .balign 0x80
    // 偏移+0x480 - IRQ中断（来自EL1/EL0）
        b el2_lower_irq_handler
    .balign 0x80
    // 偏移+0x500 - FIQ快速中断（来自EL1/EL0）
        b el2_lower_fiq_handler
    .balign 0x80
    // 偏移+0x580 - SError系统错误（来自EL1/EL0）
        b el2_lower_serror_handler
    // 组3：来自低特权级的AArch32异常（32位兼容模式）
    // 说明：现代64位系统不使用，标记为不可达
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable


// =================================================================================================
// 异常处理器实现
// =================================================================================================
.text

/// @brief fallback_handler: 框架层面的默认异常处理器
///
/// 当run_experiment函数内部发生异常时，outer_vector_table将异常路由到此handler。
/// 此handler的功能：
///   1. 读取ESR_EL1（异常综合征）和FAR_EL1（故障地址）用于诊断
///   2. 设置ELR_EL1为.run_experiment_recovery的地址，用于异常后恢复
///   3. 通过eret指令跳转到恢复代码
///
/// ESR_EL1寄存器说明：
///   ESR_EL1（Exception Syndrome Register for EL1）记录了路由到EL1的异常详情：
///   - [31:26] EC字段：异常类别（Exception Class），标识异常类型
///   - [25] IL字段：指令长度标志（Instruction Length）
///   - [24:0] ISS字段：异常特定信息（Instruction Specific Syndrome）
///   EC值与异常对应关系见本文件头部注释
///
/// FAR_EL1寄存器说明：
///   FAR_EL1（Fault Address Register for EL1）记录了引发数据/指令异常的虚拟地址
///   注意：FAR_EL1仅对数据异常和指令异常有效，对其他异常类型可能不准确

.global fallback_handler
fallback_handler:
    // 步骤1：读取诊断信息寄存器
    // ESR_EL1包含异常类别(EC)和详细异常信息(ISS)
    mrs x1, esr_el1
    // FAR_EL1包含引发异常的虚拟地址
    // 注意：对于非数据/指令异常类型，FAR_EL1可能不准确（架构规范说明）
    mrs x2, far_el1
    // 步骤2：准备诊断消息参数
    // x3 = run_experiment函数地址（用于定位异常发生在哪个函数范围内）
    adr x3, run_experiment
    // x4 = 当前栈指针（用于判断栈状态是否正常）
    mov x4, sp
    // x5 = 错误消息字符串地址
    adr x5, .Lunexpected_fault_msg

    // 步骤3：设置异常返回地址
    // 将ELR_EL1设置为.run_experiment_recovery的地址
    // 这样eret执行后，CPU会跳转到恢复代码而非返回异常发生点
    // 这是ARM64异常恢复的核心机制：通过修改ELR_EL1控制异常后的执行流
    adr x0, .run_experiment_recovery
    msr elr_el1, x0
    eret


/// @brief svc_handler: SVC指令异常处理器（K2U/U2K跨域测试核心）
///
/// 此handler处理来自EL0(用户态)的SVC指令异常。
/// SVC（Supervisor Call）指令是ARM64的系统调用机制：
///   - EL0执行SVC指令 → CPU陷入EL1 → 路由到inner_vector_table的组2同步异常条目
///   - ESR_EL1.EC = 0x15 (EC_SVC64)，标识这是SVC指令产生的异常
///
/// K2U/U2K测试场景中的SVC异常处理：
///   K2U（内核→用户态）：内核(EL1)将控制权交给用户态(EL0)，
///     用户态通过SVC指令返回内核，此时SVC异常路由到此handler
///   U2K（用户态→内核）：用户态(EL0)通过SVC指令请求内核服务，
///     SVC异常路由到此handler，handler将控制权转给内核测试代码
///
/// 处理流程：
///   1. 保存EL0的上下文（ELR_EL1保存了SVC指令的下一条指令地址，
///      SPSR_EL1保存了EL0的PSTATE状态）
///   2. 检查is_nested_fault标志 - 防止嵌套异常导致无限递归
///   3. 如果非嵌套且自定义handler(fault_handler)已注册：
///      将ELR_EL1设置为fault_handler地址，通过eret跳转到自定义handler
///      自定义handler通常位于测试用例代码内部，执行特定的异常恢复逻辑
///   4. 如果为嵌套异常或无自定义handler：跳转到默认test_case_handler
///      test_case_handler记录异常信息后跳转到recovery代码

.global svc_handler
svc_handler:
    // 步骤1：检查嵌套异常标志
    // is_nested_fault为1表示已经发生过一次异常，当前是第二次异常
    // 嵌套异常时不能再尝试跳转到自定义handler，因为handler本身可能也有问题
    // 必须直接使用默认恢复路径，避免无限递归
    adr TMP_REG1_, is_nested_fault
    ldr TMP_REG2_, [TMP_REG1_]
    cmp TMP_REG2_, #0
    b.ne .svc_handler.nested_fault

    // 步骤2：标记当前正在处理异常（设置is_nested_fault=1）
    // 这样如果后续又发生异常，会被识别为嵌套异常
    mov TMP_REG2_, #1
    str TMP_REG2_, [TMP_REG1_]

    // 步骤3：检查是否注册了自定义fault_handler
    // fault_handler指向测试用例内部的异常恢复代码
    // 如果非NULL，优先使用自定义handler，因为测试用例知道如何恢复自身状态
    adr TMP_REG2_, fault_handler
    ldr TMP_REG2_, [TMP_REG2_]
    cmp TMP_REG2_, #0
    b.eq .svc_handler.default

    // 步骤4：自定义handler已注册 - 跳转到fault_handler
    // 将ELR_EL1设置为fault_handler地址
    // eret指令会恢复SPSR_EL1中保存的PSTATE状态，并跳转到ELR_EL1指向的地址
    // 注意：eret从EL1返回时，如果SPSR_EL1.M[3:0]=0，则返回到EL0
    //       如果SPSR_EL1.M[3:0]=4，则留在EL1
    //       在SVC异常处理中，我们修改ELR_EL1而非SPSR_EL1，
    //       这意味着eret后的特权级取决于SPSR_EL1的原始值
    //       为了正确在EL1级别执行fault_handler，需要确保SPSR_EL1.M设置为EL1模式
.svc_handler.registered_handler:
    // 修改SPSR_EL1确保eret后留在EL1（而非返回EL0）
    // SPSR_EL1.M[3:0] = 0x5表示EL1h模式（AArch64，EL1使用SP_EL1）
    mrs TMP_REG3_, spsr_el1
    // 清除M[3:0]字段（bits 3:0），设置为EL1h模式(0x5)
    // ARM64 PSTATE.M编码：
    //   0x0 = EL0t（用户态，使用SP_EL0）
    //   0x4 = EL1t（内核态，使用SP_EL0）
    //   0x5 = EL1h（内核态，使用SP_EL1）- Linux内核正常运行模式
    //   0x8 = EL2t（Hypervisor，使用SP_EL0）
    //   0x9 = EL2h（Hypervisor，使用SP_ELx）
    and TMP_REG3_, TMP_REG3_, #0xFFFFFFFFFFFFFFF0  // 清除M[3:0]
    orr TMP_REG3_, TMP_REG3_, #0x5                  // 设置为EL1h模式
    msr spsr_el1, TMP_REG3_
    msr elr_el1, TMP_REG2_
    eret

    // 嵌套异常处理路径：输出错误消息后跳转到默认handler
.svc_handler.nested_fault:
    adr TMP_REG1_, .Lnested_fault_msg
    mov x0, TMP_REG1_
    bl _printk
    b .svc_handler.default

    // 默认处理路径：跳转到test_case_handler
    // test_case_handler记录异常信息后跳转到recovery代码
.svc_handler.default:
    b test_case_handler


/// @brief test_case_handler: 测试用例默认异常处理器
///
/// 此handler处理测试用例执行期间发生的所有异常（包括SVC fallback）。
/// 与svc_handler不同，test_case_handler不修改SPSR_EL1，
/// 因为它处理的是EL1自身的异常（组0/组1），eret后自然留在EL1。
///
/// 处理流程：
///   1. 检查is_nested_fault - 嵌套异常时直接使用默认恢复路径
///   2. 非嵌套时，设置is_nested_fault=1
///   3. 如果有自定义fault_handler注册，跳转到fault_handler
///   4. 否则，收集诊断信息并跳转到recovery代码
///
/// 诊断信息收集：
///   - ESR_EL1：异常综合征寄存器（EC字段标识异常类型）
///   - FAR_EL1：故障地址寄存器（引发异常的虚拟地址）
///   - loaded_test_case_entry：测试用例代码的入口地址
///   - SP：当前栈指针值

.global test_case_handler
test_case_handler:
    // 步骤1：检查嵌套异常标志
    // 如果is_nested_fault=1，说明当前异常是在异常处理过程中发生的
    // 这种情况下不能再尝试自定义handler，必须直接恢复
    adr TMP_REG1_, is_nested_fault
    ldr TMP_REG2_, [TMP_REG1_]
    cmp TMP_REG2_, #0
    b.ne .test_case_handler.default
    // 步骤2：标记当前正在处理异常
    mov TMP_REG2_, #1
    str TMP_REG2_, [TMP_REG1_]

    // 步骤3：检查自定义handler是否注册
    adr TMP_REG2_, fault_handler
    ldr TMP_REG2_, [TMP_REG2_]
    cmp TMP_REG2_, #0
    b.eq .test_case_handler.default

    // 步骤4：跳转到自定义handler
    // 设置ELR_EL1为fault_handler地址，eret跳转到handler
    // 自定义handler位于测试用例代码内部，知道如何恢复测试用例的状态
.test_case_handler.registered_handler:
    msr elr_el1, TMP_REG2_
    eret

    // 默认处理路径：收集诊断信息后恢复
.test_case_handler.default:
    // 收集异常诊断信息
    // x1 = ESR_EL1值（包含EC和ISS信息）
    mrs x1, esr_el1
    // x2 = FAR_EL1值（引发异常的虚拟地址）
    // 注意：FAR_EL1仅对数据异常和指令异常有效
    mrs x2, far_el1
    // x3 = 测试用例入口地址（用于判断异常发生在哪个测试代码范围内）
    adr x3, loaded_test_case_entry
    ldr x3, [x3]
    // x4 = 当前栈指针
    mov x4, sp
    // x5 = 错误消息字符串
    adr x5, .Ldefault_fault_msg

    // 设置恢复地址：跳转到.run_experiment_recovery
    // recovery代码会恢复栈指针并打印错误消息
    adr x0, .run_experiment_recovery
    msr elr_el1, x0
    eret


// =================================================================================================
// EL2级异常处理器
// =================================================================================================

/// @brief el2_sync_handler: EL2自身的同步异常处理器
///
/// 处理EL2级别发生的同步异常（组0/组1的同步异常条目）。
/// 这种异常通常发生在Hypervisor代码内部出现bug时。
///
/// 与EL1的fallback_handler类似，但使用ESR_EL2而非ESR_EL1：
///   ESR_EL2记录路由到EL2的异常详情，格式与ESR_EL1相同
///   ELR_EL2记录异常发生时的指令地址（即异常返回地址）
///   SPSR_EL2记录异常前的处理器状态
///
/// 恢复策略：将ELR_EL2设置为recovery代码地址，通过eret恢复执行

.global el2_sync_handler
el2_sync_handler:
    // 步骤1：读取EL2诊断信息
    // ESR_EL2包含异常类别(EC)和详细信息(ISS)
    mrs x1, esr_el2
    // ELR_EL2包含触发异常的指令地址（异常返回地址）
    mrs x2, elr_el2
    // 步骤2：准备诊断消息参数
    // x3 = 当前SP_EL2值（用于判断栈状态）
    mov x3, sp
    // x4-x5 = 错误消息字符串地址
    adr x4, .Lunexpected_el2_fault_msg
    mov x5, x4

    // 步骤3：设置恢复地址
    // 将ELR_EL2设置为.run_experiment_recovery
    // 注意：在EL2 handler中修改ELR_EL2，eret后返回到EL2或更低特权级
    // 具体返回的特权级取决于SPSR_EL2.M的值
    adr x0, .run_experiment_recovery
    msr elr_el2, x0
    // 设置SPSR_EL2确保eret后返回到EL1h模式
    // 这是因为recovery代码在EL1级别运行
    mov TMP_REG1_, #0x5        // EL1h模式编码
    msr spsr_el2, TMP_REG1_
    eret


/// @brief el2_lower_sync_handler: 来自EL1/EL0的同步异常处理器（H2G/G2H核心）
///
/// 处理来自低特权级(EL1/EL0)路由到EL2的同步异常。
/// 这是虚拟化场景的核心异常入口：
///   - 客户机VM(EL1)执行HVC指令 → VM Exit → 路由到EL2向量表组2同步异常
///   - 客户机VM访问无效内存 → 数据异常路由到EL2（取决于HCR_EL2配置）
///   - 客户机VM执行非法指令 → 指令异常路由到EL2
///
/// ESR_EL2.EC字段决定了异常类型，此handler根据EC值进行分类处理：
///   EC = 0x16 (HVC64)：HVC指令异常
///     这是G2H（客户机→宿主机）切换的触发事件
///     客户机通过HVC指令主动请求返回宿主机
///     handler恢复宿主机上下文并跳转到宿主机的landing point
///
///   EC = 0x24 (DABORT_EL1)：来自EL1的数据异常
///     客户机访问了无效的GPA（客户机物理地址）
///     可能是Meltdown类漏洞测试中的故意访问
///     handler检查是否有自定义fault_handler，若有则跳转
///
///   其他EC值：使用默认EL2异常恢复路径
///
/// 处理流程详解（HVC异常）：
///   1. 读取ESR_EL2确认EC = 0x16 (HVC64)
///   2. 读取ELR_EL2获取客户机中HVC指令的地址
///   3. 检查is_nested_fault标志
///   4. 如果非嵌套且有自定义handler：
///      - 恢复宿主机栈指针（从el2_recovery_sp）
///      - 设置ELR_EL2为宿主机的landing point地址
///      - 设置SPSR_EL2确保返回到宿主机特权级
///      - 通过eret返回宿主机执行
///   5. 如果嵌套或无自定义handler：使用默认恢复

.global el2_lower_sync_handler
el2_lower_sync_handler:
    // 步骤1：读取ESR_EL2并提取EC字段
    // ESR_EL2[31:26]是EC字段，标识异常类别
    mrs TMP_REG1_, esr_el2
    // 提取EC值：右移26位，掩码6位
    // EC = (ESR_EL2 >> 26) & 0x3F
    lsr TMP_REG2_, TMP_REG1_, #26
    and TMP_REG2_, TMP_REG2_, #0x3F

    // 步骤2：根据EC值进行分类处理
    // EC = 0x16 (HVC64) → 跳转到HVC handler
    cmp TMP_REG2_, #0x16         // EC_HVC64
    b.eq .el2_lower_sync_handler.hvc

    // EC = 0x24 (DABORT_EL1) → 数据异常处理
    // 客户机访问了无效内存地址，可能是Meltdown类测试的故意触发
    cmp TMP_REG2_, #0x24         // EC_AA64_DABORT_EL1
    b.eq .el2_lower_sync_handler.data_abort

    // EC = 0x20 (IABORT_EL1) → 指令异常处理
    // 客户机执行了非法指令
    cmp TMP_REG2_, #0x20         // EC_AA64_IABORT_EL1
    b.eq .el2_lower_sync_handler.data_abort

    // 其他EC值 → 使用默认EL2异常恢复
    b .el2_lower_sync_handler.default

    // HVC异常处理路径（G2H：客户机→宿主机切换）
    // 当客户机VM执行HVC指令时，CPU从EL1陷入EL2
    // 这是MACRO_SWITCH_G2H宏的底层实现机制
.el2_lower_sync_handler.hvc:
    // 步骤H1：检查嵌套异常标志
    adr TMP_REG3_, is_nested_fault
    ldr TMP_REG4_, [TMP_REG3_]
    cmp TMP_REG4_, #0
    b.ne .el2_lower_sync_handler.default

    // 步骤H2：标记正在处理异常
    mov TMP_REG4_, #1
    str TMP_REG4_, [TMP_REG3_]

    // 步骤H3：检查是否有自定义fault_handler
    // fault_handler在H2G/G2H场景中指向宿主机的landing point
    // landing point是MACRO_LANDING_G2H宏展开后的代码地址
    adr TMP_REG4_, fault_handler
    ldr TMP_REG4_, [TMP_REG4_]
    cmp TMP_REG4_, #0
    b.eq .el2_lower_sync_handler.default

    // 步骤H4：恢复宿主机栈指针
    // el2_recovery_sp保存了宿主机(Hypervisor)在进入客户机之前的栈指针
    // 恢复栈指针确保宿主机代码能正常使用栈
    adr TMP_REG5_, el2_recovery_sp
    ldr TMP_REG6_, [TMP_REG5_]
    mov sp, TMP_REG6_

    // 步骤H5：设置ELR_EL2为宿主机landing point地址
    // fault_handler指向宿主机的landing point代码
    // eret后CPU跳转到landing point，恢复宿主机上下文继续执行
    msr elr_el2, TMP_REG4_

    // 步骤H6：设置SPSR_EL2确保eret后返回到EL2h模式
    // SPSR_EL2.M = 0x9表示EL2h模式（Hypervisor正常运行模式）
    // 这样eret后留在EL2级别，而非返回客户机(EL1)
    mov TMP_REG5_, #0x9        // EL2h模式编码
    msr spsr_el2, TMP_REG5_
    eret

    // 数据异常/指令异常处理路径
    // 客户机VM访问了无效内存或执行了非法指令
    // 处理逻辑与SVC handler类似：检查自定义handler并跳转
.el2_lower_sync_handler.data_abort:
    // 检查嵌套异常
    adr TMP_REG3_, is_nested_fault
    ldr TMP_REG4_, [TMP_REG3_]
    cmp TMP_REG4_, #0
    b.ne .el2_lower_sync_handler.default
    mov TMP_REG4_, #1
    str TMP_REG4_, [TMP_REG3_]

    // 检查自定义handler
    adr TMP_REG4_, fault_handler
    ldr TMP_REG4_, [TMP_REG4_]
    cmp TMP_REG4_, #0
    b.eq .el2_lower_sync_handler.default

    // 恢复宿主机栈并跳转到自定义handler
    adr TMP_REG5_, el2_recovery_sp
    ldr TMP_REG6_, [TMP_REG5_]
    mov sp, TMP_REG6_

    msr elr_el2, TMP_REG4_
    // 设置SPSR_EL2确保eret后返回EL1h（恢复到宿主机内核级别执行handler）
    mov TMP_REG5_, #0x5
    msr spsr_el2, TMP_REG5_
    eret

    // 默认恢复路径：收集诊断信息后跳转到recovery
    // 适用于所有无法特殊处理的EL2异常
.el2_lower_sync_handler.default:
    mrs x1, esr_el2
    mrs x2, elr_el2
    mov x3, sp
    adr x4, .Lunexpected_el2_fault_msg
    mov x5, x4

    adr x0, .run_experiment_recovery
    msr elr_el2, x0
    mov TMP_REG1_, #0x5        // EL1h模式
    msr spsr_el2, TMP_REG1_
    eret


/// @brief el2_irq_handler: EL2级IRQ中断处理器
///
/// 处理EL2级别的IRQ中断。
/// 在虚拟化场景中，IRQ可能来自物理中断控制器或虚拟中断控制器。
/// 简化处理：跳转到recovery代码，不做复杂的IRQ处理。
/// 实际产品级Hypervisor需要区分物理IRQ和虚拟IRQ并分别处理。

.global el2_irq_handler
el2_irq_handler:
    mrs x1, esr_el2
    mrs x2, elr_el2
    mov x3, sp
    adr x4, .Lunexpected_el2_fault_msg
    mov x5, x4

    adr x0, .run_experiment_recovery
    msr elr_el2, x0
    mov TMP_REG1_, #0x5
    msr spsr_el2, TMP_REG1_
    eret


/// @brief el2_fiq_handler: EL2级FIQ快速中断处理器
///
/// 处理EL2级别的FIQ（Fast Interrupt）。
/// FIQ是ARM64的高优先级快速中断，用于需要极快响应的事件。
/// 在虚拟化场景中，FIQ通常与安全世界(TrustZone)相关。
/// 简化处理：跳转到recovery代码。

.global el2_fiq_handler
el2_fiq_handler:
    mrs x1, esr_el2
    mrs x2, elr_el2
    mov x3, sp
    adr x4, .Lunexpected_el2_fault_msg
    mov x5, x4

    adr x0, .run_experiment_recovery
    msr elr_el2, x0
    mov TMP_REG1_, #0x5
    msr spsr_el2, TMP_REG1_
    eret


/// @brief el2_serror_handler: EL2级SError系统错误处理器
///
/// 处理EL2级别的SError（System Error）中断。
/// SError是ARM64的异步系统错误信号，通常表示硬件故障：
///   - 内存ECC错误
///   - Bus错误
///   - 其他不可纠正的硬件错误
/// SError的处理策略是尽快恢复，不做复杂的错误恢复尝试。

.global el2_serror_handler
el2_serror_handler:
    mrs x1, esr_el2
    mrs x2, elr_el2
    mov x3, sp
    adr x4, .Lunexpected_el2_fault_msg
    mov x5, x4

    adr x0, .run_experiment_recovery
    msr elr_el2, x0
    mov TMP_REG1_, #0x5
    msr spsr_el2, TMP_REG1_
    eret


/// @brief el2_lower_irq_handler: 来自EL1/EL0的IRQ中断处理器
///
/// 处理来自客户机VM(EL1)或用户态(EL0)路由到EL2的IRQ中断。
/// 在虚拟化场景中，物理IRQ路由到EL2由HCR_EL2.IMO位控制。
/// Hypervisor收到IRQ后需要判断是物理IRQ还是虚拟IRQ，
/// 并决定是自己处理还是注入回客户机。
/// 简化处理：直接跳转到recovery。

.global el2_lower_irq_handler
el2_lower_irq_handler:
    b .el2_lower_sync_handler.default


/// @brief el2_lower_fiq_handler: 来自EL1/EL0的FIQ中断处理器
///
/// 处理来自低特权级路由到EL2的FIQ中断。
/// FIQ路由到EL2由HCR_EL2.FMO位控制。
/// 简化处理：跳转到默认EL2异常恢复。

.global el2_lower_fiq_handler
el2_lower_fiq_handler:
    b .el2_lower_sync_handler.default


/// @brief el2_lower_serror_handler: 来自EL1/EL0的SError处理器
///
/// 处理来自低特权级路由到EL2的SError中断。
/// SError路由到EL2由HCR_EL2.AMO位控制。
/// 客户机VM产生的SError可能是硬件故障信号，需要立即处理。
/// 简化处理：跳转到默认EL2异常恢复。

.global el2_lower_serror_handler
el2_lower_serror_handler:
    b .el2_lower_sync_handler.default


// =================================================================================================
// run_experiment_outer: 异常容错包装函数
// =================================================================================================
.text

/// @brief run_experiment_outer: run_experiment的异常容错包装器
///
/// 此函数确保run_experiment内部任何bug导致的异常都能被优雅处理，
/// 不会导致系统崩溃。它的工作流程：
///
///   1. 保存当前CPU状态（所有通用寄存器）到栈上
///      - 如果run_experiment内部bug损坏了CPU状态，保存的值可用于恢复
///      - 保存顺序从x1/x2开始，避免覆盖x0（可能包含返回值）
///   2. 保存栈指针(SP)到全局变量recovery_sp
///      - 如果run_experiment内部bug损坏了栈，recovery_sp可用于恢复SP
///   3. 安装outer_vector_table（通过set_outer_fault_handlers）
///      - outer_vector_table将所有异常路由到fallback_handler
///      - fallback_handler会跳转到.run_experiment_recovery恢复代码
///   4. 调用run_experiment
///   5. 无论是正常返回还是异常恢复，最终都会到达恢复代码：
///      - .run_experiment_normal_exit：run_experiment正常返回
///      - .run_experiment_recovery：fallback_handler跳转到此（异常恢复）
///   6. 恢复原始向量表（通过unset_outer_fault_handlers）
///   7. 恢复CPU状态（从栈上恢复所有通用寄存器）
///
/// @param void - 无参数

.global run_experiment_outer
run_experiment_outer:
    // 步骤1：保存所有通用寄存器到栈上
    // ARM64调用约定：x0-x7是参数/返回值寄存器，x8-x28是临时/ callee-saved寄存器
    // 保存顺序从x1/x2开始，因为x0后面可能用作返回值
    // 每对寄存器使用stp指令保存，栈指针递减16字节（两个8字节寄存器）
    stp x1, x2, [sp, -16]!
    stp x3, x4, [sp, -16]!
    stp x5, x6, [sp, -16]!
    stp x7, x8, [sp, -16]!
    stp x9, x10, [sp, -16]!
    stp x11, x12, [sp, -16]!
    stp x13, x14, [sp, -16]!
    stp x15, x16, [sp, -16]!
    stp x17, x18, [sp, -16]!
    stp x19, x20, [sp, -16]!
    stp x21, x22, [sp, -16]!
    stp x23, x24, [sp, -16]!
    stp x25, x26, [sp, -16]!
    stp x27, x28, [sp, -16]!
    stp x29, x30, [sp, -16]!

    // 步骤2：保存x21(SP相关)和栈指针到全局变量
    // x21是UTIL_BASE_REGISTER，在某些代码路径中可能被修改
    // 保存原始值以便恢复
    mov x21, sp

    // 步骤3：保存当前栈指针到recovery_sp全局变量
    // 如果run_experiment中的bug导致栈损坏（如SP被覆盖），
    // fallback_handler跳转到.run_experiment_recovery后，
    // 会用recovery_sp恢复正确的栈指针
    mov x0, sp
    adr x1, recovery_sp
    str x0, [x1]

    // 步骤4：安装外层向量表
    // set_outer_fault_handlers保存原始VBAR_EL1并设置为outer_vector_table
    // outer_vector_table将所有异常路由到fallback_handler
    bl set_outer_fault_handlers

    // 步骤5：调用run_experiment
    // run_experiment是测试执行的核心函数
    // 如果run_experiment内部发生异常，CPU跳转到fallback_handler
    // fallback_handler设置ELR_EL1为.run_experiment_recovery并eret
    // 这样执行流会跳转到恢复代码而非崩溃
    bl run_experiment
    b .run_experiment_normal_exit

.run_experiment_recovery:
    // 异常恢复路径（从fallback_handler跳转到此）
    //
    // 步骤R1：恢复栈指针
    // 使用recovery_sp全局变量中保存的原始SP值
    // 这一步至关重要：如果bug损坏了栈，不恢复SP就无法继续执行
    adr TMP_REG1_, recovery_sp
    ldr TMP_REG2_, [TMP_REG1_]
    mov sp, TMP_REG2_

    // 步骤R2：恢复x21
    // x21可能在异常过程中被修改，需要恢复
    mov x21, sp

    // 步骤R3：打印错误消息
    // fallback_handler已经将诊断信息放到x1(ESR)、x2(FAR)、x3(run_experiment地址)、x4(SP)中
    // x5指向错误消息字符串
    // x0 = 错误消息字符串地址（从x5复制）
    // 调用_printk输出诊断信息
    mov x0, x5
    bl _printk
    // 设置返回值为1（表示异常发生，与正常返回0区分）
    mov x0, #1

.run_experiment_normal_exit:
    // 正常返回和异常恢复的汇合点
    //
    // 步骤N1：恢复原始向量表
    // unset_outer_fault_handlers将VBAR_EL1恢复为操作系统原始向量表
    // 必须在run_experiment结束后恢复，否则系统的异常处理会继续指向我们的向量表
    // 保存x0/x1（返回值和可能的错误信息）到栈上，防止被函数调用覆盖
    stp x0, x1, [sp, -16]!
    bl unset_outer_fault_handlers
    ldp x0, x1, [sp], 16

    // 步骤N2：恢复所有通用寄存器
    // 从栈上恢复之前保存的寄存器值
    // 恢复顺序与保存顺序相反（栈是LIFO结构）
    // ldp指令从栈上加载两个8字节值到指定寄存器，栈指针递增16字节
    ldp x29, x30, [sp], 16
    ldp x27, x28, [sp], 16
    ldp x25, x26, [sp], 16
    ldp x23, x24, [sp], 16
    ldp x21, x22, [sp], 16
    ldp x19, x20, [sp], 16
    ldp x17, x18, [sp], 16
    ldp x15, x16, [sp], 16
    ldp x13, x14, [sp], 16
    ldp x11, x12, [sp], 16
    ldp x9, x10, [sp], 16
    ldp x7, x8, [sp], 16
    ldp x5, x6, [sp], 16
    ldp x3, x4, [sp], 16
    ldp x1, x2, [sp], 16

    // 步骤N3：返回调用者
    // x0包含返回值（0=正常，1=异常发生）
    // x30(lr)包含调用者的返回地址
    ret

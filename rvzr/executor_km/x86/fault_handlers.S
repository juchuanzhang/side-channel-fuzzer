/// 文件：x86-64低级异常处理汇编代码
/// 实现测试用例执行期间的异常捕获、故障恢复和安全退出机制
///
/// 本文件是论文"Enter, Exit, Page Fault, Leak"中测量执行环境的安全保障层。
/// 在x86-64架构下，测试用例会故意触发各种异常（如页故障#PF、通用保护故障#GP等）
/// 来制造微架构侧信道泄漏条件。这些异常必须被安全地捕获和恢复，不能让内核崩溃。
///
/// 异常处理架构分为三层：
///   1. **test_case_handler**：捕获测试用例执行期间发生的异常
///      当测试用例代码（在sandbox中运行）触发#PF/#GP等异常时，此处理器负责：
///      - 打印异常信息（向量号、错误码、RIP等）
///      - 调用recover_orig_state()恢复被修改的CPU状态
///      - 跳转到恢复路径，安全终止当前测量
///
///   2. **bubble_handler**：捕获测试框架代码中的异常
///      当run_experiment()本身（而非测试用例）触发异常时，此处理器负责：
///      - 打印异常信息和上下文（run_experiment地址等）
///      - 恢复CPU状态并安全退出
///      - 这种异常通常意味着executor本身存在bug
///
///   3. **nmi_handler/nested_fault_handler**：处理不可屏蔽中断和嵌套故障
///      - NMI：不可屏蔽中断，通常由硬件故障或调试器触发
///      - 嵌套故障：在异常处理过程中又发生异常，说明状态已严重损坏
///      - 这两种情况只能打印错误信息并强制退出
///
/// IDT(中断描述符表)管理：
///   - set_outer_fault_handlers()：将IDT替换为包含256个bubble_handler入口的自定义IDT
///   - set_inner_fault_handlers()：将IDT替换为包含256个test_case_handler入口的IDT
///   - 这样实现了两级异常捕获：外层(bubble)保护框架代码，内层(test_case)保护测试代码
///
/// 入口桩(entry stub)机制：
///   x86-64异常处理的一个重要问题是：某些异常(如#PF)在栈上推送错误码，
///   而其他异常(如#DE)不推送错误码。这导致栈布局不一致。
///   entry_stub_no_err和entry_stub_err宏解决了这个问题：
///   - entry_stub_no_err：为不带错误码的异常推入0作为占位，统一栈布局
///   - entry_stub_err：直接使用CPU推入的错误码
///   两种桩都将异常向量号写入r13，然后跳转到主处理器
///
/// 异常向量号与错误码对应表：
///   不带错误码(使用entry_stub_no_err)：0x00-0x07, 0x09, 0x0f, 0x10, 0x12-0x14, 0x16-0x1f, 0x20-0xff
///   带错误码(使用entry_stub_err)：
///     0x08: #DF(双重故障)
///     0x0a-0x0e: #TS/TSS段无效, #NP段不存在, #SS栈段故障, #GP通用保护, #PF页故障
///     0x11: #AC对齐检查
///     0x15: VMM通信异常
///     0x1d: #VC虚拟化异常
///     0x1e: #SX安全异常
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
.intel_syntax noprefix

#include "sandbox_constants.h"
#include "registers.h"

/// 外部C函数引用——这些函数在fault_handler.c和measurement.c中定义
.extern _printk                              /// 内核打印函数(用于输出调试信息)
.extern set_outer_fault_handlers             /// 设置外层IDT(bubble_handler覆盖全部256个向量)
.extern unset_outer_fault_handlers           /// 恢复原始IDT(取消外层异常处理覆盖)
.extern run_experiment                       /// 核心测量循环函数(在measurement.c中定义)
.extern recover_orig_state                   /// 故障安全状态恢复函数(恢复VMX/SVM/MSR/PTE等)


// =================================================================================================
// 全局变量
// =================================================================================================
/// 数据段——存储全局状态变量和错误信息字符串
.data

/// is_nested_fault：嵌套故障标志
/// 当异常处理器正在处理一个异常时又发生异常，此标志置1
/// 用于检测异常处理过程中的状态损坏——此时无法安全恢复，只能强制退出
.global is_nested_fault
is_nested_fault:
.quad 0

/// fault_recovery_sp：故障恢复栈指针
/// 在run_experiment_outer入口处保存当前栈指针(RSP)
/// 当异常导致栈损坏时，使用此值恢复到安全的栈位置
/// 这是故障恢复的关键——确保恢复代码有可用的栈空间
fault_recovery_sp:
.quad 0

/// 错误信息字符串——用于printk输出调试信息
/// 格式：\0013表示KERN_ERR级别(内核错误级日志)
/// 每条消息对应不同的异常处理场景

/// 恢复触发消息——当故障恢复路径被执行时打印
/// 表明run_experiment执行中发生了不可恢复的异常
.Lrecovery_triggered_msg:
.asciz	"\0013[rvzr_executor:run_experiment_outer]\n\
ERROR: Recovery from fault triggered during run_experiment\n"
.align

/// 不可达代码消息——当理论上不可能执行的代码路径被执行时打印
/// 通常意味着严重的逻辑错误或代码损坏
.Lunreachable_msg:
.asciz	"\0013[rvzr_executor:rvzr_executor]\n\
ERROR: unreachable code\n"
.align

/// 测试用例异常消息——test_case_handler捕获异常时打印
/// 包含完整的异常上下文：向量号、错误码、RIP、CS、RFLAGS、RSP
/// 以及沙箱寄存器R14/R15的值(用于定位沙箱数据区)
.Ltest_case_handler_msg:
.asciz	"\0013[rvzr_executor:test_case_handler]\n\
ERROR: Unhandled fault in the test case: \n\
    0 [Exception ID]:\t0x%llx\n\
    1 [Error code]:\t0x%llx\n\
    2 [RIP]:\t0x%llx\n\
    3 [CS]:\t0x%llx\n\
    4 [RFLAGS]:\t0x%llx\n\
    5 [RSP]:\t0x%llx\n\
Context:\n\
    R14: \t0x%llx\n\
    R15: \t0x%llx\n"
.align

/// 框架代码异常消息——bubble_handler捕获异常时打印
/// 与test_case_handler_msg类似，但额外包含run_experiment和run_experiment_outer的地址
/// 用于区分异常发生在测试用例代码还是框架代码中
.Lbubble_handler_msg:
.asciz	"\0013[rvzr_executor:bubble_handler]\n\
ERROR: Unexpected fault in run_experiment: \n\
    0 [Exception ID]:\t0x%llx\n\
    1 [Error code]:\t0x%llx\n\
    2 [RIP]:\t0x%llx\n\
    3 [CS]:\t0x%llx\n\
    4 [RFLAGS]:\t0x%llx\n\
    5 [RSP]:\t0x%llx\n\
Context:\n\
    run_experiment:\t\t0x%llx\n\
    run_experiment_outer:\t0x%llx\n"
.align

/// NMI异常消息——不可屏蔽中断发生时打印
/// NMI通常由硬件故障或外部调试器触发，无法被CLI指令禁用
.Lnmi_handler_msg:
.asciz	"\0013[rvzr_executor:nmi_handler]\n\
ERROR: Unhandled NMI occurred during run_experiment\n"
.align

/// 嵌套故障消息——异常处理过程中又发生异常时打印
/// 嵌套故障意味着CPU状态已严重损坏，无法安全恢复
.Lnested_fault_msg:
.asciz	"\0013[rvzr_executor:nested_fault]\n\
ERROR: Nested fault detected\n"
.align

// =================================================================================================
// 汇编宏定义
// =================================================================================================

/// unreachable宏——打印"不可达代码"错误消息并停机
/// 用于标记理论上不可能执行的代码路径
/// 如果此宏被执行，说明发生了严重的代码损坏或逻辑错误
.macro unreachable
    lea rdi, .Lunreachable_msg
    mov rsi, rcx
    call _printk
    hlt                           /// 停机指令——CPU停止执行，等待外部中断
.endm

/// entry_stub_no_err宏——生成不带错误码的异常入口桩
/// x86-64中某些异常(如#DE除零错误、#NM设备不可用)不会在栈上推入错误码
/// 这导致栈布局与带错误码的异常不一致，需要推入0作为占位来统一栈格式
///
/// 栈布局统一化处理：
///   不带错误码的异常栈: [RSP] [RFLAGS] [CS] [RIP] ← 缺少错误码
///   统一化后的栈:       [RSP] [RFLAGS] [CS] [RIP] [0=假错误码] ← 统一格式
///
/// @param name: 主处理器名称(test_case_handler或bubble_handler)
/// @param id: 异常向量号(如00=#DE, 0e=#PF等)
.macro entry_stub_no_err name, id
.global \name\()_\id              /// 导出全局符号，供IDT设置函数引用
.balign 16                        /// 16字节对齐——IDT条目要求的对齐
\name\()_\id:
    push 0                        /// 推入假错误码0——统一栈布局，与带错误码的异常一致
    mov r13, 0x\id                /// 将异常向量号写入r13——主处理器通过r13获取向量号
    jmp \name                     /// 跳转到主处理器——统一处理逻辑
.endm

/// entry_stub_err宏——生成带错误码的异常入口桩
/// x86-64中某些异常(如#PF页故障、#GP通用保护)会在栈上自动推入错误码
/// 这些异常不需要额外的假错误码，直接使用CPU推入的错误码
///
/// 带错误码的异常栈: [RSP] [RFLAGS] [CS] [RIP] [错误码] ← 已有错误码
///
/// @param name: 主处理器名称
/// @param id: 异常向量号
.macro entry_stub_err name, id
.global \name\()_\id              /// 导出全局符号
.balign 16                        /// 16字节对齐
\name\()_\id:
    mov r13, 0x\id                /// 将异常向量号写入r13
    jmp \name                     /// 跳转到主处理器(CPU已推入错误码，无需额外操作)
.endm

/// CALL_16_TIMES宏——C预处理器宏，将一个汇编宏重复调用16次
/// 用于批量生成0x20-0xFF范围的异常入口桩(这些向量号通常不发生异常，
/// 但IDT必须为全部256个向量提供入口)
/// @param macro: 要重复的汇编宏名(entry_stub_no_err)
/// @param arg: 宏的第一个参数(handler名)
/// @param id: 向量号的高位部分(如id=2生成0x20-0x2f)
#define CALL_16_TIMES(macro, arg, id)                                                              \
    macro arg, id##0; macro arg, id##1; macro arg, id##2; macro arg, id##3;                        \
    macro arg, id##4; macro arg, id##5; macro arg, id##6; macro arg, id##7;                        \
    macro arg, id##8; macro arg, id##9; macro arg, id##a; macro arg, id##b;                        \
    macro arg, id##c; macro arg, id##d; macro arg, id##e; macro arg, id##f;


// =================================================================================================
// 异常处理器实现
// =================================================================================================
.text

/// test_case_handler：测试用例异常处理器
/// 当测试用例代码在sandbox中执行时触发异常(如#PF/#GP)，CPU根据IDT跳转到此处理器
///
/// 处理流程：
///   1. CLI禁用中断——防止在异常处理过程中被中断干扰
///   2. 检查嵌套故障标志——如果已在处理异常，说明状态损坏，跳到恢复路径
///   3. 设置嵌套故障标志——标记当前正在处理异常
///   4. 打印异常信息——输出向量号、错误码、RIP、CS、RFLAGS、RSP、R14、R15
///   5. 调用recover_orig_state()——恢复被修改的CPU状态(MSR/PTE/VMX等)
///   6. 跳转到恢复路径——安全退出当前测量
///
/// 栈布局(由entry_stub统一化后)：
///   [RSP] [RFLAGS] [CS] [RIP] [错误码或0] ← r13=向量号
///   这些值依次被pop到对应的printk参数寄存器中
///
/// @param r13: 异常向量号(由entry_stub设置)
.global test_case_handler
.balign 4096                      /// 页对齐——此符号地址被用作IDT覆盖的基址
test_case_handler:
    cli                            /// 禁用中断——异常处理期间不接受新中断

    /// 检查嵌套故障标志——防止在异常处理过程中又发生异常导致无限递归
    lea rax, is_nested_fault
    cmp qword ptr [rax], 0
    jne .run_experiment_recovery   /// 嵌套故障→跳到恢复路径(不能再处理异常)
    mov qword ptr [rax], 1         /// 非嵌套故障→设置标志，标记正在处理异常

    /// 打印异常上下文信息——依次从栈上提取异常信息传递给printk
    /// 栈布局已被entry_stub统一化：[RSP][RFLAGS][CS][RIP][错误码]
    /// printk参数：rdi=格式串, rsi=向量号, rdx=错误码, rcx=RIP,
    ///             r8=CS, r9=RFLAGS, 栈=RSP, R14, R15
    lea rdi, .Ltest_case_handler_msg  /// 格式字符串
    mov rsi, r13                      /// 参数1: 异常向量号(由entry_stub写入r13)
    pop rdx                           /// 参数2: 错误码(从栈上弹出)
    pop rcx                           /// 参数3: RIP(异常发生时的指令地址)
    pop r8                            /// 参数4: CS(异常发生时的代码段)
    pop r9                            /// 参数5: RFLAGS(异常发生时的标志寄存器)
    /// 参数6+: 通过栈传递(RSP、R14、R15)
    pop rax                           /// 获取RSP值
    push r15                          /// 参数8: R15(沙箱util区基址寄存器)
    push r14                          /// 参数7: R14(沙箱data区基址寄存器)
    push rax                          /// 参数6: RSP(异常发生时的栈指针)
    xor eax, eax                      /// 无浮点参数(vsprintf要求AL=0表示无向量寄存器使用)
    call _printk                      /// 调用内核printk输出异常信息

    /// 调用recover_orig_state()恢复CPU状态——故障安全恢复
    /// 恢复内容：VMX/SVM虚拟化状态、MSR系统寄存器、PTE权限等
    /// 此函数可在异常处理器中安全调用（不会失败或崩溃）
    call recover_orig_state

    /// 跳转到恢复路径——使用fault_recovery_sp恢复栈并安全退出
    jmp .run_experiment_recovery


/// bubble_handler：框架代码异常处理器
/// 当run_experiment()本身（而非测试用例）触发异常时使用此处理器
/// 这通常意味着executor框架存在bug，而非测试用例故意触发异常
///
/// 与test_case_handler的区别：
///   - bubble_handler额外打印run_experiment和run_experiment_outer的地址
///   - 用于区分异常发生在测试用例代码还是框架代码中
///
/// @param r13: 异常向量号
.global bubble_handler
.balign 4096
bubble_handler:
    cli                            /// 禁用中断

    /// 检查嵌套故障标志
    lea rax, is_nested_fault
    cmp qword ptr [rax], 0
    jne .run_experiment_recovery
    mov qword ptr [rax], 1

    /// 打印异常上下文——与test_case_handler类似但包含框架代码地址
    lea rdi, .Lbubble_handler_msg     /// 格式字符串
    mov rsi, r13                      /// 参数1: 异常向量号
    pop rdx                           /// 参数2: 错误码
    pop rcx                           /// 参数3: RIP
    pop r8                            /// 参数4: CS
    pop r9                            /// 参数5: RFLAGS
    /// 参数6+: RSP + run_experiment地址 + run_experiment_outer地址
    pop r10                           /// 获取RSP值
    lea r11, run_experiment           /// 获取run_experiment函数地址
    lea r12, run_experiment_outer     /// 获取run_experiment_outer函数地址
    push r12                          /// 参数8: run_experiment_outer地址
    push r11                          /// 参数7: run_experiment地址
    push r10                          /// 参数6: RSP值
    xor eax, eax                      /// 无浮点参数
    call _printk
    add rsp, 16                       /// 清理栈上2个额外参数(只压了3个但格式要求2+1=3对齐)

    /// 恢复CPU状态
    call recover_orig_state

    /// 跳转到恢复路径
    jmp .run_experiment_recovery


/// nmi_handler：不可屏蔽中断处理器
/// NMI(Non-Maskable Interrupt)是x86中最高优先级的外部中断，无法被CLI禁用
/// 通常由以下原因触发：
///   - 硬件故障(内存ECC错误、总线错误等)
///   - 外部调试器触发(如kernel debugger的NMI断点)
///   - 系统管理中断(SMI)后的NMI
///   - 某些性能监控工具
///
/// 处理策略：
///   - 无法正常恢复——NMI不受控制，通常意味着严重的硬件问题
///   - 直接设置嵌套故障标志(防止后续异常尝试恢复)
///   - 恢复栈指针到安全位置
///   - 打印错误消息并跳到恢复路径
.global nmi_handler
.balign 4096
nmi_handler:
    cli                            /// 禁用中断(虽然NMI不可屏蔽，但至少阻止其他中断)

    /// 设置嵌套故障标志——标记状态已损坏，后续异常不应尝试恢复
    mov qword ptr [is_nested_fault], 1

    /// 恢复栈指针——NMI可能在任何时刻发生，当前栈可能无效
    /// 使用保存的fault_recovery_sp确保有可用的栈空间
    lea rbx, fault_recovery_sp
    mov rbx, [rbx]
    mov rsp, rbx

    /// 打印NMI错误消息
    lea rdi, .Lnmi_handler_msg
    call _printk

    /// 跳转到恢复路径——强制退出当前测量
    jmp .run_experiment_recovery


/// nested_fault_handler：嵌套故障处理器
/// 当在异常处理过程中又发生异常时触发——这是最严重的情况：
///   - 第一层异常已可能损坏了部分CPU状态
///   - 第二层异常意味着状态损坏更严重
///   - 无法安全地恢复任何状态
///
/// Revizor当前不支持多层异常恢复——嵌套故障只能打印消息并强制退出
.global nested_fault_handler
.balign 4096
nested_fault_handler:
    cli                            /// 禁用中断

    /// 打印嵌套故障消息
    lea rdi, .Lnested_fault_msg
    call _printk

    /// 直接跳到恢复路径——不做任何状态恢复尝试
    jmp .run_experiment_recovery


// =================================================================================================
// 256个异常入口桩批量生成
// =================================================================================================
/// 本节为test_case_handler和bubble_handler各生成256个入口桩
/// IDT(中断描述符表)必须为全部256个向量号(0x00-0xFF)提供处理器入口
/// 每个入口桩负责：
///   1. 统一化栈布局(确保错误码存在)
///   2. 将向量号写入r13
///   3. 跳转到主处理器
///
/// 两种入口桩类型的选择取决于异常是否会推入错误码：
///   带错误码的异常向量号：0x08(#DF), 0x0a(#TS), 0x0b(#NP), 0x0c(#SS),
///                         0x0d(#GP), 0x0e(#PF), 0x11(#AC), 0x15(VMM),
///                         0x1d(#VC), 0x1e(#SX)
///   不带错误码的异常向量号：所有其他向量号
///
/// 注意：0x00-0x1f范围的向量号逐个展开(便于精确选择正确的桩类型)
///       0x20-0xff范围的向量号使用CALL_16_TIMES批量展开(全部使用no_err桩)
.text

/// test_case_handler的256个入口桩——内层IDT使用
/// 这些入口桩地址被set_inner_fault_handlers()写入IDT
entry_stub_no_err test_case_handler, 00  /// #DE: 除零错误(无错误码)
entry_stub_no_err test_case_handler, 01  /// #DB: 调试异常(无错误码)
entry_stub_no_err test_case_handler, 02  /// NMI: 不可屏蔽中断(无错误码)
entry_stub_no_err test_case_handler, 03  /// #BP: 断点(INT3)(无错误码)
entry_stub_no_err test_case_handler, 04  /// #OF: 溢出(INTO)(无错误码)
entry_stub_no_err test_case_handler, 05  /// #BR: BOUND范围超出(无错误码)
entry_stub_no_err test_case_handler, 06  /// #UD: 无效操作码(无错误码)
entry_stub_no_err test_case_handler, 07  /// #NM: 设备不可用(无错误码)
entry_stub_err test_case_handler, 08     /// #DF: 双重故障(带错误码)
entry_stub_no_err test_case_handler, 09  /// 协处理器段超出(无错误码)
entry_stub_err test_case_handler, 0a     /// #TS: 无效TSS(带错误码)
entry_stub_err test_case_handler, 0b     /// #NP: 段不存在(带错误码)
entry_stub_err test_case_handler, 0c     /// #SS: 栈段故障(带错误码)
entry_stub_err test_case_handler, 0d     /// #GP: 通用保护故障(带错误码)——fuzzer最关心的异常
entry_stub_err test_case_handler, 0e     /// #PF: 页故障(带错误码)——fuzzer最关心的异常
entry_stub_no_err test_case_handler, 0f  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 10  /// #MF: x87 FPU浮点错误(无错误码)
entry_stub_err test_case_handler, 11     /// #AC: 对齐检查(带错误码)
entry_stub_no_err test_case_handler, 12  /// #MC: 机器检查(无错误码)
entry_stub_no_err test_case_handler, 13  /// #XM: SIMD浮点异常(无错误码)
entry_stub_no_err test_case_handler, 14  /// #VE: 虚拟化异常(无错误码)
entry_stub_err test_case_handler, 15     /// VMM通信异常(带错误码)
entry_stub_no_err test_case_handler, 16  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 17  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 18  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 19  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 1a  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 1b  /// 保留(无错误码)
entry_stub_no_err test_case_handler, 1c  /// 保留(无错误码)
entry_stub_err test_case_handler, 1d     /// #VC: 虚拟化通信异常(带错误码)
entry_stub_err test_case_handler, 1e     /// #SX: 安全异常(带错误码)
entry_stub_no_err test_case_handler, 1f  /// 保留(无错误码)
/// 向量号0x20-0xFF：全部使用no_err桩(这些向量通常用于外部中断或未分配)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 2)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 3)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 4)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 5)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 6)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 7)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 8)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 9)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, a)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, b)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, c)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, d)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, e)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, f)

/// bubble_handler的256个入口桩——外层IDT使用
/// 这些入口桩地址被set_outer_fault_handlers()写入IDT
/// 与test_case_handler使用相同的向量号分类规则
entry_stub_no_err bubble_handler, 00     /// #DE
entry_stub_no_err bubble_handler, 01     /// #DB
entry_stub_no_err bubble_handler, 02     /// NMI
entry_stub_no_err bubble_handler, 03     /// #BP
entry_stub_no_err bubble_handler, 04     /// #OF
entry_stub_no_err bubble_handler, 05     /// #BR
entry_stub_no_err bubble_handler, 06     /// #UD
entry_stub_no_err bubble_handler, 07     /// #NM
entry_stub_err bubble_handler, 08        /// #DF
entry_stub_no_err bubble_handler, 09     /// 协处理器段超出
entry_stub_err bubble_handler, 0a        /// #TS
entry_stub_err bubble_handler, 0b        /// #NP
entry_stub_err bubble_handler, 0c        /// #SS
entry_stub_err bubble_handler, 0d        /// #GP
entry_stub_err bubble_handler, 0e        /// #PF
entry_stub_no_err bubble_handler, 0f     /// 保留
entry_stub_no_err bubble_handler, 10     /// #MF
entry_stub_err bubble_handler, 11        /// #AC
entry_stub_no_err bubble_handler, 12     /// #MC
entry_stub_no_err bubble_handler, 13     /// #XM
entry_stub_no_err bubble_handler, 14     /// #VE
entry_stub_err bubble_handler, 15        /// VMM通信异常
entry_stub_no_err bubble_handler, 16     /// 保留
entry_stub_no_err bubble_handler, 17     /// 保留
entry_stub_no_err bubble_handler, 18     /// 保留
entry_stub_no_err bubble_handler, 19     /// 保留
entry_stub_no_err bubble_handler, 1a     /// 保留
entry_stub_no_err bubble_handler, 1b     /// 保留
entry_stub_no_err bubble_handler, 1c     /// 保留
entry_stub_err bubble_handler, 1d        /// #VC
entry_stub_err bubble_handler, 1e        /// #SX
entry_stub_no_err bubble_handler, 1f     /// 保留
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 2)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 3)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 4)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 5)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 6)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 7)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 8)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 9)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, a)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, b)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, c)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, d)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, e)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, f)


// =================================================================================================
// run_experiment_outer：带故障恢复的测量入口包装器
// =================================================================================================
/// run_experiment_outer是测量的最外层入口——对应论文Figure 4算法的最高层包装
///
/// 功能：在安全环境中调用run_experiment()，确保任何异常都能被安全恢复
///
/// 执行流程：
///   1. 保存全部callee-save寄存器(x86-64 ABI要求rbx/rcx/rdx/rsi/rdi/r8-r15/rbp)
///   2. 保存当前栈指针到fault_recovery_sp全局变量(用于故障恢复)
///   3. CLI禁用中断(防止测量期间被外部中断干扰)
///   4. 调用set_outer_fault_handlers()设置外层IDT
///   5. 调用run_experiment()执行测量循环
///   6. 正常退出：恢复IDT和寄存器
///   7. 故障恢复：使用fault_recovery_sp恢复栈，打印错误消息，返回错误码1
///
/// 故障恢复路径(.run_experiment_recovery)是关键的安全机制：
///   - 当test_case_handler/bubble_handler/nmi_handler捕获异常后跳到此路径
///   - 此路径使用预先保存的栈指针恢复栈(因为异常可能已损坏当前栈)
///   - 打印恢复消息，设置返回值为1(表示测量失败)
///   - 然后与正常退出共用相同的清理路径
///
/// 寄存器保存/恢复的对称性：
///   push顺序: rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 rbp
///   pop顺序:  rbp r15 r14 r13 r12 r11 r10 r9 r8 rdi rsi rdx rcx rbx
///   (x86-64栈是后进先出，所以pop顺序是push的逆序)
.text

/// run_experiment_outer：带故障恢复的测量入口函数
/// 此函数被trace_test_case()调用，是测量的最外层包装
/// @param void(无参数)
/// @return rax: 0=测量成功, 1=测量因异常而中断
.global run_experiment_outer
.balign 4096                      /// 页对齐——此符号地址被用作异常处理代码区域的标识
run_experiment_outer:
    /// 保存callee-save寄存器——x86-64 ABI要求函数必须保存这些寄存器
    /// 这些寄存器可能在run_experiment()中被修改(包括测试用例代码)
    /// 如果发生异常，恢复路径需要这些原始值来安全退出
    push rbx                       /// 通用寄存器rbx
    push rcx                       /// 通用寄存器rcx(也被用于异常向量号传递)
    push rdx                       /// 通用寄存器rdx
    push rsi                       /// 源索引寄存器rsi
    push rdi                       /// 目标索引寄存器rdi
    push r8                        /// 通用寄存器r8
    push r9                        /// 通用寄存器r9
    push r10                       /// 通用寄存器r10
    push r11                       /// 通用寄存器r11
    push r12                       /// 通用寄存器r12
    push r13                       /// 通用寄存器r13(异常向量号寄存器)
    push r14                       /// 沙箱data区基址寄存器r14
    push r15                       /// 沙箱util区基址寄存器r15
    push rbp                       /// 栈基址指针rbp
    mov rbp, rsp                   /// 设置栈帧基址(标准x86-64函数序言)

    /// 保存栈指针到全局变量——故障恢复的关键数据
    /// 当异常损坏栈后，使用此值恢复到安全的栈位置
    lea rax, fault_recovery_sp
    mov [rax], rsp

    /// CLI禁用中断——测量期间必须禁用外部中断
    /// 外部中断(如时钟中断、网络中断)会干扰微架构状态，导致测量不可重复
    /// 虽然pre_run()中已禁用中断，此处再次确认(安全冗余)
    cli

    /// 设置外层IDT——将IDT替换为包含bubble_handler的自定义IDT
    /// 外层IDT保护run_experiment()框架代码——框架代码中的异常不应传播到内核
    call set_outer_fault_handlers

    /// 调用核心测量循环——进入run_experiment()执行测量
    /// run_experiment()内部会设置内层IDT(test_case_handler)来捕获测试用例异常
    call run_experiment
    jmp .run_experiment_normal_exit  /// 正常完成测量→跳到正常退出路径

/// 故障恢复路径——异常处理器跳转到此路径安全退出
/// 这是关键的安全恢复代码——在CPU状态可能已严重损坏的情况下执行
/// 必须尽可能少地假设当前状态的有效性
.run_experiment_recovery:
    /// ---- 开始关键恢复区域 ----
    /// 注意：此区域用于从executor bug中恢复，此时内存和寄存器状态可能已完全损坏
    /// 因此以下代码必须尽可能少地做假设，并非常小心地处理内存访问

    /// 使用保存的栈指针恢复栈——这是恢复的第一步
    /// 异常可能导致当前栈指针(RSP)指向无效内存，必须使用预先保存的安全值
    lea rbx, fault_recovery_sp
    mov rbx, [rbx]
    mov rsp, rbx

    /// 打印恢复触发消息——告知用户发生了异常恢复
    lea rdi, .Lrecovery_triggered_msg
    call _printk

    /// 设置返回值为1——表示测量因异常而失败
    /// 正常完成时返回0，异常恢复时返回1
    /// trace_test_case()根据此值判断是否需要重新测量
    mov rax, 1

    /// 跳转到正常退出路径——共用清理代码
    jmp .run_experiment_normal_exit
    /// ---- 结束关键恢复区域 ----

/// 正常退出路径——正常完成和故障恢复共用此路径
/// 清理步骤：恢复IDT → 恢复寄存器 → 返回
.run_experiment_normal_exit:
    /// 保存返回值(rax)——后续的call指令可能修改rax
    push rax

    /// 恢复原始IDT——取消异常处理覆盖
    /// 将IDT恢复为内核的原始IDT，确保后续代码使用正常的异常处理
    call unset_outer_fault_handlers
    pop rax                        /// 恢复返回值

    /// 恢复callee-save寄存器——与push顺序逆序pop
    /// 这是x86-64 ABI的标准寄存器恢复顺序
    pop rbp                        /// 恢复栈基址指针
    pop r15                        /// 恢复沙箱util区基址寄存器
    pop r14                        /// 恢复沙箱data区基址寄存器
    pop r13                        /// 恢复通用寄存器
    pop r12                        /// 恢复通用寄存器
    pop r11                        /// 恢复通用寄存器
    pop r10                        /// 恢复通用寄存器
    pop r9                         /// 恢复通用寄存器
    pop r8                         /// 恢复通用寄存器
    pop rdi                        /// 恢复目标索引寄存器
    pop rsi                        /// 恢复源索引寄存器
    pop rdx                        /// 恢复通用寄存器
    pop rcx                        /// 恢复通用寄存器
    pop rbx                        /// 恢复通用寄存器

    /// 返回调用者(trace_test_case)
    ret

    /// 不可达代码标记——ret之后不应执行任何代码
    /// 如果此标记被执行，说明发生了严重的代码损坏
    unreachable

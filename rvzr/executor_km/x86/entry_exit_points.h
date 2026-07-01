/// 文件：x86-64架构测试用例的入口和出口点模板，多种变体
///      仅由code_loader.c使用
///
/// 本文件定义测试用例执行环境的入口(prologue)和出口(epilogue)汇编模板。
/// prologue负责：保存callee-save寄存器、设置沙箱基址寄存器、清零通用寄存器、
///               初始化状态寄存器和追踪寄存器、设置本地栈、开始SMI监控
/// epilogue负责：结束SMI监控、将测量结果写入沙箱输出区、恢复寄存器、返回
///
/// 寄存器保留说明：
///   部分寄存器有固定用途(见registers.h)，绝不能被测试用例代码覆盖：
///   - r12(STATUS_REGISTER): 测量状态和SMI计数
///   - r13(HTRACE_REGISTER): 硬件追踪结果
///   - r14(MEMORY_BASE_REG): 沙箱数据区基址
///   - r15(UTIL_BASE_REG): 沙箱工具区基址
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef RVZR_ENTRY_EXIT_H
#define RVZR_ENTRY_EXIT_H

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "registers.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

/// 模板标记常量——用于在生成的测试用例二进制中标记特殊位置
/// 这些值是特殊地址模式(不可访问的虚拟地址)，code_loader通过扫描这些标记来定位代码段
#define TEMPLATE_START                     0x0fff379000000000  /// 测试用例代码段起始标记
#define TEMPLATE_INSERT_TC                 0x0fff2f9000000000  /// 测试用例插入位置标记(替换为实际测试代码)
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0fff479000000000  /// 默认异常着陆点标记(跳转到此处避免崩溃)
#define TEMPLATE_END                       0x0fff279000000000  /// 测试用例代码段结束标记
#define TEMPLATE_MARKER_SIZE               8                   /// 标记大小(8字节=64位 quad)

// clang-format off
/// prologue()——测试用例入口序言
/// 在测试用例执行前设置执行环境：
/// 1. 保存callee-save寄存器(rbx/rbp/r10-r15/rflags)——防止被测试用例覆盖
/// 2. 设置MEMORY_BASE_REG(r14)=actor 0的main_area基址(通过rdi传入)
/// 3. 设置UTIL_BASE_REG(r15)=sandbox->util基址(从main_area反向偏移计算)
/// 4. 保存当前RSP到util->stored_rsp——异常恢复时需要此值
/// 5. 清零所有通用寄存器(rax/rbx/rcx/rdx/rsi/rdi/r8-r11)
/// 6. 清零保留寄存器(r12/r13)的测量相关部分
/// 7. 初始化STATUS_REGISTER为STATUS_UNINITIALIZED
/// 8. 设置本地栈(rbp=rsp, rsp-=0x1000)
/// 9. 开始SMI监控(READ_SMI_START)
static inline void prologue(void)
{
    // 由于不使用编译器跟踪寄存器破坏，必须手动保存callee-save寄存器
    // 以防止测试用例代码覆盖这些寄存器导致崩溃
    asm_volatile_intel(
        "push rbx\n"
        "push rbp\n"
        "push r10\n"
        "push r11\n"
        "push r12\n"
        "push r13\n"
        "push r14\n"
        "push r15\n"
        "pushfq\n"

        // MEMORY_BASE_REG(r14) = main_area基址
        // rdi是measurement_code的第一个参数，指向actor 0的main_area
        "mov "MEMORY_BASE_REG", rdi\n"

        // UTIL_BASE_REG(r15) = sandbox->util基址
        // 从main_area反向偏移UTIL_REL_TO_MAIN字节得到util结构地址
        "lea "UTIL_BASE_REG", ["MEMORY_BASE_REG" - "xstr(UTIL_REL_TO_MAIN)"]\n"

        // 保存当前栈指针到util->stored_rsp——异常恢复的关键数据
        // 当异常发生时，需要恢复到此栈位置才能正确返回
        "mov qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"], rsp\n"

        // 清零所有通用寄存器——确保测试用例从干净状态开始
        // 不清零r14/r15(已设置为基址)，不清零rsp/rbp(栈相关)
        "mov rax, 0\n"
        "mov rbx, 0\n"
        "mov rcx, 0\n"
        "mov rdx, 0\n"
        "mov rsi, 0\n"
        "mov rdi, 0\n"
        "mov r8,  0\n"
        "mov r9,  0\n"
        "mov r10, 0\n"
        "mov r11, 0\n"

        // 初始化特殊保留寄存器
        // r13(HTRACE_REGISTER)=0: 硬件追踪结果初始为零
        // r12(STATUS_REGISTER)=STATUS_UNINITIALIZED: 标记测量尚未开始
        "mov "HTRACE_REGISTER", 0\n"
        "mov "STATUS_REGISTER", "xstr(STATUS_UNINITIALIZED)"\n"

        // 设置本地栈——预留4KB栈空间供测试用例使用
        // rbp=rsp(帧指针), rsp-=0x1000(预留栈空间)
        "mov rbp, rsp\n"
        "sub rsp, 0x1000\n"

        // 开始监控SMI中断——记录SMI计数器起始值
        // SMI(System Management Interrupt)是不可屏蔽中断，会干扰微架构状态
        READ_SMI_START()
    );

}

/// epilogue()——测试用例出口尾声(正常测量模式)
/// 在测试用例执行后收集测量结果并恢复环境：
/// 1. 结束SMI监控(READ_SMI_END)——计算SMI差值存入STATUS_REGISTER
/// 2. 将测量结果写入util->latest_measurement结构：
///    - offset+0x00: HTRACE_REGISTER(r13) 硬件追踪结果
///    - offset+0x08: r10(PFC0) 第1个性能计数器差值
///    - offset+0x10: r9(PFC1)  第2个性能计数器差值
///    - offset+0x18: r8(PFC2)  第3个性能计数器差值
///    - offset+0x20~0x28: PFC3/PFC4(未使用,填0)
///    - offset+0x30: STATUS_REGISTER(r12) 测量状态
/// 3. 恢复RSP到util->stored_rsp——回到prologue保存的栈位置
/// 4. 恢复callee-save寄存器和rflags——与prologue的push顺序相反
/// 5. 返回0(rax=0)
static inline void epilogue(void)
{
    asm_volatile_intel(
        // 结束SMI监控——读取SMI计数器结束值，计算差值存入STATUS_REGISTER
        READ_SMI_END()

        // rax <- &latest_measurement——获取测量输出结构的地址
        "lea rax, ["UTIL_BASE_REG" + "xstr(MEASUREMENT_OFFSET)"]\n"

        // 将测量结果写入latest_measurement结构
        "mov qword ptr [rax + 0x00], "HTRACE_REGISTER" \n"  // HTrace——硬件追踪结果(P+P位串或F+R位串)
        "mov qword ptr [rax + 0x08], r10 \n"                // PFC0——第1个PMU计数器差值
        "mov qword ptr [rax + 0x10], r9 \n"                 // PFC1——第2个PMU计数器差值
        "mov qword ptr [rax + 0x18], r8 \n"                 // PFC2——第3个PMU计数器差值
        "mov qword ptr [rax + 0x20], 0 \n"                  // PFC3(未使用,填0)
        "mov qword ptr [rax + 0x28], 0 \n"                  // PFC4(未使用,填0)
        "mov qword ptr [rax + 0x30], "STATUS_REGISTER" \n"  // Measurement status——测量状态(含SMI差值)

        // 恢复栈指针到prologue保存的值——异常恢复也使用此路径
        "mov rsp, qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"]\n"

        // 恢复callee-save寄存器——与prologue中push顺序相反
        // popfq恢复rflags(含中断状态)，pop顺序: r15→r14→r13→r12→r11→r10→rbp→rbx
        "popfq\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // 返回0——表示测量正常完成
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // objtool警告消除——ret后放置int3防止误执行
    );
}

/// epilogue_dbg_gpr()——调试模式出口尾声(输出所有GPR而非测量值)
/// 与epilogue()的区别：将通用寄存器的原始值而非测量结果写入输出区
/// 用于调试测试用例对寄存器的影响
/// 输出布局：
///    - offset+0x00: rax
///    - offset+0x08: rbx
///    - offset+0x10: rcx
///    - offset+0x18: rdx
///    - offset+0x20: rsi
///    - offset+0x28: rdi
///    - offset+0x30: STATUS_REGISTER(r12) 测量状态
/// 注意：此版本破坏r14(MEMORY_BASE_REG)，将其用作输出区地址指针
///       因为所有测量已完成，MEMORY_BASE_REG不再需要
static inline void epilogue_dbg_gpr(void)
{
    asm_volatile_intel(
        // r14 <- &latest_measurement——复用MEMORY_BASE_REG作为输出指针
        // r14已不再需要(测量已完成)，可以安全破坏
        "lea r14, ["UTIL_BASE_REG" + "xstr(MEASUREMENT_OFFSET)"]\n"

        // 将通用寄存器值写入latest_measurement结构
        "mov qword ptr [r14 + 0x00], rax\n"
        "mov qword ptr [r14 + 0x08], rbx\n"
        "mov qword ptr [r14 + 0x10], rcx\n"
        "mov qword ptr [r14 + 0x18], rdx\n"
        "mov qword ptr [r14 + 0x20], rsi\n"
        "mov qword ptr [r14 + 0x28], rdi\n"
        "mov qword ptr [r14 + 0x30], "STATUS_REGISTER"\n"

        // 恢复栈指针到prologue保存的值
        "mov rsp, qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"]\n"

        // 恢复callee-save寄存器
        "popfq\n"
        "pop r15\n"
        "pop r14\n"   // r14恢复后不再是输出指针，而是prologue保存的原始值
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // 返回0
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // objtool警告消除
    );
}
// clang-format on

/// main_segment_template()——正常测量模式的完整测试用例模板
/// 模板结构：
///   TEMPLATE_START标记 → prologue → SET_REGISTER_FROM_INPUT → PIPELINE_RESET
///   → lfence → TEMPLATE_INSERT_TC(测试代码占位) → mfence
///   → 异常着陆点(jmp + TEMPLATE_DEFAULT_EXCEPTION_LANDING标记 + nop nop nop)
///   → epilogue → TEMPLATE_END标记
/// code_loader扫描这些标记来定位和替换各段代码
static void main_segment_template(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));  /// 代码段起始标记——code_loader从此处开始扫描
    prologue();                                    /// 入口序言——设置执行环境

    SET_REGISTER_FROM_INPUT();                     /// 从沙箱输入区加载初始寄存器值
    PIPELINE_RESET();                              /// 流水线重置——等待先前微操作完成

    // 测试用例占位符——code_loader将TEMPLATE_INSERT_TC替换为实际测试代码
    asm volatile("\nlfence\n");                    /// lfence确保前序代码全部完成后再开始测试
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");  /// 测试代码插入位置标记
    asm volatile("\nmfence\n");                    /// mfence确保测试代码的全部内存操作完成后再进入出口

    // 异常着陆点——测试用例触发异常时跳转到此处
    // jmp 1f跳过标记值，TEMPLATE_DEFAULT_EXCEPTION_LANDING标记供code_loader定位
    // nop nop nop填充确保安全的着陆空间(防止异常处理跳转目标不对齐)
    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue();                                    /// 出口尾声——收集测量结果并恢复环境
    asm volatile(".quad " xstr(TEMPLATE_END));     /// 代码段结束标记
}

/// main_segment_template_dbg_gpr()——调试模式的完整测试用例模板
/// 与main_segment_template()结构相同，但使用epilogue_dbg_gpr()输出GPR值
/// 用于调试测试用例对寄存器的影响，而非测量侧信道信号
static void main_segment_template_dbg_gpr(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));  /// 代码段起始标记
    prologue();                                    /// 入口序言

    SET_REGISTER_FROM_INPUT();                     /// 从沙箱输入区加载初始寄存器值
    PIPELINE_RESET();                              /// 流水线重置

    // 测试用例占位符——同正常模式
    asm volatile("\nlfence\n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("\nmfence\n");

    // 异常着陆点——同正常模式
    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue_dbg_gpr();                            /// 调试模式出口尾声——输出所有GPR值而非测量结果
    asm volatile(".quad " xstr(TEMPLATE_END));     /// 代码段结束标记
}

#endif // RVZR_ENTRY_EXIT_H

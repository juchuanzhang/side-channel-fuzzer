/// 文件：ARM64架构测试用例的入口和出口点模板
///      由code_loader.c使用
///
/// 本文件定义ARM64架构测试用例执行环境的入口(prologue)和出口(epilogue)汇编模板。
/// ARM64与x86的关键差异：
///   - 寄存器保存使用stp/ldp(pair存储)而非push/pop
///   - 基址寄存器使用x20/x21(callee-save)而非r14/r15
///   - 栈操作使用sp而非rsp，对齐要求16字节而非8字节
///   - 立即数加载使用movz/movk而非mov(64位立即数需要4条指令)
///   - 序列化使用dsb+isb而非lfence/mfence
///   - 模板标记使用不同的魔术值(0x1111/0x2222等而非0x0fff3790等)
///
/// 寄存器保留说明：
///   部分寄存器有固定用途(见registers.h)，绝不能被测试用例代码覆盖：
///   - x12(STATUS_REGISTER): 测量状态
///   - x13(HTRACE_REGISTER): 硬件追踪结果
///   - x20(MEMORY_BASE_REGISTER): 沙箱数据区基址
///   - x21(UTIL_BASE_REGISTER): 沙箱工具区基址
///   - x16: asm_snippets.h内部使用，避免使用
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ENTRY_EXIT_H_
#define _ENTRY_EXIT_H_

#include "asm_snippets.h"

/// 模板标记常量——用于在生成的测试用例二进制中标记特殊位置
/// ARM64使用与x86不同的魔术值(地址模式不同)
/// code_loader通过扫描这些标记来定位代码段
#define TEMPLATE_START                     0x0000111100001111  /// 测试用例代码段起始标记
#define TEMPLATE_INSERT_TC                 0x0000222200002222  /// 测试用例插入位置标记(替换为实际测试代码)
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0000333300003333  /// 默认异常着陆点标记(跳转到此处避免崩溃)
#define TEMPLATE_END                       0x0000444400004444  /// 测试用例代码段结束标记
#define TEMPLATE_MARKER_SIZE               8                   /// 标记大小(8字节=64位 quad)

// clang-format off
/// prologue()——ARM64测试用例入口序言
/// 在测试用例执行前设置执行环境：
/// 1. 保存callee-save寄存器(x16-x30)——使用stp(pair)和str(单个)指令
///    ARM64调用约定要求保存x19-x28，但本代码也保存了x16-x18(IP0/IP1/IP2)
///    x29(帧指针)和x30(链接寄存器)也必须保存
/// 2. 设置MEMORY_BASE_REGISTER(x20)=main_area基址(通过x0传入)
/// 3. 设置UTIL_BASE_REGISTER(x21)=sandbox->util基址(从x20减去偏移)
/// 4. 保存当前SP到util->stored_sp——异常恢复时需要此值
/// 5. 清零所有通用寄存器(x0-x15)——确保测试用例从干净状态开始
/// 6. 清零保留寄存器(x12/x13)
/// 7. 初始化STATUS_REGISTER为STATUS_UNINITIALIZED
/// 8. 预留本地栈空间(sp-=0x1000)
/// 9. 开始中断监控(READ_SMI_START，目前未实现)
static inline void prologue(void)
{
    // 由于不使用编译器跟踪寄存器破坏，必须手动保存callee-save寄存器
    // ARM64使用stp(pair store)和str(single store)替代x86的push
    // 保存顺序：x16-x17, x18-x19, x20-x21, x22-x23, x24-x25, x26-x27, x28-x29, x30
    // sp递减16字节(stp)或8字节(str)，与x86的push类似
    asm volatile("" \
        "stp x16, x17, [sp, #-16]!\n"    /// 保存IP0/IP1(过程内调用临时寄存器)
        "stp x18, x19, [sp, #-16]!\n"    /// 保存IP2(平台寄存器)/x19(callee-save)
        "stp x20, x21, [sp, #-16]!\n"    /// 保存MEMORY_BASE/UTIL_BASE(callee-save，但仍需保存原始值)
        "stp x22, x23, [sp, #-16]!\n"    /// 保存x22-x23(callee-save)
        "stp x24, x25, [sp, #-16]!\n"    /// 保存x24-x25(callee-save，即TMP_REG5/TMP_REG4)
        "stp x26, x27, [sp, #-16]!\n"    /// 保存x26-x27(callee-save，即TMP_REG3/TMP_REG2)
        "stp x28, x29, [sp, #-16]!\n"    /// 保存x28(帧指针/callee-save)/x29(帧指针)
        "str x30, [sp, #-16]!\n"         /// 保存x30(链接寄存器/LR)

        // MEMORY_BASE_REGISTER(x20) = main_area基址
        // x0是measurement_code的第一个参数，指向actor 0的main_area
        "mov "MEMORY_BASE_REGISTER", x0\n"

        // UTIL_BASE_REGISTER(x21) = sandbox->util基址
        // 从x20减去UTIL_REL_TO_MAIN偏移得到util结构地址
        // mov_imm_to_reg用于加载64位立即数(ARM64无法单条指令加载大立即数)
        "mov "UTIL_BASE_REGISTER", "MEMORY_BASE_REGISTER"\n"
        mov_imm_to_reg("x0", UTIL_REL_TO_MAIN)
        "sub "UTIL_BASE_REGISTER", "UTIL_BASE_REGISTER", x0\n"

        // 保存当前栈指针到util->stored_sp——异常恢复的关键数据
        // ARM64无法直接str sp到内存，需先mov到通用寄存器再str
        "mov x0, sp\n"
        "mov x1, #"xstr(STORED_RSP_OFFSET)"\n"
        "add x1, "UTIL_BASE_REGISTER", x1\n"
        "str x0, [x1]\n"

        // 清零所有通用寄存器——确保测试用例从干净状态开始
        // x0-x15全部清零，x16保留(IP0)，x17-x19由stp保存/恢复
        "mov x0, 0\n"
        "mov x1, 0\n"
        "mov x2, 0\n"
        "mov x3, 0\n"
        "mov x4, 0\n"
        "mov x5, 0\n"
        "mov x6, 0\n"
        "mov x7, 0\n"
        "mov x8, 0\n"    /// PFC2(x8)清零
        "mov x9, 0\n"    /// PFC1(x9)清零
        "mov x10, 0\n"   /// PFC0(x10)清零
        "mov x11, 0\n"
        "mov x12, 0\n"   /// STATUS_REGISTER清零
        "mov x13, 0\n"   /// HTRACE_REGISTER清零
        "mov x14, 0\n"
        "mov x15, 0\n"

        // 初始化特殊保留寄存器
        // x13(HTRACE_REGISTER)=0: 硬件追踪结果初始为零
        // x12(STATUS_REGISTER)=STATUS_UNINITIALIZED: 标记测量尚未开始
        // mov_imm_to_reg用于加载STATUS_UNINITIALIZED(可能不是0)
        "mov "HTRACE_REGISTER", 0\n"
        mov_imm_to_reg(STATUS_REGISTER, STATUS_UNINITIALIZED)

        // 预留本地栈空间——sp-=0x1000(4KB)
        // ARM64没有类似x86的rbp=rsp操作，直接减sp即可
        "sub sp, sp, #0x1000\n"

        // 开始监控中断——ARM64的SMI监控尚未实现(FIXME)
        READ_SMI_START()
    );


}

/// epilogue()——ARM64测试用例出口尾声(正常测量模式)
/// 在测试用例执行后收集测量结果并恢复环境：
/// 1. 结束SMI监控(READ_SMI_END，目前未实现)
/// 2. 将测量结果写入util->latest_measurement结构：
///    - offset+0x00: HTRACE_REGISTER(x13) 硬件追踪结果
///    - offset+0x08: PFC0(x10) 第1个性能计数器差值
///    - offset+0x10: PFC1(x9)  第2个性能计数器差值
///    - offset+0x18: PFC2(x8)  第3个性能计数器差值
///    - offset+0x20/0x28: PFC3/PFC4(未使用,填xzr=零寄存器)
///    - offset+0x30: STATUS_REGISTER(x12) 测量状态
/// 3. 恢复SP到util->stored_sp
/// 4. 恢复callee-save寄存器——与prologue中stp顺序相反
/// 5. 返回0(x0=0)
static inline void epilogue(void)
{
    asm volatile(""
        READ_SMI_END()   /// 结束中断监控(ARM64尚未实现)

        // x0 = &latest_measurement——获取测量输出结构的地址
        // 使用mov_imm_to_reg加载MEASUREMENT_OFFSET(64位偏移)
        "mov x0, "UTIL_BASE_REGISTER"\n"
        mov_imm_to_reg("x1", MEASUREMENT_OFFSET)
        "add x0, x0, x1\n"

        // 将测量结果写入latest_measurement结构
        // ARM64使用str(single store)而非x86的mov qword ptr[]
        // xzr是零寄存器——读取始终返回0，写入无效果(用于清零)
        "str "HTRACE_REGISTER", [x0]\n"     // HTrace——硬件追踪结果
        "str "PFC0", [x0, #8]\n"            // PFC0——第1个PMU计数器差值
        "str "PFC1", [x0, #16]\n"           // PFC1——第2个PMU计数器差值
        "str "PFC2", [x0, #24]\n"           // PFC2——第3个PMU计数器差值
        "str xzr, [x0, #32]\n"              // PFC3(未使用,填零)
        "str xzr, [x0, #40]\n"              // PFC4(未使用,填零)
        "str "STATUS_REGISTER", [x0, #48]\n" // Measurement status——测量状态

        // 恢复栈指针到prologue保存的值
        // ARM64无法直接ldr到sp，需先ldr到通用寄存器再mov到sp
        mov_imm_to_reg("x1", STORED_RSP_OFFSET)
        "add x1, "UTIL_BASE_REGISTER", x1\n"
        "ldr x0, [x1]\n"
        "mov sp, x0\n"

        // 恢复callee-save寄存器——与prologue中stp顺序相反
        // ldp(pair load)后sp递增16字节，与x86的pop类似
        // 恢复顺序：x30, x28-x29, x26-x27, x24-x25, x22-x23, x20-x21, x18-x19, x16-x17
        "ldr x30, [sp], #16\n"              /// 恢复LR(链接寄存器)
        "ldp x28, x29, [sp], #16\n"         /// 恢复x28/x29(帧指针)
        "ldp x26, x27, [sp], #16\n"         /// 恢复x26/x27(TMP_REG3/TMP_REG2)
        "ldp x24, x25, [sp], #16\n"         /// 恢复x24/x25(TMP_REG5/TMP_REG4)
        "ldp x22, x23, [sp], #16\n"         /// 恢复x22/x23(TMP_REG6)
        "ldp x20, x21, [sp], #16\n"         /// 恢复x20/x21(MEMORY_BASE/UTIL_BASE)
        "ldp x18, x19, [sp], #16\n"         /// 恢复x18/x19(IP2/callee-save)
        "ldp x16, x17, [sp], #16\n"         /// 恢复x16/x17(IP0/IP1)

        // 返回0——ARM64返回值在x0中
        "mov x0, 0\n"
        "ret\n"
    );
}

/// epilogue_dbg_gpr()——ARM64调试模式出口尾声(输出所有GPR而非测量值)
/// 与epilogue()的区别：将通用寄存器的原始值而非测量结果写入输出区
/// 输出布局：
///    - offset+0x00: x0
///    - offset+0x08: x1
///    - offset+0x10: x2
///    - offset+0x18: x3
///    - offset+0x20: x4
///    - offset+0x28: x5
///    - offset+0x30: STATUS_REGISTER(x12) 测量状态
/// 注意：此版本使用x7作为输出指针(而非x0)，因为x0-x5要输出它们的原始值
///       同时破坏x8(用于加载偏移)，但x8的值也输出不了(只使用PMC#0/#1/#2)
static inline void epilogue_dbg_gpr(void)
{
    asm volatile(""
        READ_SMI_END()   /// 结束中断监控(ARM64尚未实现)

        // x7 = &latest_measurement——使用x7作为输出指针(不与x0-x5冲突)
        "mov x7, "UTIL_BASE_REGISTER"\n"
        mov_imm_to_reg("x8", MEASUREMENT_OFFSET)   /// x8被破坏，用于加载偏移
        "add x7, x7, x8\n"

        // 将通用寄存器值写入latest_measurement结构
        "str x0, [x7]\n"
        "str x1, [x7, #8]\n"
        "str x2, [x7, #16]\n"
        "str x3, [x7, #24]\n"
        "str x4, [x7, #32]\n"
        "str x5, [x7, #40]\n"
        "str "STATUS_REGISTER", [x7, #48]\n"

        // 恢复栈指针到prologue保存的值
        mov_imm_to_reg("x0", STORED_RSP_OFFSET)
        "add x0, "UTIL_BASE_REGISTER", x0\n"
        "ldr x0, [x0]\n"
        "mov sp, x0\n"

        // 恢复callee-save寄存器——与epilogue()相同
        "ldr x30, [sp], #16\n"
        "ldp x28, x29, [sp], #16\n"
        "ldp x26, x27, [sp], #16\n"
        "ldp x24, x25, [sp], #16\n"
        "ldp x22, x23, [sp], #16\n"
        "ldp x20, x21, [sp], #16\n"
        "ldp x18, x19, [sp], #16\n"
        "ldp x16, x17, [sp], #16\n"

        // 返回0
        "mov x0, 0\n"
        "ret\n"
    );
}
// clang-format on

/// main_segment_template()——ARM64正常测量模式的完整测试用例模板
/// 模板结构：
///   TEMPLATE_START标记 → prologue → SET_REGISTER_FROM_INPUT
///   → isb+dsb(ARM64序列化) → TEMPLATE_INSERT_TC(测试代码占位) → isb+dsb
///   → 异常着陆点(b跳转 + TEMPLATE_DEFAULT_EXCEPTION_LANDING标记 + nop nop)
///   → epilogue → TEMPLATE_END标记
/// ARM64与x86的差异：
///   - 序列化使用isb+dsb SY而非lfence/mfence
///   - 异常着陆点使用b(branch)而非jmp
///   - nop填充使用1个nop而非3个nop(ARM64指令固定4字节，无需对齐)
///   - 没有PIPELINE_RESET(ARM64使用不同的流水线重置策略)
static void main_segment_template(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));  /// 代码段起始标记——code_loader从此处开始扫描
    prologue();                                    /// 入口序言——设置执行环境

    SET_REGISTER_FROM_INPUT();                     /// 从沙箱输入区加载初始寄存器值

    // 测试用例占位符——code_loader将TEMPLATE_INSERT_TC替换为实际测试代码
    // ARM64使用isb(指令序列屏障)+dsb SY(数据序列屏障)替代x86的lfence/mfence
    // isb确保之前的指令全部完成后再执行下一条
    // dsb SY确保所有数据访问完成后再继续
    asm volatile("isb\n dsb SY \n");               /// 序列化——确保前序代码全部完成
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");  /// 测试代码插入位置标记
    asm volatile("isb\n dsb SY \n");               /// 序列化——确保测试代码的数据访问全部完成

    // 异常着陆点——ARM64使用b(branch)而非jmp
    // b 1f跳过标记值，TEMPLATE_DEFAULT_EXCEPTION_LANDING标记供code_loader定位
    // nop填充确保安全的着陆空间
    asm volatile("b 1f\n"
                 ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                   "nop\n"
                                                                   "1:nop\n");

    epilogue();                                    /// 出口尾声——收集测量结果并恢复环境
    asm volatile(".quad " xstr(TEMPLATE_END));     /// 代码段结束标记
}

/// main_segment_template_dbg_gpr()——ARM64调试模式的完整测试用例模板
/// 与main_segment_template()结构相同，但使用epilogue_dbg_gpr()输出GPR值
/// 用于调试测试用例对寄存器的影响，而非测量侧信道信号
static void main_segment_template_dbg_gpr(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));  /// 代码段起始标记
    prologue();                                    /// 入口序言

    SET_REGISTER_FROM_INPUT();                     /// 从沙箱输入区加载初始寄存器值

    // 测试用例占位符——同正常模式
    asm volatile("isb\n dsb SY \n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("isb\n dsb SY \n");

    // 异常着陆点——同正常模式
    asm volatile("b 1f\n"
                 ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                   "nop\n"
                                                                   "1:nop\n");

    epilogue_dbg_gpr();                            /// 调试模式出口尾声——输出所有GPR值而非测量结果
    asm volatile(".quad " xstr(TEMPLATE_END));     /// 代码段结束标记
}

#endif // _ENTRY_EXIT_H_

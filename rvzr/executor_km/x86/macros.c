// x86架构下各种宏的实现，以及宏加载器(macro_expansion.c)的x86特定代码
//
// 宏系统工作原理（论文Section 4.4）：
// 在执行器中，宏通过"二进制补丁"（binary patching）机制实现。
// 测试用例中的宏调用位置最初是NOP指令占位符，宏扩展过程将这些NOP
// 替换为相对跳转指令（JMP），跳转到宏的实际实现代码。
// 每个宏包含两部分：
//   1) 动态配置部分（start函数）：根据宏参数动态生成机器码，可配置
//   2) 静态主体部分（body函数）：不可配置，直接复制到测试用例的宏内存区域
// 宏扩展完成后，执行流程为：NOP→JMP→[动态配置代码]→[静态主体代码]→JMP→返回原代码流
//
/// File: x86 implementation of various macros as well as x86-specific code for
///       the macro loader (macro_expansion.c)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "asm_snippets.h"
#include "fault_handler.h"
#include "macro_expansion.h"
#include "main.h"
#include "page_tables_guest.h"
#include "page_tables_host.h"
#include "registers.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "svm.h"
#include "vmx.h"

extern uint64_t is_nested_fault; // defined in fault_handlers.S
void nested_fault_handler(void); // defined in fault_handlers.S

// =================================================================================================
// 向目标缓冲区写入常量的便捷宏——用于动态生成x86机器码
// 这些宏简化了二进制补丁过程中的指令编码，将各种宽度的数值写入dest缓冲区
// =================================================================================================
#define APPEND_U8_TO_DEST(value) dest[cursor++] = value;

#define APPEND_U16_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint16_t *)(dest + cursor)) = value;                                                    \
        cursor += 2;                                                                               \
    }

#define APPEND_U32_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint32_t *)(dest + cursor)) = value;                                                    \
        cursor += 4;                                                                               \
    }

#define APPEND_U64_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint64_t *)(dest + cursor)) = value;                                                    \
        cursor += 8;                                                                               \
    }

#define APPEND_BYTES_TO_DEST(...)                                                                  \
    {                                                                                              \
        static const uint8_t bytes[] = {__VA_ARGS__};                                              \
        for (size_t i = 0; i < sizeof(bytes); i++) {                                               \
            dest[cursor++] = bytes[i];                                                             \
        }                                                                                          \
    }

// =================================================================================================
// x86指令操作码编码——将movabs（64位立即数传送）指令写入目标缓冲区
// movabs格式: REX前缀(0x48/0x49) + ModRM(0xb8+reg_id) + 8字节立即数
// REX前缀选择: reg_id >= 8时使用0x49(REX.B), 否则使用0x48
// =================================================================================================
static inline void movabs(uint8_t *dest, size_t *cursor_, uint8_t reg_id, uint64_t value)
{
    size_t cursor = *cursor_;

    // REX prefix
    APPEND_U8_TO_DEST(reg_id >= REX_BOUNDARY ? 0x49 : 0x48);

    // ModRM byte
    reg_id = reg_id & 0x7;
    APPEND_U8_TO_DEST(0xb8 + reg_id);

    // Immediate value
    APPEND_U64_TO_DEST(value);
    *cursor_ = cursor;
}

// =================================================================================================
// 辅助函数——用于计算代码段地址和更新执行器寄存器（R14/RSP/R15）
// R14指向actor的数据区（data.main_area），R15指向工具区（util），RSP指向本地栈
// 宿主机(actor.mode==HOST)直接使用sandbox内存，客户机(actor.mode==GUEST)使用GUEST_V_MEMORY_START映射
// =================================================================================================

/// @brief 根据section_id和function_id计算函数在代码段中的虚拟地址
///        用于域切换宏中确定跳转目标地址
/// @param section_id 代码段ID（对应actor编号）
/// @param function_id 函数ID（在符号表中的索引）
/// @return 函数的虚拟地址
static uint64_t get_function_addr(uint64_t section_id, uint64_t function_id)
{
    uint64_t section_base = 0;

    if (actors[section_id].mode == MODE_HOST) {
        section_base = (uint64_t)sandbox->code[section_id].section;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        section_base = (uint64_t)guest_memory->code.section;
    }

    // The code section of the main actor begins after a hardcoded prologue,
    // which we need to take into account when calculating the function address
    if (section_id == 0)
        section_base += get_main_prologue_size();

    return section_base + test_case->symbol_table[function_id].offset;
}

/// @brief 生成更新R14的指令序列——将R14设置为指定actor的数据区基址
///        R14是执行器中的"内存基址寄存器"，所有数据访问通过[r14+offset]寻址
///        域切换时必须更新R14，使新actor的数据区可被正确访问
/// @param section_id actor编号
/// @param dest 目标缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_r14(uint64_t section_id, uint8_t *dest, uint64_t cursor)
{
    uint64_t old_cursor = cursor;

    // calculate the new R14 value
    uint64_t new_r14 = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_r14 = (uint64_t)sandbox->data[section_id].main_area;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r14 = (uint64_t)guest_memory->data.main_area;
    }

    // ASM: movabs r14, new_r14
    APPEND_BYTES_TO_DEST(0x49, 0xbe);
    APPEND_U64_TO_DEST(new_r14);
    return cursor - old_cursor;
}

/// @brief 生成更新R14和RSP的指令序列——同时更新内存基址和栈指针
///        域切换时需要同时更新R14（数据区基址）和RSP（栈指针），
///        RSP = 数据区基址 + LOCAL_RSP_OFFSET，确保栈在新actor的数据区内
/// @param section_id actor编号
/// @param dest 目标缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_mem_base_and_sp(uint64_t section_id, uint8_t *dest, uint64_t cursor)
{
    uint64_t old_cursor = cursor;
    cursor += update_r14(section_id, dest, cursor);

    // calculate the new RSP value
    uint64_t new_rsp = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_rsp = (uint64_t)sandbox->data[section_id].main_area + LOCAL_RSP_OFFSET;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_rsp = (uint64_t)guest_memory->data.main_area + LOCAL_RSP_OFFSET;
    }

    // ASM: movabs rsp, new_rsp
    APPEND_BYTES_TO_DEST(0x48, 0xbc);
    APPEND_U64_TO_DEST(new_rsp);
    return cursor - old_cursor;
}

/// @brief 生成更新R15的指令序列——将R15设置为指定actor的工具区基址
///        R15是执行器中的"工具区寄存器"，测量宏中Prime/Probe使用的L1D priming缓冲区
///        以及性能计数器(PFC)相关数据都通过[r15+offset]访问
/// @param section_id actor编号
/// @param dest 目标缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_r15(uint64_t section_id, uint8_t *dest, uint64_t cursor)
{
    uint64_t old_cursor = cursor;

    // calculate the new R15 value
    uint64_t new_r15 = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_r15 = (uint64_t)sandbox->util;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r15 = (uint64_t)&guest_memory->util;
    }

    // ASM: movabs r15, new_r15
    APPEND_BYTES_TO_DEST(0x49, 0xbf);
    APPEND_U64_TO_DEST(new_r15);
    return cursor - old_cursor;
}

// =================================================================================================
// 宏实现
//
// 宏由两部分组成：动态生成部分和静态主体部分。
// 动态部分由start_macro*函数生成，可根据宏参数进行配置（如跳转目标地址、寄存器值等）。
// 静态部分由body_macro*函数定义，不可配置，在编译时已固定，通过搜索MACRO_START/MACRO_END标记
// 从函数体中提取并直接复制到测试用例的宏内存区域。
// =================================================================================================

// 测量宏 MEASUREMENT_START 和 MEASUREMENT_END -----------------------------------------------
// Prime+Probe变体——通过填充(Prime)和探测(Probe)L1数据缓存来检测缓存访问模式
// 流程: Prime(填充缓存集) → 执行被测代码 → Probe(探测缓存集，检测哪些集被访问)
// "32"表示每个缓存集读取32次以稳定填充，"1"表示快速版本只读1次
// Prime+Probe测量宏——标准版本
// 步骤：MACRO_PROLOGUE(保存寄存器) → 加载priming缓冲区地址到rax → 
//       PRIME(填充L1D缓存集，每组32次读取) → READ_PFC_START(开始性能计数) →
//       SET_SR_STARTED(设置状态寄存器为STARTED) → MACRO_EPILOGUE(恢复寄存器) → lfence
static void __attribute__((noipa)) body_macro_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "32")           //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// 快速Prime+Probe测量宏——每个缓存集只读1次，速度更快但精度稍低
static void __attribute__((noipa)) body_macro_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "1")            //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// 部分Prime+Probe测量宏——只填充部分缓存集（而非完整L1D），减少测量开销
static void __attribute__((noipa)) body_macro_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "32")   //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// 快速部分Prime+Probe测量宏——部分填充且每组只读1次
static void __attribute__((noipa)) body_macro_fast_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "1")    //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Probe测量宏（Prime+Probe的测量结束部分）——检测被测代码对L1D缓存的影响
// 步骤：检查状态寄存器是否为STARTED(否则跳到标签99直接返回) →
//       MACRO_PROLOGUE → lfence → READ_PFC_END(结束性能计数) →
//       加载priming缓冲区地址 → PROBE(逐缓存集探测，记录访问时间到HTRACE_REGISTER) →
//       SET_SR_ENDED(设置状态为ENDED) → MACRO_EPILOGUE
// PROBE将每个缓存集的访问时间编码到HTRACE_REGISTER中，形成缓存访问的"迹"(trace)
static void __attribute__((noipa)) body_macro_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 99f\n"
                       MACRO_PROLOGUE()
                       "push r15\n"
                       "lfence\n"
                       READ_PFC_END()
                       "lea r15, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n"
                       PROBE("r15", "rbx", "r11", HTRACE_REGISTER)
                       "pop r15\n"
                       "mov qword ptr [rsp - 8], 0 \n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "99:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush+Reload变体——通过刷新(Flush)和重载(Reload)特定缓存行来检测访问
// 流程: Flush(从缓存中驱逐目标行) → 执行被测代码 → Reload(重载目标行，测量访问时间)
// 如果被测代码访问了该行，Reload会更快(命中缓存)；否则较慢(需从内存读取)
// Flush+Reload相比Prime+Probe精度更高，但需要共享内存

// Flush测量宏（Flush+Reload的测量开始部分）——将actor数据区的所有缓存行从L1D驱逐
// 步骤：MACRO_PROLOGUE → 加载数据区地址到rbx → FLUSH(逐行clflush) →
//       READ_PFC_START → SET_SR_STARTED → MACRO_EPILOGUE → lfence
static void __attribute__((noipa)) body_macro_flush(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                  //
                       MACRO_PROLOGUE()    //
                       "lea rbx, [r14]\n"  //
                       FLUSH("rbx", "rax") //
                       READ_PFC_START()    //
                       SET_SR_STARTED()    //
                       MACRO_EPILOGUE()    //
                       "lfence\n"          //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Reload测量宏（Flush+Reload的测量结束部分）——重载数据区并检测被测代码是否访问了特定行
// 步骤：检查状态寄存器 → MACRO_PROLOGUE → lfence → READ_PFC_END →
//       RELOAD(逐行重载，测量访问时间到HTRACE_REGISTER) →
//       设置HTRACE_REGISTER最高位为1(标记为Flush+Reload测量) → SET_SR_ENDED → MACRO_EPILOGUE
static void __attribute__((noipa)) body_macro_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 98f\n"
                       MACRO_PROLOGUE()
                       "lfence\n"
                       READ_PFC_END()
                       RELOAD("r14", "rbx", "r11", HTRACE_REGISTER)
                       "mov rax, 1\n"
                       "shl rax, 63\n"
                       "or " HTRACE_REGISTER ", rax\n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "98:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// TSC（时间戳计数器）测量宏——使用rdtsc指令直接测量被测代码的执行时间
// 流程: TSC_START(记录开始时间) → 执行被测代码 → TSC_END(记录结束时间，计算差值)

// TSC测量开始宏——记录起始时间戳
// 步骤：MACRO_PROLOGUE → lfence; rdtsc; lfence(读取时间戳) →
//       将EDX:EAX组合为64位时间戳 → xor HTRACE_REGISTER → sub HTRACE_REGISTER(记录起始时间) →
//       lfence → READ_PFC_START → SET_SR_STARTED → MACRO_EPILOGUE → lfence
static void __attribute__((noipa)) body_macro_tsc_start(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                               //
                       MACRO_PROLOGUE()                                 //
                       "lfence; rdtsc; lfence\n"                        //
                       "shl rdx, 32\n"                                  //
                       "or rdx, rax\n"                                  //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n" //
                       "sub " HTRACE_REGISTER ", rdx\n"                 //
                       "lfence\n"                                       //
                       READ_PFC_START()                                 //
                       SET_SR_STARTED()                                 //
                       MACRO_EPILOGUE()                                 //
                       "lfence\n"                                       //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// TSC测量结束宏——记录结束时间戳并计算时间差
// 步骤：检查状态寄存器 → MACRO_PROLOGUE → READ_PFC_END → lfence; rdtsc; lfence →
//       组合64位时间戳 → add HTRACE_REGISTER(累加结束时间到HTRACE，得到总耗时) →
//       SET_SR_ENDED → MACRO_EPILOGUE
static void __attribute__((noipa)) body_macro_tsc_end(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 97f\n"
                       MACRO_PROLOGUE()
                       READ_PFC_END()
                       "lfence; rdtsc; lfence\n"
                       "shl rdx, 32\n"
                       "or rdx, rax\n"
                       "add " HTRACE_REGISTER ", rdx\n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "97:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// 故障处理宏 FAULT_HANDLER -------------------------------------------------------------------
// 当被测代码触发异常（如页面故障）时，跳转到fault_handler继续执行
// 动态配置部分：更新RSP/R14/R15为actor 0的值，检查是否为嵌套故障（防止递归异常），
// 如果是嵌套故障则跳转到test_case_handler结束测试
static inline size_t start_macro_fault_handler(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    ASSERT(args.owner == 0, "inject_macro_configurable_part");

    // Set new global address to the fault handler
    fault_handler = (char *)((uint64_t)dest + cursor);

    // Ensure that RSP, R14, and R15 are set to correct values after (potential) actor switch
    cursor += update_mem_base_and_sp(0, dest, cursor);
    cursor += update_r15(0, dest, cursor);

    // Check for nested faults; if so, jump to `test_case_handler`
    uint64_t is_nested_fault_addr = (uint64_t)&is_nested_fault;
    uint64_t test_case_handler_addr = (uint64_t)nested_fault_handler;
    //   ASM: movabs TMP_REG, is_nested_fault_addr
    movabs(dest, &cursor, TMP_REG_ID, is_nested_fault_addr);
    //   ASM: cmp byte ptr [TMP_REG], 0
    APPEND_BYTES_TO_DEST(0x41, 0x80, 0x3b, 0x00);
    //   ASM: je no_nested_fault
    APPEND_BYTES_TO_DEST(0x74, 0x10);
    //   ASM: lfence
    APPEND_BYTES_TO_DEST(0x0f, 0xae, 0xe8);
    //   ASM: movabs TMP_REG, test_case_handler_addr
    movabs(dest, &cursor, TMP_REG_ID, test_case_handler_addr);
    //   ASM: jmp TMP_REG
    APPEND_BYTES_TO_DEST(0x41, 0xff, 0xe3);
    //   ASM: no_nested_fault:
    //   ASM: incb byte ptr [TMP_REG]
    APPEND_BYTES_TO_DEST(0x41, 0xfe, 0x03);
    return cursor;
}

// 带测量的故障处理宏 FAULT_HANDLER_WITH_MEASUREMENT -------------------------------------------
// 在故障处理的同时进行侧信道测量，将测量宏与故障处理组合
// 动态配置部分：更新R14和R15为故障发生actor的地址，以便测量宏能正确访问数据区
static inline size_t start_macro_fault_handler_with_measurement(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.arg1, dest, cursor);
    cursor += update_r15(args.arg1, dest, cursor);
    return cursor;
}

// 通用域切换宏 MACRO_SWITCH --------------------------------------------------------------------
// 用于在同一特权级内不同actor之间的切换（如从actor A的函数跳转到actor B的函数）
// 动态配置部分：更新RSP/R14为目标actor的值，然后通过相对跳转(JMP)跳转到目标函数
// 注意：此宏只有动态配置部分，没有静态主体
static inline size_t start_macro_switch(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // Update RSP and R14 to the addresses within the new actor's memory
    cursor += update_mem_base_and_sp(args.arg1, dest, cursor);

    // Determine the target address for the switch
    uint64_t switch_target = get_function_addr(args.arg1, args.arg2);
    uint32_t relative_offset = switch_target - (uint64_t)dest - cursor - 5;

    // Jump to the target address (in a different actor) via a relative offset
    // ASM: jmp [RIP + relative_offset]
    APPEND_BYTES_TO_DEST(0xe9);
    APPEND_U32_TO_DEST(relative_offset);
    return cursor;
}

// 目标设置宏 MACRO_SET_K2U_TARGET ------------------------------------------------------------
// 为内核到用户态切换设置目标地址——将目标函数地址加载到R11寄存器
// 在后续的switch_k2u宏中，R11中的地址将被用作sysretq的返回地址（RIP）
static inline size_t start_macro_set_k2u_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // ASM: movabs r11, function_addr
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
    APPEND_BYTES_TO_DEST(0x49, 0xbb);
    APPEND_U64_TO_DEST(function_addr);

    return cursor;
}

// 域切换宏 MACRO_SWITCH_K2U（内核→用户态）----------------------------------------------------
// 通过sysretq指令从内核态切换到用户态
// 动态配置部分：空（无需额外配置）
// 静态主体：将R11（目标地址）复制到RCX(sysretq用RCX作为返回RIP)，
//   保存当前RSP到栈上，切换到macro专用栈，保存RFLAGS到R11(sysretq用R11返回RFLAGS)，
//   恢复原RSP，执行sysretq完成内核→用户态切换
static inline size_t start_macro_switch_k2u(macro_args_t /*args*/, uint8_t * /*dest*/) { return 0; }

static void __attribute__((noipa)) body_macro_switch_k2u(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "mov rcx, r11\n"
                       "mov qword ptr [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8], rsp\n"
                       "lea rsp, [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8]\n"
                       "pushfq\n"
                       "pop r11\n"
                       "pop rsp\n"
                       "sysretq\n");
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// 目标设置宏 MACRO_SET_U2K_TARGET ------------------------------------------------------------
// 为用户态到内核切换设置目标地址——同时设置SYSENTER_CS_MSR(0xc0000082)为目标函数地址
// 此宏将目标地址写入MSR，使得syscall指令返回时直接跳转到目标函数
// 详细的指令序列：保存RSP→切换栈→压栈保存rax/rcx/rdx/RFLAGS→
//   将目标地址写入MSR 0xc0000082(wrmsr)→恢复RFLAGS→清零栈上残留值→恢复各寄存器→恢复RSP
// 注意：每次syscall都会清除rcx和r11，所以栈上残留值必须清零以防泄露
static inline size_t start_macro_set_u2k_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
    uint32_t macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;

    // ASM: mov [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
    APPEND_BYTES_TO_DEST(0x49, 0x89, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: lea rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
    APPEND_BYTES_TO_DEST(0x49, 0x8d, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: push rax
    APPEND_U8_TO_DEST(0x50);
    // ASM: push rcx
    APPEND_U8_TO_DEST(0x51);
    // ASM: push rdx
    APPEND_U8_TO_DEST(0x52);
    // ASM: pushf
    APPEND_U8_TO_DEST(0x9c);
    // ASM: movabs rax, function_addr
    APPEND_BYTES_TO_DEST(0x48, 0xb8);
    APPEND_U64_TO_DEST(function_addr);
    // ASM: mov rdx, rax
    APPEND_BYTES_TO_DEST(0x48, 0x89, 0xc2);
    // ASM: shr rdx, 0x20
    APPEND_BYTES_TO_DEST(0x48, 0xc1, 0xea, 0x20);
    // ASM: movabs rcx, 0xc0000082
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0xc0000082);
    // ASM: wrmsr
    APPEND_BYTES_TO_DEST(0x0f, 0x30);
    // ASM: popf
    APPEND_U8_TO_DEST(0x9d);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rdx
    APPEND_U8_TO_DEST(0x5a);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rcx
    APPEND_U8_TO_DEST(0x59);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rax
    APPEND_U8_TO_DEST(0x58);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rsp
    APPEND_U8_TO_DEST(0x5c);

    return cursor;
}

// 域切换宏 MACRO_SWITCH_U2K（用户态→内核）----------------------------------------------------
// 通过syscall指令从用户态切换到内核态
// 静态主体：仅执行一条syscall指令，内核侧的着陆宏(landing_u2k)将恢复执行
static void __attribute__((noipa)) body_macro_switch_u2k(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel("syscall\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// 目标设置宏 MACRO_SET_H2G_TARGET（宿主机→客户机目标设置）------------------------------------
// Intel与AMD的实现差异：
//   Intel (VMX): 将目标函数地址加载到R11，然后加载对应guest的VMCS物理地址(vmptrld)，
//     在body部分通过vmwrite将R11写入GUEST_RIP字段(0x681e)，设置VM-entry后的执行地址
//   AMD (SVM): 直接将目标函数地址写入VMCB的RIP字段(偏移VMCB_RIP_OFFSET)，
//     VMCB是AMD虚拟化的控制结构，VMRUN启动时从VMCB.RIP读取客户机入口地址
static inline size_t start_macro_set_h2g_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        // Intel VMX: 加载VMCS指针(vmptrld)并将目标地址存入R11
        // body部分将通过vmwrite r11→GUEST_RIP来设置VM-entry目标
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        uint64_t vmcs_hpa_addr = (uint64_t)&vmcs_hpas[args.arg1];

        // ASM: movabs r11, &vmcs_hpa
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(vmcs_hpa_addr);
        // ASM: vmptrld [r11]
        APPEND_BYTES_TO_DEST(0x41, 0x0f, 0xc7, 0x33);
        // ASM: movabs r11, function_addr
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(function_addr);

    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // AMD SVM: 直接将目标函数地址写入VMCB.RIP字段
        // VMCB是AMD虚拟化的控制结构，VMRUN启动时从VMCB.RIP读取客户机入口地址
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        uint64_t vmcb_hva_addr = (uint64_t)&vmcb_hvas[args.arg1];

        // ASM: movabs r11, &vmcb_hva
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(vmcb_hva_addr);
        // ASM: mov r11, [r11]
        APPEND_BYTES_TO_DEST(0x4d, 0x8b, 0x1b);
        // ASM: add r11, VMCB_RIP_OFFSET
        APPEND_BYTES_TO_DEST(0x49, 0x81, 0xc3);
        APPEND_U32_TO_DEST(VMCB_RIP_OFFSET);
        // ASM: mov dword ptr [r11], function_addr[0:31]
        APPEND_BYTES_TO_DEST(0x49, 0xc7, 0x03);
        APPEND_U32_TO_DEST(function_addr & 0xFFFFFFFF);
        // ASM: add r11, 4
        APPEND_BYTES_TO_DEST(0x49, 0x83, 0xc3, 0x04);
        // ASM: mov dword ptr [r11], function_addr[32:63]
        APPEND_BYTES_TO_DEST(0x49, 0xc7, 0x03);
        APPEND_U32_TO_DEST((function_addr >> 32) & 0xFFFFFFFF);
    }

    return cursor;
}

// 宏主体 MACRO_SET_H2G_TARGET（宿主机→客户机目标设置的静态部分）---------------------------
// Intel: 将R11中的目标地址通过vmwrite写入GUEST_RIP(字段号0x681e)
// AMD: 无需额外操作（动态部分已直接修改VMCB.RIP）
static void __attribute__((noipa)) body_macro_set_h2g_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel(""                      // r11 contains the target address
                       MACRO_PROLOGUE()        //
                       "mov rcx, 0x0000681e\n" // GUEST_RIP
                       "vmwrite rcx, r11 \n"   //
                       MACRO_EPILOGUE()        //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// 域切换宏 MACRO_SWITCH_H2G（宿主机→客户机切换）--------------------------------------------
// Intel与AMD的实现差异：
//   Intel (VMX): 动态部分无操作；静态主体执行vmresume指令恢复VM-entry，进入客户机
//   AMD (SVM): 动态部分将VMCB HPA加载到rax；静态主体执行clgi→vmsave→vmrun→vmload→stgi序列
//     clgi禁用全局中断，vmsave保存宿主机状态到VMCB，vmrun加载客户机VMCB并进入客户机，
//     vmload恢复宿主机状态，stgi重新启用全局中断
static inline size_t start_macro_switch_h2g(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        // Intel VMX: 无需动态配置，vmresume将自动恢复VM-entry
    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // AMD SVM: 将VMCB的物理地址(HPA)加载到rax，供body部分使用
        // ASM: movabs rax, &vmcb_hpa
        APPEND_BYTES_TO_DEST(0x48, 0xb8);
        APPEND_U64_TO_DEST((uint64_t)&vmcb_hpas[args.arg1]);
    }
    return cursor;
}

// 宏主体 MACRO_SWITCH_H2G（宿主机→客户机切换的静态部分）
// Intel: 执行vmresume恢复VM-entry进入客户机
// AMD: 执行clgi→vmsave→vmrun→vmload→stgi序列
static void __attribute__((noipa)) body_macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmresume\n");
#else
    asm_volatile_intel("" // rax contains the current VMCB pointer
                       "clgi\n"
                       "mov rax, qword ptr [rax]\n" //
                       "vmsave rax\n"               //
                       "vmrun rax\n"                //
                       "vmload rax\n"
                       "mov rax, 0\n" //
                       "stgi\n"       //
                       "");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// 目标设置宏 MACRO_SET_G2H_TARGET（客户机→宿主机目标设置）------------------------------------
// Intel (VMX): 将目标函数地址加载到R11，body部分通过vmwrite写入HOST_RIP(0x6c16)
//   这样VM-exit后处理器自动跳转到HOST_RIP指定的地址
// AMD (SVM): 无需额外操作——#VMEXIT后自动返回宿主机，着陆宏(landing_g2h)负责恢复执行
static inline size_t start_macro_set_g2h_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        // ASM: movabs r11, function_addr
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(function_addr);
    } else {
        // Nothing for AMD
    }
    return cursor;
}

// 宏主体 MACRO_SET_G2H_TARGET（客户机→宿主机目标设置的静态部分）
// Intel: MACRO_PROLOGUE → vmwrite r11→HOST_RIP(0x6c16) → MACRO_EPILOGUE
//   设置VM-exit后宿主机的执行入口地址
// AMD: 无操作（宿主机入口在VMCB中已预设）
static void __attribute__((noipa)) body_macro_set_g2h_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == VENDOR_INTEL_
    asm_volatile_intel(""                      // r11 contains the target address
                       MACRO_PROLOGUE()        //
                       "mov rcx, 0x00006c16\n" // HOST_RIP
                       "vmwrite rcx, r11 \n"   //
                       MACRO_EPILOGUE()        //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// 域切换宏 MACRO_SWITCH_G2H（客户机→宿主机切换）--------------------------------------------
// Intel (VMX): 执行vmcall触发VM-exit，从客户机切换到宿主机
// AMD (SVM): 执行vmmcall触发#VMEXIT，从客户机切换到宿主机
// Intel和AMD使用不同的指令来触发虚拟化退出
static void __attribute__((noipa)) body_macro_switch_g2h(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmcall\n");
#else
    asm_volatile_intel("vmmcall\n");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// 着陆宏 MACRO_LANDING_K2U（内核→用户态切换后的着陆点）------------------------------------
// 从内核切换到用户态后，需要更新RSP和R14以匹配新actor的地址空间
// 同时将RCX清零——sysretq会破坏RCX（它被用作返回RIP），需要重新初始化
static inline size_t start_macro_landing_k2u(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_mem_base_and_sp(args.owner, dest, cursor);
    // ASM: movabs rcx, 0  # rcx was corrupted during context switch; set to zero
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0);
    return cursor;
}

// 着陆宏 MACRO_LANDING_U2K（用户态→内核切换后的着陆点）------------------------------------
// 从用户态切换到内核后，需要更新R14以匹配新actor的地址空间
// RSP由syscall指令自动恢复（syscall保存RSP到MSR，sysret恢复），无需手动更新
// 将RCX清零——syscall指令会破坏RCX（保存返回RIP），需要重新初始化
static inline size_t start_macro_landing_u2k(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    // rsp is automatically restored by syscall instruction

    // ASM: movabs rcx, 0  # rcx was corrupted during context switch; set to zero
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0);

    return cursor;
}

// 着陆宏 MACRO_LANDING_H2G（宿主机→客户机切换后的着陆点）------------------------------------
// 从宿主机进入客户机后，需要更新R14和R15以匹配客户机actor的地址空间
// AMD额外需要将rax清零——AMD的vmrun/vmsave序列会破坏rax，需要重新初始化
static inline size_t start_macro_landing_h2g(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    cursor += update_r15(args.owner, dest, cursor);

    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // ASM: mov rax, 0
        APPEND_BYTES_TO_DEST(0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00);
    }
    return cursor;
}

// 着陆宏 MACRO_LANDING_G2H（客户机→宿主机切换后的着陆点）------------------------------------
// 从客户机返回宿主机后，需要更新R14和R15以匹配宿主机actor的地址空间
// AMD额外需要将rax清零——同landing_h2g，SVM序列会破坏rax
static inline size_t start_macro_landing_g2h(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    cursor += update_r15(args.owner, dest, cursor);

    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // ASM: mov rax, 0
        APPEND_BYTES_TO_DEST(0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00);
    }

    return cursor;
}

// 数据权限设置宏 MACRO_SET_DATA_PERMISSIONS ---------------------------------------------------
// 修改目标actor数据页的PTE（页表项）权限位，用于配置侧信道测量的访问权限
// 动态配置部分：切换到macro专用栈→获取目标PTE指针→对PTE低16位应用OR(mask_set)和AND(mask_clear)
//   mask_set设置权限位（如Present、Write、User等），mask_clear清除权限位
//   操作完成后清零栈上残留值并恢复原RSP，防止信息泄露
// 此宏允许模糊测试器动态改变数据页的可访问性，以触发不同的缓存行为
static inline size_t start_macro_set_data_permissions(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // get safe bits to set/clear
    uint16_t mask_set = args.arg2;
    uint16_t mask_clear = args.arg3;

    // get the target PTE
    uint64_t actor_id = args.arg1;
    uint64_t page_id = (actor_id * N_DATA_PAGES_PER_ACTOR) + FAULTY_PAGE_ID;
    pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
    ASSERT(ptep != NULL, "start_macro_set_data_permissions");

    uint32_t macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;

    // Switch stack
    // ASM: mov [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
    APPEND_BYTES_TO_DEST(0x49, 0x89, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: lea rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
    APPEND_BYTES_TO_DEST(0x49, 0x8d, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: push rax
    APPEND_U8_TO_DEST(0x50);

    // Get pointer to PTE
    // ASM: mov rax, ptep
    APPEND_BYTES_TO_DEST(0x48, 0xb8);
    APPEND_U64_TO_DEST((uint64_t)ptep);

    // Apply the set and clear masks to the lowest 16 bits of the PTE
    // note that we leave the remaining bits unchanged because arg2 and arg3 are 16-bit values
    //   ASM: or qword ptr [r11], mask_set
    APPEND_BYTES_TO_DEST(0x66, 0x81, 0x08);
    APPEND_U16_TO_DEST(mask_set);
    //   ASM: and qword ptr [r11], mask_clear
    APPEND_BYTES_TO_DEST(0x66, 0x81, 0x20);
    APPEND_U16_TO_DEST(mask_clear);

    // Restore stack
    // ASM: pop rax
    APPEND_U8_TO_DEST(0x58);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop rsp
    APPEND_U8_TO_DEST(0x5c);
    return cursor;
}

// =================================================================================================
// 宏描述符表 macro_descriptors —— 宏类型到具体实现函数的映射关系
//
// 每个宏类型(TYPE_XXX)对应一个描述符，包含两个函数指针：
//   .start: 动态配置部分生成函数（根据宏参数动态生成机器码），NULL表示无动态部分
//   .body:  静态主体部分函数（编译时固定的代码，通过MACRO_START/MACRO_END标记提取），NULL表示无静态部分
//
// 映射关系说明：
//   TYPE_PRIME/FAST_PRIME/PARTIAL_PRIME/FAST_PARTIAL_PRIME → Prime+Probe测量开始
//   TYPE_PROBE → Prime+Probe测量结束（所有P+P变体共用同一个probe）
//   TYPE_FLUSH → Flush+Reload测量开始（刷新缓存行）
//   TYPE_EVICT → Evict+Reload测量开始（使用prime方式驱逐，与TYPE_PRIME共用body）
//   TYPE_RELOAD → Flush+Reload/Evict+Reload测量结束
//   TYPE_TSC_START/END → TSC时间戳测量的开始和结束
//   TYPE_FAULT_HANDLER → 纯故障处理（无测量）
//   TYPE_FAULT_AND_PROBE/RELOAD/TSC_END → 带测量的故障处理（组合故障处理+对应测量结束宏）
//   TYPE_SWITCH → 同特权级actor切换
//   TYPE_SET_K2U_TARGET/SWITCH_K2U → 内核→用户态切换的设置和执行
//   TYPE_SET_U2K_TARGET/SWITCH_U2K → 用户态→内核切换的设置和执行
//   TYPE_SET_H2G_TARGET/SWITCH_H2G → 宿主机→客户机切换的设置和执行
//   TYPE_SET_G2H_TARGET/SWITCH_G2H → 客机机→宿主机切换的设置和执行
//   TYPE_LANDING_K2U/U2K/H2G/G2H → 域切换后的着陆点（恢复寄存器）
//   TYPE_SET_DATA_PERMISSIONS → 修改数据页PTE权限位
// =================================================================================================
macro_descr_t macro_descriptors[] = {
    [TYPE_UNDEFINED] = {.start = NULL, .body = NULL},
    [TYPE_PRIME] = {.start = NULL, .body = body_macro_prime},
    [TYPE_FAST_PRIME] = {.start = NULL, .body = body_macro_fast_prime},
    [TYPE_PARTIAL_PRIME] = {.start = NULL, .body = body_macro_partial_prime},
    [TYPE_FAST_PARTIAL_PRIME] = {.start = NULL, .body = body_macro_fast_partial_prime},
    [TYPE_PROBE] = {.start = NULL, .body = body_macro_probe},
    [TYPE_FLUSH] = {.start = NULL, .body = body_macro_flush},
    [TYPE_EVICT] = {.start = NULL, .body = body_macro_prime},
    [TYPE_RELOAD] = {.start = NULL, .body = body_macro_reload},
    [TYPE_TSC_START] = {.start = NULL, .body = body_macro_tsc_start},
    [TYPE_TSC_END] = {.start = NULL, .body = body_macro_tsc_end},
    [TYPE_FAULT_HANDLER] = {.start = start_macro_fault_handler, .body = NULL},
    [TYPE_FAULT_AND_PROBE] = {.start = start_macro_fault_handler_with_measurement,
                              .body = body_macro_probe},
    [TYPE_FAULT_AND_RELOAD] = {.start = start_macro_fault_handler_with_measurement,
                               .body = body_macro_reload},
    [TYPE_FAULT_AND_TSC_END] = {.start = start_macro_fault_handler_with_measurement,
                                .body = body_macro_tsc_end},
    [TYPE_SWITCH] = {.start = start_macro_switch, .body = NULL},
    [TYPE_SET_K2U_TARGET] = {.start = start_macro_set_k2u_target, .body = NULL},
    [TYPE_SWITCH_K2U] = {.start = start_macro_switch_k2u, .body = body_macro_switch_k2u},
    [TYPE_SET_U2K_TARGET] = {.start = start_macro_set_u2k_target, .body = NULL},
    [TYPE_SWITCH_U2K] = {.start = NULL, .body = body_macro_switch_u2k},
    [TYPE_SET_H2G_TARGET] = {.start = start_macro_set_h2g_target,
                             .body = body_macro_set_h2g_target},
    [TYPE_SWITCH_H2G] = {.start = start_macro_switch_h2g, .body = body_macro_switch_h2g},
    [TYPE_SET_G2H_TARGET] = {.start = start_macro_set_g2h_target,
                             .body = body_macro_set_g2h_target},
    [TYPE_SWITCH_G2H] = {.start = NULL, .body = body_macro_switch_g2h},
    [TYPE_LANDING_K2U] = {.start = start_macro_landing_k2u, .body = NULL},
    [TYPE_LANDING_U2K] = {.start = start_macro_landing_u2k, .body = NULL},
    [TYPE_LANDING_H2G] = {.start = start_macro_landing_h2g, .body = NULL},
    [TYPE_LANDING_G2H] = {.start = start_macro_landing_g2h, .body = NULL},
    [TYPE_SET_DATA_PERMISSIONS] = {.start = start_macro_set_data_permissions, .body = NULL},
};

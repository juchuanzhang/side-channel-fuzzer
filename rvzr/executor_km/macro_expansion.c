// 宏扩展引擎——测试用例中宏的展开与二进制补丁机制
//
// 本文件实现了架构无关的宏扩展逻辑，是论文Section 4.4中描述的宏系统的核心。
// 宏扩展的工作流程：
//   1) 从测试用例符号表中获取宏的类型(MACRO_ID)和参数
//   2) 根据MACRO_ID和当前测量模式(measurement_mode)确定宏的子类型(TYPE_XXX)
//   3) 从宏描述符表(macro_descriptors)获取对应的实现函数
//   4) 在代码区的NOP占位符位置写入相对跳转指令(JMP)，跳转到宏内存区
//   5) 在宏内存区依次注入动态配置代码(start函数)和静态主体代码(body函数)
//   6) 在宏代码末尾添加返回跳转(JMP)，跳回原代码流的NOP之后的指令
//
// 二进制补丁的关键：insert_relative_jmp_n_fence函数将NOP替换为JMP+lfence，
// JMP的偏移量指向宏内存区中的扩展代码，lfence防止直线推测(straight-line speculation)
//
/// File: Expansion of macros in the test case; used primarily by code_loader.c
///       This file contains architecture-independent code for expanding macros in the test case.
///       For concrete architecture-specific implementations of macros, see <arch>/macros.c.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "fault_handler.h"
#include "macro_expansion.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

// 宏扩展的最大尺寸限制——用于安全检查，防止越界
#define MAX_MACRO_START_OFFSET 0x100  // 动态配置部分最大256字节
#define MAX_MACRO_LENGTH       0x800  // 静态主体部分最大2KB

// 主代码段序幕(prologue)的大小——主actor的代码段不从偏移0开始，而是从一个固定的序幕开始
// 代码加载器将此大小传递给宏加载器，以便宏在计算函数地址时考虑此偏移
static size_t main_prologue_size = 0;

// =================================================================================================
// 辅助函数
// =================================================================================================
/// @brief 主代码段序幕大小的设置/获取接口
///        因为主section不从偏移零开始（有固定序幕），宏需要知道此偏移才能正确计算函数地址
/// @param size 序幕大小（字节）
void set_main_prologue_size(size_t size) { main_prologue_size = size; }
size_t get_main_prologue_size(void) { return main_prologue_size; }

/// @brief 根据宏ID和当前测量模式确定宏的子类型——这是宏扩展的核心映射逻辑
///        测量宏(MACRO_MEASUREMENT_START/END)的子类型取决于measurement_mode：
///          PRIME_PROBE → TYPE_PRIME/TYPE_PROBE
///          FAST_PRIME_PROBE → TYPE_FAST_PRIME/TYPE_PROBE
///          PARTIAL_PRIME_PROBE → TYPE_PARTIAL_PRIME/TYPE_PROBE
///          FLUSH_RELOAD → TYPE_FLUSH/TYPE_RELOAD
///          EVICT_RELOAD → TYPE_EVICT(与TYPE_PRIME共用body)/TYPE_RELOAD
///          TSC → TYPE_TSC_START/TYPE_TSC_END
///        带测量的故障处理宏的子类型同理，组合了故障处理+对应测量结束宏
///        域切换宏直接映射到对应子类型，无需考虑测量模式
/// @param macro_id ID of the macro
/// @return Pointer to the macro descriptor
static macro_descr_t *get_macro_subtype_from_id(uint64_t macro_id)
{
    // 确定宏子类型——根据宏ID和测量模式的组合映射到具体实现类型
    macro_subtype_e macro_subtype = TYPE_UNDEFINED;
    switch (macro_id) {
    case MACRO_MEASUREMENT_START:
        // 测量开始宏：根据测量模式选择对应的Prime/Flush/Evict/TSC变体
        switch (measurement_mode) {
        case PRIME_PROBE:
            macro_subtype = TYPE_PRIME;
            break;
        case FAST_PRIME_PROBE:
            macro_subtype = TYPE_FAST_PRIME;
            break;
        case PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_PARTIAL_PRIME;
            break;
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_FAST_PARTIAL_PRIME;
            break;
        case FLUSH_RELOAD:
            macro_subtype = TYPE_FLUSH;
            break;
        case EVICT_RELOAD:
            macro_subtype = TYPE_EVICT;
            break;
        case TSC:
            macro_subtype = TYPE_TSC_START;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    case MACRO_FAULT_HANDLER_WITH_MEASUREMENT:
        // 带测量的故障处理宏：组合故障处理+对应测量结束宏
        switch (measurement_mode) {
        case PRIME_PROBE:
        case FAST_PRIME_PROBE:
        case PARTIAL_PRIME_PROBE:
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_FAULT_AND_PROBE;
            break;
        case FLUSH_RELOAD:
        case EVICT_RELOAD:
            macro_subtype = TYPE_FAULT_AND_RELOAD;
            break;
        case TSC:
            macro_subtype = TYPE_FAULT_AND_TSC_END;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    case MACRO_MEASUREMENT_END:
        // 测量结束宏：根据测量模式选择对应的Probe/Reload/TSC_END变体
        switch (measurement_mode) {
        case PRIME_PROBE:
        case FAST_PRIME_PROBE:
        case PARTIAL_PRIME_PROBE:
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_PROBE;
            break;
        case FLUSH_RELOAD:
        case EVICT_RELOAD:
            macro_subtype = TYPE_RELOAD;
            break;
        case TSC:
            macro_subtype = TYPE_TSC_END;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    // 域切换相关宏：直接映射，不依赖测量模式
    case MACRO_SWITCH_K2U:
        macro_subtype = TYPE_SWITCH_K2U;       // 内核→用户态切换
        break;
    case MACRO_SWITCH_U2K:
        macro_subtype = TYPE_SWITCH_U2K;       // 用户态→内核切换
        break;
    case MACRO_SWITCH_H2G:
        macro_subtype = TYPE_SWITCH_H2G;       // 宿主机→客户机切换
        break;
    case MACRO_SWITCH_G2H:
        macro_subtype = TYPE_SWITCH_G2H;       // 客户机→宿主机切换
        break;
    case MACRO_SET_H2G_TARGET:
        macro_subtype = TYPE_SET_H2G_TARGET;   // 设置H2G切换目标
        break;
    case MACRO_SET_G2H_TARGET:
        macro_subtype = TYPE_SET_G2H_TARGET;   // 设置G2H切换目标
        break;
    case MACRO_FAULT_HANDLER:
        macro_subtype = TYPE_FAULT_HANDLER;    // 纯故障处理（无测量）
        break;
    case MACRO_SWITCH:
        macro_subtype = TYPE_SWITCH;           // 同特权级actor切换
        break;
    case MACRO_SET_K2U_TARGET:
        macro_subtype = TYPE_SET_K2U_TARGET;   // 设置K2U切换目标
        break;
    case MACRO_SET_U2K_TARGET:
        macro_subtype = TYPE_SET_U2K_TARGET;   // 设置U2K切换目标
        break;
    case MACRO_LANDING_K2U:
        macro_subtype = TYPE_LANDING_K2U;      // K2U着陆点
        break;
    case MACRO_LANDING_U2K:
        macro_subtype = TYPE_LANDING_U2K;      // U2K着陆点
        break;
    case MACRO_LANDING_H2G:
        macro_subtype = TYPE_LANDING_H2G;      // H2G着陆点
        break;
    case MACRO_LANDING_G2H:
        macro_subtype = TYPE_LANDING_G2H;      // G2H着陆点
        break;
    case MACRO_SET_DATA_PERMISSIONS:
        macro_subtype = TYPE_SET_DATA_PERMISSIONS; // 修改数据页PTE权限
        break;
    default:
        PRINT_ERRS("get_macro_subtype_from_id", "macro_id %llu is not valid\n", macro_id);
        return NULL;
    }

    // 从宏描述符表中获取对应的实现描述符，验证start和body至少有一个不为NULL
    macro_descr_t *descr = &macro_descriptors[macro_subtype];
    if (descr->start == NULL && descr->body == NULL) {
        PRINT_ERRS("get_macro_subtype_from_id", "macro_id %llu is not implemented\n", macro_id);
        return NULL;
    }
    return descr;
}

/// @brief 检查给定指针是否指向MACRO_START标记——用于在body函数中定位静态代码的起始位置
///        MACRO_START是一个8字节魔数标记，嵌入在每个body_macro*函数的开头，
///        用于在运行时从函数体中提取实际的指令代码（跳过标记本身）
/// @param ptr
/// @return True if the pointer points to the start of a macro, false otherwise
static inline bool is_macro_start(uint8_t *ptr)
{
    return (ptr)[7] == ((MACRO_START >> 56) & 0xFF) && (ptr)[6] == ((MACRO_START >> 48) & 0xFF) &&
           (ptr)[5] == ((MACRO_START >> 40) & 0xFF) && (ptr)[4] == ((MACRO_START >> 32) & 0xFF) &&
           (ptr)[3] == ((MACRO_START >> 24) & 0xFF) && (ptr)[2] == ((MACRO_START >> 16) & 0xFF) &&
           (ptr)[1] == ((MACRO_START >> 8) & 0xFF) && (ptr)[0] == ((MACRO_START) & 0xFF);
}

/// @brief 检查给定指针是否指向MACRO_END标记——用于在body函数中定位静态代码的结束位置
///        MACRO_END也是一个8字节魔数标记，嵌入在每个body_macro*函数的末尾
/// @param ptr
/// @return True if the pointer points to the end of a macro, false otherwise
static inline bool is_macro_end(uint8_t *ptr)
{
    return (ptr)[7] == ((MACRO_END >> 56) & 0xFF) && (ptr)[6] == ((MACRO_END >> 48) & 0xFF) &&
           (ptr)[5] == ((MACRO_END >> 40) & 0xFF) && (ptr)[4] == ((MACRO_END >> 32) & 0xFF) &&
           (ptr)[3] == ((MACRO_END >> 24) & 0xFF) && (ptr)[2] == ((MACRO_END >> 16) & 0xFF) &&
           (ptr)[1] == ((MACRO_END >> 8) & 0xFF) && (ptr)[0] == ((MACRO_END) & 0xFF);
}

/// @brief 在指定位置插入相对跳转指令+内存屏障——这是二进制补丁的核心操作
///        将测试用例中的NOP占位符替换为JMP指令，跳转到宏内存区中的扩展代码
///        x86_64: JMP指令(0xe9, 5字节) + lfence(3字节) = 8字节
///        ARM: B指令(4字节) + isb(4字节) + dsb SY(4字节) = 12字节
///        lfence/isb防止直线推测(straight-line speculation)攻击——确保JMP之后不会继续执行NOP后的指令
/// @param dest Destination buffer
/// @param target Target address for the jump
/// @return Size of the added code, in bytes
static inline uint64_t insert_relative_jmp_n_fence(uint8_t *dest, int32_t target)
{
    uint64_t cursor = 0;

#if defined(ARCH_X86_64)
    // x86_64: JMP相对跳转指令编码
    // 格式: 0xe9(操作码) + 4字节相对偏移(目标地址 - 当前地址 - 5字节指令长度)
    const int jmp_opcode_size = 5;
    target -= jmp_opcode_size;

    // jmp *target
    dest[cursor++] = 0xe9; // start of the jump opcode
    *((uint32_t *)&dest[cursor]) = target;
    cursor += 4;

    // lfence——防止直线推测，确保JMP确实被执行后再继续
    dest[cursor++] = 0x0f;
    dest[cursor++] = 0xae;
    dest[cursor++] = 0xe8;
#elif defined(ARCH_ARM)
    // ARM架构: 偏移量以4字节(dword)为单位计算
    // offsets in ARM are in dwords
    target = target / 4;

    // the target for a jump is a 26-bit signed offset from the current PC
    int target_sign = target < 0 ? 1 : 0;
    ASSERT(target < 0x02000000 && target >= -0x02000000, "insert_relative_jmp_n_fence");
    target = (target & 0x3FFFFFF) | (target_sign << 25);

    // b *target
    *((uint32_t *)&dest[cursor]) = 0x14000000; // start of the jump opcode
    *((uint32_t *)&dest[cursor]) |= target;
    cursor += 4;

    // isb
    *((uint32_t *)&dest[cursor]) = 0xd5033fdf;
    cursor += 4;

    // dsb SY
    *((uint32_t *)&dest[cursor]) = 0xd5033f9f;
    cursor += 4;

#endif

    return cursor;
}

// =================================================================================================
// 宏扩展逻辑——将测试用例中的宏调用替换为实际的可执行代码
// =================================================================================================

/// @brief 动态生成宏的可配置部分——根据宏参数生成定制化的机器码
///        宏参数从测试用例符号表中提取，以压缩格式(4个16位字段)存储
///        arg1/arg2/arg3/arg4分别表示actor ID、函数ID、权限掩码等
/// @param[in] descr Pointer to the macro descriptor
/// @param[in] args Compressed representation of the macro arguments, as received from the test case
///            symbol table
/// @param[in] owner ID of the actor owning the macro
/// @param[out] dest Pointer to the destination buffer
/// @return Size of the added code, in bytes
static uint64_t inject_macro_configurable_part(macro_descr_t *descr, uint64_t args, uint64_t owner,
                                               uint8_t *dest)
{
    // 从压缩的64位参数中提取4个16位字段和owner字段
    macro_args_t args_struct = {
        .arg1 = (args >> 0x00) & 0xFFFF,
        .arg2 = (args >> 0x10) & 0xFFFF,
        .arg3 = (args >> 0x20) & 0xFFFF,
        .arg4 = (args >> 0x30) & 0xFFFF,
        .owner = owner,
    };

    // 调用宏描述符中的start函数，生成动态配置代码
    size_t cursor = descr->start(args_struct, dest);
    return cursor;
}

/// @brief 注入宏的静态主体部分——从body函数中提取编译时固定的指令代码
///        通过搜索MACRO_START和MACRO_END标记来确定代码的起止位置，
///        然后将标记之间的原始机器码复制到目标缓冲区
/// @param[in] descr Pointer to the macro descriptor
/// @param[out] dest Pointer to the destination buffer
/// @return Size of the added code, in bytes
static uint64_t inject_macro_static_part(macro_descr_t *descr, uint8_t *dest)
{
    // 在body函数体中搜索MACRO_START标记，定位静态代码的起始位置
    // MACRO_START标记之前可能有编译器生成的代码（如函数序言），需要跳过
    uint8_t *macro_wrapper_start = (uint8_t *)descr->body;
    uint8_t *macro_start = macro_wrapper_start;
    while (!is_macro_start(macro_start)) {
        macro_start++;
        ASSERT(macro_start - macro_wrapper_start < MAX_MACRO_START_OFFSET, "get_macro_ptr");
    }
    macro_start += MACRO_START_TOKEN_LENGTH;

    // 搜索MACRO_END标记，定位静态代码的结束位置
    uint8_t *macro_end = macro_start;
    while (!is_macro_end(macro_end)) {
        macro_end++;
        ASSERT(macro_end - macro_start < MAX_MACRO_LENGTH, "get_macro_ptr");
    }
    // 如果静态代码为空（如某些宏只有动态部分），直接返回0
    if (macro_end - macro_start == 0)
        return 0;

    // 将MACRO_START和MACRO_END之间的原始机器码复制到目标缓冲区
    size_t size = macro_end - macro_start;
    memcpy(dest, macro_start, size);
    return size;
}

/// @brief expand_macro——宏扩展的主入口函数，完成整个宏的展开过程
///        完整流程：
///        1) 在代码区(code_dest)的NOP位置写入JMP指令，跳转到宏内存区(macro_dest)
///        2) 在宏内存区注入动态配置代码（start函数生成的机器码）
///        3) 在宏内存区注入静态主体代码（从body函数提取的原始机器码）
///        4) 在宏代码末尾添加返回JMP指令，跳回原代码流的NOP之后位置
///        执行流：NOP位置 → JMP(跳到宏区) → [动态代码] → [静态代码] → JMP(返回) → NOP后继续
/// @param macro Macro to expand
/// @param[in] dest Destination address for placing the JMP instruction
/// @param[in] macro_dest Destination buffer for the expanded macro
/// @param[out] macro_size Size of the expanded macro
/// @return 0 on success, -1 on failure
int expand_macro(tc_symbol_entry_t *macro, uint8_t *code_dest, uint8_t *macro_dest,
                 size_t *macro_size)
{
    uint64_t code_cursor = 0;
    uint64_t macro_cursor = 0;

    // 从符号表获取宏的类型ID（如MACRO_MEASUREMENT_START、MACRO_SWITCH_H2G等）
    symbol_id_t type_id = macro->id;
    ASSERT(type_id != 0, "expand_macro");

    // 根据宏ID和测量模式获取宏描述符（包含start和body函数指针）
    macro_descr_t *descr = get_macro_subtype_from_id(type_id);
    ASSERT(descr != NULL, "expand_macro");

    // 步骤1: 代码区——将NOP替换为相对跳转指令(JMP)+lfence
    // 计算JMP的目标偏移量: macro_dest相对于code_dest的偏移
    int32_t target = (int32_t)(&macro_dest[macro_cursor] - code_dest);
    code_cursor += insert_relative_jmp_n_fence(&code_dest[code_cursor], target);

    // 步骤2: 宏内存区——注入动态配置代码（如果宏有start函数）
    if (descr->start != NULL) {
        macro_cursor += inject_macro_configurable_part(descr, macro->args, macro->owner,
                                                       &macro_dest[macro_cursor]);
    }
    ASSERT(macro_cursor >= 0, "expand_macro");

    // 步骤3: 宏内存区——注入静态主体代码（如果宏有body函数）
    if (descr->body != NULL) {
        macro_cursor += inject_macro_static_part(descr, &macro_dest[macro_cursor]);
    }
    ASSERT(macro_cursor >= 0, "expand_macro");

    // 步骤4: 宏内存区——在宏代码末尾添加返回跳转(JMP+lfence)
    // 跳回原代码流中NOP占位符之后的位置，完成宏执行后恢复原始执行流
    target = (int32_t)(&code_dest[code_cursor] - &macro_dest[macro_cursor]);
    macro_cursor += insert_relative_jmp_n_fence(&macro_dest[macro_cursor], target);

    *macro_size = macro_cursor;
    return 0;
}

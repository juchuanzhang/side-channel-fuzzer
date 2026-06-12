/// File: Multiple variants of test case entry and exit points, for ARM64 architecture
///      used exclusively by code_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "code_loader.h"
#include "macro_expansion.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "fault_handler.h"

#ifdef ARCH_X86_64
#include "x86/entry_exit_points.h"
#elif defined(ARCH_ARM)
#include "arm64/entry_exit_points.h"
#endif

// =================================================================================================
// 本地常量和声明
// =================================================================================================

// 每个section的最大分配大小 = 展开后的section代码 + 展开后的宏代码
#define PER_SECTION_ALLOC_SIZE (MAX_EXPANDED_SECTION_SIZE + MAX_EXPANDED_MACROS_SIZE)
#define MAX_TEMPLATE_SIZE      0x1000 // 用于合理性检查，防止模板溢出

// 全局指针：指向加载完成的测试用例入口代码地址
// 测试执行时将从该地址开始执行
uint8_t *loaded_test_case_entry = NULL; // global

static int load_section_main(void);
static int load_section(uint64_t section_id);
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id);
static int expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                          size_t *size_section, size_t *size_macros);

// =================================================================================================
// 代码加载逻辑
// =================================================================================================
int load_sandbox_code(void)
{
    int err = 0;
    ASSERT(sandbox->code != NULL, "load_sandbox_code");

    // 重新初始化代码区，填充NOP指令
    reset_code_area();

    // 为每个section(actor)加载代码
    // section 0是main actor（主机内核态），使用特殊模板加载
    // 其他section是辅助actor，直接展开加载
    for (int section_id = 0; section_id < n_actors; section_id++) {
        if (section_id == 0)
            err |= load_section_main();
        else
            err |= load_section(section_id);
    }
    return err;
}

// 加载非main section的代码，直接展开section及其宏到沙箱代码区
static int load_section(uint64_t section_id)
{
    // 获取该section在沙箱代码区中的目标地址
    uint8_t *section = sandbox->code[section_id].section;
    uint8_t *macros = sandbox->code[section_id].macros;
    size_t size_section = 0, size_macros = 0;
    int err = expand_section(section_id, section, macros, &size_section, &size_macros);
    CHECK_ERR("load_section");

    return 0;
}

// 加载main section（section 0）的代码
// main section使用特殊的模板加载，模板包含：
//   1. 前导代码(prologue)：保存寄存器、初始化测量等
//   2. 测试用例代码：插入到模板的TEMPLATE_INSERT_TC标记处
//   3. 异常处理代码：根据是否有显式fault handler决定
//   4. 后续代码(epilogue)：恢复寄存器、返回测量结果等
static int load_section_main(void)
{
    int err = 0;

    // 验证main section的owner必须是0（即主机内核态）
    ASSERT(test_case->metadata[0].owner == 0, "load_section_main");
    uint8_t *dest = (uint8_t *)&sandbox->code[0].section;
    uint8_t *macro_dest = sandbox->code[0].macros;

    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // 重置全局变量
    fault_handler = NULL;
    loaded_test_case_entry = NULL;

    // 根据调试模式选择模板
    // dbg_gpr模式使用额外的GPR(通用寄存器)调试模板
    uint8_t *src = (dbg_gpr_mode) ? (uint8_t *)main_segment_template_dbg_gpr
                                  : (uint8_t *)main_segment_template;

    // 扫描模板，跳过编译器插入的前导指令，找到TEMPLATE_START标记
    // 模板中可能包含编译器生成的函数头指令，需要跳过
    for (;; src_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_START");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_START)
            break;
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // 复制模板的前导代码(prologue)部分
    // 从TEMPLATE_START到TEMPLATE_INSERT_TC之间的代码是prologue
    // prologue包含：保存寄存器、设置测量起始点、初始化actor状态等
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_INSERT_TC");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_INSERT_TC)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // 通知宏加载器main section的前导代码大小
    // 前导代码大小影响宏展开时的地址计算
    set_main_prologue_size(dest_cursor);

    // 将测试用例代码展开并插入到模板的TEMPLATE_INSERT_TC位置
    // 同时展开测试用例中的宏指令
    size_t size_section = 0, size_macros = 0;
    err = expand_section(0, &dest[dest_cursor], macro_dest, &size_section, &size_macros);
    CHECK_ERR("load_section_main");
    dest_cursor += size_section;
    macros_cursor += size_macros;

    // 处理异常处理(fault handler)部分
    // 模板中TEMPLATE_DEFAULT_EXCEPTION_LANDING标记处需要插入fault handler
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; EXCEPTION_LANDING");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_DEFAULT_EXCEPTION_LANDING) {

            // 如果测试用例已经声明了显式的fault handler宏，
            // 则跳过默认fault handler，保留8字节NOP占位符以保持兼容性
            if (test_case->features.has_explicit_fault_handler) {
                dest_cursor += MACRO_PLACEHOLDER_SIZE;
                break;
            }

            // 设置默认fault handler为main actor末尾的异常着陆点
            fault_handler = (char *)&dest[dest_cursor];

            // 展开默认fault handler宏
            // 默认fault handler包含测量结束逻辑和从异常恢复的代码
            tc_symbol_entry_t measurement_end = (tc_symbol_entry_t){
                .id = MACRO_FAULT_HANDLER_WITH_MEASUREMENT, .offset = 0, .owner = 0, .args = 0};
            size_macros = 0;
            err = expand_macro(&measurement_end, &dest[dest_cursor], &macro_dest[macros_cursor],
                               &size_macros);
            CHECK_ERR("load_section_main");

            macros_cursor += size_macros;
            dest_cursor += MACRO_PLACEHOLDER_SIZE;
            break;
        }
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // 复制模板的后续代码(epilogue)部分
    // 从异常处理点到TEMPLATE_END之间的代码是epilogue
    // epilogue包含：恢复寄存器、返回测量结果等
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main: TEMPLATE_END");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_END)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    // 验证展开后的代码大小不超过最大限制
    ASSERT(dest_cursor < MAX_EXPANDED_SECTION_SIZE, "load_section_main");

    // 设置全局入口指针，执行时从此处开始
    loaded_test_case_entry = dest;
    return 0;
}

/// @brief 获取指定section中的第一个宏入口
/// @param section_id section的ID编号
/// @return 指向该section第一个宏的指针，如果没有宏则返回NULL
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id)
{
    tc_symbol_entry_t *entry = test_case->symbol_table;
    tc_symbol_entry_t *end = entry + (test_case->symbol_table_size / sizeof(*entry));
    // 在符号表中查找属于该section且id非零(非函数)的第一个宏
    // 符号表按owner和offset排序，所以找到第一个匹配即可
    while (entry->owner != section_id || entry->id == 0) {
        entry++;
        if (entry >= end)
            return NULL;
    }
    return entry;
}

/// @brief 展开一个section的代码及其宏到目标缓冲区
/// @param[in] section_id 要展开的section ID
/// @param[in] dest 展开后section代码的目标地址
/// @param[in] macros_dest 展开后宏代码的目标地址
/// @param[out] size_section 展开后section代码的大小
/// @param[out] size_macros 展开后宏代码的大小
/// @return 0表示成功，-1表示失败
static int expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                          size_t *size_section, size_t *size_macros)
{
    int err = 0;
    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // 获取未展开的section原始代码
    uint8_t *section = test_case->sections[section_id].code;
    size_t section_size = test_case->metadata[section_id].size;
    ASSERT(section_size <= MAX_SECTION_SIZE, "expand_section");

    // 获取该section中的第一个宏
    tc_symbol_entry_t *macro = get_section_macros_start(section_id);

    // 如果没有宏需要展开，直接复制代码即可
    if (macro == NULL) {
        memcpy(dest, section, section_size);
        *size_section = section_size;
        *size_macros = 0;
        return 0;
    }

    // 否则，逐字节扫描section代码，遇到宏占位符时调用expand_macro展开
    // 宏占位符是8字节的特殊标记(MACRO_PLACEHOLDER_SIZE)，在展开时被替换为实际宏代码
    for (src_cursor = 0; src_cursor < section_size; src_cursor++, dest_cursor++) {
        // 如果当前字节不是宏占位符的位置，直接复制原始字节
        if (macro == NULL || src_cursor != macro->offset) {
            dest[dest_cursor] = section[src_cursor];
            continue;
        }
        // PRINT_ERR("macro id: %d, macro owner: %d, macro args: %d, offset: %d\n", macro->id,
        //   macro->owner, macro->args, macro->offset);

        // 到达宏占位符位置
        ASSERT(macro->owner == section_id, "expand_section");
        ASSERT(macro->id != 0, "expand_section");

        // 展开宏：将宏占位符替换为展开后的宏代码
        size_t macro_size = 0;
        err = expand_macro(macro, &dest[dest_cursor], &macros_dest[macros_cursor], &macro_size);
        CHECK_ERR("expand_section");

        // 更新游标：跳过宏占位符的大小
        // -1是因为循环中游标还会自动递增一次
        src_cursor += MACRO_PLACEHOLDER_SIZE - 1;  // -1 because it will be incremented in the loop
        dest_cursor += MACRO_PLACEHOLDER_SIZE - 1; // -1 because it will be incremented in the loop
        macros_cursor += macro_size;
        macro++;

        // 如果当前section的所有宏都已处理完，将macro设为NULL
        // 后续字节将直接复制，不再检查宏占位符
        if (macro->owner != section_id)
            macro = NULL;
    }

    // 验证没有发生越界
    ASSERT(src_cursor == section_size, "expand_section");

    *size_section = dest_cursor;
    *size_macros = macros_cursor;
    return 0;
}

// =================================================================================================
int init_code_loader(void)
{
    // NOTE: we assume the sandbox is already allocated by sandbox_manager
    return 0;
}

void free_code_loader(void) {}

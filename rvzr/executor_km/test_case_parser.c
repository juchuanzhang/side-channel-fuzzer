/// File:
///   - Parsing of test cases in RCBF format (see docs/devel/binary-formats.md)
///   - Management of TC-related data structures
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "test_case_parser.h"
#include "macro_expansion.h"
#include "main.h"
#include "shortcuts.h"

// 全局测试用例结构，存储解析后的测试用例所有数据
test_case_t *test_case = NULL;   // global
// 全局actor元数据表，描述每个actor的属性（权限级别、运行模式等）
actor_metadata_t *actors = NULL; // global
// 全局actor数量，默认为1（只有主机内核态actor）
size_t n_actors = 1;             // global

static size_t n_symbols;

static int new_test_case(test_case_t **test_case_p);

// =================================================================================================
// 测试用例加载的状态机
// =================================================================================================
// _is_receiving_test_case: 是否正在接收测试用例数据
// _cursor: 当前解析位置的全局游标
// highest_n_actors/highest_n_symbols: 记录历史最大值，避免频繁重新分配
static bool _is_receiving_test_case = false;
static uint64_t _cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_symbols = 0;
// 预分配的各种表缓冲区，跨测试用例复用
static actor_metadata_t *_allocated_actor_table;
static tc_symbol_entry_t *_allocated_symbol_table;
static tc_section_metadata_entry_t *_allocated_metadata;
static tc_section_t *_allocated_data;

/// @brief 初始化测试用例解析状态机
/// 解析RCBF格式的测试用例头部（包含actor数量和符号数量）
/// @param buf 指向包含测试用例数据（一部分）的缓冲区
/// @return 错误码；0表示成功
static int __batch_tc_parsing_start(const char *buf)
{
    int ret = 0;

    // 重置游标，开始新一轮解析
    _cursor = 0;

    // 创建新的测试用例结构
    SAFE_FREE(test_case);
    if (new_test_case(&test_case) != 0) {
        PRINT_ERRS("__batch_tc_parsing_start", "Failed to create test case\n");
        return -ENOMEM;
    }

    // 从RCBF头部读取actor数量（第1个8字节字段）
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ASSERT(new_n_actors > 0, "__batch_tc_parsing_start");
    ret += 8;

    // 从RCBF头部读取符号数量（第2个8字节字段）
    // 符号表包含宏定义、函数入口等信息
    uint64_t new_n_symbols = ((uint64_t *)buf)[1];
    ASSERT_MSG(new_n_symbols <= MAX_SYMBOLS, "__batch_tc_parsing_start",
               "n_symbols (%llu) > MAX_SYMBOLS (%u)\n", new_n_symbols, MAX_SYMBOLS);
    ret += 8;

    // 计算各表的大小
    test_case->actor_table_size = new_n_actors * sizeof(actor_metadata_t);
    test_case->symbol_table_size = new_n_symbols * sizeof(tc_symbol_entry_t);
    test_case->metadata_size = new_n_actors * sizeof(tc_section_metadata_entry_t);
    test_case->sections_size = new_n_actors * sizeof(tc_section_t);

    // 根据需要重新分配内存缓冲区
    // 只在数量增加时重新分配，否则复用之前的缓冲区
    if (new_n_symbols > highest_n_symbols || !_allocated_symbol_table) {
        SAFE_FREE(_allocated_symbol_table);
        // +1确保即使测试用例为空也有有效分配
        _allocated_symbol_table = CHECKED_MALLOC(test_case->symbol_table_size + 1);
        highest_n_symbols = new_n_symbols;
    }
    if (new_n_actors > highest_n_actors || !_allocated_data) {
        SAFE_FREE(_allocated_actor_table);
        SAFE_FREE(_allocated_metadata);
        SAFE_VFREE(_allocated_data);
        // actor_table和metadata用kmalloc（小），section data用vmalloc（可能很大）
        _allocated_actor_table = CHECKED_MALLOC(test_case->actor_table_size);
        _allocated_metadata = CHECKED_MALLOC(test_case->metadata_size);
        _allocated_data = CHECKED_VMALLOC(test_case->sections_size);
        highest_n_actors = new_n_actors;
    }

    // 清零所有预分配的缓冲区
    memset(_allocated_actor_table, 0, highest_n_actors * sizeof(actor_metadata_t));
    memset(_allocated_symbol_table, 0, highest_n_symbols * sizeof(tc_symbol_entry_t));
    memset(_allocated_metadata, 0, highest_n_actors * sizeof(tc_section_metadata_entry_t));
    memset(_allocated_data, 0, highest_n_actors * sizeof(tc_section_t));

    // 将预分配缓冲区绑定到测试用例结构
    test_case->actor_table = _allocated_actor_table;
    test_case->symbol_table = _allocated_symbol_table;
    test_case->metadata = _allocated_metadata;
    test_case->sections = _allocated_data;

    // 更新全局变量
    n_symbols = new_n_symbols;
    n_actors = new_n_actors;
    actors = test_case->actor_table;

    ASSERT(ret < PAGE_SIZE, "__batch_tc_parsing_start");
    return ret;
}

/// @brief 完成解析后的处理：
///        - 完整性检查（宏排序、必需符号等）
///        - 设置测试用例特性标志（是否包含VM actor、用户态actor等）
///        - 类型检查actor切换目标（权限级别和运行模式是否匹配）
/// @param void
/// @return 错误码；0表示成功
static int __batch_tc_parsing_end(void)
{
    // 验证符号表中的宏按owner和offset排序
    // 排序是code_loader正确展开宏的前提条件
    // 同时检查是否包含必需的符号：测量起始(MEASUREMENT_START)、测量结束(MEASUREMENT_END)、
    // main函数入口(owner=0, offset=0)
    bool macros_ordered = true;
    bool has_start, has_end = false;
    bool has_main = false;
    tc_symbol_entry_t *prev_e = NULL;
    for (tc_symbol_entry_t *e = test_case->symbol_table; e < test_case->symbol_table + n_symbols;
         e++) {
        // 检查必需符号是否存在
        if (e->id == MACRO_MEASUREMENT_START)
            has_start = true;
        if (e->id == MACRO_MEASUREMENT_END)
            has_end = true;
        if (e->owner == 0 && e->offset == 0)
            has_main = true;

        // 检查宏排序：非函数符号必须按owner递增，同owner内按offset递增
        if (prev_e && e->id != NONMACRO_FUNCTION && prev_e->id != NONMACRO_FUNCTION) {
            if (e->owner < prev_e->owner)
                macros_ordered = false;
            if (e->owner == prev_e->owner && e->offset < prev_e->offset)
                macros_ordered = false;
        }

        // 类型检查actor切换目标宏
        // K2U(内核到用户)的目标必须是用户态(PL_USER)
        // U2K(用户到内核)的目标必须是内核态(PL_KERNEL)
        // H2G(主机到客户机)的目标必须是客户机模式(MODE_GUEST)
        // G2H(客户机到主机)的目标必须是主机模式(MODE_HOST)
        if (e->id == MACRO_SET_K2U_TARGET)
            ASSERT((actors[e->args & 0xFF].pl == PL_USER), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_U2K_TARGET)
            ASSERT((actors[e->args & 0xFF].pl == PL_KERNEL), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_H2G_TARGET)
            ASSERT((actors[e->args & 0xFF].mode == MODE_GUEST), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_G2H_TARGET)
            ASSERT((actors[e->args & 0xFF].mode == MODE_HOST), "__batch_tc_parsing_end");

        prev_e = e;
    }
    if (!macros_ordered) {
        PRINT_ERRS("__batch_tc_parsing_end", "Macros in the symbol table are not ordered\n");
        return -1;
    }
    if (!has_start || !has_end) {
        PRINT_ERRS("__batch_tc_parsing_end", "Symbol table does not contain measurement "
                                             "start/end\n");
        return -1;
    }
    if (!has_main) {
        PRINT_ERRS("__batch_tc_parsing_end", "Symbol table does not contain main function\n");
        return -1;
    }

    // 设置测试用例特性标志
    // 如果任何actor是客户机模式(VM)，设置includes_vm_actors
    // 如果任何actor是用户态，设置includes_user_actors
    for (int i = 0; i < n_actors; i++) {
        if (actors[i].mode == MODE_GUEST) {
            test_case->features.includes_vm_actors = true;
            break;
        }
        if (actors[i].pl == PL_USER) {
            test_case->features.includes_user_actors = true;
            break;
        }
    }

    // 检查测试用例是否声明了显式的fault handler宏
    // 如果没有，code_loader将使用默认的fault handler
    bool fault_handler_found = false;
    for (tc_symbol_entry_t *e = test_case->symbol_table; e < test_case->symbol_table + n_symbols;
         e++) {
        if (e->id == MACRO_FAULT_HANDLER) {
            fault_handler_found = true;
            break;
        }
    }
    test_case->features.has_explicit_fault_handler = fault_handler_found;
    return 0;
}

/// 解析通过sysfs传入的RCBF格式的测试用例
/// RCBF格式分为多个阶段：头部、actor表、符号表、元数据、各section数据
/// 使用状态机逐步解析，因为sysfs写入可能分多次调用
/// (详见docs/devel/binary-formats.md)
ssize_t parse_test_case_buffer(const char *buf, size_t count, bool *finished)
{
    ASSERT(*finished == false, "parse_test_case_buffer");

    static size_t curr_section_id = 0;
    static size_t curr_section_start = 0;
    static size_t curr_section_end = 0;
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    // 计算各阶段的边界位置
    int actor_table_end = TC_HEADER_SIZE + test_case->actor_table_size;
    int symbol_table_end = actor_table_end + test_case->symbol_table_size;
    int metadata_end = symbol_table_end + test_case->metadata_size;

    if (!_is_receiving_test_case) // 开始新的批次：解析头部
    {
        consumed_bytes = __batch_tc_parsing_start(buf);
        if (consumed_bytes != TC_HEADER_SIZE) {
            PRINT_ERRS("parse_test_case_buffer", "Error parsing header\n");
            return -1;
        }

        _cursor += consumed_bytes;
        _is_receiving_test_case = true;
    } else if (_cursor < actor_table_end) // 解析actor表阶段
    {
        // 逐字节复制actor元数据
        size_t at_cursor = _cursor - TC_HEADER_SIZE;
        for (; at_cursor < test_case->actor_table_size && byte_id < count;) {
            ((char *)test_case->actor_table)[at_cursor] = buf[byte_id];
            byte_id++;
            at_cursor++;
        }
        _cursor = at_cursor + TC_HEADER_SIZE;
        consumed_bytes = byte_id;
    } else if (_cursor < symbol_table_end) // 解析符号表阶段
    {
        // 逐字节复制符号表（宏定义和函数入口）
        size_t st_cursor = _cursor - actor_table_end;
        for (; st_cursor < test_case->symbol_table_size && byte_id < count;) {
            ((char *)test_case->symbol_table)[st_cursor] = buf[byte_id];
            byte_id++;
            st_cursor++;
        }
        _cursor = st_cursor + actor_table_end;
        consumed_bytes = byte_id;
    } else if (_cursor < metadata_end) // 解析section元数据阶段
    {
        // 逐字节复制每个section的大小等元数据
        size_t metadata_cursor = _cursor - symbol_table_end;
        for (; metadata_cursor < test_case->metadata_size && byte_id < count;) {
            ((char *)test_case->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        _cursor = metadata_cursor + symbol_table_end;
        consumed_bytes = byte_id;
    } else // 解析section代码数据阶段
    {
        // 逐section复制测试用例的代码数据
        // 每个section对应一个actor的代码
        if (curr_section_id == 0) {
            curr_section_start = metadata_end;
            curr_section_end = metadata_end + test_case->metadata[0].size;
        }
        // 检查section大小不超过最大限制
        // 每个section的代码将被加载到沙箱代码区，大小受限
        if (test_case->metadata[curr_section_id].size > MAX_SECTION_SIZE) {
            PRINT_ERRS("parse_test_case_buffer", "Section size exceeds MAX_SECTION_SIZE\n");
            _is_receiving_test_case = false;
            return -1;
        }
        // printk(KERN_ERR "parse_test_case_buffer: curr_section_start = %lu; curr_section_end =
        // "
        //                 "%lu; curr_section_id = %lu\n",
        //        curr_section_start, curr_section_end, curr_section_id);

        size_t func_cursor = _cursor - curr_section_start;
        bool func_finished = false;
        for (; byte_id < count;) {
            test_case->sections[curr_section_id].code[func_cursor] = buf[byte_id];
            byte_id++;
            func_cursor++;
            if (func_cursor >= test_case->metadata[curr_section_id].size) {
                func_finished = true;
                break;
            }
        }
        _cursor = func_cursor + curr_section_start;
        consumed_bytes = byte_id;

        if (func_finished) {
            curr_section_id++;
            curr_section_start = curr_section_end;
            curr_section_end = curr_section_end + test_case->metadata[curr_section_id].size;
        }
    }

    // 检查是否已完成所有section的解析
    // 所有actor的代码数据都已复制完毕
    if (curr_section_id >= n_actors) {
        curr_section_id = 0;
        curr_section_start = 0;
        curr_section_end = 0;

        _is_receiving_test_case = false;
        *finished = true;

        // 调用__batch_tc_parsing_end完成最终验证和特性设置
        if (__batch_tc_parsing_end())
            return -1;

        ASSERT_MSG(consumed_bytes == count, "parse_test_case_buffer",
                   "consumed_bytes (%lu) != count (%lu)\n", consumed_bytes, count);
    }
    // printk(KERN_ERR "parse_test_case_buffer: consumed_bytes = %lu; count = %lu; _cursor =
    // %llu, " "fid: %ld, finished: %d\n",
    //    consumed_bytes, count, _cursor, curr_section_id, *finished);

    return consumed_bytes;
}

/// 查询测试用例解析是否已完成
bool tc_parsing_completed(void) { return !_is_receiving_test_case; }

// =================================================================================================

/// @brief 创建新的测试用例结构，使用默认值初始化
/// @param test_case_p 指向测试用例指针的指针
/// @return 0表示成功；-ENOMEM表示内存分配失败
static int new_test_case(test_case_t **test_case_p)
{
    test_case_t *tc = CHECKED_MALLOC(sizeof(test_case_t));
    memset(tc, 0, sizeof(test_case_t)); // 清零以防残留数据

    // 设置默认大小（1个actor的最小配置）
    tc->actor_table_size = sizeof(actor_metadata_t);
    tc->symbol_table_size = 0;
    tc->metadata_size = sizeof(tc_section_metadata_entry_t);
    tc->sections_size = sizeof(tc_section_t);
    tc->actor_table = _allocated_actor_table;
    tc->symbol_table = _allocated_symbol_table;
    tc->metadata = _allocated_metadata;
    tc->sections = _allocated_data;

    // 默认特性：不包含VM actor、不包含用户态actor、没有显式fault handler
    tc->features.includes_vm_actors = false;
    tc->features.includes_user_actors = false;
    tc->features.has_explicit_fault_handler = false;

    *test_case_p = tc;
    return 0;
}

// 初始化测试用例解析器
// 分配各表的最小缓冲区，创建默认(dummy)测试用例
int init_test_case_parser(void)
{
    // 初始化本地状态
    n_symbols = 0;
    _is_receiving_test_case = false;
    _cursor = 0;
    _allocated_actor_table = CHECKED_MALLOC(sizeof(actor_metadata_t));
    _allocated_symbol_table = CHECKED_MALLOC(1);
    _allocated_metadata = CHECKED_MALLOC(sizeof(tc_section_metadata_entry_t));
    _allocated_data = CHECKED_VMALLOC(sizeof(tc_section_t));

    // 创建默认(dummy)测试用例（1个actor的最小配置）
    // 这个dummy测试用例确保系统在加载正式测试用例之前也能安全运行
    if (new_test_case(&test_case) != 0) {
        PRINT_ERRS("init_test_case_parser", "Failed to create test case\n");
        return -ENOMEM;
    }
    actors = test_case->actor_table;
    return 0;
}

void free_test_case_parser(void)
{
    SAFE_FREE(test_case);
    SAFE_FREE(_allocated_actor_table);
    SAFE_FREE(_allocated_symbol_table);
    SAFE_FREE(_allocated_metadata);
    SAFE_VFREE(_allocated_data);
    actors = NULL;
}

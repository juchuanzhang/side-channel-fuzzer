/// File: Header for the test case parser and manager
///
// ==============================================================================
// 测试用例解析器头文件概述：
// 本文件定义了模糊测试用例(test case)的解析接口和数据结构。
//
// 测试用例是模糊测试引擎生成的二进制数据，包含：
//   1. Actor元数据表(actor_table)：描述每个Actor的ID、模式、特权级和权限
//   2. 符号表(symbol_table)：描述测试代码中的宏标记和函数入口点
//      每个符号包含owner(所属Actor)、offset(代码段偏移)、id(宏类型)、args(宏参数)
//   3. 代码段元数据(metadata)：描述每个代码段的大小和所属Actor
//   4. 代码段(sections)：实际的测试代码二进制数据
//
// 解析流程：
//   1. 模糊测试引擎通过sysfs将测试用例数据写入内核模块
//   2. parse_test_case_buffer分批接收数据，解析头部和各区域
//   3. 解析完成后，test_case结构体包含所有解析结果
//   4. 代码加载器和宏展开器使用test_case中的数据构建可执行的沙箱代码
//
// tc_features_t描述测试用例的特征：
//   - includes_vm_actors：是否包含Guest模式Actor（需要虚拟化支持）
//   - includes_user_actors：是否包含User特权级Actor（需要权限切换）
//   - has_explicit_fault_handler：是否有显式故障处理宏
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _TEST_CASE_PARSER_H_
#define _TEST_CASE_PARSER_H_

#include "actor.h"

/// 最大代码段数量——等于最大Actor数量（每个Actor一个代码段）
#define MAX_SECTIONS            MAX_ACTORS
/// 最大符号数量——128个宏/函数入口点足以覆盖复杂测试用例
#define MAX_SYMBOLS             128
/// 最大代码段大小——必须精确为1页(4KB)，以便检测sysfs缓冲行为
/// sysfs写入可能分多次完成，4KB边界有助于判断数据完整性
#define MAX_SECTION_SIZE        4096 // NOTE: must be exactly 1 page to detect sysfs buffering
/// 最大加载代码段大小——2页(8KB)，包含原始代码+宏展开代码
#define MAX_LOADED_SECTION_SIZE (4096 * 2)
/// 测试用例头部大小——包含n_actors(8B) + n_symbols(8B)
#define TC_HEADER_SIZE          (2 * sizeof(uint64_t))

/// 代码段大小类型
typedef uint64_t section_size_t;
/// 代码段元数据保留字段类型
typedef uint64_t section_metadata_reserved_t;
/// 代码段ID类型
typedef uint64_t section_id_t;
/// 符号偏移量类型——符号在代码段中的字节偏移
typedef uint64_t symbol_offset_t;
/// 符号ID类型——对应macro_name_e枚举值
typedef uint64_t symbol_id_t;
/// 符号参数类型——宏的参数编码
typedef uint64_t symbol_args_t;

/// 代码段元数据条目——描述一个代码段的基本信息
typedef struct {
    actor_id_t owner;                           // 代码段所属的Actor ID
    section_size_t size;                        // 代码段的大小（字节）
    section_metadata_reserved_t reserved;       // 保留字段（未使用）
} tc_section_metadata_entry_t;

/// 代码段结构体——包含一个Actor的全部测试代码
typedef struct {
    char code[MAX_SECTION_SIZE];                // 代码数据——4KB的二进制代码
} tc_section_t;

/// 符号表条目——描述测试代码中的宏标记或函数入口点
/// 宏标记(MACRO_START/MACRO_END)在代码加载时被展开为对应的汇编代码
typedef struct {
    actor_id_t owner;                           // 符号所属的Actor ID
    symbol_offset_t offset;                     // 符号在代码段中的字节偏移
    symbol_id_t id;                             // 符号类型ID——对应macro_name_e枚举
    symbol_args_t args;                         // 符号参数——编码为64位值，传递给宏展开
} tc_symbol_entry_t;

/// 测试用例特征描述——标记测试用例需要哪些执行器特性
typedef struct {
    bool includes_vm_actors;                    // 是否包含Guest模式Actor——需要VMX/SVM/ARM VM
    bool includes_user_actors;                  // 是否包含User特权级Actor——需要权限切换机制
    bool has_explicit_fault_handler;            // 是否有显式故障处理宏——影响故障处理器配置
} tc_features_t;

/// 测试用例结构体——包含解析后的所有测试用例数据
/// 是测试用例解析的最终产出，包含所有元数据和代码段
typedef struct {
    tc_features_t features;                     // 测试用例特征——决定执行器的配置需求
    size_t actor_table_size;                    // Actor元数据表大小
    size_t symbol_table_size;                   // 符号表大小
    size_t metadata_size;                       // 代码段元数据大小
    size_t sections_size;                       // 代码段总大小
    actor_metadata_t *actor_table;              // Actor元数据数组——描述所有Actor的配置
    tc_symbol_entry_t *symbol_table;            // 符号表数组——描述所有宏标记
    tc_section_metadata_entry_t *metadata;      // 代码段元数据数组
    tc_section_t *sections;                     // 代码段数组——包含所有Actor的测试代码
} test_case_t;

/// 全局测试用例实例——存储当前解析的测试用例数据
extern test_case_t *test_case;

/// 解析从sysfs接收的测试用例数据缓冲区
/// 支持分批接收——sysfs可能分多次写入数据
/// @param buf 数据缓冲区
/// @param count 数据大小
/// @param finished 输出参数，标记是否已完成所有数据的接收
/// @return 已解析的字节数，负数表示错误
ssize_t parse_test_case_buffer(const char *buf, size_t count, bool *finished);

/// 检查测试用例解析是否已完成——所有代码段数据已接收并解析完毕
bool tc_parsing_completed(void);

/// 初始化测试用例解析器——分配test_case和各区域内存
/// @return 0表示成功，负数表示错误码
int init_test_case_parser(void);

/// 释放测试用例解析器分配的所有内存
void free_test_case_parser(void);

#endif // _TEST_CASE_PARSER_H_

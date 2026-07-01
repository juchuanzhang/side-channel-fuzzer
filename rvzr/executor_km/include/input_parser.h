/// File: Header for the input parser
///
// ==============================================================================
// 输入解析器头文件概述：
// 本文件定义了模糊测试输入数据的解析接口和数据结构。
//
// 输入解析器负责：
//   1. 从sysfs设备文件接收模糊测试输入数据
//   2. 解析输入批次(input_batch_t)的结构：元数据+数据区域
//   3. 将解析后的数据存储在内存中，供data_loader加载到沙箱
//
// 输入数据布局：
//   - 每条输入(input_fragment_t)包含三个区域：
//     main_area：主输入页（不触发页故障）
//     faulty_area：故障输入页（可触发页故障——用于模拟Meltdown类攻击）
//     reg_init_region：寄存器初始化区域（设置测试前的CPU寄存器初始值）
//
// 批量输入支持：一次可加载最多1M条输入(MAX_INPUTS)，
// 每条输入针对不同的Actor，支持多Actor协同测试场景。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _INPUT_PARSER_H_
#define _INPUT_PARSER_H_

#include "sandbox_manager.h"

/// 寄存器初始化区域大小——对齐到页边界(4096)
/// 包含8个64位GPR初始值 + 8个256位YMM初始值 = 320字节，
/// 对齐到4096以满足页表管理要求
#define REG_INIT_AREA_SIZE_ALIGNED 4096

/// 输入片段大小类型
typedef uint64_t input_fragment_size_t;
/// 输入片段保留字段类型
typedef uint64_t input_fragment_reserved_field_t;

/// 输入片段元数据条目——描述单条输入的大小和保留信息
typedef struct {
    input_fragment_size_t size;               // 该片段的数据大小
    input_fragment_reserved_field_t reserved; // 保留字段（未使用）
} input_fragment_metadata_entry_t;

/// 输入片段——一条完整的模糊测试输入数据
/// 包含三个区域，分别映射到沙箱的不同内存页：
///   - main_area：主输入页，页表设置为可正常访问
///   - faulty_area：故障输入页，页表可配置为触发页故障（用于Meltdown类测试）
///   - reg_init_region：寄存器初始化区域，测试前从此区域加载寄存器初始值
typedef struct {
    char main_area[MAIN_AREA_SIZE];           // 主输入页——不触发页故障
    char faulty_area[FAULTY_AREA_SIZE];       // 故障输入页——可触发页故障
    char reg_init_region[REG_INIT_AREA_SIZE_ALIGNED]; // 寄存器初始化区域
} input_fragment_t;

/// 输入批次——包含多条输入的完整数据包
/// 由模糊测试引擎一次性写入sysfs，解析器分批处理
/// fields说明：
///   - metadata_size：元数据区域总大小
///   - data_size：数据区域总大小
///   - metadata：元数据数组，每个条目描述一条输入片段
///   - data：输入片段数组，包含所有Actor的所有输入数据
typedef struct {
    size_t metadata_size;                                // 元数据区域大小
    size_t data_size;                                    // 数据区域大小
    input_fragment_metadata_entry_t *metadata;           // 元数据数组指针
    input_fragment_t *data;                              // 输入数据数组指针
} input_batch_t;

/// 最大输入数量限制——1M条输入足够覆盖模糊测试的所有批次场景
#define MAX_INPUTS            (1024 * 1024)
/// 批次头部大小——包含n_actors(8B) + n_inputs(8B)
#define BATCH_HEADER_SIZE     16 // sizeof(n_actors) + sizeof(n_inputs)
/// 单条输入片段对齐后的大小——用于计算数据区域的偏移量
#define FRAGMENT_SIZE_ALIGNED (MAIN_AREA_SIZE + FAULTY_AREA_SIZE + REG_INIT_AREA_SIZE_ALIGNED)

/// 全局输入批次——存储所有解析后的模糊测试输入数据
extern input_batch_t *inputs;

/// 全局输入数量——当前批次中的输入条数
extern size_t n_inputs;

/// 获取指定输入ID和Actor ID对应的输入片段
/// 根据input_id和actor_id在输入数据数组中定位对应的输入片段
/// @param input_id 输入索引号
/// @param actor_id Actor索引号
/// @return 指向对应输入片段的指针
input_fragment_t *get_input_fragment(uint64_t input_id, uint64_t actor_id);

/// 获取指定输入片段（不进行边界检查）——高性能版本
/// 仅在确认输入ID有效时使用，避免额外的边界检查开销
input_fragment_t *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id);

/// 解析从sysfs接收的输入数据缓冲区
/// 支持分批接收：模糊测试引擎可能分多次写入数据
/// @param buf 数据缓冲区
/// @param count 数据大小
/// @param finished 输出参数，标记是否已完成所有数据的接收
/// @return 已解析的字节数，负数表示错误
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished);

/// 检查输入解析是否已完成——所有输入数据已接收并解析完毕
bool input_parsing_completed(void);

/// 初始化输入解析器——分配inputs和元数据内存
/// @return 0表示成功，负数表示错误码
int init_input_parser(void);

/// 释放输入解析器分配的所有内存
void free_input_parser(void);

#endif // _INPUT_PARSER_H_

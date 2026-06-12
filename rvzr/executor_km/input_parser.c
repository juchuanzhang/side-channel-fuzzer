/// File:
///   - Parsing inputs
///   - Management of input-related data structures
///   - Accessors to the input data
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/slab.h> // PAGE_SIZE

#include "actor.h"
#include "input_parser.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

// 全局输入批次结构，存储所有actor的所有输入数据
input_batch_t *inputs = NULL; // global
// 全局输入数量，即每个actor有多少组不同的输入数据
size_t n_inputs = 0;          // global

// =================================================================================================
// 输入获取的状态机
// =================================================================================================
// is_receiving_inputs: 是否正在接收输入数据（状态机标志）
// cursor: 当前解析位置的全局游标
// highest_n_actors/highest_n_inputs: 记录历史最大值，避免频繁重新分配内存
static bool is_receiving_inputs = false;
static uint64_t cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_inputs = 0;
// 预分配的metadata和data缓冲区，跨批次复用
static input_fragment_metadata_entry_t *allocated_metadata;
static input_fragment_t *allocated_data;

/// 初始化输入解析状态机
/// 解析RCBF格式的输入数据批次头部（包含actor数量和输入数量）
/// RCBF = Relayed Chunked Binary Format，详见docs/devel/binary-formats.md
static int start_batch_input_parsing(const char *buf)
{
    int ret = 0;

    // 重置游标，开始新一轮解析
    cursor = 0;

    // 创建新的输入批次结构
    SAFE_FREE(inputs);
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));

    // 读取actor数量（从RCBF头部第1个8字节字段）
    // 此处验证actor数量与test_case_parser中声明的n_actors一致
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ASSERT_MSG(new_n_actors == n_actors, "start_batch_input_parsing",
               "Mismatch in n_actors;"
               " Either inputs were loaded befor the test case,\n"
               "or the declared n_actors does not match "
               "(n_actors = %lu, new_n_actors = %llu)\n",
               n_actors, new_n_actors);
    ret += 8;

    // 读取输入数量（从RCBF头部第2个8字节字段）
    // 每个actor有n_inputs组不同的输入数据
    uint64_t new_n_inputs = ((uint64_t *)buf)[1];
    ASSERT(new_n_inputs != 0, "start_batch_input_parsing");
    ASSERT_MSG((int)new_n_inputs <= MAX_INPUTS, "start_batch_input_parsing",
               "n_inputs (%llu) > MAX_INPUTS (%u)\n", new_n_inputs, MAX_INPUTS);
    ret += 8;

    // 计算metadata和data的存储大小
    // metadata不需要乘以输入数量，因为每组输入共享相同的metadata
    // data需要乘以actor数量×输入数量
    inputs->metadata_size = new_n_actors * sizeof(input_fragment_metadata_entry_t);
    inputs->data_size = new_n_actors * new_n_inputs * sizeof(input_fragment_t);

    // 如果actor数量或输入数量增加，需要重新分配更大的缓冲区
    // 否则复用之前的分配，避免频繁的内存分配/释放
    if (new_n_actors > highest_n_actors || new_n_inputs > highest_n_inputs || !allocated_metadata ||
        !allocated_data) {
        SAFE_FREE(allocated_metadata);
        SAFE_VFREE(allocated_data);
        // metadata使用kmalloc（小且频繁访问），data使用vmalloc（可能很大）
        allocated_metadata = CHECKED_MALLOC(inputs->metadata_size);
        allocated_data = CHECKED_VMALLOC(inputs->data_size);
        highest_n_actors = new_n_actors;
        highest_n_inputs = new_n_inputs;
    }

    // 更新全局指针和变量
    inputs->metadata = allocated_metadata;
    inputs->data = allocated_data;
    n_inputs = new_n_inputs;
    // 注意：n_actors不在此处更新，由test_case_parser负责

    ASSERT(ret < PAGE_SIZE, "start_batch_input_parsing");
    return ret;
}

/// 解析通过sysfs传入的RCBF格式输入数据
/// RCBF格式分三个阶段：批次头部、metadata、data
/// 由于sysfs写入可能分多次调用，使用状态机逐步解析
/// (格式描述详见docs/devel/binary-formats.md)
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished)
{
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    if (!is_receiving_inputs) // 开始新的批次：解析批次头部
    {
        // 消费批次头部的固定大小部分
        // 假设头部足够小，可以在一次调用中完成解析
        consumed_bytes = start_batch_input_parsing(buf);
        cursor += consumed_bytes;
        if (consumed_bytes <= 0)
            return -1;

        is_receiving_inputs = true;
    } else if (cursor < BATCH_HEADER_SIZE + inputs->metadata_size) // 解析metadata阶段
    {
        // 逐字节复制metadata数据
        size_t metadata_cursor = cursor - BATCH_HEADER_SIZE;
        size_t end = inputs->metadata_size;
        for (; metadata_cursor < end && byte_id < count;) {
            ((char *)inputs->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        cursor = metadata_cursor + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    } else // 解析data阶段
    {
        // 逐字节复制输入数据
        // FIXME: 此实现不是最优的，会复制fragment_size和FRAGMENT_SIZE_ALIGNED之间的未使用数据
        size_t data_cursor = cursor - inputs->metadata_size - BATCH_HEADER_SIZE;
        size_t end = inputs->data_size;
        for (; data_cursor < end && byte_id < count;) {
            ((char *)inputs->data)[data_cursor] = buf[byte_id];
            byte_id++;
            data_cursor++;
        }
        cursor = data_cursor + inputs->metadata_size + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    }

    // 检查是否已完成所有数据的解析
    size_t data_end = BATCH_HEADER_SIZE + inputs->metadata_size + inputs->data_size;
    if (cursor >= data_end) {
        is_receiving_inputs = false;
        *finished = true;
    }
    // printk(KERN_ERR "parse_input_buffer: consumed_bytes = %lu; count = %lu; cursor = %llu; end =
    // "
    //                 "%lu; finished = %d\n",
    //        consumed_bytes, count, cursor, data_end, *finished);
    return consumed_bytes;
}

// =================================================================================================
// Misc. functions
// =================================================================================================

/// @brief 获取指定actor和input_id的输入数据片段（带边界检查）
/// @param actor_id: 0是客户机0，1是客户机1，主机是最后一个
/// @param input_id: 输入编号
/// @return 对应的输入数据片段指针，出错返回NULL
input_fragment_t *get_input_fragment(uint64_t input_id, uint64_t actor_id)
{
    ASSERT_ENULL(inputs != NULL, "get_input_fragment");
    if (actor_id >= n_actors) {
        PRINT_ERRS("get_input_fragment", "actor_id (%llu) >= n_actors (%lu)\n", actor_id, n_actors);
        return NULL;
    }
    if (input_id >= n_inputs) {
        PRINT_ERRS("get_input_fragment", "input_id (%llu) >= n_inputs (%lu)\n", input_id, n_inputs);
        return NULL;
    }

    return &inputs->data[(actor_id * n_inputs) + input_id];
}

/// @brief 获取输入数据片段的不安全版本（无边界检查，用于性能敏感路径）
/// 注意：此版本使用不同的索引顺序(input_id * n_actors + actor_id)
/// 与安全版本的(actor_id * n_inputs + input_id)不同
/// @param input_id 输入编号
/// @param actor_id actor编号
/// @return 输入数据片段指针
input_fragment_t *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id)
{
    return &inputs->data[(input_id * n_actors) + actor_id];
}

/// 查询输入解析是否已完成
/// 返回true表示当前没有在接收输入数据
bool input_parsing_completed(void) { return !is_receiving_inputs; }

// =================================================================================================
// 初始化输入解析器
// 分配初始的输入批次结构和最小缓冲区
int init_input_parser(void)
{
    is_receiving_inputs = false;
    cursor = 0;
    n_inputs = 0;
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));
    allocated_data = CHECKED_VMALLOC(sizeof(input_fragment_t));
    allocated_metadata = CHECKED_MALLOC(sizeof(input_fragment_metadata_entry_t));
    inputs->data_size = 0;
    inputs->metadata_size = 0;
    inputs->data = allocated_data;
    inputs->metadata = allocated_metadata;
    return 0;
}

void free_input_parser(void)
{
    SAFE_FREE(inputs);
    SAFE_FREE(allocated_metadata);
    SAFE_VFREE(allocated_data);
}

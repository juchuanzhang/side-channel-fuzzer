/// File: Header for data_loader.c
///
// ==============================================================================
// 数据加载器头文件概述：
// 本文件定义了将模糊测试输入数据加载到沙箱(sandbox)中的接口。
//
// 数据加载器负责：
//   1. 在内核模块初始化时预分配数据区域内存
//   2. 在每次测试执行前，根据input_id选择对应的输入数据，
//      拷贝到沙箱的main_area和faulty_area区域
//   3. 设置数据区域的页表权限（如faulty_area的User/Present位，
//      控制是否触发页故障——这是侧信道测试的关键配置）
//
// input_id参数指定当前要使用的输入批次中的哪一条输入数据，
// 用于支持批量输入测试（一次加载多条输入，逐条执行测量）。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _DATA_LOADER_H_
#define _DATA_LOADER_H_

#include <linux/types.h>

/// 将指定输入ID的模糊测试数据加载到沙箱的数据区域
/// 包括拷贝main_area和faulty_area数据，设置页表权限
/// @param input_id 输入数据的索引号（在input_batch_t中选择对应条目）
/// @return 0表示成功，负数表示错误码
int load_sandbox_data(int input_id);

/// 初始化数据加载器——预分配数据区域内存
/// @return 0表示成功，负数表示错误码
int init_data_loader(void);

/// 释放数据加载器分配的所有内存
void free_data_loader(void);

#endif // _DATA_LOADER_H_

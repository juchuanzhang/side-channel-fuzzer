/// File: Header for code_loader.c
///
// ==============================================================================
// 代码加载器头文件概述：
// 本文件定义了将测试用例代码加载到沙箱(sandbox)中的接口。
//
// 代码加载器负责：
//   1. 在内核模块初始化时预分配代码区域内存
//   2. 在每次测试执行前，将解析后的测试用例代码（包括宏展开后的代码）
//      拷贝到沙箱的代码区域(actor_code_t)
//   3. 设置代码区域的页表权限（使代码页可执行但不可写）
//
// loaded_test_case_entry指向当前加载的测试用例代码入口点地址，
// 测量执行时CPU从此地址开始执行测试代码。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _CODE_LOADER_H_
#define _CODE_LOADER_H_

#include <linux/types.h>

/// 当前加载的测试用例代码入口点地址
/// 每次执行测试前，code_loader将测试代码拷贝到沙箱，
/// 并将此指针设置为沙箱代码区域的起始地址
extern uint8_t *loaded_test_case_entry;

/// 将测试用例代码加载到沙箱的代码区域
/// 包括拷贝代码段和展开宏，设置页表权限为可执行
/// @return 0表示成功，负数表示错误码
int load_sandbox_code(void);

/// 初始化代码加载器——预分配代码区域内存
/// @return 0表示成功，负数表示错误码
int init_code_loader(void);

/// 释放代码加载器分配的所有内存
void free_code_loader(void);

#endif // _CODE_LOADER_H_

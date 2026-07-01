/// 文件：ARM64架构预分配寄存器的符号名定义
/// 本文件为ARM64架构中具有特殊用途的寄存器定义符号名，
/// 防止汇编代码和C代码中误用这些保留寄存器。
/// ARM64调用约定：x0-x7为参数/返回值寄存器，x8为间接结果寄存器，
/// x9-x15为临时寄存器，x16-x17为IP0/IP1(过程内调用)，x18为IP2(平台寄存器)，
/// x19-x28为callee-save寄存器，x29为帧指针，x30为链接寄存器(LR)。
/// 本文件保留x12/x13(临时)和x20-x28(callee-save)用于测量特殊用途。
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ARM64_REGISTERS_H_
#define _ARM64_REGISTERS_H_

/// 保留寄存器——以下寄存器在整个测量过程中有固定用途，绝不能被覆盖
/// STATUS_REGISTER(x12): 测量状态寄存器，低8位记录执行阶段(STATUS_UNINITIALIZED/STARTED/ENDED)
/// STATUS_REGISTER_32(w12): 状态寄存器的32位版本，用于and/orr操作(零扩展高32位)
/// HTRACE_REGISTER(x13): 硬件追踪结果寄存器，累加侧信道观测值(如L1D P+P探查位串)
/// MEMORY_BASE_REGISTER(x20): 沙箱主数据区基址寄存器，指向actor 0的main_area(callee-save)
/// UTIL_BASE_REGISTER(x21): 沙箱工具区基址寄存器，指向sandbox->util结构(callee-save)
#define STATUS_REGISTER         "x12"
#define STATUS_REGISTER_32      "w12"

#define HTRACE_REGISTER         "x13"

#define MEMORY_BASE_REGISTER    "x20"
#define MEMORY_BASE_REGISTER_ID 0x14

#define UTIL_BASE_REGISTER      "x21"
#define UTIL_BASE_REGISTER_     x21
#define UTIL_BASE_REGISTER_ID   0x15

/// 临时寄存器——用于各种中间计算，可在宏内部自由使用但需注意跨宏依赖
/// TMP_REG1(x28): 第1个临时寄存器(callee-save)，最常用的中间计算寄存器
/// TMP_REG2(x27): 第2个临时寄存器(callee-save)，用于需要多个临时值的场景
/// TMP_REG3(x26): 第3个临时寄存器(callee-save)
/// TMP_REG4(x25): 第4个临时寄存器(callee-save)
/// TMP_REG5(x24): 第5个临时寄存器(callee-save)
/// TMP_REG6(x23): 第6个临时寄存器(callee-save)
#define TMP_REG1                "x28"
#define TMP_REG1_               x28
#define TMP_REG1_ID             0x1c

#define TMP_REG2                "x27"
#define TMP_REG2_               x27
#define TMP_REG2_ID             0x1b

#define TMP_REG3                "x26"
#define TMP_REG3_               x26

#define TMP_REG4                "x25"
#define TMP_REG4_               x25

#define TMP_REG5                "x24"
#define TMP_REG5_               x24

#define TMP_REG6                "x23"
#define TMP_REG6_               x23

/// 注意：x16由asm_snippets.h内部代码使用(如mov_imm_to_reg中的临时寄存器)，
///       测试用例代码应避免使用x16，防止冲突

/// 性能计数器寄存器——用于存储PMU读取的差值(起始值-结束值后的结果)
/// PFC0(x10): 第1个性能计数器差值存储位置(PMEVCNTR0)
/// PFC1(x9):  第2个性能计数器差值存储位置(PMEVCNTR1)
/// PFC2(x8):  第3个性能计数器差值存储位置(PMEVCNTR2)
/// 注意：ARM64只使用PMC#0/#1/#2三个计数器(x86使用PMC#1/#2/#3)
#define PFC0 "x10"
#define PFC1 "x9"
#define PFC2 "x8"

#endif // _ARM64_REGISTERS_H_

/// 文件：x86-64架构预分配寄存器的符号名定义
/// 本文件为x86-64架构中具有特殊用途的寄存器定义符号名，
/// 防止汇编代码和C代码中误用这些保留寄存器。
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_REGISTERS_H_
#define X86_REGISTERS_H_

/// 寄存器ID号——对应x86-64指令编码中的寄存器编号
/// RAX=0x0, RCX=0x1, RDX=0x2, RBX=0x3, RSP=0x4, RBP=0x5, RSI=0x6, RDI=0x7
#define RAX_REG_ID 0x0
#define RCX_REG_ID 0x1
#define RDX_REG_ID 0x2
#define RBX_REG_ID 0x3
#define RSP_REG_ID 0x4
#define RBP_REG_ID 0x5
#define RSI_REG_ID 0x6
#define RDI_REG_ID 0x7

/// REX前缀边界——0x8以上的寄存器需要REX前缀才能在指令中访问
/// R8=0x8 ~ R15=0xf
#define REX_BOUNDARY 0x8
#define R8_REG_ID    0x8
#define R9_REG_ID    0x9
#define R10_REG_ID   0xa
#define R11_REG_ID   0xb
#define R12_REG_ID   0xc
#define R13_REG_ID   0xd
#define R14_REG_ID   0xe
#define R15_REG_ID   0xf

/// 保留寄存器——以下寄存器在整个测量过程中有固定用途，绝不能被覆盖
/// STATUS_REGISTER(r12): 测量状态寄存器，记录当前执行阶段(未初始化/已开始/已结束)和SMI计数
/// STATUS_REGISTER_32(r12d): 状态寄存器的32位版本，用于清除高位SMI状态(零扩展高32位)
/// STATUS_REGISTER_8(r12b): 状态寄存器的8位版本，用于设置执行阶段标志(不影响高56位)
/// HTRACE_REGISTER(r13): 硬件追踪结果寄存器，累加侧信道观测值(如L1D Prime+Probe探查结果)
/// MEMORY_BASE_REG(r14): 沙箱主数据区基址寄存器，指向actor 0的main_area
/// UTIL_BASE_REG(r15): 沙箱工具区基址寄存器，指向sandbox->util结构(含测量输出、栈保存等)
#define STATUS_REGISTER    "r12"
#define STATUS_REGISTER_32 "r12d"
#define STATUS_REGISTER_8  "r12b"

#define HTRACE_REGISTER "r13"
#define MEMORY_BASE_REG "r14"
#define UTIL_BASE_REG   "r15"

/// TMP_REG(r11): 临时寄存器，用于各种中间计算(如宏栈管理中的地址计算、P+P中的偏移计算)
#define TMP_REG    "r11"
#define TMP_REG_ID (R11_REG_ID)

/// 性能计数器寄存器——用于存储PMU读取的差值(起始值-结束值后的结果)
/// PFC0(r10): 第1个性能计数器差值存储位置(PMC#1)
/// PFC1(r9):  第2个性能计数器差值存储位置(PMC#2)
/// PFC2(r8):  第3个性能计数器差值存储位置(PMC#3)
#define PFC0 "r10"
#define PFC1 "r9"
#define PFC2 "r8"

#endif // X86_REGISTERS_H_

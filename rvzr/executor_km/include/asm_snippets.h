/// File: Building blocks for creating macros;
///       This file re-directs to the correct architecture-specific file.
///
// ==============================================================================
// 汇编片段头文件概述：
// 本文件是架构无关的汇编宏入口，根据VENDOR_ID重定向到对应的架构特定文件。
//
// 汇编片段(assembler snippets)是侧信道测试用例中宏(macro)的基础构建块，
// 用于实现以下关键操作：
//   - 测量开始/结束（Prime+Probe, Flush+Reload, TSC等）
//   - 特权级切换（Kernel↔User, Host↔Guest）
//   - 故障处理器的入口/出口代码
//
// 架构差异：
//   - x86_64：使用Intel语法内联汇编，依赖特定指令（如clflush, invlpg, mfence）
//   - ARM64：使用AArch64指令集，依赖特定指令（如dc ivac, dsb, isb）
//
// 重定向规则：
//   - VENDOR_ID == VENDOR_INTEL_ 或 VENDOR_AMD_ → x86/asm_snippets.h (x86_64架构)
//   - VENDOR_ID == VENDOR_ARM_ → arm64/asm_snippets.h (ARM64架构)
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ASM_SNIPPETS_H_
#define _ASM_SNIPPETS_H_

#include "hardware_desc.h"

// 根据CPU厂商ID(VENDOR_ID)重定向到对应的架构特定汇编片段头文件
#if defined(ARCH_X86_64)
#include "../x86/asm_snippets.h"
#elif defined(ARCH_ARM)
#include "../arm64/asm_snippets.h"
#endif

#endif // _ASM_SNIPPETS_H_
/// File: Header for fault handling
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _FAULT_HANDLER_H_
#define _FAULT_HANDLER_H_

#include "hardware_desc.h"
#include <linux/interrupt.h>
#include <linux/version.h>
#include <linux/types.h>

#ifdef ARCH_ARM
typedef uint32_t opcode_t;
typedef struct {
    opcode_t code[32];
} __attribute__((packed)) vector_table_entry_t;
typedef struct {
    vector_table_entry_t vector_table[16];
} __attribute__((packed)) vector_table_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct idt_data {
    unsigned int vector;
    unsigned int segment;
    struct idt_bits bits;
    const void *addr;
};
#endif

#ifdef ARCH_X86_64

#include <../arch/x86/include/asm/traps.h>

// By default, we handle General Protection Fault and Page Fault
#define HANDLED_FAULTS_DEFAULT ((1 << X86_TRAP_GP) | (1 << X86_TRAP_PF))

#elif defined(ARCH_ARM)

// ARM64 ESR异常类别(Exception Class)定义
// ESR_ELx[31:26]为EC字段，标识异常类型
#define EC_SVC64            0x15    // SVC指令异常（EL0→EL1）
#define EC_HVC64            0x16    // HVC指令异常（EL1→EL2）
#define EC_SMC64            0x17    // SMC指令异常
#define EC_MRS_MSR          0x18    // MRS/MSR系统寄存器访问陷阱
#define EC_AA64_IABORT_EL1  0x20    // 指令异常 - 来自低特权级
#define EC_AA64_IABORT_CUR  0x21    // 指令异常 - 当前特权级
#define EC_AA64_PCALIGN     0x22    // PC对齐异常
#define EC_AA64_DABORT_EL1  0x24    // 数据异常 - 来自低特权级
#define EC_AA64_DABORT_CUR  0x25    // 数据异常 - 当前特权级
#define EC_AA64_SPALIGN     0x26    // SP对齐异常
#define EC_AA64_FP          0x28    // 浮点异常
#define EC_AA64_SERROR      0x2F    // 系统错误中断

// ARM64默认处理的异常类别：数据异常(来自低特权级)、指令异常(来自低特权级)
// 这些是侧信道测试(Meltdown类)中最常见的异常类型
#define HANDLED_FAULTS_DEFAULT ((1U << EC_AA64_DABORT_EL1) | (1U << EC_AA64_IABORT_EL1))

#endif

extern char *fault_handler;
extern uint32_t handled_faults;
extern uint64_t is_nested_fault;

bool esr_ec_matches_handled_faults(uint64_t esr_value);

// x86-only globals
extern struct desc_ptr test_case_idtr;

// ARM64-only globals
extern vector_table_t *orig_vbar_el2_ptr;

void set_outer_fault_handlers(void);
void unset_outer_fault_handlers(void);
void set_inner_fault_handlers(void);
void unset_inner_fault_handlers(void);
void set_el2_fault_handlers(void);
void unset_el2_fault_handlers(void);

int init_fault_handler(void);
void free_fault_handler(void);

#endif // _FAULT_HANDLER_H_

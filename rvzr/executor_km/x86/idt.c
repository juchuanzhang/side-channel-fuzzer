/// File:
///  - Fault handling and IDT management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/interrupt.h>

#include "code_loader.h"
#include "hardware_desc.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"

// 全局已处理异常的位掩码，每一位对应一个中断向量号
uint32_t handled_faults = 0;          // global
// 全局fault handler地址，指向测试用例内部的异常处理代码
// 当测试用例发生异常时，跳转到此地址执行异常恢复逻辑
char *fault_handler = NULL;           // global
// 全局测试用例的IDTR（中断描述符表寄存器）值
// 用于在测试执行期间切换到自定义IDT
struct desc_ptr test_case_idtr = {0}; // global

// 两级IDT策略：
// bubble_idt - 外层IDT，用于测试执行框架本身的异常保护
// test_case_idt - 内层IDT，用于测试用例内部的异常捕获
// 执行流程：原始IDT -> bubble_idt -> test_case_idt
static gate_desc *bubble_idt = NULL;
static gate_desc *test_case_idt = NULL;

// 保存原始IDTR值，用于测试结束后恢复系统IDT
static struct desc_ptr orig_idtr = {0};
// bubble IDT的IDTR值，用于从test_case_idt恢复到bubble_idt
static struct desc_ptr bubble_idtr = {0};

// 来自fault_handlers.S的汇编声明
// test_case_handler: 内层(测试用例)异常处理入口
// bubble_handler: 外层(框架)异常处理入口
// nmi_handler: NMI(不可屏蔽中断)处理入口
// is_nested_fault: 标记是否发生了嵌套异常（异常中又发生异常）
void test_case_handler(void);
void bubble_handler(void);
void nmi_handler(void);
extern uint64_t is_nested_fault;

#define BIT_CHECK(a, b) (!!((a) & (1ULL << (b))))

// =================================================================================================
// 处理器声明和列表
// =================================================================================================
// fault_handlers.S中使用汇编宏生成256个入口的stub函数（每个中断向量一个）
// 这里声明这些函数并创建指针数组用于IDT初始化

// 使用宏生成256个handler入口声明和指针列表
// 例如：test_case_handler_0, test_case_handler_1, ..., test_case_handler_255

#define MULTI_ENTRY_HANDLER_DECLARATIONS_ID(name, id) void name##_##id(void);
#define MULTI_ENTRY_HANDLER_DECLARATIONS(name)                                                     \
    CALL_256_TIMES(MULTI_ENTRY_HANDLER_DECLARATIONS_ID, name)

#define MULTI_ENTRY_HANDLER_LIST_ID(name, id) name##_##id,
#define MULTI_ENTRY_HANDLER_LIST(name)        CALL_256_TIMES(MULTI_ENTRY_HANDLER_LIST_ID, name)

MULTI_ENTRY_HANDLER_DECLARATIONS(test_case_handler);
static void *test_case_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(test_case_handler) NULL,
};

MULTI_ENTRY_HANDLER_DECLARATIONS(bubble_handler);
static void *bubble_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(bubble_handler) NULL,
};

// =================================================================================================
// IDT管理
// =================================================================================================
// 内联汇编实现SIDT/LIDT指令，用于读取和加载IDTR
// 使用mfence确保指令顺序执行，防止IDT切换期间的竞态条件
inline static void native_sidt(void *dtr)
{
    asm volatile("sidt %0\n mfence\n" : "=m"(*((struct desc_ptr *)dtr)));
}

inline static void native_lidt(void *dtr)
{
    asm volatile("lidt %0\n mfence\n" ::"m"(*((struct desc_ptr *)dtr)));
}

// 设置中断门描述符：创建一个64位中断门条目并写入IDT
// DPL=0表示只有内核态可以触发此中断门（防止用户态恶意触发）
static void set_intr_gate_default(gate_desc *idt, int interrupt_id, void *handler)
{
    gate_desc desc = {
        .offset_low = (u16)(unsigned long)handler,
        .segment = __KERNEL_CS,
        .bits = (struct idt_bits){.ist = 0, .zero = 0, .type = GATE_INTERRUPT, .dpl = 0, .p = 1},
        .offset_middle = (u16)((unsigned long)handler >> 16),
        .offset_high = (u32)((unsigned long)handler >> 32),
        .reserved = 0,
    };
    write_idt_entry(idt, interrupt_id, &desc);
}

// 配置自定义IDT：设置256个中断向量对应的处理函数
// 策略：
//   - NMI中断(#2)：使用专用nmi_handler（NMI不能被屏蔽，必须正确处理）
//   - 已处理的异常(0-31)：使用main_handler（通常是fault_handler）
//   - Double Fault(#8)和Machine Check(#18)：使用原始OS处理函数（CPU状态已损坏，不能自定义处理）
//   - 其他所有中断：使用secondary_handlers（通常是bubble_handlers或test_case_handlers）
static void idt_set_custom_handlers(gate_desc *idt, struct desc_ptr *idtr, void *main_handler,
                                    void **secondary_handlers)
{
    for (int idx = 0; idx < 256; idx++) {
        if (idx == X86_TRAP_NMI) {
            set_intr_gate_default(idt, idx, nmi_handler);
            continue;
        }

        if (main_handler != NULL && idx < 32 && BIT_CHECK(handled_faults, idx)) {
            set_intr_gate_default(idt, idx, main_handler);
            continue;
        }

        switch (idx) {
        // if we ever get a machine check exception, the CPU is definitely in a bad state
        // so we should let OS handle it
        case X86_TRAP_DF:
        case X86_TRAP_MC: {
            // case 22 ... 31: {
            gate_desc *org_handler = &((gate_desc *)orig_idtr.address)[idx];
            write_idt_entry(idt, idx, org_handler);
            break;
        }
        default:
            // all other exceptions are dispatched to the secondary handler
            set_intr_gate_default(idt, idx, secondary_handlers[idx]);
            break;
        }
    }
    idtr->address = (unsigned long)idt;
    idtr->size = (sizeof(gate_desc) * 256) - 1;
    native_lidt(idtr);
}

// 设置外层fault handler（bubble IDT）
// 在测试执行框架层面提供异常保护
// bubble_idt不使用main_handler（NULL），所有异常都由bubble_handlers处理
// 这确保即使测试用例的IDT配置有问题，框架层面也能捕获异常
void set_outer_fault_handlers(void)
{
    // 保存原始系统IDT，以便测试结束后恢复
    native_sidt(&orig_idtr);
    // 安装bubble IDT，替换系统IDT
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, NULL, bubble_handlers);
    // 重置嵌套异常标志
    is_nested_fault = 0;
}

// 恢复原始系统IDT
// 测试执行完毕后，将IDT恢复为操作系统原始的IDT
void unset_outer_fault_handlers(void)
{
    if (orig_idtr.address != 0) {
        native_lidt(&orig_idtr); // restore original IDT
    } else {
        PRINT_ERR("unset_outer_fault_handlers: original IDT is not set\n");
    }
}

// 设置内层fault handler（test case IDT）
// 在测试用例层面提供异常捕获
// 使用fault_handler作为main_handler处理已声明的异常
// 其他异常由test_case_handlers处理（记录异常类型等信息）
void set_inner_fault_handlers(void)
{
    idt_set_custom_handlers(test_case_idt, &test_case_idtr, fault_handler, test_case_handlers);
    is_nested_fault = 0;
}

// 恢复bubble IDT（从test_case_idt回到bubble_idt）
// 测试用例执行完毕后，将IDT从内层恢复到外层
void unset_inner_fault_handlers(void)
{
    if (bubble_idtr.address != 0) {
        native_lidt(&bubble_idtr); // restore bubble IDT
    } else {
        PRINT_ERR("unset_inner_fault_handlers: bubble IDT is not set\n");
    }
}

// =================================================================================================
// 初始化fault handler模块
// 分配两个IDT表（256个gate_desc条目），设置默认fault_handler
int init_fault_handler(void)
{
    // 默认fault handler指向test_case_handler（通用异常处理入口）
    fault_handler = (void *)test_case_handler;

    // 分配bubble IDT（外层，用于框架保护）
    bubble_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    // 分配test case IDT（内层，用于测试用例异常捕获）
    test_case_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    test_case_idtr.address = (unsigned long)test_case_idt;
    return 0;
}

void free_fault_handler(void)
{
    SAFE_FREE(bubble_idt);
    SAFE_FREE(test_case_idt);
}

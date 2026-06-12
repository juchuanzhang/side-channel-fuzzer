/// File:
///  - Parsing inputs and test cases
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "actor.h"
#include "data_loader.h"
#include "input_parser.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

/// @brief 此函数的双重作用：
/// 1. 用当前输入数据初始化沙箱的数据区
/// 2. 通过直接初始化（而非memset）间接设置部分内存缓冲区的微架构状态（如存储缓冲区），
///    从而减少测量的非确定性
/// 注意：故意避免使用memset，因为直接初始化更有效地训练微架构状态
/// @param input_id 输入数据的编号
/// @return 0表示成功
int load_sandbox_data(int input_id)
{
    // 注意：此函数有意避免使用memset（少数例外），
    // 因为我们发现直接初始化更有效地训练微架构状态

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_data_t *dest = &sandbox->data[actor_id];
        input_fragment_t *source = get_input_fragment_unsafe(input_id, actor_id);

        // 清零沙箱数据区周围的保护区域
        // underflow_pad和overflow_pad防止越界访问影响测量
        if (!quick_and_dirty_mode) {
            memset(&dest->underflow_pad[0], 0, UNDERFLOW_PAD_SIZE * sizeof(char));
            for (int j = 0; j < OVERFLOW_PAD_SIZE / 8; j += 1) {
                ((uint64_t *)dest->overflow_pad)[j] = 0;
            }
        }

        // 初始化main_area：将输入数据逐8字节复制到沙箱main_area
        // main_area是测试用例的主要数据访问区域
        uint64_t *main_src = (uint64_t *)source->main_area;
        uint64_t *main_dest = (uint64_t *)dest->main_area;
        for (int j = 0; j < MAIN_AREA_SIZE / 8; j += 1) {
            main_dest[j] = main_src[j];
        }

        // 初始化faulty_area：将输入数据复制到沙箱faulty_area
        // faulty_area用于测试页错误(page fault)相关的侧信道漏洞
        // 其PTE权限可以被动态修改，触发页面访问违规
        uint64_t *faulty_src = (uint64_t *)source->faulty_area;
        uint64_t *faulty_dest = (uint64_t *)dest->faulty_area;
        for (int j = 0; j < FAULTY_AREA_SIZE / 8; j += 1) {
            faulty_dest[j] = faulty_src[j];
        }

        // 初始化寄存器初始值区域
        // 这些值将在代码加载模板(code_loader template)中被加载到CPU寄存器
        uint64_t *reg_src = (uint64_t *)source->reg_init_region;
        uint64_t *reg_dest = (uint64_t *)dest->reg_init_area;
        for (int j = 0; j < REG_INIT_AREA_SIZE / 8; j += 1) {
            reg_dest[j] = reg_src[j];
        }

        // 确保标志寄存器(EFLAGS)的值合法
        // 只保留允许的标志位，并确保bit 1(必须为1)被设置
#if defined(ARCH_X86_64)
        // x86_64: 2263 = 0x8D7 = 允许的EFLAGS位掩码，bit 1始终为1(保留位)
        reg_dest[6] = (reg_src[6] & 2263) | 2;
#elif defined(ARCH_ARM)
        // ARM: 只保留NZCV标志位(高4位)，左移到PSTATE位置
        reg_dest[6] = (reg_src[6] << 28);
#endif

        // 注意：RSP和RBP不从输入数据取值，
        // 而是在模板中设置为栈基址(macro_stack的顶部)
    }

#if defined(ARCH_X86_64)
    // 初始化SIMD寄存器（MMX和YMM/AVX）
    // 注意：通用寄存器(GPR)由测试用例模板直接初始化，见code_loader.c
    // MMX和YMM的初始化数据有重叠，这是有意为之
    uint64_t *simd_src = (uint64_t *)&get_input_fragment_unsafe(input_id, 0)->reg_init_region[64];
    asm volatile(""
                 "movq 0x00(%0), %%mm0\n"
                 "movq 0x08(%0), %%mm1\n"
                 "movq 0x10(%0), %%mm2\n"
                 "movq 0x18(%0), %%mm3\n"
                 "movq 0x20(%0), %%mm4\n"
                 "movq 0x28(%0), %%mm5\n"
                 "movq 0x30(%0), %%mm6\n"
                 "movq 0x38(%0), %%mm7\n"
                 // MMX和YMM初始化值的重叠是有意设计的
                 "vmovdqa 0x00(%0), %%ymm0\n"
                 "vmovdqa 0x20(%0), %%ymm1\n"
                 "vmovdqa 0x40(%0), %%ymm2\n"
                 "vmovdqa 0x60(%0), %%ymm3\n"
                 "vmovdqa 0x80(%0), %%ymm4\n"
                 "vmovdqa 0xa0(%0), %%ymm5\n"
                 "vmovdqa 0xc0(%0), %%ymm6\n"
                 "vmovdqa 0xe0(%0), %%ymm7\n" ::"r"(&simd_src[0]));
#endif

    return 0;
}

// =================================================================================================
int init_data_loader(void) { return 0; }

void free_data_loader(void) {}

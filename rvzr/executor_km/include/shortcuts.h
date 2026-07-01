/// File: Header for common macros
///
// ==============================================================================
// 公共宏头文件概述：
// 本文件定义了侧信道模糊测试框架中使用的通用宏和内联函数，
// 包括字符串处理、汇编嵌入、MSR访问、位操作、日志记录、错误处理、
// 内存管理和地址翻译等工具。
//
// 关键功能分类：
//   1. 字符串与汇编宏：STRINGIFY, asm_volatile_intel等
//   2. MSR访问宏：wrmsr64/rdmsr64(x86), write_msr/read_msr(ARM64)
//      直接读写MSR用于配置PMU、虚拟化控制、缓存属性等
//   3. 位操作宏：BIT_——构造单比特掩码，用于设置/清除寄存器位
//   4. 日志与错误处理：PRINT_ERR, ASSERT, CHECK_ERR等
//      所有日志输出带有[rvzr_executor]前缀，便于内核日志过滤
//   5. 内存管理：CHECKED_MALLOC, SAFE_FREE等
//      自动检查分配失败和释放空指针，简化内核内存管理代码
//   6. 地址翻译：vmalloc_to_phys, native_page_invalidate
//      vmalloc地址→物理地址翻译和TLB无效化，用于EPT/NPT页表配置
//
// 注意：本文件包含内核版本兼容性处理（如6.16+的wrmsr签名变更）。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef KM_SHORTCUTS_H
#define KM_SHORTCUTS_H

#include "hardware_desc.h"
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>    // kfree, kmalloc
#include <linux/vmalloc.h> // vfree, vmalloc

#ifdef ARCH_X86_64
#include <../arch/x86/include/asm/desc.h>
#endif

// =================================================================================================
// 字符串与汇编宏
// =================================================================================================
/// 字符串化宏——将宏参数转换为字符串字面量
/// STRINGIFY(...)直接字符串化，xstr(s)先展开宏再字符串化
#define STRINGIFY(...) #__VA_ARGS__

/// 二级字符串化宏——先展开s中的宏，再转换为字符串
#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s)  #s

/// Intel语法内联汇编宏——在GCC的AT&T语法环境中嵌入Intel语法汇编
/// 先切换到Intel语法(.intel_syntax noprefix)，执行ASM代码，
/// 再切换回AT&T语法(.att_syntax noprefix)
/// 用于侧信道测试的汇编原语（Prime, Probe, Flush等）
// clang-format off
#define asm_volatile_intel(ASM)                                                                    \
    asm volatile("\n.intel_syntax noprefix\n"                                                      \
                    ASM                                                                            \
                 ".att_syntax noprefix\n")
// clang-format on

// =================================================================================================
// MSR访问宏——直接读写CPU模型特定寄存器
// =================================================================================================
#ifdef ARCH_X86_64
/// x86_64 MSR写入宏——写入64位值到指定MSR
/// 内核6.16+改变了native_write_msr的签名：从(msr, low, high)变为(msr, val)
/// 此宏自动适配不同内核版本的API
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define wrmsr64(msr, value) native_write_msr(msr, value)
#else
#define wrmsr64(msr, value) native_write_msr(msr, (uint32_t)(value), (uint32_t)((value) >> 32))
#endif
/// x86_64 MSR读取宏——从指定MSR读取64位值
#define rdmsr64(msr) native_read_msr(msr)
#elif defined(ARCH_ARM)
/// ARM64 MSR写入宏——通过内联汇编写入系统寄存器
/// NAME为系统寄存器名称字符串（如"HCR_EL2"），VALUE为要写入的值
/// 写入后执行isb指令确保后续指令使用新的寄存器值
#define write_msr(NAME, VALUE) asm volatile("msr " NAME ", %0\n isb\n" ::"r"(VALUE));
/// ARM64 MSR读取宏——通过内联汇编从系统寄存器读取值
/// NAME为系统寄存器名称字符串，VAR为存储读取值的变量
/// 读取前执行isb指令确保所有之前的系统寄存器写入已完成
#define read_msr(NAME, VAR)    asm volatile("mrs %0, " NAME "\n isb\n" : "=r"(VAR));
#endif

// =================================================================================================
// 位操作宏
// =================================================================================================
/// 单比特掩码构造宏——生成第x位的1掩码
/// 例如：BIT_(0) = 1, BIT_(3) = 8, BIT_(63) = 0x8000000000000000
/// 常用于设置/清除MSR和控制寄存器的特定位
#define BIT_(x) (1ULL << (x))

// =================================================================================================
// 日志与错误处理宏——所有日志带有[rvzr_executor]前缀
// =================================================================================================
/// 错误日志宏——输出KERN_ERR级别的日志
/// 前缀为[rvzr_executor]，便于在内核日志中过滤执行器消息
#define PRINT_ERR(msg, ...)                                                                        \
    do {                                                                                           \
        printk(KERN_ERR "[rvzr_executor] " msg, ##__VA_ARGS__);                                    \
    } while (0)
/// 带源标识的错误日志宏——前缀包含源文件标识(src)
/// 例如：PRINT_ERRS("vmx", "...") 输出 [rvzr_executor:vmx] ...
#define PRINT_ERRS(src, msg, ...)                                                                  \
    do {                                                                                           \
        printk(KERN_ERR "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);                            \
    } while (0)

/// 警告日志宏——输出KERN_WARNING级别的日志
#define PRINT_WARN(msg, ...) printk(KERN_WARNING "[rvzr_executor] " msg, ##__VA_ARGS__);
/// 带源标识的警告日志宏
#define PRINT_WARNS(src, msg, ...)                                                                 \
    printk(KERN_WARNING "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);

/// 断言宏——条件不满足时输出错误日志并返回-EIO
/// 用于检查内核操作的关键条件（如分配成功、配置有效等）
#define ASSERT(condition, src)                                                                     \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) "\n");                                \
        return -EIO;                                                                               \
    }

/// 带消息的断言宏——条件不满足时输出错误日志+附加消息并返回-EIO
#define ASSERT_MSG(condition, src, msg, ...)                                                       \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) ";\n" msg, ##__VA_ARGS__);            \
        return -EIO;                                                                               \
    }

/// 返回NULL的断言宏——条件不满足时输出错误日志并返回NULL
/// 用于需要返回指针的函数中的错误检查
#define ASSERT_ENULL(condition, src)                                                               \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) "\n");                                \
        return NULL;                                                                               \
    }

/// 带消息返回NULL的断言宏
#define ASSERT_MSG_ENULL(condition, src, ...)                                                      \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) ";" msg, ##__VA_ARGS__);              \
        return NULL;                                                                               \
    }

/// 错误检查宏——检查err变量，非零时输出错误消息并返回-EIO
#define CHECK_ERR(msg)                                                                             \
    if (err) {                                                                                     \
        PRINT_ERR(" Error [" msg "]\n");                                                           \
        return -EIO;                                                                               \
    }

/// 未实现宏——标记未实现的函数，输出错误日志并返回-ENOSYS
#define UNIMPLEMENTED(src)                                                                         \
    PRINT_ERRS(src, "Unimplemented\n");                                                            \
    return -ENOSYS;

// =================================================================================================
// 内存管理宏——自动检查分配失败和安全释放
// =================================================================================================
// NOLINTBEGIN(bugprone-macro-parentheses)

/// 检查式kmalloc——分配内存，失败时输出错误并返回-ENOMEM
/// 使用GCC语句表达式({...})使宏可以作为表达式使用
#define CHECKED_MALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kmalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })
/// 检查式kzalloc——分配并清零内存，失败时输出错误并返回-ENOMEM
#define CHECKED_ZALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kzalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error zero-allocating memory\n");                                          \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })
/// 安全释放宏——释放kmalloc分配的内存并置NULL指针
/// 检查指针非空后再释放，避免kfree(NULL)的冗余调用
#define SAFE_FREE(x)                                                                               \
    if (x) {                                                                                       \
        kfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

/// 检查式vmalloc——分配虚拟连续内存，失败时输出错误并返回-ENOMEM
/// vmalloc分配的内存虚拟连续但物理可能不连续
#define CHECKED_VMALLOC(x)                                                                         \
    ({                                                                                             \
        void *ptr = vmalloc(x);                                                                    \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })
/// 安全vfree宏——释放vmalloc分配的内存并置NULL指针
#define SAFE_VFREE(x)                                                                              \
    if (x) {                                                                                       \
        vfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

/// 检查式页分配——分配物理连续的内存页，失败时输出错误并返回-ENOMEM
/// alloc_pages分配的内存物理连续，对缓存行为一致性至关重要
#define CHECKED_ALLOC_PAGES(size)                                                                  \
    ({                                                                                             \
        struct page *ptr = alloc_pages(GFP_KERNEL, get_order(size));                               \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating pages\n");                                                \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })

/// 安全释放页宏——释放alloc_pages分配的内存页并置NULL指针
#define SAFE_PAGES_FREE(x, size)                                                                   \
    if (x) {                                                                                       \
        __free_pages(x, get_order(size));                                                          \
        x = NULL;                                                                                  \
    }

// NOLINTEND(bugprone-macro-parentheses)

// =================================================================================================
// 调用序列宏——重复调用宏16次或256次
// =================================================================================================
/// 调用16次宏——将macro(arg, id0)到macro(arg, idf)展开为16次调用
/// 用于Prime+Probe中填充所有16个缓存行（8-way缓存需要8次，16次覆盖2个缓存集）
#define CALL_16_TIMES(macro, arg, id)                                                              \
    macro(arg, id##0) macro(arg, id##1) macro(arg, id##2) macro(arg, id##3) macro(arg, id##4)      \
        macro(arg, id##5) macro(arg, id##6) macro(arg, id##7) macro(arg, id##8) macro(arg, id##9)  \
            macro(arg, id##a) macro(arg, id##b) macro(arg, id##c) macro(arg, id##d)                \
                macro(arg, id##e) macro(arg, id##f)
/// 调用256次宏——将macro(arg, 0x00)到macro(arg, 0xff)展开为256次调用
/// 用于填充完整的256个缓存集（4KB/way × 8-way = 32KB L1D缓存）
#define CALL_256_TIMES(macro, arg)                                                                 \
    CALL_16_TIMES(macro, arg, 0)                                                                   \
    CALL_16_TIMES(macro, arg, 1)                                                                   \
    CALL_16_TIMES(macro, arg, 2)                                                                   \
    CALL_16_TIMES(macro, arg, 3)                                                                   \
    CALL_16_TIMES(macro, arg, 4)                                                                   \
    CALL_16_TIMES(macro, arg, 5)                                                                   \
    CALL_16_TIMES(macro, arg, 6)                                                                   \
    CALL_16_TIMES(macro, arg, 7)                                                                   \
    CALL_16_TIMES(macro, arg, 8)                                                                   \
    CALL_16_TIMES(macro, arg, 9)                                                                   \
    CALL_16_TIMES(macro, arg, a)                                                                   \
    CALL_16_TIMES(macro, arg, b)                                                                   \
    CALL_16_TIMES(macro, arg, c)                                                                   \
    CALL_16_TIMES(macro, arg, d)                                                                   \
    CALL_16_TIMES(macro, arg, e)                                                                   \
    CALL_16_TIMES(macro, arg, f)

// =================================================================================================
// 地址翻译函数——vmalloc地址→物理地址和TLB无效化
// =================================================================================================

/// vmalloc虚拟地址→物理地址翻译
/// vmalloc分配的内存需要先通过vmalloc_to_page找到对应的struct page，
/// 再通过page_to_phys获取物理地址
/// 用于配置EPT/NPT/Stage-2页表——这些页表需要物理地址而非虚拟地址
static inline uint64_t vmalloc_to_phys(void *hva)
{
    struct page *page = vmalloc_to_page(hva);
    if (!page)
        return 0;
    uint64_t hpa = page_to_phys(page);
    return hpa;
}

/// 本地页无效化——冲刷指定虚拟地址的TLB条目
/// x86_64使用invlpg指令，ARM64使用tlbi vale1is指令+dsb屏障
/// 用于修改PTE权限后刷新TLB，确保CPU使用新的页表配置
/// 必须在修改PTE后调用，否则CPU可能继续使用旧的TLB缓存
static inline void native_page_invalidate(uint64_t hva)
{
#ifdef ARCH_X86_64
    asm volatile("invlpg (%0)" ::"r"(hva) : "memory");
#elif defined(ARCH_ARM)
    hva >>= 12;
    hva &= 0xfffffffffffULL;
    asm volatile("dsb ishst\n tlbi vale1is, %0\n dsb ish\n" ::"r"(hva) : "memory");
#endif
}

#endif // KM_SHORTCUTS_H

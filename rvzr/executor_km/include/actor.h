/// File: Header describing actor metadata
///
// ==============================================================================
// Actor元数据头文件概述：
// 本文件定义了侧信道模糊测试中"Actor"（执行主体）的元数据结构，
// 是论文"Enter, Exit, Page Fault, Leak"中多Actor模型的基础。
//
// Actor是测试用例中的独立执行主体，可以运行在不同的特权级和执行模式下：
//   - Host模式（宿主机/内核态）vs Guest模式（虚拟机/客户机态）
//   - Kernel特权级（内核态）vs User特权级（用户态）
//
// 多Actor设计使得测试用例可以模拟跨特权级的交互场景，
// 例如：Meltdown（User→Kernel）、Spectre-V2（Guest→Host）等侧信道攻击。
//
// 关键数据结构：
//   - actor_metadata_t：描述单个Actor的ID、模式、特权级和内存权限配置
//   - actors数组：存储所有Actor的元数据，由test_case_parser填充
//   - n_actors：当前测试用例中的Actor数量
//
// 最大Actor数量限制为16（MAX_ACTORS），与侧信道测试的典型场景匹配。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ACTOR_H_
#define _ACTOR_H_

#include <linux/types.h>

/// 最大Actor数量限制
/// 16个Actor足以覆盖所有典型的侧信道测试场景
/// （例如：2个Host+2个Guest+多个不同特权级组合）
#define MAX_ACTORS 16

/// Actor标识符类型——每个Actor有唯一的ID
typedef uint64_t actor_id_t;
/// Actor执行模式类型——Host或Guest
typedef uint64_t actor_mode_t;
/// Actor特权级类型——Kernel或User
typedef uint64_t actor_pl_t;

/// Actor执行模式枚举
/// MODE_HOST：Actor在宿主机环境下运行（直接在物理CPU上执行）
/// MODE_GUEST：Actor在虚拟机环境下运行（通过VMX/SVM/ARM VM进入guest）
/// Guest模式Actor的代码在虚拟化环境中执行，
/// 其内存访问通过EPT/NPT/Stage-2页表进行翻译和控制
enum {
    MODE_HOST = 0,
    MODE_GUEST = 1,
};

/// Actor特权级枚举
/// PL_KERNEL：Actor在内核特权级运行（x86: Ring0, ARM64: EL1）
/// PL_USER：Actor在用户特权级运行（x86: Ring3, ARM64: EL0）
/// User特权级Actor用于模拟攻击者进程，Kernel特权级Actor用于模拟被攻击的目标
enum {
    PL_KERNEL = 0,
    PL_USER = 1,
};

/// Actor元数据结构体——描述单个执行主体的所有配置信息
/// 每个Actor在测试用例中有独立的代码段、数据段和权限配置。
/// fields说明：
///   - id：Actor的唯一标识符，用于索引sandbox中的数据和代码区域
///   - mode：执行模式（Host/Guest），决定是否需要虚拟化进入/退出
///   - pl：特权级（Kernel/User），决定页表权限和可访问的资源
///   - data_permissions：数据区域的PTE/EPT权限位（如Present、RW、User等）
///   - data_ept_properties：数据区域的EPT扩展属性（如内存类型、抑制VE等）
///   - code_permissions：代码区域的PTE/EPT权限位
typedef struct {
    actor_id_t id;                  // Actor唯一标识符
    actor_mode_t mode;              // 执行模式：Host或Guest
    actor_pl_t pl;                  // 特权级：Kernel或User
    uint64_t data_permissions;      // 数据区域的页表权限配置
    uint64_t data_ept_properties;   // 数据区域的EPT扩展属性配置
    uint64_t code_permissions;      // 代码区域的页表权限配置
} actor_metadata_t;

/// 当前测试用例中的Actor数量
/// 由test_case_parser从输入中解析并填充
extern size_t n_actors;

/// Actor元数据数组——存储所有Actor的配置信息
/// 数组索引对应actor_id，每个元素描述一个Actor的完整配置
extern actor_metadata_t *actors;

#endif // _ACTOR_H_

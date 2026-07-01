/// File: Header for page table functions
///
// ==============================================================================
// 宿主机页表管理头文件概述：
// 本文件定义了宿主机(host)侧页表的管理接口，控制沙箱内存区域的访问权限。
//
// 宿主机页表管理的核心功能：
//   1. 缓存沙箱页表的PTE指针(sandbox_pteps)——避免每次测试都遍历四级页表
//      PTE指针缓存使得SET_DATA_PERMISSIONS宏可以在汇编中直接修改PTE，
//      无需调用C函数遍历页表（遍历页表需要数百个时钟周期，严重影响测量精度）
//
//   2. 保存和恢复原始页表权限——测试前保存，测试后恢复
//      确保每次测试的页表权限配置一致，不受前一次测试影响
//
//   3. 动态修改沙箱页的权限——实现故障注入和侧信道测试的关键配置
//      - 设置faulty_area为用户可访问（Ring3/EL0）：测试Meltdown类越权读取
//      - 恢复faulty_area为内核专有：测试正常情况下的访问控制
//
// sandbox_ptes_t和sandbox_pteps_t分别存储PTE值和PTE指针，
// 每个Actor有独立的数据、代码和工具区域PTE配置。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLE_H_
#define _PAGE_TABLE_H_

#include "page_tables_common.h"
#include <linux/kernel.h>

/// 沙箱PTE值结构体——存储沙箱各区域的PTE内容（用于快速恢复）
/// 每个Actor有三个区域的PTE：数据区、代码区、工具区
typedef struct {
    pte_t_ *data_ptes;  // 数据区域的PTE数组——包含main_area和faulty_area的PTE
    pte_t_ *code_ptes;  // 代码区域的PTE数组——包含测试代码的PTE
    pte_t_ *util_ptes;  // 工具区域的PTE数组——包含测量工具数据(l1d_priming_area等)的PTE
} sandbox_ptes_t;

/// 沙箱PTE指针结构体——缓存各区域PTE的指针地址（用于SET_DATA_PERMISSIONS宏）
/// 在汇编中直接通过这些指针修改PTE，避免C函数调用和页表遍历的开销
typedef struct {
    pte_t_ **data_pteps;  // 数据区域PTE指针数组
    pte_t_ **code_pteps;  // 代码区域PTE指针数组
    pte_t_ **util_pteps;  // 工具区域PTE指针数组
} sandbox_pteps_t;

/// 全局沙箱PTE指针缓存——每个输入/Actor组合对应一组PTE指针
/// 在init阶段通过cache_host_pteps()填充，测试时直接使用
extern sandbox_pteps_t *sandbox_pteps;

/// 获取指定虚拟地址对应的PTE——遍历四级页表找到最后的PTE条目
/// @param hva 虚拟地址
/// @return 指向PTE的指针（内核类型pte_t，非自定义pte_t_）
pte_t *get_pte(uint64_t hva);

/// 缓存沙箱所有区域的宿主机PTE指针——避免测试时遍历页表
/// 为每个Actor的数据、代码、工具区域缓存PTE指针到sandbox_pteps数组
/// @return 0表示成功，负数表示错误码
int cache_host_pteps(void);

/// 保存沙箱区域的原始宿主机页表权限——测试前调用
/// 保存所有沙箱PTE的原始权限位，用于测试后恢复
/// @return 0表示成功，负数表示错误码
int store_orig_host_permissions(void);

/// 恢复沙箱区域的原始宿主机页表权限——测试后调用
/// 将所有沙箱PTE恢复为store_orig_host_permissions保存的原始值
/// @return 0表示成功，负数表示错误码
int restore_orig_host_permissions(void);

/// 设置沙箱数据页为用户可访问——使main_area/faulty_area可在Ring3/EL0访问
/// 用于模拟攻击者进程在低特权级下访问本应受保护的数据
/// @return 0表示成功，负数表示错误码
int set_user_pages(void);

/// 设置faulty_area的宿主机权限为故障触发配置——移除权限位触发页故障
/// Meltdown类测试：移除Present位→触发#PF，但投机执行仍可读取数据
void set_faulty_page_host_permissions(void);

/// 恢复faulty_area的宿主机权限为正常配置——恢复权限位使访问合法
void restore_faulty_page_host_permissions(void);

/// 初始化页表管理器——分配sandbox_ptes和sandbox_pteps数组
/// @return 0表示成功，负数表示错误码
int init_page_table_manager(void);

/// 释放页表管理器分配的所有内存
void free_page_table_manager(void);

#endif // _PAGE_TABLE_H_

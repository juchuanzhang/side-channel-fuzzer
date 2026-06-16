/// File: Header for ARM64 VM (virtualization) management — equivalent to vmx.h and svm.h
///
// ==============================================================================
// ARM64虚拟化管理头文件概述：
// 本文件定义了ARM64架构下虚拟机（VM）管理的核心数据结构和接口函数，
// 是论文"Enter, Exit, Page Fault, Leak"中ARM64平台VM Actor Configuration的基础。
//
// 与x86架构的关键区别：
// - x86使用VMCS（Intel VMX）或VMCB（AMD SVM）这种专用内存结构来管理虚拟机状态，
//   所有配置通过vmwrite/VMCB字段设置。
// - ARM64没有类似的专用内存结构，而是直接使用系统寄存器来管理虚拟化：
//   HCR_EL2控制陷阱(trap)行为，VTTBR_EL2指向Stage-2页表，
//   VBAR_EL2指向guest异常向量表，SPSR_EL2/ELR_EL2控制guest入口点。
// - x86的VM进入通过VMLAUNCH/VMRUN指令，ARM64通过eret指令从EL2返回EL1。
// - x86的VM退出由VMCS/VMCB控制位触发，ARM64由HCR_EL2陷阱位触发。
//
// 本文件定义的vm_t结构体保存了所有需要配置的EL2系统寄存器值，
// 相当于x86中VMCS/VMCB的角色——在VM操作前将这些值写入对应的系统寄存器，
// 在VM操作后恢复原始值。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_VM_H_
#define _RVZR_EXECUTOR_VM_H_

#include <linux/types.h>

#include "vm_constants.h"

// =================================================================================================
// ARM64 VM状态结构体
// ==============================================================================
// vm_state_t：保存ARM64虚拟化所需的全部EL2系统寄存器配置
//
// 在x86中，VMCS/VMCB是专用的内存结构，包含了guest/host状态和控制字段。
// ARM64没有这种结构，虚拟化配置直接通过系统寄存器完成。
// vm_state_t的作用是保存这些系统寄存器的"目标值"，在启动VM操作时
// 将这些值写入对应的系统寄存器，在停止VM操作时恢复原始值。
//
// 各字段说明：
// - hcr_el2: Hypervisor Configuration Register，控制哪些操作会触发陷阱到EL2
//   相当于x86 VMCS的执行控制字段(VM-Execution Controls)
// - vttbr_el2: Virtualization Translation Table Base Register，指向Stage-2页表
//   相当于x86 VMCS的EPT_POINTER或VMCB的nested_cr3
// - vbar_el2: Vector Base Address Register (EL2)，指向EL2异常向量表
//   当guest触发陷阱时，CPU跳转到此地址处理异常
// - spsr_el2: Saved Program Status Register (EL2)，保存guest的PSTATE
//   用于eret时恢复guest的处理器状态（特权级、中断屏蔽等）
// - elr_el2: Exception Link Register (EL2)，保存guest的入口点地址
//   eret指令从EL2返回EL1时，CPU跳转到此地址开始执行guest代码
// - far_el2: Fault Address Register (EL2)，记录触发异常的虚拟地址
//   相当于x86 VM退出时的GUEST_LINEAR_ADDRESS
// - esr_el2: Exception Syndrome Register (EL2)，记录异常的原因和类型
//   相当于x86 VM退出时的VM_EXIT_REASON + EXIT_QUALIFICATION
// - mair_el2: Memory Attribute Indirection Register (EL2)
//   定义Stage-2页表中可用的内存属性（如Cacheable、Device等）
// - tcr_el2: Translation Control Register (EL2)
//   控制Stage-2页表的翻译参数（如物理地址宽度、granule大小等）
// - sctlr_el1: System Control Register (EL1)，guest的系统控制寄存器
//   控制guest的MMU、缓存、对齐检查等（在eret前通过SPSR_EL2间接配置）
// - vmpidr_el2: Virtualized Multiprocessor ID Register
//   guest看到的CPU标识符，用于多核虚拟化
// - csselr_el1: Cache Size Selection Register (EL1)
//   选择要访问的缓存级别，用于缓存大小查询
typedef struct {
    uint64_t hcr_el2;        // 虚拟化配置寄存器——控制哪些操作陷阱到EL2
    uint64_t vttbr_el2;      // Stage-2页表基址寄存器——指向guest的嵌套页表
    uint64_t vbar_el2;       // EL2异常向量表基址——guest异常处理入口
    uint64_t spsr_el2;       // 保存的程序状态寄存器——guest的PSTATE
    uint64_t elr_el2;        // 异常链接寄存器——guest代码入口点
    uint64_t far_el2;        // 故障地址寄存器——触发异常的地址
    uint64_t esr_el2;        // 异常综合征寄存器——异常原因和类型
    uint64_t mair_el2;       // 内存属性间接寄存器——Stage-2内存属性定义
    uint64_t tcr_el2;        // 翻译控制寄存器——Stage-2翻译参数
    uint64_t sctlr_el1;      // 系统控制寄存器(EL1)——guest的MMU/缓存控制
    uint64_t vmpidr_el2;     // 虚拟化多处理器ID寄存器——guest看到的CPU ID
    uint64_t csselr_el1;     // 缓存大小选择寄存器——选择缓存级别
} vm_state_t;

// =================================================================================================
// VTTBR_EL2结构体——Stage-2页表基址寄存器的位域分解
// ==============================================================================
// VTTBR_EL2是ARM64 Stage-2翻译的页表基址寄存器，类似于x86的EPTP或VMCB的nested_cr3。
// 它指向Stage-2页表的L0/L1层（取决于物理地址宽度配置）。
//
// 位域说明：
// - ASID[63:48]: Address Space Identifier，16位，区分不同guest的TLB条目
//   类似于x86 SVM的ASID字段，用于TLB标签
// - BADDR[47:1]: 页表基址，指向Stage-2页表的物理地址，必须对齐到页表granule大小
//   类似于x86 EPTP的物理页帧号
// - Cn[0]: 末位，必须为0（页表基址必须2字节对齐）
typedef struct {
    uint64_t asid : 16;  // 地址空间标识符——TLB标签，区分不同guest的翻译
    uint64_t baddr : 47; // 页表基址物理地址——指向Stage-2页表根页
    uint64_t cn : 1;     // 末位，必须为0——页表基址对齐要求
} __attribute__((packed)) vttbr_el2_t;

// =================================================================================================
// 模块接口——全局变量和函数声明
// ==============================================================================

// vm_is_on：全局标志，标记VM操作是否已启动
// 类似于x86的vmx_is_on/svm_is_on，为true表示当前正在运行guest actor
extern bool vm_is_on;

// vm_states：每个guest actor对应的VM状态数组
// 数组索引为actor_id，每个元素保存了该actor需要配置的EL2系统寄存器值
// 在set_vm_state()中为每个guest actor填充此数组，
// 在start_vm_operation()中将这些值写入对应的系统寄存器
extern vm_state_t *vm_states;

// vttbr_hpas：每个guest actor对应的Stage-2页表物理地址数组
// 数组索引为actor_id，每个元素保存了该actor的Stage-2页表根页的物理地址
// 在set_vm_state()中设置，用于配置VTTBR_EL2的BADDR字段
// 类似于x86的vmcs_hpas（VMCS物理地址数组）或vmcb_hpas（VMCB物理地址数组）
extern uint64_t *vttbr_hpas;

// =================================================================================================
// 函数接口——与vmx.h/svm.h对应的ARM64虚拟化管理函数
// ==============================================================================

// vm_check_cpu_compatibility：检查CPU是否支持ARM64虚拟化所需的特性
// 类似于vmx_check_cpu_compatibility()/svm_check_cpu_compatibility()
// 验证项目：
// - 当前异常级别（必须为EL2或在KVM框架下可访问EL2寄存器）
// - HCR_EL2支持的陷阱位（如VM位、WFI陷阱位等）
// - 物理地址宽度（ID_AA64MMFR0_EL1.PARange）
// - Stage-2翻译支持（ID_AA64MMFR0_EL1.S2PS）
// - VHE(虚拟化主机扩展)是否可用
int vm_check_cpu_compatibility(void);

// start_vm_operation：启动VM操作，保存原始EL2寄存器并配置虚拟化环境
// 类似于start_vmx_operation()/start_svm_operation()
// 流程：
// 1. 保存原始EL2系统寄存器值（store_orig_vm_state已提前调用）
// 2. 设置HCR_EL2为虚拟化配置（启用VM位和所需陷阱位）
// 3. 配置VBAR_EL2指向guest异常向量表
// 4. 配置MAIR_EL2/TCR_EL2等Stage-2翻译相关寄存器
int start_vm_operation(void);

// stop_vm_operation：停止VM操作，恢复原始EL2寄存器值
// 类似于stop_vmx_operation()/stop_svm_operation()
// 此函数可在异常处理程序中使用，不会失败
// 流程：将所有EL2系统寄存器恢复为store_orig_vm_state保存的原始值
void stop_vm_operation(void);

// store_orig_vm_state：保存原始EL2系统寄存器状态
// 类似于store_orig_vmcs_state()/store_orig_vmcb_state()
// 在fuzzer启动前保存宿主机的EL2寄存器值，用于fuzzer退出时恢复
int store_orig_vm_state(void);

// restore_orig_vm_state：恢复原始EL2系统寄存器状态
// 类似于restore_orig_vmcs_state()/restore_orig_vmcb_state()
// 此函数可在异常处理程序中使用，仅在出错时打印警告
void restore_orig_vm_state(void);

// set_vm_state：为所有guest actor配置VM状态——VM Actor Configuration的核心入口
// 类似于set_vmcs_state()/set_vmcb_state()
// 流程：为每个guest actor填充vm_states数组：
// - 配置HCR_EL2陷阱位（控制哪些操作触发VM退出）
// - 配置VTTBR_EL2（指向该actor的Stage-2页表物理地址）
// - 配置VBAR_EL2（指向guest异常向量表）
// - 配置SPSR_EL2/ELR_EL2（guest入口点和处理器状态）
int set_vm_state(void);

// print_vm_exit_info：打印VM退出事件的详细信息
// 类似于print_vmx_exit_info()/print_svm_exit_info()
// 解码ESR_EL2中的异常原因（EC类码和ISS具体信息）
int print_vm_exit_info(void);

// init_vm：VM模块初始化——分配vm_states和vttbr_hpas数组
// 类似于init_vmx()/init_svm()
int init_vm(void);

// free_vm：释放VM模块分配的所有内存
// 类似于free_vmx()/free_svm()
void free_vm(void);

#endif // _RVZR_EXECUTOR_VM_H_

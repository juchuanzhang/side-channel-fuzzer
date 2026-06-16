/// 文件：ARM64架构下的异常处理与向量表管理
///
/// 本文件实现了ARM64（AArch64）架构上完整的跨域异常处理机制，支持以下三类异常场景：
///   1. EL0→EL1 异常处理（K2U/U2K测试）：用户态(EL0)触发SVC、数据异常等，
///      通过VBAR_EL1向量表路由到本模块的handler
///   2. EL1→EL2 异常处理（H2G/G2H测试）：客户机VM(EL1)触发HVC、数据异常等，
///      通过VBAR_EL2向量表路由到本模块的handler
///   3. ESR异常类别(EC)过滤：使用ESR_EL1.EC或ESR_EL2.EC字段进行异常分类，
///      通过位掩码(handled_faults)过滤需要处理的异常类型
///
/// ARM64异常等级(Exception Level)架构：
///   EL0 - 用户态应用（最低特权级，无法访问大部分系统资源）
///   EL1 - 操作系统内核（Linux内核运行于此级别，管理进程调度、内存映射等）
///   EL2 - 虚拟化管理层(Hypervisor)（负责VM创建、切换、陷入/陷出管理）
///   EL3 - 安全监控层(Secure Monitor)（TrustZone安全世界切换，最高特权级）
///
/// 异常路由规则：
///   EL0的异常 → 路由到EL1处理（通过VBAR_EL1向量表）
///   EL1的异常 → 路由到EL2处理（通过VBAR_EL2向量表，用于虚拟化场景）
///   EL2的异常 → 路由到EL3处理（通过VBAR_EL3向量表，用于安全世界切换）
///
/// Copyright (C) Microsoft Corporation
/// SPDX-License-Identifier: MIT

#include <linux/interrupt.h>

#include "code_loader.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"

// =================================================================================================
// ARM64 ESR异常类别(Exception Class)定义
// =================================================================================================
// ESR_EL1和ESR_EL2寄存器的[31:26]位（即EC字段）用于标识异常的类型。
// 每种异常类型对应一个唯一的EC值，用于异常分类和过滤。
// EC值是6位宽，范围0x00~0x3F，实际使用的值见下表。
//
// 异常类别与特权级关系：
//   - SVC64(0x15): EL0→EL1的同步异常，用户态通过SVC指令请求内核服务
//   - HVC64(0x16): EL1→EL2的同步异常，客户机内核通过HVC指令请求Hypervisor服务
//   - SMC64(0x17): EL1→EL3(或EL2→EL3)的同步异常，请求安全监控服务
//   - MRS/MSR(0x18): 系统寄存器访问陷阱，当非特权级尝试访问受限系统寄存器时触发
//   - IABORT_EL1(0x20): 来自低特权级的指令异常（如EL0执行非法指令）
//   - IABORT_CUR(0x21): 当前特权级的指令异常（如EL1自身执行非法指令）
//   - DABORT_EL1(0x24): 来自低特权级的数据异常（如EL0访问无效内存地址）
//   - DABORT_CUR(0x25): 当前特权级的数据异常（如EL1自身访问无效内存地址）
//   - PCALIGN(0x22): PC对齐异常，程序计数器未对齐到4字节边界
//   - SPALIGN(0x26): SP对齐异常，栈指针未对齐到16字节边界
//   - FP(0x28): 浮点异常，浮点运算产生异常结果
//   - SERROR(0x2F): 系统错误中断(SError)，异步的硬件错误信号

// EC值定义 - 用于异常类别标识
#define EC_SVC64        0x15    // SVC指令异常（AArch64，EL0→EL1）
#define EC_HVC64        0x16    // HVC指令异常（AArch64，EL1→EL2）
#define EC_SMC64        0x17    // SMC指令异常（AArch64，EL1/EL2→EL3）
#define EC_MRS_MSR      0x18    // MRS/MSR系统寄存器访问陷阱
#define EC_AA64_IABORT_EL1  0x20    // 指令异常 - 来自低特权级（EL0→EL1）
#define EC_AA64_PCALIGN     0x22    // PC对齐异常
#define EC_AA64_IABORT_CUR  0x21    // 指令异常 - 当前特权级（EL1自身）
#define EC_AA64_DABORT_EL1  0x24    // 数据异常 - 来自低特权级（EL0→EL1）
#define EC_AA64_SPALIGN     0x26    // SP对齐异常
#define EC_AA64_DABORT_CUR  0x25    // 数据异常 - 当前特权级（EL1自身）
#define EC_AA64_FP          0x28    // 浮点异常
#define EC_AA64_SERROR      0x2F    // 系统错误中断(SError)

// =================================================================================================
// ARM64向量表数据结构定义
// =================================================================================================
// ARM64向量表结构：
//   - 每个向量表包含16个条目，分为4组，每组4个条目
//   - 每个条目最多容纳32条ARM64指令（每条指令4字节=32位）
//   - 向量表整体大小：16 * 32 * 4 = 2048字节，必须对齐到2048字节边界
//   - VBAR_EL1/VBAR_EL2寄存器指向向量表的基地址
//
// 向量表布局（16个条目分4组）：
//   组0：当前EL使用SP_EL0的异常（EL1t/EL2t模式）
//     [0]  同步异常（Synchronous）
//     [1]  IRQ中断
//     [2]  FIQ中断
//     [3]  SError系统错误
//   组1：当前EL使用SP_ELx的异常（EL1h/EL2h模式）
//     [4]  同步异常
//     [5]  IRQ中断
//     [6]  FIQ中断
//     [7]  SError系统错误
//   组2：来自低特权级使用AArch64的异常（EL0→EL1 / EL1→EL2）
//     [8]  同步异常（SVC/HVC等同步陷入指令在此处理）
//     [9]  IRQ中断
//     [10] FIQ中断
//     [11] SError系统错误
//   组3：来自低特权级使用AArch32的异常（32位兼容模式）
//     [12] 同步异常
//     [13] IRQ中断
//     [14] FIQ中断
//     [15] SError系统错误
//
// 重要说明：
//   - 组2的第[8]条目是EL0→EL1同步异常入口，SVC指令产生的异常路由到此
//   - 对于EL2向量表，组2的第[8]条目是EL1→EL2同步异常入口，HVC指令路由到此
//   - 组3（AArch32）在现代64位系统中通常不使用，标记为不可达

typedef uint32_t opcode_t; // ARM64指令编码为32位固定长度

// 向量表条目：每个条目包含32条指令的空间（32 * 4 = 128字节）
// ARM64向量表条目必须从向量表基地址偏移0x00、0x80、0x100...等128字节对齐位置开始
typedef struct {
    opcode_t code[32];
} __attribute__((packed)) vector_table_entry_t;

// 向量表结构：16个条目组成完整的异常向量表
// 总大小 = 16 * 128 = 2048字节，必须对齐到2048字节边界
typedef struct {
    vector_table_entry_t vector_table[16];
} __attribute__((packed)) vector_table_t;

// =================================================================================================
// 向量表引用声明
// =================================================================================================
// outer_vector_table: 外层向量表，用于保护run_experiment框架本身
//   当run_experiment函数内部发生异常时，跳转到fallback_handler进行恢复
// inner_vector_table: 内层向量表，用于捕获测试用例中的异常
//   当测试用例执行期间发生异常时，跳转到test_case_handler进行处理
// el2_vector_table: EL2级向量表，用于虚拟化场景下的异常处理
//   当客户机VM(EL1)触发HVC、数据异常等时，通过VBAR_EL2路由到此向量表

extern vector_table_t outer_vector_table;
extern vector_table_t inner_vector_table;
extern vector_table_t el2_vector_table;

// =================================================================================================
// 全局变量
// =================================================================================================
// handled_faults: 异常类别(EC)过滤位掩码
//   每一位对应一个ESR_ELx.EC值，若该位为1则表示需要处理该类异常
//   类似于x86 idt.c中的handled_faults，但使用ARM64的EC值而非中断向量号
//   例如：(1 << EC_AA64_DABORT_EL1) 表示处理来自低特权级的数据异常
//   默认值HANDLED_FAULTS_DEFAULT包含必要的异常类型
uint32_t handled_faults = 0;

// fault_handler: 自定义异常处理函数地址
//   当测试用例注册了自定义handler时，异常发生后跳转到此地址
//   若为NULL，则使用默认的test_case_handler
char *fault_handler = NULL;

// is_nested_fault: 嵌套异常标志
//   当异常处理过程中又发生异常时置为1，防止无限递归
//   与exception.S中的代码共享，汇编handler会检查此标志
uint64_t is_nested_fault = 0;

// orig_vector_table_ptr: 保存原始VBAR_EL1向量表指针
//   在set_outer_fault_handlers中保存，在unset_outer_fault_handlers中恢复
vector_table_t *orig_vector_table_ptr = NULL;

// orig_vbar_el2_ptr: 保存原始VBAR_EL2向量表指针
//   在set_el2_fault_handlers中保存，在unset_el2_fault_handlers中恢复
//   仅在虚拟化场景（includes_vm_actors=true）时使用
vector_table_t *orig_vbar_el2_ptr = NULL;

// =================================================================================================
// VBAR_EL1向量表寄存器操作
// =================================================================================================
// VBAR_EL1（Vector Base Address Register for EL1）：
//   指向EL1级异常向量表的基地址。当EL1或EL0发生异常时，
//   CPU根据VBAR_EL1的值找到对应的向量表条目并跳转执行。
//   读写权限：EL1可读写，EL0不可访问。

// 读取VBAR_EL1寄存器值，返回当前向量表指针
static inline vector_table_t *vbar_el1_read(void)
{
    vector_table_t *vbar_el1 = NULL;
    asm volatile("mrs %0, vbar_el1" : "=r"(vbar_el1));
    return vbar_el1;
}

// 写入VBAR_EL1寄存器，设置新的向量表指针
// 参数vbar_el1指向自定义向量表的基地址（必须2048字节对齐）
static inline void vbar_el1_write(vector_table_t *vbar_el1)
{
    asm volatile("msr vbar_el1, %0" ::"r"(vbar_el1));
}

// =================================================================================================
// VBAR_EL2向量表寄存器操作
// =================================================================================================
// VBAR_EL2（Vector Base Address Register for EL2）：
//   指向EL2级异常向量表的基地址。当EL2或EL1发生异常且路由到EL2时，
//   CPU根据VBAR_EL2的值找到对应的向量表条目并跳转执行。
//   在虚拟化场景中，客户机VM(EL1)的异常（HVC、数据异常等）会路由到EL2处理。
//   读写权限：EL2可读写，EL1不可访问（除非HCR_EL2配置了特定路由规则）。

// 读取VBAR_EL2寄存器值，返回当前向量表指针
// 注意：此函数仅在EL2特权级下可执行，在EL1下会产生异常
static inline vector_table_t *vbar_el2_read(void)
{
    vector_table_t *vbar_el2 = NULL;
    asm volatile("mrs %0, vbar_el2" : "=r"(vbar_el2));
    return vbar_el2;
}

// 写入VBAR_EL2寄存器，设置新的向量表指针
// 参数vbar_el2指向自定义向量表的基地址（必须2048字节对齐）
static inline void vbar_el2_write(vector_table_t *vbar_el2)
{
    asm volatile("msr vbar_el2, %0" ::"r"(vbar_el2));
}

// =================================================================================================
// ESR异常类别(EC)匹配函数
// =================================================================================================
// esr_ec_matches_handled_faults：检查给定的ESR异常类别(EC)是否在handled_faults掩码中
//
// 参数说明：
//   esr_value - ESR_EL1或ESR_EL2寄存器的完整值
//               ESR寄存器格式：
//               [31:26] EC   - 异常类别(Exception Class)，6位宽
//               [25]    IL   - 指令长度标志(0=16位, 1=32位)
//               [24:0]  ISS  - 异常特定信息(Exception Specific Information)
//
// 工作原理：
//   1. 从ESR值中提取EC字段：EC = (esr_value >> 26) & 0x3F
//   2. 检查handled_faults位掩码中EC对应位是否为1
//   3. 如果EC对应位为1，说明该异常类型需要被处理
//
// 使用场景：
//   - 在异常handler中判断当前异常是否属于已注册的处理范围
//   - 在SVC/HVC handler中过滤是否需要转发到fault_handler
//   - 类似于x86 idt.c中 BIT_CHECK(handled_faults, idx) 的功能
//     但ARM64使用EC值(6位)而非x86中断向量号(8位)
//
// 示例：
//   esr_ec_matches_handled_faults(esr_el1) 检查ESR_EL1.EC是否在过滤掩码中
//   esr_ec_matches_handled_faults(esr_el2) 检查ESR_EL2.EC是否在过滤掩码中

static inline uint32_t esr_extract_ec(uint64_t esr_value)
{
    // ESR寄存器[31:26]为EC字段，右移26位并掩码6位即可提取
    return (uint32_t)((esr_value >> 26) & 0x3F);
}

bool esr_ec_matches_handled_faults(uint64_t esr_value)
{
    uint32_t ec = esr_extract_ec(esr_value);
    // 检查handled_faults掩码中EC对应位是否置位
    // handled_faults是32位掩码，EC值范围0x00~0x2F，可完全容纳
    return (handled_faults & (1U << ec)) != 0;
}

// =================================================================================================
// 外层向量表管理（EL1级框架保护）
// =================================================================================================
// set_outer_fault_handlers：设置外层向量表（bubble级异常保护）
//   保存原始VBAR_EL1，替换为outer_vector_table
//   outer_vector_table将所有异常路由到fallback_handler，用于保护run_experiment框架
//   执行流程：原始向量表 → outer_vector_table（框架保护）
//
// 调用时机：run_experiment_outer函数开头，在执行run_experiment之前
// 目的：确保run_experiment函数中的任何bug不会导致系统崩溃

void set_outer_fault_handlers(void)
{
    // 保存原始向量表指针，用于后续恢复
    orig_vector_table_ptr = vbar_el1_read();

    // 设置VBAR_EL1指向我们的外层向量表
    // outer_vector_table中所有条目指向fallback_handler
    vbar_el1_write(&outer_vector_table);
}

// unset_outer_fault_handlers：恢复原始向量表
//   将VBAR_EL1恢复为操作系统原始的向量表指针
//   在run_experiment_outer函数结束时调用，无论是正常返回还是异常恢复
void unset_outer_fault_handlers(void)
{
    // 恢复原始向量表，还原操作系统默认的异常处理
    vbar_el1_write(orig_vector_table_ptr);
}

// =================================================================================================
// 内层向量表管理（EL1级测试用例异常捕获）
// =================================================================================================
// set_inner_fault_handlers：设置内层向量表（测试用例级异常捕获）
//   将VBAR_EL1替换为inner_vector_table
//   inner_vector_table将异常路由到test_case_handler或fault_handler
//   执行流程：outer_vector_table → inner_vector_table（测试用例捕获）
//
// 当测试用例中存在VM actor时（includes_vm_actors=true），还需要：
//   - 设置VBAR_EL2指向el2_vector_table，用于捕获客户机VM的异常
//   - 这样EL1→EL2的异常（HVC等）也能被我们的handler捕获
//
// 调用时机：sandbox_manager执行测试用例之前
// 目的：捕获测试用例中的所有异常（Meltdown类漏洞测试等）

void set_inner_fault_handlers(void)
{
    // 重置嵌套异常标志，确保新测试用例开始时标志为0
    is_nested_fault = 0;

    // 设置VBAR_EL1指向内层向量表
    // inner_vector_table中的异常条目指向test_case_handler
    // test_case_handler会检查fault_handler是否注册，优先使用自定义handler
    vbar_el1_write(&inner_vector_table);

    // 如果当前测试用例包含VM actor（虚拟化场景），需要设置EL2向量表
    // 这样客户机VM(EL1)产生的异常（HVC、数据异常等）会路由到我们的EL2 handler
    // 而不是被原始Hypervisor处理，从而实现对跨域异常的完整捕获
    if (test_case && test_case->features.includes_vm_actors) {
        set_el2_fault_handlers();
    }
}

// unset_inner_fault_handlers：从内层向量表恢复到外层向量表
//   将VBAR_EL1恢复为outer_vector_table（从测试用例级回到框架保护级）
//   如果EL2向量表也被设置，则同时恢复VBAR_EL2
//   执行流程：inner_vector_table → outer_vector_table（框架保护）
void unset_inner_fault_handlers(void)
{
    // 恢复EL1向量表到外层（框架保护级）
    vbar_el1_write(&outer_vector_table);

    // 如果EL2向量表被设置，恢复原始VBAR_EL2
    if (test_case && test_case->features.includes_vm_actors) {
        unset_el2_fault_handlers();
    }
}

// =================================================================================================
// EL2向量表管理（虚拟化场景异常处理）
// =================================================================================================
// set_el2_fault_handlers：设置EL2级向量表，用于捕获客户机VM的异常
//
// 在虚拟化场景中，客户机VM运行在EL1，其异常路由规则如下：
//   - SVC指令（EL0→EL1）：留在客户机内部处理，不路由到EL2
//   - HVC指令（EL1→EL2）：路由到EL2的Hypervisor处理
//   - 数据异常（取决于HCR_EL2路由配置）：
//     若HCR_EL2.TSC=1，则EL1的同步异常路由到EL2
//     若HCR_EL2.API=0/APK=0，则MRS/MSR陷阱路由到EL2
//     若HCR_EL2.AMO=1/FMO=1/IMO=1，则SError/FIQ/IRQ路由到EL2
//
// 设置EL2向量表后，这些路由到EL2的异常会被我们的handler捕获，
// 从而实现H2G/G2H测试场景下的完整异常控制。

void set_el2_fault_handlers(void)
{
    // 保存原始VBAR_EL2向量表指针
    // 原始VBAR_EL2通常指向KVM或其他Hypervisor的向量表
    orig_vbar_el2_ptr = vbar_el2_read();

    // 设置VBAR_EL2指向我们的EL2向量表
    // el2_vector_table包含以下handler：
    //   el2_sync_handler     - EL2自身的同步异常处理
    //   el2_lower_sync_handler - 来自EL1的同步异常处理（HVC等）
    //   el2_irq_handler/el2_fiq_handler/el2_serror_handler - 各种中断处理
    vbar_el2_write(&el2_vector_table);
}

// unset_el2_fault_handlers：恢复原始EL2向量表
//   将VBAR_EL2恢复为原始Hypervisor向量表（如KVM的向量表）
//   在测试用例执行结束后调用，确保Hypervisor正常运作
void unset_el2_fault_handlers(void)
{
    // 恢复原始VBAR_EL2向量表
    if (orig_vbar_el2_ptr != NULL) {
        vbar_el2_write(orig_vbar_el2_ptr);
    } else {
        PRINT_ERR("unset_el2_fault_handlers: 原始VBAR_EL2向量表指针为空\n");
    }
}

// =================================================================================================
// 模块初始化与清理
// =================================================================================================
// init_fault_handler：初始化异常处理模块
//   设置默认的handled_faults掩码和fault_handler指针
//   ARM64默认掩码包含：数据异常(来自低特权级)、指令异常、对齐异常等
//   这些是侧信道测试中最常见的异常类型

int init_fault_handler(void)
{
    // 设置默认handled_faults掩码
    // 包含以下关键异常类别（对应ARM64 ESR.EC值）：
    //   EC_AA64_DABORT_EL1 (0x24) - 来自低特权级的数据异常（Meltdown类测试核心异常）
    //   EC_AA64_IABORT_EL1 (0x20) - 来自低特权级的指令异常
    //   EC_AA64_DABORT_CUR (0x25) - 当前特权级的数据异常
    //   EC_AA64_IABORT_CUR (0x21) - 当前特权级的指令异常
    //   EC_SVC64 (0x15)           - SVC指令异常（K2U/U2K测试需要）
    //   EC_HVC64 (0x16)           - HVC指令异常（H2G/G2H测试需要）
    //   EC_AA64_SERROR (0x2F)     - 系统错误中断
    handled_faults = HANDLED_FAULTS_DEFAULT | 
                     (1U << EC_AA64_DABORT_EL1) | 
                     (1U << EC_AA64_IABORT_EL1) |
                     (1U << EC_AA64_DABORT_CUR) | 
                     (1U << EC_AA64_IABORT_CUR) |
                     (1U << EC_SVC64) | 
                     (1U << EC_HVC64) |
                     (1U << EC_AA64_SERROR);

    // 初始化fault_handler为NULL，表示使用默认test_case_handler
    fault_handler = NULL;
    return 0;
}

// free_fault_handler：清理异常处理模块
//   当前ARM64实现不需要额外的清理操作
//   向量表位于汇编代码中（静态分配），无需动态释放
void free_fault_handler(void) {}

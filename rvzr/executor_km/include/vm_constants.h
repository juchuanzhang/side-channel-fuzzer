/// File: Configuration constants for ARM64 VM (virtualization) management
///       — equivalent to vmx_config.h + svm_constants.h
///
// ==============================================================================
// ARM64虚拟化常量定义文件概述：
// 本文件定义了ARM64架构下虚拟化管理所需的所有常量，包括：
// - HCR_EL2（虚拟化配置寄存器）的陷阱位定义
// - VTTBR_EL2（Stage-2页表基址寄存器）的配置常量
// - ESR_EL2（异常综合征寄存器）的解码常量
// - MAIR_EL2（内存属性间接寄存器）的值定义
// - TCR_EL2（翻译控制寄存器）的配置常量
// - Cortex-A72/A76特定的常量定义
//
// 与x86的对应关系：
// - HCR_EL2陷阱位 ↔ VMX执行控制(VM-Execution Controls)或SVM拦截位(intercept bits)
// - VTTBR_EL2 ↔ VMX的EPT_POINTER或SVM的nested_cr3
// - ESR_EL2 ↔ VMX的VM_EXIT_REASON或SVM的exit_code
// - MAIR_EL2 ↔ VMX的PAT MSR或SVM的g_pat
// - TCR_EL2 ↔ VMX的EPTP配置位或SVM的NCTL配置
//
// ARM64虚拟化架构说明：
// ARM64的虚拟化通过EL2（异常级别2，即虚拟化管理器/hypervisor级别）实现。
// 当HCR_EL2.VM=1时，EL1（guest运行级别）的所有内存访问都经过Stage-2翻译，
// 即先通过guest的Stage-1页表将虚拟地址翻译为中间物理地址(IPA)，
// 再通过Stage-2页表将IPA翻译为真实物理地址(PA)。
// 这种两层翻译机制与x86的EPT/NPT完全对应。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_VM_CONSTANTS_H_
#define _RVZR_EXECUTOR_VM_CONSTANTS_H_

// =================================================================================================
// 最大guest数量
// ==============================================================================
// 与x86的VMX_MAX_NUM_GUESTS/SVM_MAX_NUM_GUESTS对应
// 限制为64个guest actor，不要增加此值——需要仔细评估TLB和内存开销
#define VM_MAX_NUM_GUESTS 64

// =================================================================================================
// HCR_EL2陷阱位定义——Hypervisor Configuration Register
// ==============================================================================
// HCR_EL2是ARM64虚拟化的核心控制寄存器，决定哪些操作会从EL1陷阱到EL2。
// 这与x86 VMX的执行控制字段(VM-Execution Controls)和SVM的拦截位(intercept bits)
// 功能完全对应：置1的位表示对应的操作会触发"VM退出"（陷阱到EL2）。
//
// HCR_EL2位域总览（ARM Architecture Reference Manual D24.1.1）：
// 位0-63各控制不同的陷阱行为，以下只列出与fuzzer相关的位。

// ---- 基本虚拟化控制位 ----

// HCR_EL2.VM (bit 1)：虚拟化使能位
// 置1后启用Stage-2地址翻译，EL1的所有内存访问都经过Stage-2页表
// 这是ARM64虚拟化的基础——没有此位，guest的内存访问不受控制
// 相当于x86 VMX的EPT启用(SECONDARY_EXEC_ENABLE_EPT)或SVM的NP启用(SVM_NESTED_CTL_NP_ENABLE)
#define HCR_VM_BIT        (1ULL << 1)

// HCR_EL2.PTW (bit 24)：Page Table Walk陷阱位
// 置1后，Stage-1页表遍历产生的Stage-2访问故障会陷阱到EL2
// 用于检测guest页表遍历中的访问违规
#define HCR_PTW_BIT       (1ULL << 24)

// HCR_EL2.FWB (bit 43)：Force Write-Back位
// 置1后，Stage-2页表中的缓存属性覆盖Stage-1的属性
// 确保host可以强制guest的内存访问使用Write-Back缓存策略
#define HCR_FWB_BIT       (1ULL << 43)

// ---- 指令陷阱位 ----

// HCR_EL2.TWI (bit 13)：Trap WFI指令位
// 置1后，guest执行WFI(Wait For Interrupt)指令时陷阱到EL2
// 类似于x86 VMX的CPU_BASED_HLT_EXITING——防止guest无限等待中断
#define HCR_TRAP_WFI      (1ULL << 13)

// HCR_EL2.TWE (bit 14)：Trap WFE指令位
// 置1后，guest执行WFE(Wait For Event)指令时陷阱到EL2
// 类似于x86 VMX的CPU_BASED_PAUSE_EXITING——防止guest无限等待事件
#define HCR_TRAP_WFE      (1ULL << 14)

// HCR_EL2.TSC (bit 19)：Trap SMC指令位
// 置1后，guest执行SMC(Secure Monitor Call)指令时陷阱到EL2
// SMC是ARM64的安全监控调用，类似于x86的SYSENTER/SYSCALL
// fuzzer需要陷阱SMC以防止guest调用安全监控服务
#define HCR_TRAP_SMC      (1ULL << 19)

// HCR_EL2.TID (bit 20)：Trap ID寄存器位
// 置1后，guest读取ID寄存器(MIDR_EL1/REVIDR_EL1等)时陷阱到EL2
// 用于虚拟化CPU标识信息，防止guest获取真实硬件信息
#define HCR_TRAP_ID_REGS  (1ULL << 20)

// HCR_EL2.TIDCP (bit 20+具体位)：Trap实现定义的CP系统寄存器
// 置1后，guest访问实现定义的系统寄存器时陷阱到EL2
#define HCR_TRAP_IMP_DEF  (1ULL << 15)

// HCR_EL2.TACR (bit 34)：Trap ACTLR_EL1/ACTLR_EL2位
// 置1后，guest访问ACTLR(Auxiliary Control Register)时陷阱到EL2
// 注意：bit 34在ARMv8.0中为TACR，在ARMv8.1+VHE中为E2H，两者含义取决于VHE是否启用
#define HCR_TRAP_ACR      (1ULL << 34)

// ---- 系统寄存器陷阱位 ----

// HCR_EL2.TVM (bit 26)：Trap Virtual Memory系统寄存器位
// 置1后，guest对虚拟内存系统寄存器的写操作陷阱到EL2
// 包括SCTLR_EL1、TTBR0_EL1、TTBR1_EL1、TCR_EL1等
// 类似于x86 VMX的CR0/CR3/CR4读写退出控制
#define HCR_TRAP_VM_REGS  (1ULL << 26)

// HCR_EL2.TRVM (bit 30)：Trap Read Virtual Memory系统寄存器位
// 置1后，guest对虚拟内存系统寄存器的读操作也陷阱到EL2
// 与TVM配合使用，确保guest对MMU配置寄存器的任何访问都被拦截
#define HCR_TRAP_RVM_REGS (1ULL << 30)

// HCR_EL2.TSW (bit 31)：Trap Set Way缓存操作位
// 置1后，guest执行DC SW/ISW/Set/Way缓存维护指令时陷阱到EL2
// 类似于x86 VMX的CPU_BASED_INVLPG_EXITING或SVM的INVD拦截
#define HCR_TRAP_SW       (1ULL << 31)

// HCR_EL2.TTLB (bit 25)：Trap TLB维护操作位
// 置1后，guest执行TLBI(TLB Invalidate)指令时陷阱到EL2
// 防止guest直接操作TLB，确保虚拟化环境下的TLB一致性
#define HCR_TRAP_TLB_OPS  (1ULL << 25)

// HCR_EL2.TOCU (bit 27)：Trap Cache维护操作（统一）位
// 置1后，guest执行统一缓存维护操作(IC/DC IVAU等)时陷阱到EL2
#define HCR_TRAP_CACHU    (1ULL << 27)

// HCR_EL2.TIC (bit 28)：Trap IC缓存维护操作位
// 置1后，guest执行IC IVAU/IC ALLU等指令缓存维护操作时陷阱到EL2
#define HCR_TRAP_IC       (1ULL << 28)

// HCR_EL2.TDC (bit 29)：Trap DC缓存维护操作位
// 置1后，guest执行DC VAU/DC ALLU等数据缓存维护操作时陷阱到EL2
#define HCR_TRAP_DC       (1ULL << 29)

// ---- 中断和异常陷阱位 ----

// HCR_EL2.IMO (bit 40)：Interrupt Mask Override位
// 置1后，EL1的中断(PIRQ)被路由到EL2处理
// 类似于x86 VMX的PIN_BASED_EXT_INTR_MASK——外部中断由host处理
#define HCR_IMO_BIT       (1ULL << 40)

// HCR_EL2.FMO (bit 41)：FIQ Mask Override位
// 置1后，EL1的快速中断(FIQ)被路由到EL2处理
#define HCR_FMO_BIT       (1ULL << 41)

// HCR_EL2.AMO (bit 42)：SError Mask Override位
// 置1后，EL1的异步SError(系统错误)被路由到EL2处理
#define HCR_AMO_BIT       (1ULL << 42)

// HCR_EL2.TGE (bit 27)：Trap General Exceptions位
// 置1后，所有EL0/EL1的异常都路由到EL2，而不是EL1
// 这是VHE(Virtualization Host Extension)模式的关键位
// 注意：bit 27在ARMv8.0中为TOCU，在VHE模式下为TGE，含义取决于E2H位
#define HCR_TGE_BIT       (1ULL << 27)

// ---- E2H和VHE相关位 ----

// HCR_EL2.E2H (bit 34)：EL2 Host模式位
// 置1后启用VHE(Virtualization Host Extension)，host运行在EL2而非EL1
// VHE模式下，host可以直接访问EL2寄存器而不需要world switch
#define HCR_E2H_BIT       (1ULL << 34)

// ---- 默认HCR_EL2配置 ----
// 必须置1的位：启用虚拟化(VM)、陷阱WFI/WFE/SMC、路由中断/FIQ到EL2
// 这些位确保guest的行为完全受host控制
#define MUST_SET_HCR_EL2                                                                          \
    (HCR_VM_BIT | HCR_TRAP_WFI | HCR_TRAP_WFE | HCR_TRAP_SMC | HCR_IMO_BIT | HCR_FMO_BIT |      \
     HCR_AMO_BIT | HCR_TRAP_VM_REGS | HCR_TRAP_RVM_REGS | HCR_TRAP_TLB_OPS | HCR_TRAP_SW |      \
     HCR_TRAP_ID_REGS)

// 必须清0的位：不启用TGE（不将所有异常路由到EL2）、不启用E2H（不使用VHE模式）
// TGE和E2H会改变host的运行模式，不适合fuzzer的world switch设计
#define MUST_CLEAR_HCR_EL2 (HCR_TGE_BIT | HCR_E2H_BIT)

// =================================================================================================
// VTTBR_EL2配置常量——Stage-2页表基址寄存器
// ==============================================================================
// VTTBR_EL2指向Stage-2页表的根页，类似于x86的EPTP或VMCB的nested_cr3。
// 每个guest actor使用独立的Stage-2页表，实现actor间的地址空间隔离。

// VTTBR_EL2_ASID_WIDTH: ASID字段的宽度（16位）
// ASID(Address Space Identifier)用于区分不同guest的TLB条目
// 类似于x86 SVM的ASID或VMX的VPID
#define VTTBR_EL2_ASID_WIDTH  16

// VTTBR_EL2_BADDR_SHIFT: 页表基址字段的位移
// VTTBR_EL2.BADDR字段的起始位位置，物理地址左移此值得到BADDR字段值
#define VTTBR_EL2_BADDR_SHIFT 1

// VTTBR_EL2_ASID_SHIFT: ASID字段的位移
// ASID位于VTTBR_EL2的高16位[63:48]
#define VTTBR_EL2_ASID_SHIFT  48

// =================================================================================================
// ESR_EL2解码常量——Exception Syndrome Register
// ==============================================================================
// ESR_EL2记录了从EL1陷阱到EL2时的异常原因，类似于x86 VMX的VM_EXIT_REASON。
// ESR_EL2的EC(Exception Class)字段标识异常类别，
// ISS(Instruction Specific Syndrome)字段提供具体的异常细节。
//
// ESR_EL2位域结构：
// [31:26] EC: Exception Class——异常类别码，6位
// [25]    IL: Instruction Length——1=32位指令，0=16位指令（ARM64通常IL=1）
// [24:0]  ISS: Instruction Specific Syndrome——异常具体信息，25位

// ---- ESR_EL2.EC字段位掩码和位移 ----
// EC字段位于ESR_EL2的[31:26]，6位宽度
#define ESR_EC_SHIFT       26
#define ESR_EC_MASK        (0x3FULL << ESR_EC_SHIFT)
#define ESR_EC_WIDTH       6

// ---- ESR_EL2.IL字段 ----
// IL=1表示陷阱指令为32位（ARM64标准指令长度）
#define ESR_IL_BIT         (1ULL << 25)

// ---- ESR_EL2.ISS字段位掩码和位移 ----
// ISS字段位于ESR_EL2的[24:0]，25位宽度
#define ESR_ISS_MASK       0x1FFFFFFULL

// ---- EC值定义——Exception Class异常类别码 ----
// EC值标识了陷阱到EL2的异常类别，类似于x86 VMX的基本退出原因码
// 以下列出与fuzzer相关的EC值（ARM Architecture Reference Manual D24.2.1）

// EC=0x00: Unknown Reason——未知原因的异常
#define EC_UNKNOWN         0x00

// EC=0x01: WFI/WFE陷阱——guest执行WFI或WFE指令被陷阱
// 由HCR_EL2.TWI/TWE触发
// 类似于x86 VMX的EXIT_REASON_HLT或SVM的VMCB_INTERCEPT_HLT
#define EC_WFI_WFE         0x01

// EC=0x03: MCR/MRC系统寄存器访问(EL1到EL2)——32位系统寄存器读写陷阱(AArch32)
#define EC_SYSREG_32       0x03

// EC=0x04: MCR/MRC系统寄存器访问(EL0到EL1)——从EL0访问系统寄存器(AArch32)
#define EC_SYSREG_32_EL0   0x04

// EC=0x15: MSR/MRS系统寄存器访问(EL1到EL2)——64位系统寄存器读写陷阱(AArch64)
// 由HCR_EL2的各种陷阱位触发（TVM/TRVM/TID等）
// 类似于x86 VMX的EXIT_REASON_CR_ACCESS或SVM的CR拦截
#define EC_SYSREG_64       0x18

// EC=0x06: MSR/MRS系统寄存器访问(EL0到EL1)——从EL0访问64位系统寄存器(AArch32)
#define EC_SYSREG_64_EL0   0x06

// EC=0x17: SMC陷阱——guest执行SMC指令被陷阱(AArch64)
// 由HCR_EL2.TSC触发
// SMC(Secure Monitor Call)是ARM64的安全监控调用指令
#define EC_SMC64           0x17

// EC=0x16: HVC指令——guest执行HVC(Hypervisor Call)指令(AArch64)
// HVC是guest主动请求hypervisor服务的指令
// 类似于x86 VMX的EXIT_REASON_VMCALL或SVM的VMCB_INTERCEPT_VMMCALL
// fuzzer使用HVC作为guest主动退出的机制
#define EC_HVC64           0x16

// EC=0x15: SVC指令(EL1)——guest执行SVC(Supervisor Call)指令(AArch64)
// SVC是ARM64的系统调用指令，从EL1陷阱到EL2
#define EC_SVC64           0x15

// EC=0x0A: SVC指令(EL0)——从EL0执行SVC指令(AArch32)
#define EC_SVC32           0x0A

// EC=0x20: 指令中止(EL1)——guest发生指令取址时的内存访问故障(AArch64)
// 在Stage-2翻译中发生故障时触发，类似于x86 VMX的EPT Violation
// 这是fuzzer侧信道分析的关键事件——guest的代码取址故障可能暴露缓存状态
#define EC_IABORT_EL1      0x20

// EC=0x21: 指令中止(EL2)——EL2发生指令取址故障(AArch64)
#define EC_IABORT_EL2      0x21

// EC=0x24: 数据中止(EL1)——guest发生数据访问时的内存访问故障(AArch64)
// 在Stage-2翻译中发生故障时触发，类似于x86 VMX的EPT Violation
// 这是fuzzer侧信道分析最关键的VM退出类型——通过控制Stage-2页表权限，
// 可以观察guest的内存访问模式（Prime+Probe、Flush+Reload等）
#define EC_DABORT_EL1      0x24

// EC=0x25: 数据中止(EL2)——EL2发生数据访问故障(AArch64)
#define EC_DABORT_EL2      0x25

// EC=0x26: 数据中止(SP alignment)——栈指针对齐故障
#define EC_DABORT_SP_ALIGN 0x26

// ---- ISS字段解码常量（数据中止/指令中止） ----
// 当EC=EC_DABORT_EL1或EC_IABORT_EL1时，ISS字段的位域含义如下：
// ISS[9]: DFSC/IFSC的扩展位，与ISS[5:0]组合为9位故障码
// ISS[8]: LPA(Large Physical Address)位
// ISS[7]: VNCR(Virtual Nested Context Register)位
// ISS[6]: AR(Accurate)位
// ISS[5:0]: DFSC/IFSC(Data/Instruction Fault Status Code)——故障状态码

// ISS中DFSC/IFSC故障码的掩码和位置
#define ISS_FSC_SHIFT      0
#define ISS_FSC_MASK       0x3FULL

// ISS的WnR(Write not Read)位——bit 6
// WnR=1表示故障由写操作触发，WnR=0表示由读操作触发
// 这是区分读写故障的关键位，对Flush+Reload等侧信道攻击模式很重要
#define ISS_WNR_BIT        (1ULL << 6)

// ISS的AR(Accuracy Reliable)位——bit 6（与WnR共用）
#define ISS_AR_BIT         (1ULL << 6)

// ISS的VNCR位——bit 7
// VNCR=1表示故障与虚拟嵌套上下文寄存器有关
#define ISS_VNCR_BIT       (1ULL << 7)

// ISS的LPA位——bit 8
#define ISS_LPA_BIT        (1ULL << 8)

// ISS的DFSC扩展位——bit 9
// 与FSC[5:0]组合为9位故障码，支持更多故障类型
#define ISS_FSC_EXT_BIT    (1ULL << 9)

// ---- 数据/指令故障状态码(FSC)定义 ----
// FSC是ISS[5:0]（或ISS[9:0]扩展后）的故障码，类似于x86 VMX的退出资格

// Address Size Fault——地址大小故障（虚拟地址超出范围）
#define FSC_ADDR_SIZE_FAULT     0x00

// Translation Fault (level 0/1/2/3)——翻译故障（页表中找不到映射）
// level对应页表层级：L0=0x03, L1=0x05, L2=0x06, L3=0x07
#define FSC_TRANS_FAULT_L0      0x03
#define FSC_TRANS_FAULT_L1      0x05
#define FSC_TRANS_FAULT_L2      0x06
#define FSC_TRANS_FAULT_L3      0x07

// Access Flag Fault——访问标志位故障（页表项AF位未设置）
#define FSC_ACCESS_FLAG_FAULT   0x09

// Permission Fault (level 0/1/2/3)——权限故障（页表项权限不满足访问要求）
// 这是fuzzer最关心的故障类型——通过修改Stage-2页表权限，
// 可以精确控制哪些内存访问触发VM退出
#define FSC_PERM_FAULT_L0      0x0C
#define FSC_PERM_FAULT_L1      0x0D
#define FSC_PERM_FAULT_L2      0x0E
#define FSC_PERM_FAULT_L3      0x0F

// SError——异步系统错误
#define FSC_SEA                 0x10

// External Abort (non-translatable)——外部中止（无法翻译的地址）
#define FSC_EXT_ABORT_NTRANS   0x14

// External Abort (translatable)——外部中止（可翻译的地址）
#define FSC_EXT_ABORT_TRANS    0x16

// ---- ISS字段解码常量（系统寄存器访问） ----
// 当EC=EC_SYSREG_64或EC_SYSREG_32时，ISS字段的位域含义如下：
// ISS[20:19]: Op0字段——系统寄存器编码的Op0
// ISS[18:15]: Op1字段——系统寄存器编码的Op1
// ISS[14:10]: CRn字段——系统寄存器编码的CRn
// ISS[9:5]:   CRm字段——系统寄存器编码的CRm
// ISS[4:1]:   Op2字段——系统寄存器编码的Op2
// ISS[0]:     Rt字段方向位（0=读MRS，1=写MSR）

#define ISS_SYSREG_OP0_SHIFT   19
#define ISS_SYSREG_OP0_MASK    (0x3ULL << ISS_SYSREG_OP0_SHIFT)
#define ISS_SYSREG_OP1_SHIFT   15
#define ISS_SYSREG_OP1_MASK    (0xFULL << ISS_SYSREG_OP1_SHIFT)
#define ISS_SYSREG_CRN_SHIFT   10
#define ISS_SYSREG_CRN_MASK    (0xFULL << ISS_SYSREG_CRN_SHIFT)
#define ISS_SYSREG_CRM_SHIFT   5
#define ISS_SYSREG_CRM_MASK    (0xFULL << ISS_SYSREG_CRM_SHIFT)
#define ISS_SYSREG_OP2_SHIFT   1
#define ISS_SYSREG_OP2_MASK    (0x7ULL << ISS_SYSREG_OP2_SHIFT)
#define ISS_SYSREG_DIR_BIT     (1ULL << 0) // 0=MRS(读), 1=MSR(写)

// =================================================================================================
// MAIR_EL2值定义——Memory Attribute Indirection Register
// ==============================================================================
// MAIR_EL2定义了Stage-2页表中可用的8种内存属性，类似于x86的PAT(Page Attribute Table)。
// 页表项中的AttrIndx[2:0]字段选择MAIR_EL2中的对应属性。
//
// MAIR_EL2是64位寄存器，分为8个8位字段，每个字段定义一种内存属性：
// [63:56] Attr7, [55:48] Attr6, [47:40] Attr5, [39:32] Attr4,
// [31:24] Attr3, [23:16] Attr2, [15:8]  Attr1, [7:0]   Attr0
//
// ARM内存属性编码（8位字段）：
// 高4位为主属性(Outer)，低4位为内部属性(Inner)
// 常用编码值：
//   0xFF = Normal Memory, Write-Back, Read/Write Allocate (WBRA)——最强缓存属性
//   0x04 = Normal Memory, Non-Cacheable——不缓存，直接访问内存
//   0x00 = Device-nGnRnE——最强设备属性（无 Gathering、无 Reordering、无 Early Write Ack）
//   0x44 = Normal Memory, Write-Through, Read Allocate——写透缓存

// AttrIndx=0: Device-nGnRnE（设备内存，最严格）
// 用于MMIO设备区域，保证访问顺序和完成确认
// AttrIndx=0对应页表项AttrIndx[2:0]=000
#define MAIR_ATTR0_DEVICE_nGnRnE    0x00ULL

// AttrIndx=1: Normal Memory, Non-Cacheable
// 用于需要直接访问内存的区域（如DMA缓冲区）
#define MAIR_ATTR1_NORMAL_NC        0x44ULL

// AttrIndx=2: Normal Memory, Write-Back, Read/Write Allocate
// 这是最常用的缓存属性——对数据和代码区域使用WB缓存策略
// 类似于x86 PAT中的WB(Write Back)类型
#define MAIR_ATTR2_NORMAL_WBRA      0xFFULL

// AttrIndx=3: Normal Memory, Write-Through, Read Allocate
#define MAIR_ATTR3_NORMAL_WTRA      0xBBULL

// ---- 默认MAIR_EL2配置值 ----
// 将Attr0设为Device，Attr1设为NC，Attr2设为WB，其余设为WB
// 这与x86 VMX中EPTP的内存类型(WB=6)和SVM中g_pat的配置对应
#define DEFAULT_MAIR_EL2                                                                          \
    ((MAIR_ATTR0_DEVICE_nGnRnE << 0) | (MAIR_ATTR1_NORMAL_NC << 8) |                             \
     (MAIR_ATTR2_NORMAL_WBRA << 16) | (MAIR_ATTR3_NORMAL_WTRA << 24) |                            \
     (MAIR_ATTR2_NORMAL_WBRA << 32) | (MAIR_ATTR2_NORMAL_WBRA << 40) |                            \
     (MAIR_ATTR2_NORMAL_WBRA << 48) | (MAIR_ATTR2_NORMAL_WBRA << 56))

// =================================================================================================
// TCR_EL2配置常量——Translation Control Register for Stage-2
// ==============================================================================
// TCR_EL2控制Stage-2翻译的参数，类似于x86 VMX的EPTP配置位。
// 包括物理地址宽度、页表granule大小、翻译起始级别等。
//
// TCR_EL2位域（部分与fuzzer相关的位）：
// [31]  PS: Physical Size——物理地址宽度编码
// [23:20] T0SZ: Translation Size Offset——IPA地址宽度=64-T0SZ
// [19:18] SL0: Starting Level——页表起始级别
// [15:14] TG0: Granule Size——页表粒度大小编码
// [29:28] IRGN0: Inner Cacheability——内缓存属性
// [27:26] ORGN0: Outer Cacheability——外缓存属性
// [25:24] SH0: Shareability——共享属性

// ---- TCR_EL2.PS字段编码（物理地址宽度） ----
// PS编码对应ID_AA64MMFR0_EL1.PARange的值
#define TCR_PS_32_BITS   0x0ULL // 物理地址32位
#define TCR_PS_36_BITS   0x1ULL // 物理地址36位
#define TCR_PS_40_BITS   0x2ULL // 物理地址40位
#define TCR_PS_42_BITS   0x3ULL // 物理地址42位
#define TCR_PS_44_BITS   0x4ULL // 物理地址44位
#define TCR_PS_48_BITS   0x5ULL // 物理地址48位（最常用的宽度）

// ---- TCR_EL2.TG0字段编码（页表粒度大小） ----
// TG0编码决定Stage-2页表使用的最小映射单位
#define TCR_TG0_4KB      0x0ULL // 4KB粒度——最常用的页表粒度
#define TCR_TG0_16KB     0x2ULL // 16KB粒度
#define TCR_TG0_64KB     0x1ULL // 64KB粒度

// ---- TCR_EL2.T0SZ字段——IPA地址宽度 ----
// T0SZ = 64 - IPA_WIDTH，IPA_WIDTH为Intermediate Physical Address宽度
// 对于48位IPA（覆盖256TB地址空间），T0SZ=16
#define TCR_T0SZ_48BIT_IPA  16ULL
#define TCR_T0SZ_40BIT_IPA  24ULL
#define TCR_T0SZ_36BIT_IPA  28ULL

// ---- TCR_EL2.SL0字段——页表起始级别 ----
// SL0决定Stage-2页表的起始遍历级别
// SL0=0: 从Level0开始遍历（需要4级页表，用于更大的地址空间）
// SL0=1: 从Level1开始遍历（需要3级页表，用于48位IPA）
// SL0=2: 从Level2开始遍历（需要2级页表）
#define TCR_SL0_LEVEL_1  0x1ULL // 从Level1开始——对应48位IPA+4KB粒度
#define TCR_SL0_LEVEL_2  0x2ULL // 从Level2开始——对应较小地址空间

// ---- TCR_EL2缓存和共享属性编码 ----
// IRGN0/ORGN0编码：
#define TCR_IRGN0_WBWA   0x1ULL // Inner Write-Back, Write-Allocate
#define TCR_IRGN0_NC     0x0ULL // Inner Non-Cacheable
#define TCR_ORGN0_WBWA   0x1ULL // Outer Write-Back, Write-Allocate
#define TCR_ORGN0_NC     0x0ULL // Outer Non-Cacheable

// SH0编码：
#define TCR_SH0_NS       0x0ULL // Non-Shareable
#define TCR_SH0_OS       0x2ULL // Outer Shareable
#define TCR_SH0_IS       0x3ULL // Inner Shareable（最常用）

// ---- 默认TCR_EL2配置值 ----
// 使用48位IPA、4KB粒度、从Level1开始遍历、WB缓存、Inner Shareable
#define DEFAULT_TCR_EL2                                                                            \
    ((TCR_PS_48_BITS << 31) | (TCR_T0SZ_48BIT_IPA << 0) |                                         \
     (TCR_TG0_4KB << 14) | (TCR_SL0_LEVEL_1 << 6) |                                               \
     (TCR_IRGN0_WBWA << 8) | (TCR_ORGN0_WBWA << 10) | (TCR_SH0_IS << 12))

// =================================================================================================
// SCTLR_EL1配置常量——System Control Register (EL1)
// ==============================================================================
// SCTLR_EL1控制guest的MMU、缓存、对齐检查等行为
// 类似于x86 VMX中GUEST_CR0的角色

// SCTLR_EL1.M (bit 0): MMU使能位——置1启用Stage-1翻译
#define SCTLR_M_BIT       (1ULL << 0)

// SCTLR_EL1.A (bit 1): 对齐检查位——置1启用对齐检查
#define SCTLR_A_BIT       (1ULL << 1)

// SCTLR_EL1.C (bit 2): 数据缓存使能位——置1启用数据缓存
#define SCTLR_C_BIT       (1ULL << 2)

// SCTLR_EL1.SA (bit 3): 栈对齐检查位——置1启用SP对齐检查
#define SCTLR_SA_BIT      (1ULL << 3)

// SCTLR_EL1.I (bit 12): 指令缓存使能位——置1启用指令缓存
#define SCTLR_I_BIT       (1ULL << 12)

// SCTLR_EL1.WXN (bit 19): Write-Xor-Execute位——置1后可写区域不可执行
#define SCTLR_WXN_BIT     (1ULL << 19)

// ---- guest SCTLR_EL1必须置1的位 ----
// 类似于x86 VMX的MUST_SET_BITS_CR0_VMX_GUEST
#define MUST_SET_SCTLR_EL1_GUEST  (SCTLR_M_BIT | SCTLR_C_BIT | SCTLR_I_BIT | SCTLR_A_BIT)

// ---- guest SCTLR_EL1必须清0的位 ----
// 类似于x86 VMX的MUST_CLEAR_BITS_CR0_VMX_GUEST
#define MUST_CLEAR_SCTLR_EL1_GUEST (SCTLR_WXN_BIT)

// =================================================================================================
// SPSR_EL2配置常量——Saved Program Status Register (EL2)
// ==============================================================================
// SPSR_EL2保存了eret返回时恢复的PSTATE值，定义了guest的初始处理器状态
// PSTATE位域包括：处理器模式(M[4])、执行状态(M[3:0])、中断屏蔽(D/A/I/F[9:6])等

// ---- PSTATE模式编码 ----
// EL1h模式（EL1 + 使用SP_EL1）——guest运行在EL1且使用EL1栈指针
// 这是ARM64 Linux内核的正常运行模式
#define SPSR_EL1h_MODE    0x05ULL // M[4]=0, M[3:0]=0101 → EL1h

// ---- PSTATE中断屏蔽位 ----
// 这些位控制guest的中断屏蔽状态
// 在VM进入时通常屏蔽所有中断，防止guest初始化期间被中断干扰
#define SPSR_D_MASK       (1ULL << 9)  // Debug异常屏蔽
#define SPSR_A_MASK       (1ULL << 8)  // SError屏蔽
#define SPSR_I_MASK       (1ULL << 7)  // IRQ屏蔽
#define SPSR_F_MASK       (1ULL << 6)  // FIQ屏蔽

// ---- 默认SPSR_EL2配置值 ----
// EL1h模式 + 屏蔽所有中断（与x86 VMX的GUEST_INTERRUPTIBILITY_INFO对应）
#define DEFAULT_SPSR_EL2  (SPSR_EL1h_MODE | SPSR_D_MASK | SPSR_A_MASK | SPSR_I_MASK | SPSR_F_MASK)

// =================================================================================================
// Cortex-A72/A76特定常量
// ==============================================================================
// Cortex-A72（ARMv8.0-A）和Cortex-A76（ARMv8.2-A）是常见的ARM64处理器型号
// 以下常量定义了这些处理器特定的ID寄存器值和特性参数

// ---- MIDR_EL1（Main ID Register）编码 ----
// MIDR_EL1格式：[31:24]Implementer, [23:20]Variant, [19:16]Architecture,
//                [15:4]PartNum, [3:0]Revision

// ARM Implementer ID = 0x41 (ASCII 'A')
#define ARM_IMPLEMENTER_ID      0x41ULL

// Cortex-A72 Part Number = 0xD08
#define CORTEX_A72_PART_NUM     0xD08ULL

// Cortex-A76 Part Number = 0xD0B
#define CORTEX_A76_PART_NUM     0xD0BULL

// ---- ID_AA64MMFR0_EL1（AArch64 Memory Model Feature Register 0） ----
// 这个寄存器报告了物理地址宽度(PARange)和Stage-2翻译支持的特性

// PARange字段编码（[3:0]）——物理地址宽度
// 与TCR_EL2.PS字段使用相同的编码
#define MMFR0_PARange_32       0x0ULL // 32位物理地址
#define MMFR0_PARange_36       0x1ULL // 36位物理地址
#define MMFR0_PARange_40       0x2ULL // 40位物理地址
#define MMFR0_PARange_42       0x3ULL // 42位物理地址
#define MMFR0_PARange_44       0x4ULL // 44位物理地址
#define MMFR0_PARange_48       0x5ULL // 48位物理地址
#define MMFR0_PARange_52       0x6ULL // 52位物理地址（ARMv8.5+）

// S2PS字段编码（[19:16]）——Stage-2物理地址宽度
#define MMFR0_S2PS_SAME_AS_PARange  0x0ULL // S2 PS = PARange（最常见）

// ---- ID_AA64MMFR1_EL1（AArch64 Memory Model Feature Register 1） ----
// VH字段编码（[7:4]）——虚拟化主机扩展(VHE)支持
#define MMFR1_VH_NOT_IMPL     0x0ULL // VHE未实现
#define MMFR1_VH_IMPL         0x1ULL // VHE已实现

// ---- ID_AA64PFR0_EL1（AArch64 Processor Feature Register 0） ----
// EL2字段编码（[19:16]）——EL2支持
#define PFR0_EL2_NOT_IMPL     0x0ULL // EL2未实现
#define PFR0_EL2_IMPL         0x1ULL // EL2已实现

// ---- 性能计数器相关常量 ----
// Cortex-A72/A76的L1数据缓存配置（与fuzzer的侧信道分析密切相关）

// Cortex-A72 L1D: 48KB, 3-way associative, 64-byte line
#define CORTEX_A72_L1D_SIZE_KB     48
#define CORTEX_A72_L1D_ASSOCIATIVITY 3
#define CORTEX_A72_L1D_LINE_SIZE    64

// Cortex-A76 L1D: 64KB, 4-way associative, 64-byte line
#define CORTEX_A76_L1D_SIZE_KB     64
#define CORTEX_A76_L1D_ASSOCIATIVITY 4
#define CORTEX_A76_L1D_LINE_SIZE    64

// =================================================================================================
// 异常向量表偏移常量
// ==============================================================================
// ARM64异常向量表(VBAR)的结构不同于x86的IDT。
// 每个异常类型占0x80字节（最多4条指令×4字节=0x10，但有间距），16个条目共0x800字节。
//
// 向量表布局（ARM Architecture Reference Manual D24.6.2）：
// 基址+0x000: Current EL with SP0同步异常
// 基址+0x080: Current EL with SP0 IRQ中断
// 基址+0x100: Current EL with SP0 FIQ快速中断
// 基址+0x180: Current EL with SP0 SError
// 基址+0x200: Current EL with SPx同步异常
// 基址+0x280: Current EL with SPx IRQ
// 基址+0x300: Current EL with SPx FIQ
// 基址+0x380: Current EL with SPx SError
// 基址+0x400: Lower EL using AArch64同步异常
// 基址+0x480: Lower EL using AArch64 IRQ
// 基址+0x500: Lower EL using AArch64 FIQ
// 基址+0x580: Lower EL using AArch64 SError
// 基址+0x600: Lower EL using AArch32同步异常
// 基址+0x680: Lower EL using AArch32 IRQ
// 基址+0x700: Lower EL using AArch32 FIQ
// 基址+0x780: Lower EL using AArch32 SError

// 从EL1陷阱到EL2的异常使用"Lower EL using AArch64"组（偏移0x400-0x580）
// 以下偏移是guest异常在EL2向量表中的位置
#define VBAR_OFFSET_SYNC_EL0_SP0  0x000
#define VBAR_OFFSET_IRQ_EL0_SP0   0x080
#define VBAR_OFFSET_FIQ_EL0_SP0   0x100
#define VBAR_OFFSET_SERR_EL0_SP0  0x180
#define VBAR_OFFSET_SYNC_CUR_SPX  0x200
#define VBAR_OFFSET_IRQ_CUR_SPX   0x280
#define VBAR_OFFSET_FIQ_CUR_SPX   0x300
#define VBAR_OFFSET_SERR_CUR_SPX  0x380
#define VBAR_OFFSET_SYNC_LOWER_A64 0x400 // 关键偏移——guest同步异常（包括HVC/SMC/系统寄存器陷阱）
#define VBAR_OFFSET_IRQ_LOWER_A64 0x480 // guest IRQ中断
#define VBAR_OFFSET_FIQ_LOWER_A64 0x500 // guest FIQ快速中断
#define VBAR_OFFSET_SERR_LOWER_A64 0x580 // guest SError
#define VBAR_OFFSET_SYNC_LOWER_A32 0x600
#define VBAR_OFFSET_IRQ_LOWER_A32 0x680
#define VBAR_OFFSET_FIQ_LOWER_A32 0x700
#define VBAR_OFFSET_SERR_LOWER_A32 0x780

// 向量表总大小
#define VBAR_TABLE_SIZE           0x800

#endif // _RVZR_EXECUTOR_VM_CONSTANTS_H_

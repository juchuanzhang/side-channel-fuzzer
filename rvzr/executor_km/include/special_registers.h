/// 文件：特殊寄存器管理的头文件
/// 定义ARM64/x86_64系统寄存器保存/恢复的数据结构和接口函数
///
/// 特殊寄存器（MSR/系统寄存器）管理是侧信道模糊测试工具的核心基础设施之一。
/// 在测试执行期间，执行器需要修改CPU的系统控制寄存器来：
///   - 禁用硬件预取器，减少缓存预取带来的测量噪声
///   - 启用从低特权级别访问性能计数器，使测试用例能直接读取PMC
///   - 为用户态actor重定向异常向量（SVC→fault_handler）
///   - 为虚拟机actor配置虚拟化陷阱和第二阶段页表
/// 测试执行完毕后，所有修改必须恢复为原始值，否则宿主系统将不稳定。
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MSR_H_
#define _MSR_H_

#include <linux/types.h>
#include "hardware_desc.h"

/// @brief 特殊寄存器状态保存结构
///        用于在测试执行前保存关键系统寄存器的原始值，执行后恢复，
///        确保宿主系统在执行器进行潜在危险操作后仍然稳定运行。
///
/// ARM64架构下需要保存的系统寄存器分为以下几组：
///   1. EL1系统控制寄存器组 - 控制内存管理、异常处理等核心功能
///      这些寄存器控制MMU、缓存、异常向量等，任何误配置都可能导致系统崩溃
///   2. EL2虚拟化控制寄存器组 - 仅在存在VM actor时需要保存和修改
///      这些寄存器控制第二阶段翻译、虚拟化陷阱等，仅在运行虚拟机actor时使用
///   3. EL0性能监控与浮点寄存器 - PMU访问控制与浮点运算状态
///      PMUSERENR_EL0控制EL0对PMU的访问权限，FPCR/FPSR保存浮点状态
///   4. 实现特定寄存器 - Cortex A72/A76的预取器控制等
///      这些寄存器的编码和位定义因处理器型号而异，需要根据MIDR_EL1动态选择
///
/// x86_64架构下需要保存的MSR包括：
///   CR0/CR4 - 控制寄存器，控制缓存、虚拟化等
///   EFER - 扩展特性使能寄存器，控制长模式、SVM等
///   LSTAR - syscall入口点MSR
///   SPEC_CTRL - 投机控制寄存器（SSBP补丁）
///   预取器控制MSR - 禁用/启用硬件预取器
///   FS/GS基址 - 段寄存器基址
///   GDTR - 全局描述符表寄存器
typedef struct {
#if defined(ARCH_X86_64)
    /// CR0控制寄存器 - x86_64最重要的控制寄存器之一
    /// [29] NW - Not Write-through (缓存写策略)
    /// [30] CD - Cache Disable (禁用CPU缓存)
    /// [0]  PE - Protection Enable (保护模式)
    /// [31] PG - Paging Enable (分页启用)
    uint64_t cr0;

    /// CR4控制寄存器 - 控制高级CPU特性
    /// [7]  PCE - Performance Counter Enable (允许任意特权级别执行RDPMC)
    /// [21] SMAP - Supervisor Mode Access Prevention
    /// [20] SMEP - Supervisor Mode Execution Prevention
    /// [13] VMXE - VMX Enable (Intel虚拟化)
    uint64_t cr4;

    /// EFER - 扩展特性使能寄存器
    /// [0]  SCE - System Call Extensions (SYSCALL/SYSRET启用)
    /// [8]  LME - Long Mode Enable (长模式启用)
    /// [10] LMA - Long Mode Active (长模式活跃)
    /// [12] SVME - Secure Virtual Machine Enable (AMD SVM)
    uint64_t efer;

    /// LSTAR - syscall目标地址MSR
    /// 存储SYSCALL指令跳转到的目标地址（内核入口点）
    uint64_t lstar;

    /// SPEC_CTRL - 投机控制寄存器
    /// [1]  IBRS - Indirect Branch Restricted Speculation
    /// [2]  STIBP - Single Thread Indirect Branch Predictor
    /// [4]  SSBD - Speculative Store Bypass Disable
    uint64_t spec_ctrl;

    /// 预取器控制MSR - 控制硬件预取器的启用/禁用
    /// 禁用预取器可减少侧信道测量中的缓存预取噪声
    uint64_t prefetcher_ctrl;

    /// SYSCFG - AMD系统配置MSR（仅AMD平台）
    uint64_t syscfg;

    /// FS_BASE - FS段基址MSR
    uint64_t fs_base;

    /// GS_BASE - GS段基址MSR
    uint64_t gs_base;

    /// GDTR基址和限制 - 全局描述符表寄存器
    uint64_t gdtr_base;
    uint16_t gdtr_limit;

#elif defined(ARCH_ARM)
    // =====================================================================
    // EL1 系统控制寄存器组
    // 这些寄存器控制ARM64核心的内存管理、异常处理和缓存行为
    // =====================================================================

    /// SCTLR_EL1 - 系统控制寄存器（EL1级别）
    /// ARM64最重要的系统控制寄存器，类似于x86的CR0，控制以下核心功能：
    ///   [0]  M    - MMU启用位。1=启用虚拟地址翻译，0=物理地址直通
    ///   [1]  A    - 对齐检查启用位。1=非对齐访问触发对齐故障
    ///   [2]  C    - 数据缓存启用位(DCache)。1=启用数据缓存
    ///   [3]  SA   - 栈对齐检查启用位。1=EL1的SP必须16字节对齐
    ///   [4]  SA0  - EL0栈对齐检查启用位
    ///   [5]  CP15 - CP15屏障启用位(已弃用)
    ///   [6]  UCIS - 特定约束指令启用位
    ///   [7]  EE   - 异常入口端序。1=大端异常入口，0=小端异常入口
    ///   [8]  EIS  - 异常入口端序(EL0)
    ///   [9]  E0E  - EL0数据端序
    ///   [10] E0S  - EL0栈端序
    ///   [16] UCI  - 特定缓存维护指令启用(EL0可执行DC CVAC等)
    ///   [18] WXN  - 写执行永不启用。1=可写区域不可执行
    ///   [22] NTBI - 非顶层字节忽略(TCR_EL2.TBI0/1控制)
    ///   [24] DZE  - EL0 DC ZVA指令启用(ZVA=零虚拟地址)
    ///   [25] I    - 指令缓存启用位(ICache)。1=启用指令缓存
    ///   [26] UCT  - EL0 CTR_EL0读取启用
    ///   [28] EDBE - EL0数据大端启用
    ///   [29] SP1  - EL1 SP启用
    ///   [30] SP0  - EL0 SP启用
    ///   [31] TCF0 - EL0标签检查故障控制(MTE)
    ///   [32] TCF  - EL1标签检查故障控制(MTE)
    ///   [34] BT0  - EL0分支目标识别启用(BTI)
    ///   [35] BT   - EL1分支目标识别启用(BTI)
    ///   [36] ITD  - 特定指令跟踪禁用
    ///   [38] SME  - 流匹配启用(SME)
    ///   [40] nTLSMD - 非TLSMD启用(延迟TLB维护)
    ///   [41] TLSMD  - 延迟TLB维护启用
    ///   [44] DSSBS - 数据SSBS(投机存储绕过安全)启用
    ///   [56] ENDBR - ENDBR指令启用
    /// 在侧信道测试中，关键是确保C=1（数据缓存启用），
    /// 否则基于缓存的侧信道测量(htrace)无法工作
    uint64_t sctlr_el1;

    /// TTBR0_EL1 - 页表基址寄存器0（EL1级别）
    /// 指向用户态(EL0)和低地址空间的页表。
    /// ARM64使用TTBR0和TTBR1分割地址空间：
    ///   - TTBR0_EL1管理低地址空间(0到2^(64-T0SZ)-1)
    ///   - TTBR1_EL1管理高地址空间(2^(64-T1SZ)到2^64-1)
    /// 对于用户态actor，需要将TTBR0_EL1设置为指向用户actor的页表，
    /// 并配置相应的访问权限（通过页表属性位）
    uint64_t ttbr0_el1;

    /// TTBR1_EL1 - 页表基址寄存器1（EL1级别）
    /// 指向内核高地址空间的页表。
    /// 在Linux内核中，TTBR1_EL1通常指向内核的swapper_pg_dir页表
    uint64_t ttbr1_el1;

    /// TCR_EL1 - 页表控制寄存器（EL1级别）
    /// 配置TTBR0_EL1和TTBR1_EL1的翻译参数：
    ///   [5:0]   T0SZ  - TTBR0地址空间大小(虚拟地址位数=64-T0SZ)
    ///   [7:6]   SL0   - TTBR0起始查找级别
    ///   [8]     IRGN0 - TTBR0内部缓存属性(Normal WB-WA)
    ///   [9]     ORGN0 - TTBR0外部缓存属性
    ///   [10:9]  SH0   - TTBR0共享属性(Inner/Outer Shareable)
    ///   [11]    EPD0  - TTBR0翻译禁用位
    ///   [13:12] TG0   - TTBR0粒度(4KB=0,64KB=1,16KB=2)
    ///   [15:14] PS    - 物理地址大小(32-52位)
    ///   [16]    TBI0  - TTBR0顶层字节忽略
    ///   [21:16] T1SZ  - TTBR1地址空间大小
    ///   [23:22] SL1   - TTBR1起始查找级别
    ///   [24]    IRGN1 - TTBR1内部缓存属性
    ///   [25]    ORGN1 - TTBR1外部缓存属性
    ///   [27:26] SH1   - TTBR1共享属性
    ///   [28]    EPD1  - TTBR1翻译禁用位
    ///   [30:29] TG1   - TTBR1粒度(16KB=1,4KB=2,64KB=3)
    ///   [33:32] IPS   - 中间物理地址大小
    ///   [36]    TBI1  - TTBR1顶层字节忽略
    ///   [37]    HA    - 硬件访问标志更新启用(AP[2]硬件更新)
    ///   [39]    HD    - 硬件脏标志启用
    uint64_t tcr_el1;

    /// MAIR_EL1 - 内存属性间接寄存器（EL1级别）
    /// 定义8个内存属性索引(Attr0-Attr7)，每个索引占8位。
    /// 页表项中的MAIR索引号(PTE[4:2]或PTE[5:2])指向此寄存器的对应属性。
    /// 典型配置(Linux内核)：
    ///   Attr0: 0xFF = Normal Inner/Outer Cacheable WB-WA (Write-Back Write-Allocate)
    ///   Attr1: 0x04 = Normal Inner/Outer Cacheable WT-RA (Write-Through Read-Allocate)
    ///   Attr2: 0x44 = Normal Inner Cacheable WB-WA, Outer Non-Cacheable
    ///   Attr3: 0x00 = Normal Inner/Outer Non-Cacheable
    ///   Attr4: 0x44 = Device-nGnRE (Non-Gathering Non-Reordering Early-write)
    ///   Attr5: 0x04 = Device-nGnRnE (Non-Gathering Non-Reordering No-Early-write)
    ///   Attr6: 0x04 = Normal Inner Cacheable WT-RA, Outer Non-Cacheable
    ///   Attr7: 0x00 = Normal Inner/Outer Non-Cacheable
    /// 在侧信道测试中，关键属性是WB-WA(Attr0)，这是L1/L2缓存的默认属性
    uint64_t mair_el1;

    /// VBAR_EL1 - 向量基址寄存器（EL1级别）
    /// 指向EL1异常向量表的基地址。
    /// ARM64异常向量表包含16个向量入口，每个入口占128字节(32条ARM指令)：
    ///   偏移0x000: 当前EL的SP0同步异常
    ///   偏移0x080: 当前EL的SP0IRQ异常
    ///   偏移0x100: 当前EL的SP0 FIQ异常
    ///   偏移0x180: 当前EL的SP0 SError异常
    ///   偏移0x200: 当前EL的SPx同步异常(含SVC/SMC/HVC)
    ///   偏移0x280: 当前EL的SPx IRQ异常
    ///   偏移0x300: 当前EL的SPx FIQ异常
    ///   偏移0x380: 当前EL的SPx SError异常
    ///   偏移0x400: 低EL的AArch64同步异常(含SVC from EL0)
    ///   偏移0x480: 低EL的AArch64 IRQ异常
    ///   偏移0x500: 低EL的AArch64 FIQ异常
    ///   偏移0x580: 低EL的AArch64 SError异常
    ///   偏移0x600: 低EL的AArch32同步异常
    ///   偏移0x680: 低EL的AArch32 IRQ异常
    ///   偏移0x700: 低EL的AArch32 FIQ异常
    ///   偏移0x780: 低EL的AArch32 SError异常
    /// 对于用户态actor，SVC异常向量入口(偏移0x400)必须重定向到fault_handler
    /// 以捕获用户态actor的系统调用请求
    uint64_t vbar_el1;

    /// SPSR_EL1 - 保存的程序状态寄存器（EL1级别）
    /// 记录异常发生前的PSTATE（处理器状态）：
    ///   [3:0] M  - 异常前的特权级别(EL)和SP选择
    ///              0b0000=EL0t, 0b0101=EL1h, 0b0110=EL2h
    ///   [6]   F  - FIQ掩码(1=禁用FIQ)
    ///   [7]   I  - IRQ掩码(1=禁用IRQ)
    ///   [9]   D  - Debug掩码
    ///   [21]  SS - 软件步进标志
    ///   [22]  IL - 非法异常状态
    ///   [23]  SSBS - 投机存储绕过安全位
    ///   [28]  PAN - 特权访问永不位(防止内核访问用户内存)
    ///   [31]  N   - 负数条件标志
    ///   [30]  Z   - 零条件标志
    ///   [29]  C   - 进位条件标志
    ///   [28]  V   - 溢出条件标志
    uint64_t spsr_el1;

    /// ELR_EL1 - 异常链接寄存器（EL1级别）
    /// 保存异常返回地址，ERET指令将PC恢复到此地址
    uint64_t elr_el1;

    /// SP_EL0 - EL0栈指针寄存器
    /// 用户态(EL0)程序的栈指针。ARM64有独立的SP_EL0和SP_EL1寄存器，
    /// 在异常处理中使用SP_ELx（当前EL的SP）或SP_EL0（EL0的SP）
    uint64_t sp_el0;

    /// FAR_EL1 - 故障地址寄存器（EL1级别）
    /// 记录最近发生的同步故障（如页故障、对齐故障）的虚拟地址
    /// 对于页故障，FAR_EL1保存触发故障的访问地址
    uint64_t far_el1;

    /// ESR_EL1 - 异常症状寄存器（EL1级别）
    /// 描述最近异常的类别和原因：
    ///   [31:26] EC - 异常类别(Exception Class)
    ///              0b000000=未知原因
    ///              0b010001=SVC from AArch64(重要：用户actor的SVC异常)
    ///              0b100000=指令abort(低EL)
    ///              0b100101=数据abort(低EL，含页故障)
    ///              0b110000=SP对齐故障
    ///   [25]    IL - 指令长度(1=32位ARM指令，0=16位Thumb指令)
    ///   [24:0]  ISS - 异常特定症状信息(Exception Specific Syndrome)
    ///              对于数据abort(EC=0b100101)：
    ///              ISS[9]  = WnR(写而非读标志)
    ///              ISS[5:0] = DFSC(数据故障状态码)
    uint64_t esr_el1;

    // =====================================================================
    // EL2 虚拟化控制寄存器组
    // 仅在测试用例包含VM actor时需要保存和修改。
    // EL2是ARM64的虚拟化管理级别，控制客户机(VM)的行为。
    // =====================================================================

    /// HCR_EL2 - 虚拟化配置寄存器（EL2级别）
    /// 控制从EL0/EL1到EL2的陷阱行为和虚拟化特性：
    ///   [0]   VM   - 虚拟化管理器启用(=第二阶段翻译启用)
    ///   [1]   SWIO - STA/STB指令陷阱(步进跟踪)
    ///   [2]   PTW  - 页表遍历陷阱(Stage-2页表遍历错误)
    ///   [3]   FMO  - FIQ掩码覆盖(FIQ路由到EL2)
    ///   [4]   IMO  - IRQ掩码覆盖(IRQ路由到EL2)
    ///   [5]   AMO  - SError掩码覆盖(SError路由到EL2)
    ///   [7]   PT   - 保护陷阱启用
    ///   [8]   TSC  - SVC指令陷阱(SVC从EL0/EL1陷阱到EL2)
    ///   [9]   TSW  - 缓存维护指令陷阱(DC SW等)
    ///   [10]  TCR  - TLB缓存维护指令陷阱
    ///   [12]  TVO  - 虚拟机偏移陷阱
    ///   [13]  TIC  - Icache维护指令陷阱
    ///   [14]  TID  - IMPLEMENTATION DEFINED指令陷阱
    ///   [15]  TPR  - 特权寄存器陷阱(MSR/MRS从EL1陷阱到EL2)
    ///   [16]  TPC  - 性能计数器陷阱(PMU寄存器从EL1陷阱到EL2)
    ///   [17]  TPU  - PMU用户访问陷阱
    ///   [18]  TTR  - TLB维护指令陷阱(TLBBI等)
    ///   [19]  TWE  - WFE陷阱
    ///   [20]  TWI  - WFI陷阱
    ///   [21]  TD   - 调试陷阱
    ///   [22]  TDE  - 调试异常陷阱
    ///   [23]  HD   - 硬件断点陷阱
    ///   [24]  HCD  - 硬件上下文断点陷阱
    ///   [26]  TSC2 - 第二个SVC陷阱位(EL2的SVC)
    ///   [27]  TTR2 - 第二组TLB陷阱
    ///   [28]  TTLB - TLB维护陷阱
    ///   [29]  TVM  - 虚拟内存控制陷阱(MSR/MRS控制MMU)
    ///   [30]  TRVM - 虚拟内存读取陷阱(读取MMU配置)
    ///   [31]  RW   - 低EL执行模式。1=AArch64, 0=AArch32
    ///   [33]  TSC  - SVC陷阱(扩展位，与[8]配合)
    ///   [34]  TSW  - 缓存维护陷阱(扩展位)
    ///   [38]  TVM  - 虚拟内存陷阱(扩展位)
    ///   [40]  TRVM - 内存读取陷阱(扩展位)
    ///   [41]  TWI  - WFI陷阱(扩展位)
    ///   [44]  TPU  - PMU用户陷阱(扩展位)
    ///   [45]  TPC  - PMU计数器陷阱(扩展位)
    ///   [47]  FC   - 强制上下文同步
    ///   [48]  E2H  - EL2启用主机特性(VHE模式)
    ///   [52]  API  - 特权访问永不位(AP[3]不可写)
    ///   [54]  APK  - 特权访问永不键位(PAN键不可写)
    ///   [58]  FIEN - FPEN陷阱(浮点/NEON指令陷阱)
    ///   [61]  NV   - 嵌套虚拟化启用
    ///   [62]  NV1  - 嵌套虚拟化模式1
    ///   [63]  NV2  - 嵌套虚拟化模式2
    /// 对于VM actor的关键配置：
    ///   - VM=1: 启用第二阶段翻译(S2PT)
    ///   - RW=1: 客户机使用AArch64
    ///   - TSC=1: SVC陷阱到EL2(捕获客户机系统调用)
    ///   - IMO=1, FMO=1: 中断路由到EL2
    ///   - TPMCR=0: 不陷阱PMCR(允许客户机访问PMU)
    uint64_t hcr_el2;

    /// VTTBR_EL2 - 虚拟页表基址寄存器（EL2级别）
    /// 指向第二阶段页表(S2PT)的基地址。
    /// ARM64虚拟化使用两阶段地址翻译：
    ///   第一阶段(IPA→VA): 由客户机的TTBR0_EL1/TTBR1_EL1控制
    ///   第二阶段(IPA→PA): 由VTTBR_EL2控制，将客户机物理地址(IPA)
    ///                      翻译为宿主机物理地址(HPA)
    /// 这类似于x86的EPT/NPT机制。
    /// 在侧信道测试中，S2PT用于构建HPA-GPA地址碰撞，
    /// 以检测依赖物理地址布局的侧信道泄漏
    uint64_t vttbr_el2;

    /// VBAR_EL2 - 向量基址寄存器（EL2级别）
    /// 指向EL2异常向量表的基地址。
    /// 当客户机(VM)发生异常且被HCR_EL2陷阱位路由到EL2时，
    /// 处理器根据VBAR_EL2找到对应的异常处理向量
    uint64_t vbar_el2;

    /// SPSR_EL2 - 保存的程序状态寄存器（EL2级别）
    /// 保存EL2异常发生前的PSTATE，用于ERET返回到客户机
    uint64_t spsr_el2;

    /// ELR_EL2 - 异常链接寄存器（EL2级别）
    /// 保存从EL2返回到客户机的目标地址
    uint64_t elr_el2;

    /// MAIR_EL2 - 内存属性间接寄存器（EL2级别）
    /// 定义第二阶段翻译(S2PT)使用的内存属性。
    /// 与MAIR_EL1类似，但用于EL2的地址翻译属性配置。
    /// S2PT页表项中的MAIR索引号指向此寄存器的对应属性描述
    uint64_t mair_el2;

    /// TCR_EL2 - 页表控制寄存器（EL2级别）
    /// 配置VTTBR_EL2的翻译参数（类似于TCR_EL1对TTBR的控制）：
    ///   [5:0]   T0SZ  - 地址空间大小(64-T0SZ=虚拟地址位数)
    ///   [8]     IRGN0 - 内部缓存属性
    ///   [10]    ORGN0 - 外部缓存属性
    ///   [12:10] SH0   - 共享属性
    ///   [14:12] TG0   - 粒度(4KB/16KB/64KB)
    ///   [18:16] PS    - 物理地址大小
    ///   [21:16] T1SZ  - 第二地址空间大小(VHE模式)
    uint64_t tcr_el2;

    // =====================================================================
    // 性能监控与调试控制寄存器
    // 这些寄存器控制PMU的访问权限和计数器行为
    // =====================================================================

    /// PMCR_EL0 - 性能监控控制寄存器（EL0级别）
    /// 控制ARM64 PMU的全局行为：
    ///   [0]  E  - 启用所有计数器(全局启用位)
    ///   [1]  P  - 重置事件计数器(写1清零所有事件计数器)
    ///   [2]  C  - 重置周期计数器(写1清零周期计数器)
    ///   [3]  D  - 周期计数器时钟分频器(1=除以64计数)
    ///   [4]  X  - 导出启用(允许外部调试器访问PMU)
    ///   [5]  DP - 禁用周期计数器(1=停止周期计数器计数)
    ///   [6]  LC - 周期计数器长计数启用(56位而非32位)
    ///   [11:7] N - 可用计数器数量(实现定义，A72=6，A76=6)
    /// 测试用例需要PMCR_EL0.E=1启用计数器，PMCR_EL0.DP=0启用周期计数器
    uint64_t pmcr_el0;

    /// MDCR_EL2 - 监控调试配置寄存器（EL2级别）
    /// 控制从低EL对PMU和调试寄存器的访问陷阱：
    ///   [7]  HPME   - 硬件性能监控事件启用(允许PMU计数)
    ///   [8]  TDOSA  - 调试OS访问陷阱(从EL1/EL0的调试寄存器陷阱到EL2)
    ///   [9]  TDA    - 调试访问陷阱(从EL0的调试寄存器陷阱到EL2)
    ///   [10] TDR    - 调试ROM访问陷阱
    ///   [11] TDRA   - 调试寄存器访问陷阱
    ///   [12] TDE    - 调试异常陷阱
    ///   [14] HPMD   - 硬件性能监控禁用(陷阱PMU事件到EL2)
    ///   [17] MPMDE  - 性能监控禁用陷阱
    ///   [28] TPMCR  - PMCR陷阱(从EL1/EL0的PMCR访问陷阱到EL2)
    ///   [29] TPMS   - PMSELR陷阱
    ///   [30] TPMRC  - PMXEVCNTR陷阱(计数器寄存器读取陷阱)
    ///   [31] TPMR   - PMXEVTYPER陷阱(事件类型寄存器陷阱)
    /// 关键配置：
    ///   - HPME=1, HPMD=0: 启用PMU事件计数
    ///   - TPMCR=0: 不陷阱PMCR(允许EL0/EL1访问PMCR_EL0)
    ///   - TPMRC=0: 不陷阱计数器读取(允许直接读取PMC值)
    uint64_t mdcr_el2;

    /// PMUSERENR_EL0 - 性能监控用户使能寄存器（EL0级别）
    /// 控制EL0(用户态)对PMU寄存器的访问权限：
    ///   [0] EN  - 启用EL0对PMU寄存器的访问
    ///             EN=1时，EL0可以直接读取PMXEVCNTR_EL0等寄存器
    ///             这对于侧信道测试至关重要，因为测试用例运行在EL0
    ///             需要直接读取PMC值来收集硬件追踪(htrace)
    ///   [2] CR  - 启用EL0对周期计数器寄存器的访问(PMCCNTR_EL0)
    ///   [3] ER  - 启用EL0对事件计数器寄存器的访问(PMXEVCNTR_EL0)
    ///   [4] SW  - 启用EL0对PMU软件增量寄存器的访问(PMSWINC_EL0)
    /// 在侧信道测试中，必须设置EN=1使测试用例能从EL0读取PMC值
    uint64_t pmuserenr_el0;

    // =====================================================================
    // EL0 浮点控制寄存器
    // 浮点状态可能被测试用例修改，需要在测试后恢复
    // =====================================================================

    /// FPCR - 浮点控制寄存器
    /// 控制浮点运算的行为：
    ///   [22:20] RMODE - 舍入模式(RN=000, RP=001, RM=010, RZ=011)
    ///   [24]    FZ    - Flush-to-zero模式(次正规数→零)
    ///   [25]    DN    - Default NaN模式(所有NaN→默认NaN)
    ///   [26]    AH    - Alternative half-precision模式
    ///   [19]    NEP   - NaN传播增强模式
    uint64_t fpcr;

    /// FPSR - 浮点状态寄存器
    /// 记录浮点运算的状态标志：
    ///   [0]  IOC - Invalid Operation Cumulative(非法运算)
    ///   [1]  DZC - Division by Zero Cumulative(除零)
    ///   [2]  OFC - Overflow Cumulative(溢出)
    ///   [3]  UFC - Underflow Cumulative(下溢)
    ///   [4]  IXC - Inexact Cumulative(不精确)
    ///   [7]  IDC - Input Denormal Cumulative(输入次正规数)
    uint64_t fpsr;

    // =====================================================================
    // 实现特定寄存器（Cortex A72/A76预取器控制）
    // 这些寄存器的编码和位定义因处理器实现而异。
    // 必须根据MIDR_EL1识别的CPU型号来选择正确的编码和掩码。
    //
    // ARM64实现特定寄存器使用S3_0_C15_C<x>_<y>编码格式访问，
    // 该编码空间在ARMv8-A中为IMPLEMENTATION DEFINED。
    // 不同Cortex型号可能使用不同的CRm和Op2值。
    //
    // Cortex A72 (MIDR_EL1.Part=0xD08, ARMv8.0-A):
    //   CPUACTLR_EL1编码: S3_0_C15_C2_0
    //   - bit[56]: L2数据预取禁用(L2 prefetch disable)
    //     设置此位后，L2缓存的数据预取器停止预取操作，
    //     减少预取器干扰侧信道测量的缓存访问模式
    //   - bit[51]: L1数据预取禁用(L1 data prefetch disable)
    //     设置此位后，L1数据缓存的预取器停止预取操作，
    //     这对于Prime+Probe等缓存侧信道测试至关重要，
    //     因为预取器可能提前将数据加载到缓存中导致假阳性
    //
    // Cortex A76 (MIDR_EL1.Part=0xD0B, ARMv8.2-A):
    //   CPUACTLR_EL1编码: S3_0_C15_C2_0
    //   - bit[56]: 数据预取禁用(data prefetch disable)
    //     注意：A76的bit[56]同时控制L1和L2预取器，
    //     与A72分开控制L1(bit[51])和L2(bit[56])不同
    //   - bit[51]: 不用于预取器控制(A76此位为RES0或其他功能)
    //
    // 警告：这些编码来自ARM Cortex TRM（技术参考手册），
    // 不同版本的TRM可能给出不同的编码。如果预取器控制失败，
    // 请检查实际CPU的TRM文档确认正确编码。
    // =====================================================================

    /// CPUACTLR_EL1 - CPU辅助控制寄存器（实现特定）
    /// 保存原始CPUACTLR_EL1值，用于恢复预取器配置。
    /// 此寄存器用于控制L1/L2数据预取器，减少侧信道测量噪声。
    /// 编码和位定义因Cortex型号而异（参见上方注释）
    uint64_t cpuactlr_el1;

    /// CPUECTLR_EL1 - CPU扩展控制寄存器（实现特定）
    /// 保存原始CPUECTLR_EL1值。
    /// Cortex A72的CPUECTLR_EL1控制处理器微架构行为：
    ///   - 流水线配置
    ///   - 预取策略细节
    ///   - L2缓存行为控制
    /// Cortex A76的CPUECTLR_EL1功能类似但位定义不同
    uint64_t cpuectlr_el1;

    // =====================================================================
    // 用户actor专用保存字段
    // =====================================================================

    /// vbar_el1_saved - 用户actor入口时保存的原始VBAR_EL1值
    /// 当配置用户actor的SVC异常向量时，需要修改VBAR_EL1
    /// 使其指向我们的fault_handler向量表（inner_vector_table），
    /// 这样EL0的SVC异常会跳转到fault_handler处理。
    /// 原始的VBAR_EL1值（通常是内核的异常向量表地址）
    /// 保存在此字段中，以便测试完成后恢复。
    /// 如果没有用户actor，此字段不会被使用。
    uint64_t vbar_el1_saved;
#endif
} __attribute__((packed)) special_registers_t;

/// 全局原始特殊寄存器状态指针
/// 指向分配的special_registers_t结构，用于保存和恢复寄存器状态
extern special_registers_t *orig_special_registers_state;

/// @brief 设置特殊寄存器：保存原始状态，然后根据测试用例需求修改
/// 配置顺序：保存原始状态 -> 禁用预取器 -> 启用PMU EL0访问
///            -> (用户actor)配置VBAR_EL1和TTBR0_EL1
///            -> (VM actor)配置HCR_EL2和VTTBR_EL2
/// @return 0表示成功，负数表示错误码
int set_special_registers(void);

/// @brief 恢复特殊寄存器：将所有修改过的寄存器恢复到原始值
/// 使用if-zero安全检查，因为初始化可能中途失败导致部分寄存器未保存
void restore_special_registers(void);

/// @brief 初始化特殊寄存器管理器：分配special_registers_t结构
/// @return 0表示成功，负数表示错误码
int init_special_register_manager(void);

/// @brief 释放特殊寄存器管理器：释放分配的内存
void free_special_register_manager(void);

#ifdef ARCH_ARM
/// @brief 为用户态actor配置系统寄存器
/// 设置VBAR_EL1使SVC异常重定向到fault_handler，
/// 配置TTBR0_EL1页表使EL0可以访问沙箱内存
/// @return 0表示成功，负数表示错误码
int set_msrs_for_user_actors(void);

/// @brief 为虚拟机(VM)actor配置系统寄存器
/// 配置HCR_EL2陷阱位使客户机操作路由到EL2，
/// 设置VTTBR_EL2使第二阶段页表(S2PT)生效，
/// 配置其他EL2寄存器(VBAR_EL2, MAIR_EL2, TCR_EL2等)
/// @return 0表示成功，负数表示错误码
int set_msrs_for_vm_actors(void);
#endif

#endif // _MSR_H_

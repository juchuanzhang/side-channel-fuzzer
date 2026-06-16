/// 文件：ARM64系统寄存器（MSR/系统寄存器）管理的实现
///
/// 本文件实现了ARM64架构下系统寄存器的保存、修改和恢复功能。
/// 这些功能是侧信道模糊测试工具(Revizor)的核心基础设施：
///
/// 【背景与动机】
/// 侧信道攻击利用微架构状态（缓存、TLB、分支预测器等）的共享性
/// 来泄露本应隔离的信息。为了精确检测这种泄露，必须：
///   1. 禁用硬件预取器：预取器会主动将数据加载到缓存，
///      产生与侧信道泄露模式类似的缓存访问痕迹，导致假阳性。
///      禁用预取器确保只有被测代码的显式访问才会影响缓存状态。
///   2. 启用EL0的PMU访问：测试用例运行在最低特权级别(EL0)，
///      需要直接读取性能计数器(PMC)值来收集硬件追踪(htrace)，
///      否则每次读取PMC都需要系统调用，引入不可控的测量噪声。
///   3. 重定向异常向量：用户态actor执行SVC指令时，
///      应跳转到我们的fault_handler处理，而非内核的正常系统调用处理，
///      确保测试用例的异常行为在沙箱内被安全处理。
///   4. 配置虚拟化寄存器：VM actor需要第二阶段页表(S2PT)和
///      虚拟化陷阱来隔离客户机与宿主机，同时允许HPA-GPA地址碰撞
///      以检测物理地址依赖的侧信道泄露。
///
/// 【ARM64与x86的差异】
/// ARM64的系统寄存器访问使用mrs(msr read)/msr(msr write)指令，
/// 而x86使用rdmsr/wrmsr指令。ARM64的关键差异：
///   - ARM64有4个特权级别(EL0-EL3)，x86有0-3环(Ring0-Ring3)
///   - ARM64的VBAR_ELx指向异常向量表(16个128字节入口)，
///     x86的IDT指向中断描述符表(256个16字节入口)
///   - ARM64的虚拟化使用两阶段翻译(S1PT+S2PT)，
///     x86使用EPT(Intel)或NPT(AMD)单阶段嵌套翻译
///   - ARM64的实现特定寄存器(CPUACTLR_EL1等)编码因Cortex型号而异，
///     x86的MSR使用统一的地址空间
///
/// 【实现特定寄存器访问】
/// ARM64的实现特定寄存器使用S3_0_C15_C<x>_<y>编码格式，
/// 该编码空间为IMPLEMENTATION DEFINED，不同Cortex型号使用
/// 不同的CRm和Op2值。本文件根据MIDR_EL1识别的CPU型号
/// 动态选择正确的编码和位掩码。
///
/// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "special_registers.h"
#include "fault_handler.h"
#include "main.h"
#include "shortcuts.h"
#include "test_case_parser.h"

/// 全局原始特殊寄存器状态指针
/// 指向分配的special_registers_t结构，用于保存所有修改前的寄存器值
/// 测试执行前保存，执行后恢复，确保系统稳定性
special_registers_t *orig_special_registers_state = NULL;

// =====================================================================
// ARM64实现特定寄存器编码定义
//
// ARM64的实现特定系统寄存器没有固定的名称，而是通过
// S<Op0>_<Op1>_C<CRn>_C<CRm>_<Op2>编码格式在mrs/msr指令中访问。
//
// 不同Cortex型号的实现特定寄存器编码不同：
//   Cortex A72: CPUACTLR_EL1 = S3_0_C15_C2_0
//               CPUECTLR_EL1 = S3_0_C15_C1_0
//   Cortex A76: CPUACTLR_EL1 = S3_0_C15_C2_0 (与A72相同编码)
//               CPUECTLR_EL1 = S3_0_C15_C1_0 (与A72相同编码)
//
// 注意：以上编码来自ARM Cortex TRM（技术参考手册），但不同版本
// 的TRM可能给出不同编码。如果预取器控制失败，请检查实际CPU的
// TRM文档确认正确编码。编码格式说明：
//   S3    = Op0=3 (系统寄存器空间)
//   _0    = Op1=0 (EL1级别访问)
//   _C15  = CRn=15 (实现定义寄存器组)
//   _C2_0 = CRm=2, Op2=0 (CPUACTLR_EL1的编码)
//   _C1_0 = CRm=1, Op2=0 (CPUECTLR_EL1的编码)
// =====================================================================

/// Cortex A72的CPUACTLR_EL1系统寄存器编码
/// 此寄存器控制L1/L2数据预取器：
///   bit[56]: L2数据预取禁用(L2 prefetch disable)
///   bit[51]: L1数据预取禁用(L1 data prefetch disable)
/// 禁用预取器是减少侧信道测量噪声的关键步骤
#define CPUACTLR_EL1_ENCODING "S3_0_C15_C2_0"

/// Cortex A72/A76的CPUECTLR_EL1系统寄存器编码
/// 此寄存器控制处理器微架构行为（预取策略、流水线配置等）
#define CPUECTLR_EL1_ENCODING "S3_0_C15_C1_0"

// =====================================================================
// ARM64实现特定预取器控制位掩码
//
// 不同Cortex型号的预取器控制位不同：
//   Cortex A72 (ARMv8.0-A):
///     - bit[56]: L2数据预取禁用
///       设置此位后L2缓存的数据预取器停止工作，
///       L2预取器会根据访问模式提前将数据从主存加载到L2，
///       这会在Prime+Probe测量中产生与真实驱逐模式类似的缓存痕迹，
///       导致假阳性（误判为侧信道泄露）。
///     - bit[51]: L1数据预取禁用
///       设置此位后L1数据缓存的预取器停止工作，
///       L1预取器会根据访问模式提前将数据从L2加载到L1，
///       在侧信道测量中同样会产生假阳性。
///       A72可以分别控制L1和L2预取器，提供了最精细的控制粒度。
///
///   Cortex A76 (ARMv8.2-A):
///     - bit[56]: 数据预取禁用(data prefetch disable)
///       注意：A76的bit[56]同时控制L1和L2数据预取器，
///       不能像A72那样分别控制。这是因为A76的预取器设计
///       将L1和L2预取统一管理，bit[56]实际上禁用了整个预取流水线。
///     - bit[51]: 不用于预取器控制(A76此位为RES0或保留功能)
///
///   其他Cortex型号：
///     预取器控制位可能完全不同，本文件仅处理A72和A76。
///     对于未知型号，预取器控制功能将跳过（打印警告信息）。
// =====================================================================

/// Cortex A72 L2数据预取禁用掩码 - CPUACTLR_EL1 bit[56]
/// A72可以单独禁用L2预取器，而保持L1预取器启用
#define CORTEX_A72_L2_PREFETCH_DISABLE BIT_(56)

/// Cortex A72 L1数据预取禁用掩码 - CPUACTLR_EL1 bit[51]
/// A72可以单独禁用L1预取器，而保持L2预取器启用
/// 通常同时禁用L1和L2预取器以获得最干净的侧信道测量
#define CORTEX_A72_L1_PREFETCH_DISABLE BIT_(51)

/// Cortex A72完整预取器禁用掩码 - 同时禁用L1和L2预取器
/// 这是侧信道测试的标准配置，消除所有预取器产生的缓存噪声
#define CORTEX_A72_PREFETCH_DISABLE_ALL (CORTEX_A72_L2_PREFETCH_DISABLE | CORTEX_A72_L1_PREFETCH_DISABLE)

/// Cortex A76数据预取禁用掩码 - CPUACTLR_EL1 bit[56]
/// A76的bit[56]同时禁用L1和L2预取器（统一控制）
/// 无法像A72那样分别控制L1和L2
#define CORTEX_A76_PREFETCH_DISABLE BIT_(56)

// =====================================================================
// ARM64 PMU访问控制位掩码
// =====================================================================

/// PMUSERENR_EL0.EN位掩码 - 启用EL0对PMU寄存器的访问
/// 设置此位后，EL0程序可以直接读取PMXEVCNTR_EL0等PMU寄存器，
/// 无需通过系统调用。这对侧信道测试至关重要，因为：
///   1. 测试用例运行在EL0（用户态），需要读取PMC值收集htrace
///   2. 通过SVC读取PMC会引入不可控的系统调用延迟和缓存噪声
///   3. 直接从EL0读取PMC是最精确的测量方法
#define PMUSERENR_EL0_EN BIT_(0)

/// PMUSERENR_EL0.CR位掩码 - 启用EL0对周期计数器(PMCCNTR_EL0)的访问
#define PMUSERENR_EL0_CR BIT_(2)

/// PMUSERENR_EL0.ER位掩码 - 启用EL0对事件计数器(PMEVCNTR<n>)的访问
#define PMUSERENR_EL0_ER BIT_(3)

// =====================================================================
// ARM64异常向量相关常量
// =====================================================================

/// SVC异常向量偏移量（EL0 AArch64同步异常向量入口）
/// 当EL0程序执行SVC指令时，CPU跳转到VBAR_EL1 + 0x400处执行异常处理。
/// 这是ARM64异常向量表的第9个入口（偏移0x400）：
///   低EL的AArch64同步异常向量，包含：
///     - SVC指令（从EL0调用系统服务）
///     - HVC指令（从EL0调用虚拟化管理器）
///     - SMC指令（从EL0调用安全监控器）
/// 在侧信道测试中，用户态actor执行SVC指令后应跳转到fault_handler，
/// 而不是内核的正常系统调用处理函数，以确保测试在沙箱内安全终止。
#define SVC_VECTOR_OFFSET_EL0_AA64 0x400

// =====================================================================
// 私有模块级函数
// =====================================================================

/// @brief 读取实现特定系统寄存器（CPUACTLR_EL1/CPUECTLR_EL1）
/// 根据CPU型号选择正确的系统寄存器编码。
/// 注意：实现特定寄存器的编码因处理器型号而异，
/// 目前仅支持Cortex A72和A76，其他型号将打印警告并返回0
/// @param reg_encoding 系统寄存器编码字符串（如"S3_0_C15_C2_0"）
/// @return 寄存器值，若读取失败则返回0
static inline uint64_t read_impl_specific_reg(const char *reg_encoding)
{
    uint64_t val = 0;
    asm volatile("mrs %0, " reg_encoding "\n isb\n" : "=r"(val));
    return val;
}

/// @brief 写入实现特定系统寄存器（CPUACTLR_EL1/CPUECTLR_EL1）
/// 根据CPU型号选择正确的系统寄存器编码并写入值。
/// 注意：写入实现特定寄存器需要谨慎，错误的值可能导致处理器异常。
/// 写入后添加ISB屏障确保后续指令看到新的寄存器值。
/// @param reg_encoding 系统寄存器编码字符串
/// @param value 要写入的值
static inline void write_impl_specific_reg(const char *reg_encoding, uint64_t value)
{
    asm volatile("msr " reg_encoding ", %0\n isb\n" :: "r"(value));
}

// =====================================================================
// 保存原始系统寄存器状态
// =====================================================================

/// @brief 保存所有关键系统寄存器的原始值
/// 在修改任何系统寄存器之前调用，将当前值保存到orig_special_registers_state。
/// 这些保存的值将在测试执行完毕后用于恢复系统状态，确保宿主系统稳定。
///
/// 保存策略：
///   1. EL1核心控制寄存器组 - 必须保存，这些寄存器控制MMU、缓存等核心功能
///   2. EL2虚拟化寄存器组 - 仅在当前EL>=2时保存（如果运行在EL1则跳过）
///   3. EL0性能监控与浮点寄存器 - 必须保存，PMU和浮点状态可能被测试修改
///   4. 实现特定寄存器 - 根据CPU型号保存CPUACTLR_EL1和CPUECTLR_EL1
///
/// @return 0表示成功，-EIO表示断言失败
static int store_special_registers(void)
{
    ASSERT(orig_special_registers_state != NULL, "store_special_registers");
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));

    // === EL1 核心控制寄存器组 ===
    // 这些寄存器控制ARM64处理器的内存管理、异常处理和缓存行为，
    // 是系统稳定运行的基础。任何误配置都可能导致：
    //   - MMU配置错误 → 内存访问异常 → 内核崩溃
    //   - 缓存配置错误 → 数据一致性问题 → 文件系统损坏
    //   - 异常向量表丢失 → 无法处理中断 → 系统死锁

    // SCTLR_EL1：系统控制寄存器，控制MMU、缓存、对齐检查等
    // 测试用例可能修改此寄存器（例如临时禁用对齐检查），
    // 必须保存原始值以便恢复
    read_msr("SCTLR_EL1", orig_special_registers_state->sctlr_el1);

    // TTBR0_EL1：页表基址寄存器0，指向EL0/EL1低地址空间页表
    // 对于用户态actor，需要将此寄存器修改为指向沙箱页表
    // 原始值指向内核的用户空间页表（pgd）
    read_msr("TTBR0_EL1", orig_special_registers_state->ttbr0_el1);

    // TTBR1_EL1：页表基址寄存器1，指向内核高地址空间页表
    // Linux内核使用swapper_pg_dir作为TTBR1_EL1的页表基址
    read_msr("TTBR1_EL1", orig_special_registers_state->ttbr1_el1);

    // TCR_EL1：页表控制寄存器，配置TTBR0/TTBR1的翻译参数
    // 包含地址空间大小、粒度、缓存属性等关键配置
    read_msr("TCR_EL1", orig_special_registers_state->tcr_el1);

    // MAIR_EL1：内存属性间接寄存器，定义页表属性的缓存行为
    // 页表项的AttrIdx字段指向此寄存器中对应的属性描述
    read_msr("MAIR_EL1", orig_special_registers_state->mair_el1);

    // VBAR_EL1：向量基址寄存器，指向异常向量表基地址
    // 用户态actor的SVC异常需要通过此寄存器重定向到fault_handler
    read_msr("VBAR_EL1", orig_special_registers_state->vbar_el1);

    // SPSR_EL1：保存的程序状态寄存器，记录异常发生前的PSTATE
    read_msr("SPSR_EL1", orig_special_registers_state->spsr_el1);

    // ELR_EL1：异常链接寄存器，保存异常返回地址
    read_msr("ELR_EL1", orig_special_registers_state->elr_el1);

    // SP_EL0：EL0栈指针，用户态程序的栈指针寄存器
    read_msr("SP_EL0", orig_special_registers_state->sp_el0);

    // FAR_EL1：故障地址寄存器，记录最近故障的虚拟地址
    read_msr("FAR_EL1", orig_special_registers_state->far_el1);

    // ESR_EL1：异常症状寄存器，记录最近异常的类别和原因
    read_msr("ESR_EL1", orig_special_registers_state->esr_el1);

    // === EL0 性能监控与浮点寄存器 ===
    // PMU和浮点寄存器可能被测试用例修改（特别是FPCR/FPSR）
    // 需要保存原始值以确保测试后恢复

    // PMCR_EL0：性能监控控制寄存器
    // 控制PMU的全局启用/禁用和计数器重置
    read_msr("PMCR_EL0", orig_special_registers_state->pmcr_el0);

    // PMUSERENR_EL0：性能监控用户使能寄存器
    // 控制EL0对PMU的访问权限，测试用例需要此权限
    read_msr("PMUSERENR_EL0", orig_special_registers_state->pmuserenr_el0);

    // FPCR：浮点控制寄存器
    // 控制浮点运算的舍入模式、flush-to-zero等行为
    // 测试用例可能修改舍入模式来影响浮点运算结果
    read_msr("FPCR", orig_special_registers_state->fpcr);

    // FPSR：浮点状态寄存器
    // 记录浮点运算的状态标志（溢出、除零等）
    read_msr("FPSR", orig_special_registers_state->fpsr);

    // === EL2 虚拟化寄存器组 ===
    // 仅在当前异常级别>=2时保存（如果运行在EL1则这些寄存器不可访问）
    // ARM64的EL2寄存器只有在EL2或更高级别才能通过mrs/msr访问
    // Linux内核通常运行在EL1（使用KVM时才在EL2运行）

    // 检测当前异常级别
    uint64_t current_el = 0;
    read_msr("CurrentEL", current_el);
    current_el = (current_el >> 2) & 0b11;

    if (current_el >= 2) {
        // HCR_EL2：虚拟化配置寄存器，控制EL0/EL1到EL2的陷阱行为
        // 仅在存在VM actor时需要修改，但仍保存原始值以防意外修改
        read_msr("HCR_EL2", orig_special_registers_state->hcr_el2);

        // VTTBR_EL2：虚拟页表基址寄存器，指向第二阶段页表(S2PT)
        // VM actor使用此寄存器进行GPA→HPA地址翻译
        read_msr("VTTBR_EL2", orig_special_registers_state->vttbr_el2);

        // VBAR_EL2：EL2向量基址寄存器，指向EL2异常向量表
        read_msr("VBAR_EL2", orig_special_registers_state->vbar_el2);

        // SPSR_EL2：保存的程序状态寄存器（EL2）
        read_msr("SPSR_EL2", orig_special_registers_state->spsr_el2);

        // ELR_EL2：异常链接寄存器（EL2）
        read_msr("ELR_EL2", orig_special_registers_state->elr_el2);

        // MAIR_EL2：内存属性间接寄存器（EL2）
        // 用于S2PT的内存属性配置
        read_msr("MAIR_EL2", orig_special_registers_state->mair_el2);

        // TCR_EL2：页表控制寄存器（EL2）
        // 控制VTTBR_EL2的地址空间配置
        read_msr("TCR_EL2", orig_special_registers_state->tcr_el2);

        // MDCR_EL2：监控调试配置寄存器
        // 控制PMU和调试寄存器的EL2陷阱行为
        read_msr("MDCR_EL2", orig_special_registers_state->mdcr_el2);
    }

    // === 实现特定寄存器 ===
    // 根据CPU型号保存CPUACTLR_EL1和CPUECTLR_EL1
    // 这些寄存器控制硬件预取器等微架构行为，
    // 对侧信道测量精度有重大影响

    if (cpuinfo->implementer == ARM_IMPLEMENTER_ID) {
        // ARM自研核心，检查具体型号
        if (cpuinfo->part == CORTEX_A72_PART || cpuinfo->part == CORTEX_A76_PART) {
            // Cortex A72/A76：保存CPUACTLR_EL1和CPUECTLR_EL1
            // 这些寄存器包含预取器控制位，测试前需要禁用预取器，
            // 测试后需要恢复原始预取器配置
            orig_special_registers_state->cpuactlr_el1 =
                read_impl_specific_reg(CPUACTLR_EL1_ENCODING);
            orig_special_registers_state->cpuectlr_el1 =
                read_impl_specific_reg(CPUECTLR_EL1_ENCODING);
        } else {
            // 其他ARM Cortex型号（A73/A75/A77等）
            // 预取器控制编码可能不同，暂不保存
            // 如果未来支持新型号，需在此处添加对应的编码和位掩码
            PRINT_WARNS("store_special_registers",
                        "Unsupported ARM Cortex part 0x%x; "
                        "prefetcher control registers will NOT be saved\n",
                        cpuinfo->part);
        }
    } else {
        // 非ARM实现（如Qualcomm Kryo、Samsung Mongoose等）
        // 实现特定寄存器编码与ARM Cortex完全不同
        PRINT_WARNS("store_special_registers",
                    "Non-ARM implementer 0x%x; "
                    "implementation-specific registers will NOT be saved\n",
                    cpuinfo->implementer);
    }

    return 0;
}

// =====================================================================
// 预取器控制辅助函数
// =====================================================================

/// @brief 禁用ARM64硬件数据预取器
/// 根据CPU型号(Cortex A72/A76)选择正确的CPUACTLR_EL1位掩码，
/// 设置预取器禁用位来减少侧信道测量噪声。
///
/// 硬件预取器的工作原理：
///   预取器监视CPU的缓存访问模式（如顺序访问、步幅访问），
///   并提前将预测会被访问的数据加载到缓存中。
///   这种主动加载会改变缓存状态，在侧信道测量中表现为：
///   - Prime+Probe：预取器提前加载的数据占据缓存行，
///     使得被测代码的实际驱逐效果难以精确追踪
///   - Flush+Reload：预取器可能提前将刷新掉的缓存行重新加载，
///     导致Reload阶段的计数无法区分预取与真实访问
///   禁用预取器后，缓存状态的变化仅由被测代码的显式访问引起，
///   使侧信道测量结果更加精确和可重复。
///
/// @return 0表示成功，-EIO表示不支持或操作失败
static int disable_arm_prefetchers(void)
{
    // 检查是否为ARM实现
    if (cpuinfo->implementer != ARM_IMPLEMENTER_ID) {
        PRINT_WARNS("disable_arm_prefetchers",
                    "Non-ARM implementer 0x%x; cannot disable prefetchers\n",
                    cpuinfo->implementer);
        return 0; // 不视为错误，仅跳过预取器控制
    }

    uint64_t cpuactlr = read_impl_specific_reg(CPUACTLR_EL1_ENCODING);
    uint64_t prefetch_mask = 0;

    // 根据Cortex型号选择正确的预取器禁用位掩码
    switch (cpuinfo->part) {
    case CORTEX_A72_PART:
        // Cortex A72 (ARMv8.0-A): 可以分别控制L1和L2预取器
        // bit[56] = L2数据预取禁用
        // bit[51] = L1数据预取禁用
        // 通常同时禁用两者以获得最干净的侧信道测量
        // 注意：如果只需要测试L2预取器对侧信道的影响，
        // 可以只禁用L2而保持L1启用，但这不是常规配置
        prefetch_mask = CORTEX_A72_PREFETCH_DISABLE_ALL;
        PRINT_WARNS("disable_arm_prefetchers",
                    "Cortex A72: disabling L1 (bit51) and L2 (bit56) "
                    "data prefetchers\n");
        break;

    case CORTEX_A76_PART:
        // Cortex A76 (ARMv8.2-A): bit[56]同时控制L1和L2预取器
        // A76的预取器设计将L1和L2预取统一管理，
        // 不像A72那样可以分别控制。
        // 设置bit[56]会禁用整个预取流水线，
        // 包括L1预取器和L2预取器
        prefetch_mask = CORTEX_A76_PREFETCH_DISABLE;
        PRINT_WARNS("disable_arm_prefetchers",
                    "Cortex A76: disabling combined L1+L2 data prefetcher "
                    "(bit56)\n");
        break;

    default:
        // 其他ARM Cortex型号：预取器控制位编码可能不同
        // 不做任何修改，打印警告让用户知道预取器仍在运行
        PRINT_WARNS("disable_arm_prefetchers",
                    "Unsupported ARM Cortex part 0x%x; "
                    "prefetcher control NOT applied (measurement noise "
                    "may be higher)\n",
                    cpuinfo->part);
        return 0; // 不视为错误，仅跳过
    }

    // 应用预取器禁用掩码
    cpuactlr |= prefetch_mask;
    write_impl_specific_reg(CPUACTLR_EL1_ENCODING, cpuactlr);

    // 验证写入是否生效
    // 实现特定寄存器在某些情况下可能不可写（如安全配置锁定）
    uint64_t verify = read_impl_specific_reg(CPUACTLR_EL1_ENCODING);
    if ((verify & prefetch_mask) != prefetch_mask) {
        PRINT_ERRS("disable_arm_prefetchers",
                   "Failed to set prefetcher disable bits; "
                   "expected 0x%llx but got 0x%llx. "
                   "This may be caused by secure configuration lock "
                   "or firmware policy\n",
                   prefetch_mask, verify & prefetch_mask);
        // 不返回错误，因为预取器控制失败不影响测试的基本功能
        // 仅影响测量精度（噪声可能更高）
    }

    return 0;
}

/// @brief 启用从EL0级别访问ARM64 PMU寄存器
/// 设置PMUSERENR_EL0.EN位，允许EL0程序直接读取PMU寄存器。
///
/// 为什么需要EL0 PMU访问：
///   侧信道模糊测试的测试用例运行在最低特权级别(EL0)，
///   需要频繁读取性能计数器(PMC)值来收集硬件追踪(htrace)。
///   如果PMUSERENR_EL0.EN=0（默认状态），EL0程序访问PMU寄存器
///   会触发异常(UNDEFINED)，必须通过SVC系统调用让内核读取PMC。
///   但系统调用本身会引入不可控的测量噪声：
///   - SVC指令会修改缓存状态（内核系统调用处理代码的缓存足迹）
///   - 系统调用延迟不固定（内核调度器可能插入其他任务）
///   - 内核异常处理会刷新部分微架构状态
///   设置PMUSERENR_EL0.EN=1后，EL0可以直接通过mrs指令读取
///   PMXEVCNTR_EL0等寄存器，消除了系统调用引入的噪声。
///
/// 同时清除MDCR_EL2.TPMCR位（如果运行在EL2），确保PMCR_EL0
/// 不会被陷阱到EL2，使EL0可以正常访问PMCR。
///
/// @return 0表示成功
static int enable_pmu_el0_access(void)
{
    // 设置PMUSERENR_EL0：启用EL0对PMU寄存器的访问
    // EN=1：允许EL0访问PMU寄存器（PMXEVCNTR_EL0等）
    // CR=1：允许EL0访问周期计数器(PMCCNTR_EL0)
    // ER=1：允许EL0访问事件计数器(PMEVCNTR<n>通过PMXEVCNTR_EL0视图)
    // 这些权限对于侧信道测试的EL0代码是必需的
    uint64_t pmuserenr = PMUSERENR_EL0_EN | PMUSERENR_EL0_CR | PMUSERENR_EL0_ER;
    write_msr("PMUSERENR_EL0", pmuserenr);

    // 如果运行在EL2，还需要清除MDCR_EL2.TPMCR位
    // TPMCR位会使从EL0/EL1对PMCR_EL0的访问陷阱到EL2，
    // 导致EL0代码无法访问PMU控制寄存器
    uint64_t current_el = 0;
    read_msr("CurrentEL", current_el);
    current_el = (current_el >> 2) & 0b11;

    if (current_el >= 2) {
        uint64_t mdcr = 0;
        read_msr("MDCR_EL2", mdcr);
        // 清除TPMCR位(bit[28])：不陷阱PMCR访问到EL2
        // TPMCR=0意味着EL0/EL1可以直接访问PMCR_EL0和PMXEVTYPER_EL0
        // 而不会触发异常到EL2
        mdcr &= ~BIT_(28); // TPMCR
        write_msr("MDCR_EL2", mdcr);
    }

    return 0;
}

// =====================================================================
// 用户态actor配置
// =====================================================================

/// @brief 为用户态actor配置ARM64系统寄存器
///
/// 用户态actor运行在EL0（最低特权级别），通过SVC指令与EL1通信。
/// 在侧信道测试中，用户态actor执行SVC指令后应跳转到fault_handler，
/// 而不是内核的正常系统调用处理函数。这确保了：
///   1. 测试用例的异常行为在沙箱内被安全处理
///   2. SVC异常不会触发内核的完整系统调用处理流程
///      （后者会引入大量不可控的微架构噪声）
///   3. fault_handler可以精确记录异常发生时的微架构状态
///
/// 配置步骤：
///   1. 保存当前VBAR_EL1到vbar_el1_saved字段
///   2. 设置VBAR_EL1指向我们的异常向量表（inner_vector_table）
///      使SVC异常(偏移0x400)重定向到fault_handler
///   3. （可选）配置TTBR0_EL1页表权限，使EL0可以访问沙箱内存
///
/// 注意：此处保存VBAR_EL1到vbar_el1_saved而非vbar_el1字段，
/// 因为vbar_el1字段已在store_special_registers()中保存了原始值，
/// 而vbar_el1_saved用于记录"用户actor专用"的VBAR_EL1修改前的值。
/// 这样在restore_special_registers()中可以分别恢复：
///   - vbar_el1 → store_special_registers保存的原始值
///   - vbar_el1_saved → 用户actor修改前的值（可能已经被set_outer_fault_handlers修改）
///
/// @return 0表示成功，-EIO表示断言失败
int set_msrs_for_user_actors(void)
{
    // 保存当前VBAR_EL1到vbar_el1_saved字段
    // 当前VBAR_EL1可能已经被set_outer_fault_handlers()修改为outer_vector_table，
    // 也可能仍然是内核的原始向量表。无论哪种情况，都需要保存当前值。
    read_msr("VBAR_EL1", orig_special_registers_state->vbar_el1_saved);

    // 设置VBAR_EL1指向inner_vector_table
    // inner_vector_table是fault_handler.c中定义的异常向量表，
    // 其SVC异常向量入口(偏移0x400)被配置为跳转到fault_handler处理函数。
    // 当用户态actor执行SVC指令时，CPU根据VBAR_EL1 + 0x400找到
    // 对应的异常处理代码，跳转到fault_handler安全终止测试用例。
    //
    // 注意：这里使用set_inner_fault_handlers()函数（来自fault_handler.c）
    // 而非直接写VBAR_EL1，因为set_inner_fault_handlers还设置了
    // is_nested_fault标志等辅助状态。
    set_inner_fault_handlers();

    // TTBR0_EL1页表权限配置
    // 在ARM64中，TTBR0_EL1指向EL0/EL1低地址空间的页表。
    // 页表项(PTE)中的AP(Access Permissions)字段控制访问权限：
    //   AP[2:1] = 00 → EL0不可访问，EL1可读写(内核专用页)
    //   AP[2:1] = 01 → EL0/EL1均可读写(共享页，如沙箱数据)
    //   AP[2:1] = 10 → EL0不可访问，EL1只读
    //   AP[2:1] = 11 → EL0/EL1均可只读(共享只读页，如代码页)
    //
    // 对于用户态actor，沙箱内存页需要在TTBR0_EL1的页表中
    // 设置为EL0可访问(AP=01或AP=11)。这通常由sandbox_manager.c
    // 的页表管理代码处理(set_sandbox_page_tables等)，
    // 此处仅确保TTBR0_EL1指向包含正确权限的页表。
    //
    // 注意：如果使用FORCE_SMAP_OFF类似x86的配置，
    // ARM64中没有SMAP/SMEP的等价机制（ARM64的权限控制
    // 通过PTE的AP字段实现，而非像x86通过CR4.SMAP/CR4.SMEP位），
    // 因此不需要像x86那样禁用SMAP/SMEP。
    // ARM64的WXN位(SCTLR_EL1[18])可以实现类似SMEP的功能，
    // 但在侧信道测试中我们通常保持WXN=0以允许在内核态执行用户代码。

    return 0;
}

// =====================================================================
// 虚拟机(VM)actor配置
// =====================================================================

/// @brief 为虚拟机(VM)actor配置ARM64系统寄存器
///
/// VM actor运行在客户机(EL1或EL0)，通过ARM64虚拟化扩展(EL2)与宿主机隔离。
/// ARM64虚拟化使用两阶段地址翻译：
///   第一阶段(S1PT): 客户机的虚拟地址(VA) → 客户机物理地址(IPA)
///                    由客户机的TTBR0_EL1/TTBR1_EL1控制
///   第二阶段(S2PT): 客户机物理地址(IPA) → 宿主机物理地址(HPA)
///                    由VTTBR_EL2控制
///
/// HCR_EL2寄存器控制从客户机到宿主机(EL2)的陷阱行为，
/// 类似于x86的VMCS控制字段(VM-Execution Controls/VM-Exit Controls)。
///
/// 配置步骤：
///   1. 设置HCR_EL2的陷阱位，将关键操作路由到EL2
///   2. 设置VTTBR_EL2指向第二阶段页表(S2PT)
///   3. 配置VBAR_EL2使EL2异常跳转到我们的处理函数
///   4. 设置MAIR_EL2和TCR_EL2配置S2PT的内存属性和翻译参数
///
/// 关键HCR_EL2陷阱位配置：
///   VM=1:  启用第二阶段翻译(S2PT)，这是虚拟化的基础
///   RW=1:  客户机使用AArch64模式
///   TSC=1: SVC指令陷阱到EL2（捕获客户机的系统调用请求）
///   IMO=1: IRQ路由到EL2（虚拟化中断处理）
///   FMO=1: FIQ路由到EL2
///   AMO=1: SError路由到EL2
///   TWI=1: WFI指令陷阱到EL2（防止客户机长时间挂起）
///   TWE=1: WFE指令陷阱到EL2
///   TPMCR=0: 不陷阱PMCR访问（允许客户机访问PMU）
///
/// 注意：目前ARM64的VM actor支持仍在开发中，
/// page_tables_guest.c中的大部分函数仍是stub实现。
/// S2PT的完整配置需要guest_page_tables模块完成后才能使用。
///
/// @return 0表示成功，-EIO表示断言失败
int set_msrs_for_vm_actors(void)
{
    uint64_t current_el = 0;
    read_msr("CurrentEL", current_el);
    current_el = (current_el >> 2) & 0b11;

    // VM actor配置需要在EL2或更高级别执行
    // 如果当前运行在EL1，无法修改EL2寄存器
    ASSERT_MSG(current_el >= 2, "set_msrs_for_vm_actors",
               "VM actors require EL2 access, but currently running at EL%d\n",
               (int)current_el);

    // === HCR_EL2 配置 ===
    // 构建HCR_EL2的陷阱位配置值
    // HCR_EL2是ARM64虚拟化的核心控制寄存器，
    // 类似于x86 VMX的VM-Execution Controls和VM-Exit Controls的组合
    uint64_t hcr = 0;

    // VM=1(bit[0]): 启用虚拟化管理器，即启用第二阶段翻译(S2PT)
    // 这是ARM64虚拟化的基础控制位。设置后：
    //   - 所有客户机的内存访问经过两阶段翻译(VA→IPA→HPA)
    //   - S2PT由VTTBR_EL2指向的页表控制
    //   - 未映射的IPA会触发Stage-2页故障(路由到EL2)
    hcr |= BIT_(0); // VM

    // RW=1(bit[31]): 低异常级别(EL0/EL1)使用AArch64模式
    // RW=0时低EL使用AArch32模式，我们不支持AArch32客户机
    hcr |= BIT_(31); // RW

    // TSC=1(bit[8]): SVC指令陷阱到EL2
    // 当客户机(EL0/EL1)执行SVC指令时，不直接在客户机内部处理，
    // 而是触发异常到EL2（类似x86的VM-Exit on SYSCALL）。
    // 这允许宿主机拦截客户机的系统调用请求，
    // 在侧信道测试中用于安全终止VM actor
    hcr |= BIT_(8); // TSC

    // IMO=1(bit[4]): IRQ中断路由到EL2
    // 设置后，IRQ(普通中断)不再在客户机内部处理，
    // 而是路由到EL2（类似x86的VM-Exit on external interrupt）。
    // 这允许宿主机控制客户机的中断交付时机
    hcr |= BIT_(4); // IMO

    // FMO=1(bit[3]): FIQ中断路由到EL2
    // 设置后，FIQ(快速中断)路由到EL2
    hcr |= BIT_(3); // FMO

    // AMO=1(bit[5]): SError异步错误路由到EL2
    // 设置后，SError(异步错误)路由到EL2
    hcr |= BIT_(5); // AMO

    // TWI=1(bit[20]): WFI指令陷阱到EL2
    // WFI(Wait For Interrupt)指令让CPU进入低功耗状态等待中断。
    // 陷阱WFI可以防止客户机长时间挂起，宿主机可以：
    //   - 继续运行其他vCPU
    //   - 在有中断时唤醒客户机
    hcr |= BIT_(20); // TWI

    // TWE=1(bit[19]): WFE指令陷阱到EL2
    // WFE(Wait For Event)指令让CPU等待事件信号。
    // 与TWI类似的理由进行陷阱
    hcr |= BIT_(19); // TWE

    // 注意：TPMCR(bit[28])保持为0，不陷阱PMCR_EL0访问
    // 这允许客户机(EL0/EL1)直接访问PMU控制寄存器，
    // 使测试用例可以在VM内配置和读取PMC值
    // TPMRC(bit[30])也保持为0，不陷阱计数器读取

    // 写入HCR_EL2配置
    write_msr("HCR_EL2", hcr);

    // === VTTBR_EL2 配置 ===
    // VTTBR_EL2指向第二阶段页表(S2PT)的基地址。
    // S2PT将客户机物理地址(IPA)翻译为宿主机物理地址(HPA)，
    // 类似于x86的EPT(Extended Page Tables)。
    //
    // 注意：S2PT的实际设置需要page_tables_guest模块提供，
    // 目前该模块尚未完全实现（大部分函数为stub）。
    // 在S2PT可用之前，此处的VTTBR_EL2设置暂时跳过。
    // 当S2PT实现完成后，取消注释以下代码。
    //
    // if (ept_ptr != NULL) {
    //     write_msr("VTTBR_EL2", (uint64_t)ept_ptr);
    // }

    // === VBAR_EL2 配置 ===
    // VBAR_EL2指向EL2异常向量表基地址。
    // 当客户机操作被HCR_EL2陷阱位路由到EL2时，
    // 处理器根据VBAR_EL2 + 偏移找到对应的异常处理向量。
    // 需要将VBAR_EL2设置为指向我们的EL2异常向量表，
    // 以捕获和虚拟化客户机的异常请求。
    //
    // 注意：EL2向量表的布局与EL1向量表相同(16个128字节入口)，
    // 但入口的异常来源不同（来自低EL的陷阱而非直接异常）。
    //
    // 目前EL2向量表尚未完全实现，暂时跳过VBAR_EL2设置。
    // 当VM actor支持完成后，取消注释以下代码。
    //
    // write_msr("VBAR_EL2", (uint64_t)&vm_vector_table);

    // === MAIR_EL2 配置 ===
    // MAIR_EL2定义S2PT使用的内存属性。
    // S2PT页表项的AttrIdx字段指向此寄存器中对应的属性描述。
    // 通常将MAIR_EL2设置为与MAIR_EL1相同的值，
    // 使S2PT使用与宿主机相同的内存属性配置。
    write_msr("MAIR_EL2", orig_special_registers_state->mair_el1);

    // === TCR_EL2 配置 ===
    // TCR_EL2控制VTTBR_EL2的翻译参数。
    // 需要配置的参数：
    //   T0SZ: 地址空间大小(64-T0SZ=IPA地址位数)
    //   PS: 物理地址大小(必须与宿主机物理地址位数匹配)
    //   TG0: 粒度(通常与宿主机页表粒度相同=4KB)
    //
    // 使用宿主机的TCR_EL1相关参数来配置TCR_EL2，
    // 确保S2PT的翻译参数与宿主机物理地址空间匹配。
    uint64_t tcr_el2 = 0;
    // T0SZ: 从TCR_EL1中提取TTBR0的地址空间大小
    // TCR_EL1[5:0] = T0SZ，复制到TCR_EL2[5:0]
    tcr_el2 |= orig_special_registers_state->tcr_el1 & 0b111111; // T0SZ
    // PS: 物理地址大小，从TCR_EL1[33:32](IPS字段)复制
    // IPS编码：0=32位, 1=36位, 2=40位, 3=42位, 4=44位, 5=48位, 6=52位
    uint64_t ips = (orig_special_registers_state->tcr_el1 >> 32) & 0b111;
    tcr_el2 |= (ips << 16); // TCR_EL2[18:16] = PS
    // TG0: 粒度，从TCR_EL1[13:12](TG0字段)复制
    // TG0编码：0=4KB, 1=64KB, 2=16KB
    uint64_t tg0 = (orig_special_registers_state->tcr_el1 >> 12) & 0b11;
    tcr_el2 |= (tg0 << 14); // TCR_EL2[15:14] = TG0
    // SH0: 共享属性，从TCR_EL1[17:16](SH0字段)复制
    uint64_t sh0 = (orig_special_registers_state->tcr_el1 >> 16) & 0b11;
    tcr_el2 |= (sh0 << 12); // TCR_EL2[13:12] = SH0
    // ORGN0: 外部缓存属性，从TCR_EL1[10](ORGN0字段)复制
    uint64_t orgn0 = (orig_special_registers_state->tcr_el1 >> 10) & 0b1;
    tcr_el2 |= (orgn0 << 10); // TCR_EL2[10] = ORGN0
    // IRGN0: 内部缓存属性，从TCR_EL1[8](IRGN0字段)复制
    uint64_t irgn0 = (orig_special_registers_state->tcr_el1 >> 8) & 0b1;
    tcr_el2 |= (irgn0 << 8); // TCR_EL2[8] = IRGN0

    write_msr("TCR_EL2", tcr_el2);

    return 0;
}

// =====================================================================
// 公共接口
// =====================================================================

/// @brief 设置特殊寄存器：保存原始状态，然后根据测试用例需求修改
///
/// 配置顺序（每个步骤必须在前一步完成后执行）：
///   1. store_special_registers() - 保存所有关键寄存器的原始值
///      必须最先执行，因为后续所有修改都依赖于这些保存值来恢复
///   2. disable_arm_prefetchers() - 禁用硬件数据预取器
///      必须在保存后执行，因为需要保存原始预取器配置以便恢复
///      禁用预取器是减少侧信道测量噪声的关键步骤
///   3. enable_pmu_el0_access() - 启用EL0对PMU寄存器的访问
///      必须在禁用预取器后执行，因为PMU访问可能需要EL2配置
///   4. SCTLR_EL1配置 - 确保数据缓存启用(C位)
///      缓存必须启用才能收集基于缓存的侧信道追踪(htrace)
///   5. 用户actor配置（如果测试用例包含用户态actor）
///      配置VBAR_EL1和TTBR0_EL1
///   6. VM actor配置（如果测试用例包含虚拟机actor）
///      配置HCR_EL2和VTTBR_EL2等EL2寄存器
///
/// @return 0表示成功，负数表示错误码
int set_special_registers(void)
{
    int err = 0;

    // 步骤1：保存所有关键系统寄存器的原始值
    // 这是所有后续操作的基础，必须最先执行
    err = store_special_registers();
    CHECK_ERR("store_special_registers");

#ifndef VMBUILD
    // 步骤2：禁用硬件数据预取器
    // 根据配置决定是否禁用预取器：
    //   enable_prefetchers=false（默认）→ 禁用预取器（减少测量噪声）
    //   enable_prefetchers=true → 保持预取器启用（可能增加噪声）
    if (!enable_prefetchers) {
        err = disable_arm_prefetchers();
        CHECK_ERR("disable_arm_prefetchers");
    }

    // 步骤3：启用EL0对PMU寄存器的访问
    // 测试用例运行在EL0，需要直接读取PMC值收集htrace
    // 设置PMUSERENR_EL0.EN=1允许EL0访问PMU寄存器
    err = enable_pmu_el0_access();
    CHECK_ERR("enable_pmu_el0_access");

    // 步骤4：SCTLR_EL1配置
    // 确保数据缓存启用(SCTLR_EL1.C=1)
    // 数据缓存是侧信道测量的基础：
    //   - Prime+Probe利用L1数据缓存的占用状态
    //   - Flush+Reload利用L1数据缓存的命中/未命中
    //   - 如果数据缓存禁用(C=0)，所有内存访问直接到主存，
    //     侧信道信号消失，无法收集htrace
    uint64_t sctlr = 0;
    read_msr("SCTLR_EL1", sctlr);
    // 确保C=1(数据缓存启用)
    sctlr |= BIT_(2); // C位
    // 确保I=1(指令缓存启用)，指令缓存对测试代码的正确执行是必要的
    sctlr |= BIT_(25); // I位(ARM64的ICache启用位)
    write_msr("SCTLR_EL1", sctlr);
#endif // VMBUILD

    // 步骤5：如果测试用例包含用户态actor，配置相关系统寄存器
    // 用户态actor运行在EL0，通过SVC指令与EL1通信
    // 需要重定向SVC异常到fault_handler，并配置TTBR0_EL1页表
    if (test_case->features.includes_user_actors) {
        err = set_msrs_for_user_actors();
        CHECK_ERR("set_msrs_for_user_actors");
    }

    // 步骤6：如果测试用例包含虚拟机(VM) actor，启用虚拟化支持
    // VM actor运行在客户机(EL1或EL0)，通过ARM64 EL2虚拟化与宿主机隔离
    // 需要配置HCR_EL2陷阱位和VTTBR_EL2第二阶段页表
    if (test_case->features.includes_vm_actors) {
        err = set_msrs_for_vm_actors();
        CHECK_ERR("set_msrs_for_vm_actors");
    }

    return 0;
}

// =====================================================================
// 恢复原始系统寄存器状态
// =====================================================================

/// @brief 恢复所有修改过的系统寄存器到原始值
///
/// 恢复策略使用if-zero安全检查：
///   if-zero检查是必要的，因为初始化过程可能中途失败，
///   此时只有部分寄存器被成功保存。如果恢复操作尝试写入
///   未保存的寄存器（值为0），可能导致：
///   - 将有效寄存器设为0（如MMU禁用、缓存禁用）→ 系统崩溃
///   - 将页表基址设为0 → 内存访问异常 → 内核崩溃
///   通过if-zero检查跳过未保存的寄存器，确保恢复操作是安全的。
///
/// 恢复顺序（与设置顺序相反）：
///   6. VM actor EL2寄存器恢复（如果使用了VM actor）
///   5. 用户actor VBAR_EL1恢复（如果使用了用户actor）
///   4. 实现特定寄存器恢复（CPUACTLR_EL1/CPUECTLR_EL1）
///   3. EL2通用寄存器恢复（如果运行在EL2）
///   2. EL1核心控制寄存器恢复
///   1. EL0性能监控与浮点寄存器恢复
void restore_special_registers(void)
{
    // === EL1 核心控制寄存器恢复 ===
    // 这些寄存器控制系统核心功能，恢复顺序很重要：
    // 先恢复VBAR_EL1（确保异常处理可用），再恢复其他寄存器

    // VBAR_EL1：异常向量表基址
    // 如果用户actor修改了VBAR_EL1，vbar_el1_saved字段会保存修改前的值
    // 优先使用vbar_el1_saved恢复（因为vbar_el1保存的是store时的值，
    // 而vbar_el1_saved保存的是set_msrs_for_user_actors修改前的值）
    // 如果vbar_el1_saved为0（没有用户actor），使用vbar_el1恢复
    if (orig_special_registers_state->vbar_el1_saved != 0) {
        write_msr("VBAR_EL1", orig_special_registers_state->vbar_el1_saved);
    } else if (orig_special_registers_state->vbar_el1 != 0) {
        write_msr("VBAR_EL1", orig_special_registers_state->vbar_el1);
    }

    // SCTLR_EL1：系统控制寄存器
    // 包含MMU、缓存、对齐检查等核心配置
    // 必须确保恢复的值包含C=1和I=1（缓存启用），
    // 否则恢复后系统可能崩溃（缓存禁用→数据不一致）
    if (orig_special_registers_state->sctlr_el1 != 0) {
        write_msr("SCTLR_EL1", orig_special_registers_state->sctlr_el1);
    }

    // TTBR0_EL1：页表基址寄存器0
    // 恢复为原始内核页表基址（如果用户actor修改了它）
    if (orig_special_registers_state->ttbr0_el1 != 0) {
        write_msr("TTBR0_EL1", orig_special_registers_state->ttbr0_el1);
    }

    // TTBR1_EL1：页表基址寄存器1
    if (orig_special_registers_state->ttbr1_el1 != 0) {
        write_msr("TTBR1_EL1", orig_special_registers_state->ttbr1_el1);
    }

    // TCR_EL1：页表控制寄存器
    if (orig_special_registers_state->tcr_el1 != 0) {
        write_msr("TCR_EL1", orig_special_registers_state->tcr_el1);
    }

    // MAIR_EL1：内存属性间接寄存器
    if (orig_special_registers_state->mair_el1 != 0) {
        write_msr("MAIR_EL1", orig_special_registers_state->mair_el1);
    }

    // SPSR_EL1：保存的程序状态寄存器
    if (orig_special_registers_state->spsr_el1 != 0) {
        write_msr("SPSR_EL1", orig_special_registers_state->spsr_el1);
    }

    // ELR_EL1：异常链接寄存器
    if (orig_special_registers_state->elr_el1 != 0) {
        write_msr("ELR_EL1", orig_special_registers_state->elr_el1);
    }

    // SP_EL0：EL0栈指针
    if (orig_special_registers_state->sp_el0 != 0) {
        write_msr("SP_EL0", orig_special_registers_state->sp_el0);
    }

    // FAR_EL1：故障地址寄存器（只读寄存器，通常不恢复）
    // FAR_EL1是只读寄存器，写入会产生UNDEFINED异常
    // 但某些ARM64实现允许写入（用于调试），我们跳过恢复
    // orig_special_registers_state->far_el1 仅用于调试输出

    // ESR_EL1：异常症状寄存器（只读寄存器，通常不恢复）
    // ESR_EL1也是只读寄存器，跳过恢复
    // orig_special_registers_state->esr_el1 仅用于调试输出

    // === EL0 性能监控与浮点寄存器恢复 ===

    // PMCR_EL0：性能监控控制寄存器
    if (orig_special_registers_state->pmcr_el0 != 0) {
        write_msr("PMCR_EL0", orig_special_registers_state->pmcr_el0);
    }

    // PMUSERENR_EL0：性能监控用户使能寄存器
    // 恢复EL0的PMU访问权限到原始状态
    // 大多数内核默认PMUSERENR_EL0=0（禁用EL0 PMU访问），
    // 恢复为0可以防止非特权程序继续读取PMC
    if (orig_special_registers_state->pmuserenr_el0 != 0) {
        write_msr("PMUSERENR_EL0", orig_special_registers_state->pmuserenr_el0);
    } else {
        // 即使原始值为0，也需要显式恢复（因为我们在set时修改了它）
        // 0值意味着禁用EL0 PMU访问，这是内核的正常状态
        write_msr("PMUSERENR_EL0", 0);
    }

    // FPCR：浮点控制寄存器
    if (orig_special_registers_state->fpcr != 0) {
        write_msr("FPCR", orig_special_registers_state->fpcr);
    }

    // FPSR：浮点状态寄存器
    if (orig_special_registers_state->fpsr != 0) {
        write_msr("FPSR", orig_special_registers_state->fpsr);
    }

    // === EL2 虚拟化寄存器恢复 ===
    // 仅在运行于EL2且保存了EL2寄存器时恢复
    uint64_t current_el = 0;
    read_msr("CurrentEL", current_el);
    current_el = (current_el >> 2) & 0b11;

    if (current_el >= 2) {
        // HCR_EL2：虚拟化配置寄存器
        // 恢复陷阱位配置到原始值
        // 关键：如果HCR_EL2.VM被错误恢复为0，
        // 第二阶段翻译将禁用，可能影响KVM等虚拟化软件
        if (orig_special_registers_state->hcr_el2 != 0) {
            write_msr("HCR_EL2", orig_special_registers_state->hcr_el2);
        }

        // VTTBR_EL2：虚拟页表基址寄存器
        // 恢复为原始S2PT基址
        if (orig_special_registers_state->vttbr_el2 != 0) {
            write_msr("VTTBR_EL2", orig_special_registers_state->vttbr_el2);
        }

        // VBAR_EL2：EL2向量基址寄存器
        if (orig_special_registers_state->vbar_el2 != 0) {
            write_msr("VBAR_EL2", orig_special_registers_state->vbar_el2);
        }

        // SPSR_EL2：保存的程序状态寄存器（EL2）
        if (orig_special_registers_state->spsr_el2 != 0) {
            write_msr("SPSR_EL2", orig_special_registers_state->spsr_el2);
        }

        // ELR_EL2：异常链接寄存器（EL2）
        if (orig_special_registers_state->elr_el2 != 0) {
            write_msr("ELR_EL2", orig_special_registers_state->elr_el2);
        }

        // MAIR_EL2：内存属性间接寄存器（EL2）
        if (orig_special_registers_state->mair_el2 != 0) {
            write_msr("MAIR_EL2", orig_special_registers_state->mair_el2);
        }

        // TCR_EL2：页表控制寄存器（EL2）
        if (orig_special_registers_state->tcr_el2 != 0) {
            write_msr("TCR_EL2", orig_special_registers_state->tcr_el2);
        }

        // MDCR_EL2：监控调试配置寄存器
        // 恢复PMU陷阱位到原始配置
        if (orig_special_registers_state->mdcr_el2 != 0) {
            write_msr("MDCR_EL2", orig_special_registers_state->mdcr_el2);
        }
    }

    // === 实现特定寄存器恢复 ===
    // 根据CPU型号恢复CPUACTLR_EL1和CPUECTLR_EL1
    // 这些寄存器包含预取器控制位，恢复为原始值使预取器恢复工作

    if (cpuinfo->implementer == ARM_IMPLEMENTER_ID) {
        if (cpuinfo->part == CORTEX_A72_PART || cpuinfo->part == CORTEX_A76_PART) {
            // Cortex A72/A76：恢复CPUACTLR_EL1和CPUECTLR_EL1
            // 如果值为0（保存失败），跳过恢复以避免将有效寄存器设为0
            if (orig_special_registers_state->cpuactlr_el1 != 0) {
                write_impl_specific_reg(CPUACTLR_EL1_ENCODING,
                                         orig_special_registers_state->cpuactlr_el1);
            }
            if (orig_special_registers_state->cpuectlr_el1 != 0) {
                write_impl_specific_reg(CPUECTLR_EL1_ENCODING,
                                         orig_special_registers_state->cpuectlr_el1);
            }
        }
    }

    // 清零保存的状态结构，标记所有寄存器已恢复完毕
    // 这确保后续如果restore_special_registers意外被再次调用，
    // 所有if-zero检查都会跳过，不会重复恢复
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =====================================================================
// 初始化与释放
// =====================================================================

/// @brief 初始化特殊寄存器管理器：分配special_registers_t结构
/// 分配的内存用于保存所有关键系统寄存器的原始值。
/// 使用kzalloc确保分配的内存初始为零，这样在store_special_registers
/// 之前，所有字段都是0，避免restore_special_registers中的if-zero检查
/// 误判为有效值。
/// @return 0表示成功，-ENOMEM表示内存分配失败
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

/// @brief 释放特殊寄存器管理器：释放分配的内存
/// 使用SAFE_FREE宏释放内存并将指针设为NULL，
/// 防止后续误用已释放的内存（double-free或use-after-free）
void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

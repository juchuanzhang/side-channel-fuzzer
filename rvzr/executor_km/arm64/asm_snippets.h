/// 文件：ARM64架构汇编宏构建块集合
///
/// 本文件定义用于ARM64测量代码模板的各种汇编宏片段，包括：
/// - 状态机控制宏(SET_SR_STARTED/ENDED/TEST_SR_ENDED)
/// - 快捷宏(SPEC_FENCE/CACHE_FLUSH/mov_imm_to_reg)
/// - MSR读取宏(READ_MSR_START/END)
/// - PMU性能计数器读取宏(READ_PFC_START/END)
/// - SMI监控宏(READ_SMI_START/END，未实现FIXME)
/// - 寄存器初始化宏(SET_REGISTER_FROM_INPUT)
/// - L1D Prime+Probe宏(PRIME/PROBE，支持2/4/8路相联度)
/// - L1D Flush+Reload宏(FLUSH/RELOAD)
///
/// ARM64与x86的关键差异：
///   - 序列化使用dsb+isb而非lfence/mfence
///   - 缓存逐出使用dc civac而非clflush
///   - PMU读取使用PMSELR_EL0+PMXEVCNTR_EL0而非rdpmc
///   - MSR读取使用mrs而非rdmsr
///   - 64位立即数需要movz+movk(4条指令)而非单条mov
///   - P+P/F+R的地址计算使用add+ldr而非add指令(既读又写)
///   - L1D冲突距离(L1D_CONFLICT_DISTANCE)替代x86的固定4096偏移
///   - ARM64没有宏栈管理(MACRO_PROLOGUE/MACRO_EPILOGUE)
///     因为P+P使用更少的栈空间(ldr只读不写，无需add累加)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ARM64_ASM_SNIPPETS_H_
#define _ARM64_ASM_SNIPPETS_H_

#include "hardware_desc.h"
#include "measurement.h"
#include "registers.h"

/// =================================================================================================
/// 追踪过程状态机——控制测量的执行阶段
/// =================================================================================================
/// SET_SR_STARTED(): 设置STATUS_REGISTER(w12)的8位字段为STATUS_STARTED，标记测量已开始
///   使用and清除低8位+orr设置新值，而非x86的mov r12b(ARM64无法单条指令设置8位)
/// SET_SR_ENDED(): 设置STATUS_REGISTER(w12)的8位字段为STATUS_ENDED，标记测量已结束
///   同上，and清除低8位+orr设置新值
/// TEST_SR_ENDED(): 检查STATUS_REGISTER是否为STATUS_ENDED状态
///   提取低8位(and x16, #0xFF)并比较(cmp x16, STATUS_ENDED)
///   用于异常处理中判断测量是否已结束
///   注意：此宏使用x16作为临时寄存器，调用者需确保x16可用
#define SET_SR_STARTED()                                                                           \
    "and " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", #0xFFFFFF00 \n"                           \
    "orr " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", " xstr(STATUS_STARTED) " \n"
#define SET_SR_ENDED()                                                                             \
    "and " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", #0xFFFFFF00 \n"                           \
    "orr " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", " xstr(STATUS_ENDED) " \n"
#define TEST_SR_ENDED()                                                                            \
    "mov x16, " STATUS_REGISTER " \n"                                                              \
    "and x16, x16, #0xFF \n"                                                                       \
    "cmp x16, " xstr(STATUS_ENDED) " \n"

/// =================================================================================================
/// 快捷宏——ARM64特有的常用操作
/// =================================================================================================
/// SPEC_FENCE(): ARM64序列化屏障 = dsb SY + isb
///   dsb SY: 数据序列屏障(全系统范围)，确保所有数据访问完成
///   isb: 指令序列屏障，确保指令流水线刷新，后续指令重新取指
///   组合使用相当于x86的lfence+mfence，用于测量前后的序列化
/// CACHE_FLUSH(ADDR): 缓存行逐出 = dc civac, ADDR
///   dc civac: 数据缓存操作，清理并无效指定地址的缓存行
///   相当于x86的clflush，但ARM64还清理了L2/L3中的副本(civac=clean+invalidate)
///   civac比单纯的civac更彻底(也清理了脏数据)
/// mov_imm_to_reg(DEST, SRC): 64位立即数加载宏
///   ARM64无法用单条mov指令加载64位立即数(movz只能加载16位)
///   使用4条指令(movz+movk*3)分别加载16位片段到不同位置：
///   movz DEST, #(SRC & 0xFFFF), lsl #0    —— 加载[0:15]位
///   movk DEST, #(SRC >> 16) & 0xFFFF, lsl #16 —— 加载[16:31]位
///   movk DEST, #(SRC >> 32) & 0xFFFF, lsl #32 —— 加载[32:47]位
///   movk DEST, #(SRC >> 48) & 0xFFFF, lsl #48 —— 加载[48:63]位
///   movz清零高位再写入，movk保留其他位只写入指定16位
///   注意：使用x16作为临时寄存器(其他宏也使用x16，注意冲突)
/// ================================================================================================
#define SPEC_FENCE()      "dsb SY \n isb \n"
#define CACHE_FLUSH(ADDR) "dc civac, " ADDR "\n"

// clang-format off
#define mov_imm_to_reg(DEST, SRC)                                                                      \
    "movz " DEST ", #(" xstr(SRC) ") & 0xFFFF, lsl #0 \n"                                          \
    "movk " DEST ", #(" xstr(SRC) " >> 16) & 0xFFFF, lsl #16 \n"                                   \
    "movk " DEST ", #(" xstr(SRC) " >> 32) & 0xFFFF, lsl #32 \n"                                   \
    "movk " DEST ", #(" xstr(SRC) " >> 48) & 0xFFFF, lsl #48 \n"
// clang-format on

/// =================================================================================================
/// MSR(系统寄存器)和PMU性能计数器访问器宏
/// =================================================================================================
/// ARM64使用mrs指令读取系统寄存器(对应x86的rdmsr)
/// ARM64 PMU访问流程与x86不同：
///   1. 选择计数器：msr pmselr_el0, ID (选择PMC编号)
///   2. 读取计数器：mrs DEST, pmxevcntr_el0 (读取当前选中的计数器值)
///   而x86直接rdpmc ID即可(硬件自动选择)
///
/// READ_MSR_START(ID, DEST): 读取MSR起始值并从DEST中减去(差值计算前半部分)
///   SPEC_FENCE()确保序列化→DEST清零→mrs读取系统寄存器→sub计算差值
///   破坏寄存器：x16(mrs结果临时寄存器)
///
/// READ_MSR_END(ID, DEST): 读取MSR结束值并加到DEST上(差值计算后半部分)
///   SPEC_FENCE()确保序列化→mrs读取系统寄存器→add累加差值
///   破坏寄存器：x16
/// ================================================================================================

// clobber: x16
#define READ_MSR_START(ID, DEST)                                                                   \
    SPEC_FENCE()                                                                                   \
    "mov " DEST ", #0 \n"                                                                          \
    "mrs x16, " ID " \n"                                                                           \
    "sub " DEST ", " DEST ", x16 \n"

// clobber: x16
#define READ_MSR_END(ID, DEST)                                                                     \
    SPEC_FENCE()                                                                                   \
    "mrs x16, " ID " \n"                                                                           \
    "add " DEST ", " DEST ", x16 \n"

/// READ_ONE_PFC(ID, DEST): 读取指定PMU计数器当前值
///   步骤：mov DEST, ID(设置PMC编号)→msr pmselr_el0, DEST(选择计数器)
///         →mrs DEST, pmxevcntr_el0(读取选中计数器值)
///   ID=0/1/2对应PMEVCNTR0/1/2
///   注意：ARM64只使用PMC#0/#1/#2，而非x86的PMC#1/#2/#3
///   破坏寄存器：x16(DEST如果传入x16则被覆盖)
// clobber: x16 (dest)
#define READ_ONE_PFC(ID, DEST)                                                                     \
    "mov " DEST ", " ID " \n"                                                                      \
    "msr pmselr_el0, " DEST " \n"                                                                  \
    "mrs " DEST ", pmxevcntr_el0 \n"

/// READ_PFC_START(): 读取PMC#0/#1起始值并分别从PFC0/PFC1(x10/x9)中减去
///   注意：ARM64只使用2个PMC(#0/#1)，而非x86的3个(#1/#2/#3)
///   PMC#2未使用，PFC2(x8)保持清零
///   步骤：SPEC_FENCE→PFC0/PFC1/PFC2清零→READ_ONE_PFC(1,x16)→sub PFC0
///         →READ_ONE_PFC(2,x16)→sub PFC1
///   破坏寄存器：x16, PFC0/PFC1/PFC2
// clobber: x16, PFC0, PFC1, PFC2
// clang-format off
#define READ_PFC_START() \
        SPEC_FENCE() \
        "mov " PFC0 ", #0 \n" \
        "mov " PFC1 ", #0 \n" \
        "mov " PFC2 ", #0 \n" \
        READ_ONE_PFC("1", "x16") \
        "sub " PFC0 ", " PFC0 ", x16 \n" \
        READ_ONE_PFC("2", "x16") \
        "sub " PFC1 ", " PFC1 ", x16 \n"

/// READ_PFC_END(): 读取PMC#0/#1结束值并分别加到PFC0/PFC1上
///   注意：ARM64只累加PMC#0/#1，PMC#2(PFC2)保持为0
///   步骤：SPEC_FENCE→READ_ONE_PFC(1,x16)→add PFC0
///         →READ_ONE_PFC(2,x16)→add PFC1
///   破坏寄存器：x16
// clobber: rax, rcx, rdx
#define READ_PFC_END() \
        SPEC_FENCE() \
        READ_ONE_PFC("1", "x16") \
        "add " PFC0 ", " PFC0 ", x16 \n" \
        READ_ONE_PFC("2", "x16") \
        "add " PFC1 ", " PFC1 ", x16 \n"
// clang-format on

/// =================================================================================================
/// 中断检测宏
/// =================================================================================================
/// ARM64的SMI监控尚未实现(FIXME)
/// ARM64没有SMI(System Management Interrupt)概念，但类似功能由FIQ(Fast Interrupt)
/// 提供。需要在EL2级别监控FIQ计数器，实现方式待定。
/// 当前READ_SMI_START/READ_SMI_END为空宏，不影响测量流程
/// ================================================================================================
/// @brief ARM64 SMI监控起始——尚未实现(FIXME)
///        需要在EL2级别读取FIQ计数器，实现方式待定
///  clobber: 无(空宏)
#define READ_SMI_START() // FIXME: unimplemented

/// @brief ARM64 SMI监控结束——尚未实现(FIXME)
///        需要在EL2级别读取FIQ计数器并计算差值
/// clobber: 无(空宏)
#define READ_SMI_END() // FIXME: unimplemented

/// =================================================================================================
/// 测量前/后宏——寄存器初始化
/// =================================================================================================
/// SET_REGISTER_FROM_INPUT(): 从沙箱输入区加载测试用例的初始寄存器值
/// ARM64与x86的差异：
///   - 使用ldp(pair load)而非pop，一次加载两个寄存器
///   - 使用msr nzcv, x6而非popfq(ARM64的条件标志寄存器NZCV独立于通用寄存器)
///   - 使用mov sp, x7而非mov rbp, rsp(ARM64没有独立的帧指针设置)
/// 步骤：
///   1. mov x0, #REG_INIT_OFFSET; add sp, MEMORY_BASE, x0 —— 将栈指向输入初始化区
///   2. ldp x0,x1 / ldp x2,x3 / ldp x4,x5 / ldp x6,x7 —— 从输入区依次加载初始值
///   3. msr nzcv, x6 —— 将NZCV条件标志从x6加载到PSTATE(N/Z/C/V标志)
///   4. mov sp, x7 —— 将栈指针设置为x7中的值(预设的本地栈地址)
/// 破坏寄存器：x0-x7, nzcv(条件标志), sp
/// @brief Loading of register values from the main actor's memory
/// clobber: x0-x7, nzcv, sp
// clang-format off
#define SET_REGISTER_FROM_INPUT() \
    asm volatile("\n"   \
    "mov x0, #"xstr(REG_INIT_OFFSET)" \n" \
    "add sp, "MEMORY_BASE_REGISTER", x0 \n" \
    "ldp x0, x1, [sp], #16\n" \
    "ldp x2, x3, [sp], #16\n" \
    "ldp x4, x5, [sp], #16\n" \
    "ldp x6, x7, [sp], #16\n" \
    "msr nzcv, x6\n" \
    "mov sp, x7\n");
// clang-format on

/// =================================================================================================
/// 测量原语——L1D Prime+Probe和Flush+Reload
/// =================================================================================================

/// =================================================================================================
/// L1D Prime+Probe 单缓存组操作宏
/// =================================================================================================
/// ARM64与x86的关键差异：
///   - 使用ldr(只读)而非add(既读又写)，因此需要额外的ACC(累加寄存器)参数
///   - ldr将数据读入ACC，add将ACC加到地址偏移上(形成数据依赖链防止乱序执行)
///   - 使用L1D_CONFLICT_DISTANCE而非固定4096(ARM64缓存结构不同)
///   - 不需要mfence(ARM64使用SPEC_FENCE在PRIME/PROBE外层)
///
/// PRIME_ONE_SET(BASE, OFFSET, TMP, ACC)：填充一个缓存组
///   步骤(以4路为例)：
///   1. mov TMP, BASE —— 设置基地址
///   2. add TMP, TMP, OFFSET —— 加上组内偏移
///   3. add TMP, TMP, ACC —— 加上累加器值(数据依赖，防止乱序)
///   4. ldr ACC, [TMP] —— 从当前way读取数据到ACC
///   5. add TMP, TMP, #L1D_CONFLICT_DISTANCE —— 跳到下一个way(同组内不同way)
///   6. add TMP, TMP, ACC —— 加上新读入的ACC值(数据依赖)
///   7. ldr ACC, [TMP] —— 从下一个way读取数据到ACC
///   ... 重复4-7直到遍历完所有way
///
/// 注意：ldr只读不写(不像x86的add指令既读又写)，
///       因此ARM64需要ACC寄存器来创建数据依赖链

// clang-format off
#if L1D_ASSOCIATIVITY == 2
/// 2路相联度——每个缓存组只需访问2条cache line
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#elif L1D_ASSOCIATIVITY == 4
/// 4路相联度——每个缓存组需访问4条cache line
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#elif L1D_ASSOCIATIVITY == 8
/// 8路相联度——每个缓存组需访问8条cache line
/// Cortex A72/A76的L1D使用4路相联度(4x64=256KB)而非8路
/// 但某些ARM处理器可能使用8路，保留此选项
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#else
#error "Unsupported L1D_ASSOCIATIVITY"
#endif
// clang-format on

/// @brief Prime阶段——将L1D缓存填满已知数据
/// ARM64与x86的差异：
///   - 使用SPEC_FENCE(dsb+isb)替代mfence
///   - 使用L1D_CONFLICT_DISTANCE替代固定4096作为offset上限
///   - DEPENDENCY_REGISTER替代TMP作为数据依赖累加器
///   - REP_COUNTER和MAX_REPS替代COUNTER和REPS(命名更清晰)
/// clobber: none
// clang-format off
#define PRIME(BASE, OFFSET, TMP, DEPENDENCY_REGISTER, REP_COUNTER, MAX_REPS) \
    SPEC_FENCE() \
    "mov "REP_COUNTER", "MAX_REPS"\n" \
    "1: \n" \
        "mov "OFFSET", 0 \n" \
        "mov "DEPENDENCY_REGISTER", 0 \n" \
        "2: \n" \
            SPEC_FENCE() \
            PRIME_ONE_SET(BASE, OFFSET, TMP, DEPENDENCY_REGISTER) \
            "add "OFFSET", "OFFSET", #64 \n" \
            "cmp "OFFSET", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
            "b.lt 2b \n" \
        "sub "REP_COUNTER", "REP_COUNTER", #1 \n" \
        "cmp "REP_COUNTER", xzr \n" \
        "b.ne 1b \n" \
    SPEC_FENCE()
// clang-format on

/// =================================================================================================
/// Probe阶段——重新访问Prime时填充的数据，测量访问时间判断缓存组是否被替换
/// =================================================================================================
/// ARM64 PROBE与x86 PROBE的差异：
///   - 不区分Intel/AMD版本(ARM64 PMU行为统一)
///   - 使用READ_ONE_PFC("0", EVICT_COUNT)而非READ_ONE_PFC("0")
///     DEST参数直接指定目标寄存器(而非固定rdx)
///   - 判断逻辑：PMC结束值==PMC起始值 → cache miss(被替换) → 输出1位
///               PMC结束值!=PMC起始值 → cache hit(未被替换) → 输出0位
///   - 位串使用ror(rotate right)而非shl(shift left)构建
///     ror #1使最新位进入最低位，自然构建从高位到低位的位串
///   - offset从L1D_CONFLICT_DISTANCE-64递减到0(而非从0递增到4096)
///     反向遍历减少Probe阶段的缓存污染
///
/// PROBE(BASE, OFFSET, DEPENDENCY_REGISTER, EVICT_COUNT, TMP, TRACE):
///   TRACE(HTRACE_REGISTER): 位串输出，每一位表示一个缓存组是否被测试用例访问
///   EVICT_COUNT: PMC起始值寄存器
///   步骤：
///   1. TRACE=0, DEPENDENCY_REGISTER=0, OFFSET=L1D_CONFLICT_DISTANCE-64
///   2. 对每个缓存组(从高地址到低地址)：
///      a. SPEC_FENCE序列化
///      b. READ_ONE_PFC(0, EVICT_COUNT)——读取PMC#0起始值
///      c. SPEC_FENCE序列化
///      d. PRIME_ONE_SET——重新访问缓存组(数据依赖链)
///      e. SPEC_FENCE序列化
///      f. READ_ONE_PFC(0, TMP)——读取PMC#0结束值
///      g. cmp TMP, EVICT_COUNT——比较起止值
///      h. 如果相等(PMC未递增=cache miss)→orr TRACE,#1(置1位)
///      i. mov TRACE, TRACE, ror #1——旋转位串，准备下一位
///      j. OFFSET-=64
/// clang-format off
/// @brief Probe part of the Prime+Probe attack
// clobber: none
// clang-format off
#define PROBE(BASE, OFFSET, DEPENDENCY_REGISTER, EVICT_COUNT, TMP, TRACE) \
    "mov "TRACE", 0 \n" \
    "mov "DEPENDENCY_REGISTER", 0 \n" \
    "mov "OFFSET", #"xstr(L1D_CONFLICT_DISTANCE)" \n" \
    "sub "OFFSET", "OFFSET", #64 \n" \
    "1: \n" \
        SPEC_FENCE() \
        READ_ONE_PFC("0", EVICT_COUNT) \
        SPEC_FENCE() \
        PRIME_ONE_SET(BASE, OFFSET, TMP, DEPENDENCY_REGISTER) \
        SPEC_FENCE() \
        READ_ONE_PFC("0", TMP) \
        "cmp "TMP", "EVICT_COUNT" \n" \
        "b.eq 2f \n" \
        "  orr "TRACE", "TRACE", #1 \n" \
        "2: \n" \
        "mov "TRACE", "TRACE", ror #1 \n" \
        "sub "OFFSET", "OFFSET", #64 \n" \
        "cmp "OFFSET", xzr \n" \
        "b.ge 1b \n" \
    SPEC_FENCE()
// clang-format on

/// =================================================================================================
/// Flush+Reload —— ARM64版本
/// =================================================================================================
/// FLUSH(BASE, OFFSET, TMP)：逐出整个4KB页的所有cache line
///   ARM64使用dc civac指令逐出缓存行(清理+无效，比x86的clflush更彻底)
///   步骤：
///   1. OFFSET=0
///   2. 对每条cache line(OFFSET从0到0x1000，步长64)：
///      a. add TMP, BASE, OFFSET —— 计算目标地址
///      b. CACHE_FLUSH(TMP) = dc civac, TMP —— 逐出缓存行
///      c. OFFSET+=64
///   3. SPEC_FENCE() —— 序列化，确保所有逐出操作完成
/// clobber: none
/// @brief Flush part of the Flush+Reload
// clobber: none
// clang-format off
#define FLUSH(BASE, OFFSET, TMP) \
    "mov "OFFSET", #0 \n" \
    "1: \n" \
        "add "TMP", "BASE", "OFFSET" \n" \
        CACHE_FLUSH(TMP) \
        "add "OFFSET", "OFFSET", #64 \n" \
        "cmp "OFFSET", #0x1000\n" \
        "b.lt 1b \n" \
    SPEC_FENCE()
// clang-format on

/// RELOAD(BASE, OFFSET, TMP, EVICT_COUNT, TRACE)：重新加载并测量
///   ARM64版RELOAD不区分Intel/AMD(PMU行为统一)
///   步骤：
///   1. OFFSET=0, TRACE=0
///   2. 对每条cache line(OFFSET从0到0x1000，步长64)：
///      a. SPEC_FENCE序列化
///      b. READ_ONE_PFC(0, EVICT_COUNT)——读取PMC#0起始值
///      c. SPEC_FENCE序列化
///      d. add TMP, BASE, OFFSET; ldr TMP, [TMP]——加载cache line
///      e. SPEC_FENCE序列化
///      f. READ_ONE_PFC(0, TMP)——读取PMC#0结束值
///      g. mov TRACE, TRACE, lsl #1——位串左移一位
///      h. cmp TMP, EVICT_COUNT——比较PMC起止值
///      i. 如果不等(PMC递增=慢访问=从内存加载=未被测试用例访问)→orr TRACE,#1
///      j. OFFSET+=64
///   3. SPEC_FENCE()序列化
/// clobber: none
/// @brief Reload part of the Flush+Reload
// clobber: none
// clang-format off
#define RELOAD(BASE, OFFSET, TMP, EVICT_COUNT, TRACE) \
    "mov "OFFSET", 0 \n" \
    "mov "TRACE", 0 \n" \
    "1: \n" \
        SPEC_FENCE() \
        READ_ONE_PFC("0", EVICT_COUNT) \
        SPEC_FENCE() \
        "add "TMP", "BASE", "OFFSET" \n" \
        "ldr "TMP", ["TMP"] \n" \
        SPEC_FENCE() \
        READ_ONE_PFC("0", TMP) \
        "mov "TRACE", "TRACE", lsl #1 \n" \
        "cmp "TMP", "EVICT_COUNT" \n" \
        "b.ne 2f \n" \
        "  orr "TRACE", "TRACE", #1 \n" \
        "2: \n" \
        "add "OFFSET", "OFFSET", #64 \n" \
        "cmp "OFFSET", #0x1000 \n" \
        "b.lt 1b \n" \
    SPEC_FENCE()
// clang-format on

#endif // _ARM64_ASM_SNIPPETS_H_

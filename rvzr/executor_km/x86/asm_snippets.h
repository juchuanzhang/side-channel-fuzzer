/// 文件：x86-64架构汇编宏构建块集合
///
/// 本文件定义用于测量代码模板的各种汇编宏片段，包括：
/// - 状态机控制宏(SET_SR_STARTED/ENDED)
/// - MSR读取宏(READ_MSR_START/END)
/// - PMU性能计数器读取宏(READ_PFC_START/END)
/// - SMI监控宏(READ_SMI_START/END，Intel/AMD双版本)
/// - 流水线重置宏(PIPELINE_RESET)
/// - 寄存器初始化宏(SET_REGISTER_FROM_INPUT)
/// - L1D Prime+Probe宏(PRIME/PROBE，支持2/4/8/12路相联度)
/// - L1D Flush+Reload宏(FLUSH/RELOAD)
/// - 宏栈管理宏(MACRO_PROLOGUE/MACRO_EPILOGUE)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_ASM_SNIPPETS_H_
#define X86_ASM_SNIPPETS_H_
// clang-format off

#include "hardware_desc.h"
#include "measurement.h"
#include "registers.h"
#include <asm/msr-index.h>

#ifndef VENDOR_ID
#error "VENDOR_ID is not defined! Make sure to include this header late enough."
#endif

/// =================================================================================================
/// 追踪过程状态机——控制测量的执行阶段
/// =================================================================================================
/// SET_SR_STARTED(): 设置STATUS_REGISTER的8位字段为STATUS_STARTED，标记测量已开始
/// SET_SR_ENDED():   设置STATUS_REGISTER的8位字段为STATUS_ENDED，标记测量已结束
/// 状态值定义在measurement.h中(STATUS_UNINITIALIZED/STARTED/ENDED)
/// 使用8位版本(r12b)只修改低8位，不影响高56位(SMI计数信息)
#define SET_SR_STARTED()       "mov "STATUS_REGISTER_8", "xstr(STATUS_STARTED)" \n"
#define SET_SR_ENDED()         "mov "STATUS_REGISTER_8", "xstr(STATUS_ENDED)" \n"


/// =================================================================================================
/// MSR(模型特定寄存器)访问器宏
/// =================================================================================================
/// READ_MSR_START(ID, DEST): 读取MSR起始值并从DEST中减去(差值计算的前半部分)
/// READ_MSR_END(ID, DEST): 读取MSR结束值并加到DEST上(差值计算的后半部分)
/// 两者配合使用：DEST = (结束值 - 起始值) = MSR增量
/// lfence确保rdmsr前后的指令序列化，防止乱序执行影响测量精度
/// rdmsr将MSR高32位读入edx，低32位读入eax；shl+or合并为64位值
/// 破坏寄存器：rax, rcx, rdx
///
// clobber: rax, rcx, rdx
#define READ_MSR_START(ID, DEST)                          \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "sub "DEST", rdx                         \n"

// clobber: rax, rcx, rdx
#define READ_MSR_END(ID, DEST)                            \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "add "DEST", rdx                         \n"


/// =================================================================================================
/// PMU性能计数器访问器宏
/// =================================================================================================
/// READ_ONE_PFC(ID): 使用rdpmc读取指定PMC计数器的当前值
///   ID=ECX值(1/2/3对应PMC1/2/3)，rdpmc结果: edx[高32位]|eax[低32位]
///   lfence确保rdpmc前后序列化，防止乱序执行影响计数精度
///   shl+or将edx:eax合并为64位值存入rdx
/// READ_PFC_START(): 读取PMC#1/#2/#3起始值并分别从PFC0/#1/#2(r10/r9/r8)中减去
/// READ_PFC_END():   读取PMC#1/#2/#3结束值并分别加到PFC0/#1/#2(r10/r9/r8)上
/// 最终：PFCn = (PMCn结束值 - PMCn起始值) = 计数器增量
/// 破坏寄存器：rax, rcx, rdx
///
// clobber: rax, rcx, rdx
#define READ_ONE_PFC(ID) \
        "mov rcx, "ID" \n"      \
        "lfence; rdpmc; lfence \n" \
        "shl rdx, 32; or rdx, rax \n"

// clobber: rax, rcx, rdx
#define READ_PFC_START() \
        READ_ONE_PFC("1") \
        "sub "PFC0", rdx \n" \
        READ_ONE_PFC("2") \
        "sub "PFC1", rdx \n" \
        READ_ONE_PFC("3") \
        "sub "PFC2", rdx \n"

// clobber: rax, rcx, rdx
#define READ_PFC_END() \
        READ_ONE_PFC("1") \
        "add "PFC0", rdx \n" \
        READ_ONE_PFC("2") \
        "add "PFC1", rdx \n" \
        READ_ONE_PFC("3") \
        "add "PFC2", rdx \n"


/// =================================================================================================
/// SMI(系统管理中断)检测宏
/// =================================================================================================
/// SMI是不可屏蔽的高优先级中断，会干扰微架构状态导致测量不准
/// 检测策略：读取SMI计数器(起始/结束)，计算差值，存储在STATUS_REGISTER中
/// STATUS_REGISTER布局：[63:32]=SMI计数起始值(以负偏移形式存储), [31:0]=SMI差值(结束-起始)
/// 若差值!=0则说明测量期间发生了SMI，该测量结果应丢弃

/// CLEAR_SMI_STATUS(): 清除STATUS_REGISTER高32位(将32位值复制到自己，零扩展高32位)
///   mov r12d, r12d → 高32位被清零，低32位保留
#define CLEAR_SMI_STATUS() \
   "mov "STATUS_REGISTER_32", "STATUS_REGISTER_32" \n"

#if VENDOR_ID == VENDOR_INTEL_
/// Intel SMI监控——使用MSR_SMI_COUNT(0x34)读取SMI计数器
/// READ_SMI_START(): 读取MSR 0x34当前值，计算负偏移(ecx=0-eax)，左移32位存入STATUS[63:32]
///   步骤：rdmsr读MSR→0-eax得到负偏移→shl rcx,32→CLEAR清除高32位→or合并到STATUS
/// READ_SMI_END(): 读取MSR 0x34当前值，从STATUS[63:32]取出起始偏移，加eax计算差值存入STATUS[31:0]
///   步骤：rdmsr读MSR→取出STATUS高32位→add ecx,eax得到差值→shl rcx,32→CLEAR→or合并到STATUS
/// 破坏寄存器：rax, rcx, rdx
///  clobber: rax, rcx, rdx
#define READ_SMI_START()               \
    "mov rcx, "xstr(MSR_SMI_COUNT)"\n" \
    "lfence; rdmsr; lfence         \n" \
    "mov rcx, 0                    \n" \
    "sub ecx, eax                  \n" \
    "shl rcx, 32                   \n" \
    CLEAR_SMI_STATUS()                 \
    "or "STATUS_REGISTER", rcx     \n"

/// clobber: rax, rcx, rdx
#define READ_SMI_END()                 \
    "mov rcx, "xstr(MSR_SMI_COUNT)"\n" \
    "lfence; rdmsr; lfence         \n" \
    "mov rcx, "STATUS_REGISTER"    \n" \
    "shr rcx, 32                   \n" \
    "add ecx, eax                  \n" \
    "shl rcx, 32                   \n" \
    CLEAR_SMI_STATUS()                 \
    "or "STATUS_REGISTER", rcx     \n"
#elif VENDOR_ID == VENDOR_AMD_
/// AMD SMI监控——使用PMC#5(rdpmc)读取SMI计数器
/// AMD没有MSR_SMI_COUNT，改用PMU计数器5监控SMI事件
/// READ_SMI_START/END逻辑与Intel版相同，只是用rdpmc替代rdmsr
/// 破坏寄存器：rax, rcx, rdx
///  clobber: rax, rcx, rdx
#define READ_SMI_START()            \
    "mov rcx, 5                 \n" \
    "lfence; rdpmc; lfence      \n" \
    "mov rcx, 0                 \n" \
    "sub ecx, eax               \n" \
    "shl rcx, 32                \n" \
    CLEAR_SMI_STATUS()              \
    "or "STATUS_REGISTER", rcx  \n"

/// clobber: rax, rcx, rdx
#define READ_SMI_END()              \
    "mov rcx, 5                 \n" \
    "lfence; rdpmc; lfence      \n" \
    "mov rcx, "STATUS_REGISTER" \n" \
    "shr rcx, 32                \n" \
    "add ecx, eax               \n" \
    "shl rcx, 32                \n" \
    CLEAR_SMI_STATUS()              \
    "or "STATUS_REGISTER", rcx  \n"

#endif


/// =================================================================================================
/// 流水线重置宏
/// =================================================================================================
/// 尝试将CPU流水线设置为统一初始状态，减少先前代码对测量的影响
/// 通过执行大量lfence指令，等待保留站中的所有微操作完成执行
/// 25条lfence(5x5网格)——足够让流水线排空，确保测试用例从近似空流水线状态开始
/// 破坏寄存器：无
/// clobber: none
#define PIPELINE_RESET() asm volatile(""\
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n");


/// =================================================================================================
/// 寄存器初始化宏——从沙箱输入区加载测试用例的初始寄存器值
/// =================================================================================================
/// 步骤：
/// 1. lea rsp, [MEMORY_BASE_REG + REG_INIT_OFFSET] —— 将栈指向输入初始化区
/// 2. pop rax/rbx/rcx/rdx/rsi/rdi/popfq —— 从输入区依次弹出初始值到各寄存器
/// 3. lea rsp, [MEMORY_BASE_REG + LOCAL_RSP_OFFSET] —— 将栈切换到本地栈
/// 4. mov rbp, rsp —— 设置栈帧基址
/// Intel和AMD版本代码相同(当前无架构差异)
/// Register Loading
#if VENDOR_ID == 1 // Intel
#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, ["MEMORY_BASE_REG" + "xstr(REG_INIT_OFFSET)"]\n" \
    "pop rax \n" \
    "pop rbx \n" \
    "pop rcx \n" \
    "pop rdx \n" \
    "pop rsi \n" \
    "pop rdi \n" \
    "popfq \n" \
    "lea rsp, ["MEMORY_BASE_REG" + "xstr(LOCAL_RSP_OFFSET)"]\n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");

#elif VENDOR_ID == 2 // AMD
#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, ["MEMORY_BASE_REG" + "xstr(REG_INIT_OFFSET)"]\n" \
    "pop rax \n" \
    "pop rbx \n" \
    "pop rcx \n" \
    "pop rdx \n" \
    "pop rsi \n" \
    "pop rdi \n" \
    "popfq \n" \
    "lea rsp, ["MEMORY_BASE_REG" + "xstr(LOCAL_RSP_OFFSET)"]\n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");
#endif

// =================================================================================================
/// =================================================================================================
/// L1D Prime+Probe 侧信道攻击宏
/// =================================================================================================
/// Prime+Probe原理：
///   Prime阶段：将L1D缓存填满已知数据(遍历每个缓存组的每条cache line)
///   Probe阶段：重新访问Prime时填充的数据，测量访问时间
///   如果测试用例访问了某个缓存组，对应cache line被替换，Probe时时间变长
///
/// L1D_ASSOCIATIVITY决定每个缓存组的cache line数，影响PRIME_ONE_SET/PROBE_ONE_SET的访问次数
/// 每条cache line偏移4096字节(利用同一组内不同way的地址映射，同一组的way在物理地址上相隔4KB)
///
/// PRIME_ONE_SET(BASE, OFFSET, TMP)：填充一个缓存组
///   使用add指令访问数据(既读又写)，配合mfence确保每次访问完成
///   TMP用于计算地址偏移，避免破坏OFFSET原始值
///
/// PROBE_ONE_SET(BASE, OFFSET)：探查一个缓存组
///   与PRIME_ONE_SET类似，但使用固定rax作为累加器
///
/// PRIME(BASE, OFFSET, TMP, COUNTER, REPS)：完整Prime阶段
///   外层循环：重复REPS次(多次Prime减少噪声)
///   内层循环：遍历64个缓存组(offset从0到4096，步长64字节)
///
/// PROBE_INTEL/PROBE_AMD：完整Probe阶段(Intel/AMD版本)
///   遍历每个缓存组，使用PMC#0测量访问时间
///   如果PMC增量>=L1D_ASSOCIATIVITY，说明cache miss(被测试用例替换)→输出1
///   否则说明cache hit(未被替换)→输出0
///   结果压缩为位串存入DEST(HTRACE_REGISTER)
///
/// TODO: 动态生成此代码而非硬编码各种相联度
// L1D Prime+Probe
// TODO: generate this code dynamically
#if L1D_ASSOCIATIVITY == 2
/// 2路相联度——每个缓存组只需访问2条cache line(偏移0和4096)
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n"

#elif L1D_ASSOCIATIVITY == 4
/// 4路相联度——每个缓存组需访问4条cache line(偏移0,4096,8192,12288)
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n"

#elif L1D_ASSOCIATIVITY == 8
/// 8路相联度——每个缓存组需访问8条cache line(偏移0~28672，步长4096)
/// 这是最常见的L1D相联度(Intel Core系列)
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 16384]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 20480]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 24576]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 28672]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n" \
        "add rax, ["BASE" + rax + 16384]; mfence \n" \
        "add rax, ["BASE" + rax + 20480]; mfence \n" \
        "add rax, ["BASE" + rax + 24576]; mfence \n" \
        "add rax, ["BASE" + rax + 28672]; mfence \n"

#elif L1D_ASSOCIATIVITY == 12
/// 12路相联度——每个缓存组需访问12条cache line(偏移0~45056，步长4096)
/// 某些AMD处理器的L1D使用此相联度
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 16384]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 20480]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 24576]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 28672]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 32768]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 36864]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 40960]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 45056]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n" \
        "add rax, ["BASE" + rax + 16384]; mfence \n" \
        "add rax, ["BASE" + rax + 20480]; mfence \n" \
        "add rax, ["BASE" + rax + 24576]; mfence \n" \
        "add rax, ["BASE" + rax + 28672]; mfence \n" \
        "add rax, ["BASE" + rax + 32768]; mfence \n" \
        "add rax, ["BASE" + rax + 36864]; mfence \n" \
        "add rax, ["BASE" + rax + 40960]; mfence \n" \
        "add rax, ["BASE" + rax + 45056]; mfence \n"

#else
#error "Unexpected associativity"
#endif

/// PRIME(BASE, OFFSET, TMP, COUNTER, REPS)：完整Prime阶段
/// 外层循环(COUNTER/REPS)：重复REPS次，多次Prime减少噪声
/// 内层循环(OFFSET)：遍历64个缓存组(offset从0到4096，步长64字节)
///   1: 外层循环入口，OFFSET=0
///     2: 内层循环入口，lfence序列化
///       PRIME_ONE_SET：填充当前缓存组
///       add OFFSET, 64：下一个缓存组
///     cmp OFFSET, 4096; jl 2b：未遍历完64组则继续
///   dec COUNTER; jnz 1b：未达到REPS次则继续
/// mfence：确保所有内存操作完成
/// clobber: none
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
                PRIME_ONE_SET(BASE, OFFSET, TMP)                \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"


/// PROBE_INTEL(BASE, OFFSET, TMP, DEST)：Intel版Probe阶段
/// 遍历64个缓存组(offset从0到4096，步长64字节)
/// 对每个缓存组：
///   1. 读取PMC#0起始值，减去(TMP清零后减PMC起始值)
///   2. 执行PROBE_ONE_SET(访问缓存组)
///   3. 读取PMC#0结束值，加上(TMP加上PMC结束值)
///   4. 判断：TMP>=L1D_ASSOCIATIVITY → cache miss(被替换) → shl DEST,1(输出0位)
///            TMP<L1D_ASSOCIATIVITY  → cache hit(未被替换) → shl DEST,1; or DEST,1(输出1位)
/// 结果为64位位串存入DEST(HTRACE_REGISTER)，每一位表示一个缓存组是否被测试用例访问
/// clobber: rax, rcx, rdx
#define PROBE_INTEL(BASE, OFFSET, TMP, DEST)            \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1: lfence                                  \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_ONE_PFC("0")                           \
        "   sub "TMP", rdx                          \n" \
            PROBE_ONE_SET(BASE, OFFSET)                 \
            READ_ONE_PFC("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", "xstr(L1D_ASSOCIATIVITY)"    \n" \
        "   jl 2f                                   \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

/// PROBE_AMD(BASE, OFFSET, TMP, DEST)：AMD版Probe阶段
/// 与PROBE_INTEL逻辑相同，但PMC判断条件相反：
///   TMP>0 → cache miss(AMD PMC行为：miss时计数器递增) → 输出0位
///   TMP==0 → cache hit(AMD PMC行为：hit时计数器不递增) → 输出1位
/// clobber: rax, rcx, rdx
#define PROBE_AMD(BASE, OFFSET, TMP, DEST)              \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1: lfence                                  \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_ONE_PFC("0")                           \
        "   sub "TMP", rdx                          \n" \
            PROBE_ONE_SET(BASE, OFFSET)                 \
            READ_ONE_PFC("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jg 2f                     \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

/// 根据VENDOR_ID选择对应Probe版本：Intel使用PROBE_INTEL，AMD使用PROBE_AMD
#if VENDOR_ID == 1
#define PROBE(BASE, OFFSET, TMP, DEST) PROBE_INTEL(BASE, OFFSET, TMP, DEST)
#elif VENDOR_ID == 2
#define PROBE(BASE, OFFSET, TMP, DEST) PROBE_AMD(BASE, OFFSET, TMP, DEST)
#endif

// =================================================================================================
/// =================================================================================================
/// 部分Prime+Probe(仅对L1D的部分缓存组而非全部执行P+P)
/// =================================================================================================
/// PRIME_PARTIAL：与PRIME类似，但只遍历offset 0到3840(而非4096)
/// 即跳过最后4个缓存组(3840/64=60组，留下4组未探测)
/// 用于减少P+P开销或只关注特定地址范围
// Partial Prime+Probe (P+P applied to a subset of L1D instead the whole cache)
// =================================================================================================
#define PRIME_PARTIAL(BASE, OFFSET, TMP, COUNTER, REPS)         \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
                PRIME_ONE_SET(BASE, OFFSET, TMP)                \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 3840; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

// =================================================================================================
/// =================================================================================================
/// L1D Flush+Reload 侧信道攻击宏
/// =================================================================================================
/// Flush+Reload原理：
///   Flush阶段：使用clflush指令将L1D中的目标cache line全部逐出
///   Reload阶段：重新加载被逐出的cache line，测量加载时间
///   如果测试用例访问了某条cache line，Reload时命中L3→快(PMC增量小)
///   否则Reload时需从内存加载→慢(PMC增量>0)
///
/// FLUSH(BASE, OFFSET)：逐出整个4KB页的所有cache line
///   clflush qword ptr [BASE+OFFSET]：逐出指定地址的cache line
///   遍历offset 0到4096，步长64(一条cache line=64字节)
///   clobber: none

// L1D Flush+Reload
// =================================================================================================

// clobber: none
#define FLUSH(BASE, OFFSET) \
        "mfence                                     \n" \
        "mov "OFFSET", 0                            \n" \
        "1: lfence                                  \n" \
        "   clflush qword ptr ["BASE" + "OFFSET"]   \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n" \
        "mfence                                     \n"

/// RELOAD_INTEL(BASE, OFFSET, TMP, DEST)：Intel版Reload阶段
/// 遍历64个cache line(offset从0到4096，步长64字节)
/// 对每个cache line：
///   1. 读取PMC#0起始值
///   2. mov rax, [BASE+OFFSET]——加载被逐出的cache line
///   3. 读取PMC#0结束值，计算差值TMP
///   4. 判断：TMP!=0 → 命中L3(快访问，PMC未递增) → 输出0位(未被测试用例访问)
///            TMP==0 → 从内存加载(慢访问，PMC递增了) → 输出1位(被测试用例访问)
///   结果压缩为位串存入DEST(HTRACE_REGISTER)
/// clobber: rax, rcx, rdx
#define RELOAD_INTEL(BASE, OFFSET, TMP, DEST)           \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_ONE_PFC("0")                           \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
            READ_ONE_PFC("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

/// RELOAD_AMD(BASE, OFFSET, TMP, DEST)：AMD版Reload阶段
/// 与RELOAD_INTEL逻辑相同，但PMC判断条件相反：
///   TMP==0 → 命中L3(快访问，AMD PMC不递增) → 输出0位
///   TMP!=0 → 从内存加载(慢访问，AMD PMC递增了) → 输出1位
/// (Intel和AMD的PMC行为差异导致判断逻辑相反)
/// clobber: rax, rcx, rdx
#define RELOAD_AMD(BASE, OFFSET, TMP, DEST)             \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_ONE_PFC("0")                           \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
            READ_ONE_PFC("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; je 2f                     \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

/// 根据VENDOR_ID选择对应Reload版本
#if VENDOR_ID == 1
#define RELOAD(BASE, OFFSET, TMP, DEST) RELOAD_INTEL(BASE, OFFSET, TMP, DEST)
#elif VENDOR_ID == 2
#define RELOAD(BASE, OFFSET, TMP, DEST) RELOAD_AMD(BASE, OFFSET, TMP, DEST)
#endif

// =================================================================================================
/// =================================================================================================
/// 宏栈管理——为复杂宏调用提供独立的栈空间
/// =================================================================================================
/// 问题：测试用例执行期间rsp指向本地栈(仅4KB)，某些宏(如P+P)需要更多栈空间
/// 解决：使用沙箱内存区末尾作为"宏栈"，在宏调用前切换栈指针
///
/// MACRO_PROLOGUE()：切换到宏栈并保存当前寄存器状态
///   1. 保存当前rsp到宏栈顶部——[MEMORY_BASE_REG - MACRO_STACK_TOP_OFFSET - 8]处
///   2. 切换rsp到宏栈顶部——lea rsp, [MEMORY_BASE_REG - MACRO_STACK_TOP_OFFSET - 8]
///   3. push rax/rbx/rcx/rdx/rflags——保存宏调用前可能被破坏的寄存器
///
/// MACRO_EPILOGUE()：恢复寄存器状态并切换回原始栈
///   1. pop rflags/rdx/rcx/rbx/rax——恢复保存的寄存器
///   2. 用零覆盖宏栈上的保存位置——清除残留数据防止侧信道泄漏
///   3. pop rsp——恢复原始栈指针(从宏栈顶部弹出保存的rsp值)
// Macro stack management
// =================================================================================================
/// @brief 切换栈指针到宏栈并保存flags和RAX/RBX/RCX/RDX寄存器
///        宏栈位于沙箱内存区末尾，大小约4KB，供Prime+Probe等复杂宏使用
#define MACRO_PROLOGUE()                                                                           \
    "mov qword ptr ["MEMORY_BASE_REG" - " xstr(MACRO_STACK_TOP_OFFSET) " - 8], rsp\n"            \
    "lea rsp, ["MEMORY_BASE_REG" - " xstr(MACRO_STACK_TOP_OFFSET) " - 8]\n"                      \
    "push rax\n"                                                                                   \
    "push rbx\n"                                                                                   \
    "push rcx\n"                                                                                   \
    "push rdx\n"                                                                                   \
    "pushf\n"

/// @brief 恢复保存的寄存器、清除宏栈残留数据、恢复原始栈指针
///        零覆盖5个保存位置(5*8=40字节)防止侧信道泄漏
///        pop rsp恢复到prologue保存的原始栈位置
#define MACRO_EPILOGUE()                                                                           \
    "popf\n"                                                                                       \
    "pop rdx\n"                                                                                    \
    "pop rcx\n"                                                                                    \
    "pop rbx\n"                                                                                    \
    "pop rax\n"                                                                                    \
    "mov qword ptr [rsp - 0x08], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x10], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x18], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x20], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x28], 0 \n"                                                             \
    "pop rsp\n"

// clang-format on
#endif // X86_ASM_SNIPPETS_H_

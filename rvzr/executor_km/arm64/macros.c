// =====================================================================
// ARM64架构下各种宏的实现文件——支持跨域测试的核心文件
//
// 本文件实现了支持U2U、K2U、H2G、G2H跨域侧信道测试的所有宏。
//
// ARM64异常级别(Exception Level, EL)机制：
//   EL0: 用户态——最低特权级，应用程序运行在此级别，无法访问系统寄存器
//   EL1: 内核态——操作系统内核运行在此级别，可访问大部分系统寄存器
//   EL2: 虚拟化管理态——Hypervisor运行在此级别，控制虚拟化和Stage-2地址翻译
//   EL3: 安全监控态——最高特权级，TrustZone安全固件运行在此级别
//
// ARM64跨域切换指令：
//   eret: 异常返回指令——从当前EL恢复到SPSR_ELx中保存的更低EL
//         执行eret时：PSTATE ← SPSR_ELx, PC ← ELR_ELx
//   svc #0: 超级用户调用——从EL0触发同步异常，跳转到EL1/EL2的SVC异常向量
//   hvc #0: 虚拟化管理调用——从EL1触发虚拟化异常，跳转到EL2的HVC异常向量
//
// 宏系统工作原理（论文Section 4.4）：
//   宏通过"二进制补丁"(binary patching)机制实现。测试用例中的宏调用位置
//   最初是NOP占位符，宏扩展将这些NOP替换为跳转指令，跳转到宏的实现代码。
//   每个宏包含两部分：
//     1) 动态配置部分(start函数)：根据宏参数动态生成机器码，可配置
//     2) 静态主体部分(body函数)：不可配置，通过MACRO_START/MACRO_END标记提取
//   宏扩展后执行流程：NOP→JMP→[动态代码]→[静态代码]→JMP→返回原代码流
//
// ARM64寄存器约定（详见registers.h）：
//   x20(MEMORY_BASE_REGISTER): actor数据区基址，所有数据访问通过[x20+offset]寻址
//   x21(UTIL_BASE_REGISTER): 工具区基址，测量宏的L1D priming缓冲区通过[x21+offset]访问
//   x12(STATUS_REGISTER): 测量状态寄存器，追踪Prime/Probe/Flush/Reload状态机
//   x13(HTRACE_REGISTER): 侧信道迹寄存器，存储缓存探测结果的位向量
//   x28-x23(TMP_REG1-6): 临时寄存器，宏代码可自由使用，无需保存/恢复
//   x10-x8(PFC0-2): 性能计数器寄存器
//
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
// =====================================================================

#include "asm_snippets.h"
#include "fault_handler.h"
#include "macro_expansion.h"
#include "main.h"
#include "page_tables_host.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

// =====================================================================
// ARM64虚拟化全局变量——弱符号定义
// 正式实现虚拟化管理时，应在vm.c中提供强符号定义覆盖这些占位值
// 当前为NULL/0占位值，确保文件可编译链接
// H2G/G2H宏在运行时检查这些变量非空，虚拟化未实现时会断言失败
// =====================================================================
uint64_t *vttbr_hpas __attribute__((weak)) = NULL;
uint64_t svc_vector_base __attribute__((weak)) = 0;
uint64_t hvc_vector_base __attribute__((weak)) = 0;

// =====================================================================
// 向目标缓冲区写入常量的便捷宏——用于动态生成ARM64机器码
// ARM64指令固定4字节宽度，这些宏将各种宽度的数值写入dest缓冲区
// 在域切换宏的动态配置部分(start_macro*)中大量使用
// =====================================================================
#define APPEND_U8_TO_DEST(value) dest[cursor++] = value;

#define APPEND_U16_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint16_t *)(dest + cursor)) = value;                                                    \
        cursor += 2;                                                                               \
    }

#define APPEND_U32_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint32_t *)(dest + cursor)) = value;                                                    \
        cursor += 4;                                                                               \
    }

#define APPEND_U64_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint64_t *)(dest + cursor)) = value;                                                    \
        cursor += 8;                                                                               \
    }

#define APPEND_BYTES_TO_DEST(...)                                                                  \
    {                                                                                              \
        static const uint8_t bytes[] = {__VA_ARGS__};                                              \
        for (size_t i = 0; i < sizeof(bytes); i++) {                                               \
            dest[cursor++] = bytes[i];                                                             \
        }                                                                                          \
    }

// =====================================================================
// ARM64指令操作码编码函数
//
// ARM64 A64指令集所有指令固定32位（4字节）宽度，采用固定位置编码格式。
// 以下函数根据指令格式规范生成各指令的二进制操作码，用于在start_macro*
// 函数中动态生成机器码序列。
//
// 参考文档：ARM Architecture Reference Manual (DDI 0487)
// =====================================================================

/// @brief MOVZ指令——将16位立即数零扩展至64位并写入目标寄存器
///        格式: movz rd, #imm16, lsl #shift
///        编码: sf=1, opc=10, hw=shift, imm16, rd
///        用于mov_uint64_to_reg中加载64位立即数的第1步
static inline uint32_t movz(uint8_t rd, uint16_t imm16, uint8_t shift)
{
    uint32_t opcode = 0xd2800000;
    opcode |= rd;                    // bits[4:0]: 目标寄存器编号
    opcode |= (imm16 & 0xffff) << 5; // bits[20:5]: 16位立即数
    opcode |= shift << 21;           // bits[22:21]: 移位量(0/16/32/48)
    return opcode;
}

/// @brief MOVK指令——将16位立即数插入目标寄存器的指定位置，其余位不变
///        格式: movk rd, #imm16, lsl #shift
///        编码: sf=1, opc=11, hw=shift, imm16, rd
///        用于mov_uint64_to_reg中加载64位立即数的后续步骤
///        与MOVZ配合：MOVZ加载低16位，3条MOVK分别加载高16/32/48位
static inline uint32_t movk(uint8_t rd, uint16_t imm16, uint8_t shift)
{
    uint32_t opcode = 0xf2800000;
    opcode |= rd;                    // bits[4:0]: 目标寄存器编号
    opcode |= (imm16 & 0xffff) << 5; // bits[20:5]: 16位立即数
    opcode |= shift << 21;           // bits[22:21]: 移位量(0/16/32/48)
    return opcode;
}

/// @brief ADD指令(立即数)——将rd+0写入SP，等效于MOV SP, rd
///        格式: add sp, rd, #0
///        编码: sf=1, op=0(ADD), S=0, shift=00, imm12=0, rn=rd, rd=31(SP)
///        ARM64没有直接的"MOV SP, xn"指令，使用ADD SP, xn, #0实现
static inline uint32_t mov_to_sp(uint8_t rd) { return 0x9100001f | (rd << 5); }

/// @brief B指令(无条件相对跳转)——跳转到offset偏移处的指令
///        格式: b offset
///        编码: opc=000101, imm26=offset/4
///        ARM64的B指令偏移量以4字节(指令宽度)为单位，26位有符号偏移
///        范围: ±128MB，足够覆盖sandbox内的所有跳转目标
static inline uint32_t b_imm(uint32_t offset)
{
    offset = offset / 4;
    int sign = offset < 0 ? 1 : 0;
    offset = (offset & 0x3FFFFFF) | (sign << 25);
    return 0x14000000 | offset;
}

/// @brief ORR指令(移位寄存器)——逻辑或，别名MOV rd, rn
///        格式: mov rd, rn (别名: orr rd, xzr, rn)
///        编码: sf=1, opc=01(ORR), shift=00, N=0, rm=xn, imm6=0, rn=31(XZR), rd=rd
///        注意：bits[20:16]为Rm字段(第二源操作数)，bits[9:5]为Rn字段(第一源操作数)
static inline uint32_t mov_reg(uint8_t rd, uint8_t rn)
{
    uint32_t opcode = 0xaa0003e0;
    opcode |= (rn & 0x1f) << 16; // bits[20:16]: Rm=源寄存器(MOV别名中为rn)
    opcode |= rd;                 // bits[4:0]: Rd=目标寄存器
    return opcode;
}

/// @brief ADD指令(寄存器)——三寄存器加法
///        格式: add rd, rn, rm
///        编码: sf=1, op=0(ADD), S=0, shift=00, Rm=rm, imm6=0, Rn=rn, Rd=rd
static inline uint32_t add_reg(uint8_t rd, uint8_t rn, uint8_t rm)
{
    uint32_t opcode = 0x8b000000;
    opcode |= rd;                // bits[4:0]: 目标寄存器
    opcode |= (rn & 0x1f) << 5;  // bits[9:5]: 第一源寄存器
    opcode |= (rm & 0x1f) << 16; // bits[20:16]: 第二源寄存器
    return opcode;
}

/// @brief STR指令(寄存器偏移)——64位存储，将rt写入[rn]指向的内存地址
///        格式: str rt, [rn]
///        编码: size=11(64位), V=0, opc=00, imm9=0, op=01, Rn=rn, Rt=rt
///        用于向内存写入寄存器值，如将目标地址写入util_vars字段
static inline uint32_t str_reg(uint8_t rt, uint8_t rn)
{
    uint32_t opcode = 0xf9000000;
    opcode |= rt;               // bits[4:0]: 源寄存器(要存储的值)
    opcode |= (rn & 0x1f) << 5; // bits[9:5]: 基址寄存器(目标内存地址)
    return opcode;
}

/// @brief LDR指令(寄存器偏移)——64位加载，从[rn]指向的内存地址加载到rt
///        格式: ldr rt, [rn]
///        编码: size=11(64位), V=0, opc=01, imm9=0, op=01, Rn=rn, Rt=rt
///        用于从内存读取数据到寄存器，如从util_vars读取目标地址
static inline uint32_t ldr_reg(uint8_t rt, uint8_t rn)
{
    uint32_t opcode = 0xf9400000;
    opcode |= rt;               // bits[4:0]: 目标寄存器(加载结果)
    opcode |= (rn & 0x1f) << 5; // bits[9:5]: 基址寄存器(源内存地址)
    return opcode;
}

/// @brief ORR指令(移位寄存器,无移位)——64位逻辑或，用于修改PTE权限位
///        格式: orr rd, rn, rm (无移位)
///        编码: sf=1, opc=01, shift=00, N=0, Rm=rm, imm6=0, Rn=rn, Rd=rd
///        在set_data_permissions宏中用于对PTE值应用OR掩码(mask_set)
static inline uint32_t orr_reg(uint8_t rd, uint8_t rn, uint8_t rm)
{
    uint32_t opcode = 0xAA000000;
    opcode |= rd;                // bits[4:0]: 目标寄存器
    opcode |= (rn & 0x1f) << 5;  // bits[9:5]: 第一源寄存器
    opcode |= (rm & 0x1f) << 16; // bits[20:16]: 第二源寄存器
    return opcode;
}

/// @brief AND指令(移位寄存器,无移位)——64位逻辑与，用于修改PTE权限位
///        格式: and rd, rn, rm (无移位)
///        编码: sf=1, opc=00, shift=00, N=0, Rm=rm, imm6=0, Rn=rn, Rd=rd
///        在set_data_permissions宏中用于对PTE值应用AND掩码(mask_clear)
static inline uint32_t and_reg(uint8_t rd, uint8_t rn, uint8_t rm)
{
    uint32_t opcode = 0x8A000000;
    opcode |= rd;                // bits[4:0]: 目标寄存器
    opcode |= (rn & 0x1f) << 5;  // bits[9:5]: 第一源寄存器
    opcode |= (rm & 0x1f) << 16; // bits[20:16]: 第二源寄存器
    return opcode;
}

// =====================================================================
// ARM64系统寄存器MSR指令编码常量
//
// MSR指令格式: msr <sysreg>, <xt>
// 二进制编码: 0xD5100000 | (op0<<19) | (op1<<16) | (CRn<<12) | (CRm<<8) | (op2<<5) | Rt
// 其中Rt为目标通用寄存器编号，在生成指令时动态填入
//
// 以下常量不含Rt字段(bits[4:0])，使用时需与寄存器编号OR运算
// 例如: msr ELR_EL2, x28 的编码 = MSR_ELR_EL2_ENCODING | TMP_REG1_ID
//
// 参考文档：ARM ARM D12.2.1 System instruction encoding for AArch64 system registers
// =====================================================================

// SPSR_EL2: 保存的程序状态寄存器(EL2)
// eret指令从此寄存器恢复PSTATE，包括目标异常级别(M字段)
// M字段编码: 0x0=EL0t, 0x4=EL1t, 0x5=EL1h, 0x8=EL2t, 0x9=EL2h
// 编码参数: op0=3, op1=4, CRn=4, CRm=0, op2=0
#define MSR_SPSR_EL2_ENCODING  0xD51C4000

// ELR_EL2: 异常链接寄存器(EL2)
// eret指令从此寄存器读取返回地址(PC目标值)
// K2U: ELR_EL2 = 用户态目标函数地址; H2G: ELR_EL2 = 客户机入口地址
// 编码参数: op0=3, op1=4, CRn=4, CRm=0, op2=1
#define MSR_ELR_EL2_ENCODING   0xD51C4020

// VTTBR_EL2: 虚拟化翻译表基址寄存器(EL2)
// 指向Stage-2页表(PGT)的物理基址，控制guest VM的物理内存映射
// H2G切换前需将此寄存器设为对应guest的S2PT物理地址
// 编码参数: op0=3, op1=4, CRn=2, CRm=0, op2=1
#define MSR_VTTBR_EL2_ENCODING 0xD51C2020

// VBAR_EL1: 向量基址寄存器(EL1)
// 指向异常向量表基址，SVC/IRQ/FIQ/SError等异常的处理入口
// SVC从EL0触发时跳转到VBAR_EL1 + 0x400
// 必须2KB(2048字节)对齐
// 编码参数: op0=3, op1=0, CRn=12, CRm=0, op2=0
#define MSR_VBAR_EL1_ENCODING  0xD518C000

// VBAR_EL2: 向量基址寄存器(EL2)
// 指向EL2异常向量表基址，HVC/IRQ等异常在EL2的处理入口
// HVC从EL1触发时跳转到VBAR_EL2 + 0x400
// 必须2KB对齐
// 编码参数: op0=3, op1=4, CRn=12, CRm=0, op2=0
#define MSR_VBAR_EL2_ENCODING  0xD51CC000

// =====================================================================
// ARM64关键指令操作码常量——用于动态生成的代码序列中
//
// 这些指令在域切换宏的动态配置部分(start_macro*)中作为"屏障"
// 确保MSR写入在后续指令执行前生效，维护系统寄存器修改的有序性
// =====================================================================

// ISB: 指令同步屏障——刷新处理器流水线，确保之前的MSR写入生效
//      MSR写入系统寄存器后必须紧跟ISB，否则后续指令可能使用旧值
//      编码: CRm=0xF, op2=6, Rt=0x1F (op0=3, op1=3, CRn=3)
#define OPCODE_ISB     0xD5033FDF

// DSB SY: 数据同步屏障(全系统)——确保之前的内存访问对所有观察者可见
//          在修改PTE权限后使用，确保PTE修改对后续内存访问生效
//          编码: CRm=0xF(SY选项), op2=4(DSB), Rt=0x1F
#define OPCODE_DSB_SY  0xD5033F9F

// =====================================================================
// 辅助函数——MSR写入序列生成器
//
// ARM64写入系统寄存器需要两步：(1)将值加载到通用寄存器 (2)通过MSR指令写入
// 此函数生成完整的MSR写入序列：MOVZ+MOVK加载64位值 → MSR写入 → ISB屏障
// =====================================================================

/// @brief 生成将64位值写入ARM64系统寄存器的完整指令序列
///        步骤：movz+movk加载值到src_reg → msr <sysreg>, src_reg → isb
/// @param src_reg 临时通用寄存器编号(用于暂存值，如TMP_REG1_ID=0x1c=x28)
/// @param sysreg_encoding 系统寄存器的MSR编码(不含Rt字段，如MSR_ELR_EL2_ENCODING)
/// @param value 要写入系统寄存器的64位立即数
/// @param dest 目标代码缓冲区指针
/// @param cursor 当前写入位置
/// @return 写入的字节数
static inline uint64_t msr_write_to_reg(uint8_t src_reg, uint32_t sysreg_encoding,
                                         uint64_t value, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // 步骤1: 使用MOVZ+MOVK序列将64位立即数加载到src_reg寄存器
    // ARM64没有64位立即数的单条指令，必须用4条指令逐16位拼接
    cursor += mov_uint64_to_reg(src_reg, value, dest, cursor);

    // 步骤2: 生成MSR指令——将src_reg的值写入目标系统寄存器
    // MSR编码 = 系统寄存器编码常数 | 寄存器编号(Rt字段, bits[4:0])
    uint32_t opcode = sysreg_encoding | src_reg;
    APPEND_U32_TO_DEST(opcode);

    // 步骤3: ISB指令同步屏障——确保MSR写入在后续指令执行前完成
    // ARM架构要求：修改异常级别控制寄存器(SPSR/ELR/VBAR)后必须执行ISB
    // 否则eret/svc/hvc可能使用旧的系统寄存器值，导致不可预测行为
    APPEND_U32_TO_DEST(OPCODE_ISB);

    return cursor - old_cursor;
}

// =====================================================================
// 辅助函数——64位立即数加载和地址计算
// =====================================================================

/// @brief 生成将64位立即数加载到寄存器的MOVZ+MOVK指令序列
///        ARM64没有单条加载64位立即数的指令，需4条指令逐16位拼接：
///        movz rd, #imm[0:15], lsl #0   — 加载最低16位，高位清零
///        movk rd, #imm[16:31], lsl #16 — 插入次低16位，其余位不变
///        movk rd, #imm[32:47], lsl #32 — 插入次高16位
///        movk rd, #imm[48:63], lsl #48 — 插入最高16位
/// @param rd 目标寄存器编号(0-31)
/// @param value 64位立即数值
/// @param dest 目标代码缓冲区指针
/// @param cursor 当前写入位置
/// @return 写入的字节数
static inline uint64_t mov_uint64_to_reg(uint8_t rd, uint64_t value, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    uint32_t opcode = movz(rd, value & 0xffff, 0);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, value >> 16 & 0xffff, 1);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, value >> 32 & 0xffff, 2);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, value >> 48 & 0xffff, 3);
    APPEND_U32_TO_DEST(opcode);

    return cursor - old_cursor;
}

/// @brief 根据section_id和function_id计算函数在代码段中的虚拟地址
///        用于域切换宏中确定跳转目标地址
///        代码段0(main actor)的起始位置包含硬编码的prologue，需要额外偏移
/// @param section_id 代码段ID(对应actor编号)
/// @param function_id 函数ID(符号表中的索引)
/// @return 函数的虚拟地址
static uint64_t get_function_addr(int section_id, int function_id)
{
    uint64_t section_base = 0;
    section_base = (uint64_t)sandbox->code[section_id].section;

    if (section_id == 0)
        section_base += get_main_prologue_size();

    return section_base + test_case->symbol_table[function_id].offset;
}

// =====================================================================
// 辅助函数——执行器寄存器更新
//
// 域切换后必须更新x20(数据基址)、x21(工具基址)和SP，使新actor的数据区
// 和工具区可被正确访问。每个着陆宏(landing)调用这些函数恢复寄存器。
//
// 宿主机(actor.mode==HOST)直接使用sandbox内存地址
// 客户机(actor.mode==GUEST)理论上应使用GUEST_V_MEMORY_START映射地址
// 但ARM64客户机支持尚未实现，当前仅处理HOST模式
// =====================================================================

/// @brief 生成更新x20(MEMORY_BASE_REGISTER)的指令序列
///        将x20设为指定actor的数据区基址(sandbox->data[section_id].main_area)
///        所有数据访问通过[x20+offset]寻址，域切换后必须更新x20
/// @param section_id actor编号
/// @param dest 目标代码缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_memory_base_reg(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    uint64_t new_val = (uint64_t)sandbox->data[section_id].main_area;
    uint8_t rd = MEMORY_BASE_REGISTER_ID;
    cursor += mov_uint64_to_reg(rd, new_val, dest, cursor);
    return cursor - old_cursor;
}

/// @brief 生成同时更新x20(数据基址)和SP的指令序列
///        SP = 数据区基址 + LOCAL_RSP_OFFSET(指向faulty_area之前的8字节位置)
///        确保栈在新actor的数据区内，避免栈溢出影响其他actor
/// @param section_id actor编号
/// @param dest 目标代码缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_mem_base_and_sp(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    cursor += update_memory_base_reg(section_id, dest, cursor);

    uint64_t new_sp = (uint64_t)sandbox->data[section_id].main_area + LOCAL_RSP_OFFSET;
    cursor += mov_uint64_to_reg(TMP_REG1_ID, new_sp, dest, cursor);

    // ASM: add sp, x28, #0 → MOV SP, TMP_REG1
    // ARM64无直接MOV SP指令，使用ADD SP, xn, #0等效实现
    uint32_t opcode = mov_to_sp(TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    return cursor - old_cursor;
}

/// @brief 生成更新x21(UTIL_BASE_REGISTER)的指令序列
///        将x21设为指定actor的工具区基址(sandbox->util)
///        Prime/Probe测量宏的L1D priming缓冲区通过[x21+offset]访问
///        性能计数器(PFC)相关数据也通过x21寻址
/// @param section_id actor编号
/// @param dest 目标代码缓冲区
/// @param cursor 当前写入位置
/// @return 写入的字节数
static uint64_t update_util_base_reg(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    uint64_t new_val = (uint64_t)sandbox->util;
    uint8_t rd = UTIL_BASE_REGISTER_ID;
    cursor += mov_uint64_to_reg(rd, new_val, dest, cursor);
    return cursor - old_cursor;
}

// =====================================================================
// 宏实现
//
// 宏由两部分组成：动态生成部分和静态主体部分。
// 动态部分由start_macro*函数生成，可根据宏参数进行配置（如跳转目标、
// 系统寄存器值等）。生成的代码作为二进制指令序列写入dest缓冲区。
// 静态部分由body_macro*函数定义，不可配置，在编译时已固定，
// 通过搜索MACRO_START/MACRO_END标记从函数体中提取并直接复制到
// 测试用例的宏内存区域。
// =====================================================================

// =====================================================================
// 测量宏 MEASUREMENT_START 和 MEASUREMENT_END
//
// 侧信道测量的核心原理：通过缓存访问模式推断被测代码的行为。
// Prime+Probe：填充(Prime)缓存集 → 执行被测代码 → 探测(Probe)缓存集
// Flush+Reload：刷新(Flush)缓存行 → 执行被测代码 → 重载(Reload)缓存行
// =====================================================================

// Prime+Probe测量开始宏——标准版本
// 流程：保存NZCV → 加载priming缓冲区地址 → Prime(填充L1D缓存) →
//       READ_PFC_START(开始性能计数) → SET_SR_STARTED → 恢复NZCV → dsb+isb
static void __attribute__((noipa)) body_macro_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                               //
                 "mrs " TMP_REG6 ", nzcv \n"                                      //
                 "mov " TMP_REG1 ", " UTIL_BASE_REGISTER "\n"                     //
                 "add " TMP_REG1 ", " TMP_REG1 ", " xstr(L1D_PRIMING_OFFSET) "\n" //
                 PRIME(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, TMP_REG5, "8")     //
                 READ_PFC_START()                                                 //
                 SET_SR_STARTED()                                                 //
                 "msr nzcv, " TMP_REG6 "\n"                                       //
                 SPEC_FENCE()                                                     //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// 快速Prime+Probe测量开始宏——每个缓存集只读1次，速度更快精度稍低
static void __attribute__((noipa)) body_macro_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                               //
                 "mrs " TMP_REG6 ", nzcv \n"                                      //
                 "mov " TMP_REG1 ", " UTIL_BASE_REGISTER "\n"                     //
                 "add " TMP_REG1 ", " TMP_REG1 ", " xstr(L1D_PRIMING_OFFSET) "\n" //
                 PRIME(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, TMP_REG5, "1")     //
                 READ_PFC_START()                                                 //
                 SET_SR_STARTED()                                                 //
                 "msr nzcv, " TMP_REG6 "\n"                                       //
                 SPEC_FENCE()                                                     //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Prime+Probe测量结束宏——探测缓存集，检测被测代码的缓存访问模式
// 流程：保存NZCV → 检查状态寄存器(非ENDED才执行) → READ_PFC_END →
//       Probe(逐缓存集探测，结果编码到HTRACE_REGISTER) → SET_SR_ENDED → 恢复NZCV
// HTRACE_REGISTER中的位向量表示哪些缓存集被被测代码访问过
static void __attribute__((noipa)) body_macro_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                                       //
                 "mrs " TMP_REG6 ", nzcv \n"                                              //
                 TEST_SR_ENDED()                                                          //
                 "b.eq 99f\n"                                                             //
                 READ_PFC_END()                                                           //
                 "mov " TMP_REG1 ", " UTIL_BASE_REGISTER "\n"                             //
                 "add " TMP_REG1 ", " TMP_REG1 ", " xstr(L1D_PRIMING_OFFSET) "\n"         //
                 PROBE(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, TMP_REG5, HTRACE_REGISTER) //
                 SET_SR_ENDED()                                                           //
                 "99:\n"                                                                  //
                 "msr nzcv, " TMP_REG6 "\n"                                               //
                 SPEC_FENCE()                                                             //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush+Reload测量开始宏——将actor数据区所有缓存行从L1D驱逐
// 流程：保存NZCV → 加载数据区地址 → FLUSH(逐行dc civac) →
//       READ_PFC_START → SET_SR_STARTED → 恢复NZCV → dsb+isb
static void __attribute__((noipa)) body_macro_flush(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                             //
                 "mrs " TMP_REG6 ", nzcv \n"                    //
                 "mov " TMP_REG1 ", " MEMORY_BASE_REGISTER "\n" //
                 FLUSH(TMP_REG1, TMP_REG2, TMP_REG3)            //
                 READ_PFC_START()                               //
                 SET_SR_STARTED()                               //
                 "msr nzcv, " TMP_REG6 "\n"                     //
                 SPEC_FENCE()                                   //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush+Reload测量结束宏——重载数据区并检测被测代码是否访问了特定缓存行
// 流程：保存NZCV → 检查状态 → READ_PFC_END → RELOAD(逐行重载，测访问时间) →
//       SET_SR_ENDED → 恢复NZCV
// 如果被测代码访问了某行，Reload命中缓存(快速)；否则需从内存读取(慢速)
static void __attribute__((noipa)) body_macro_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                              //
                 "mrs " TMP_REG6 ", nzcv \n"                                     //
                 TEST_SR_ENDED()                                                 //
                 "b.eq 99f\n"                                                    //
                 READ_PFC_END()                                                  //
                 "mov " TMP_REG1 ", " MEMORY_BASE_REGISTER "\n"                  //
                 RELOAD(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, HTRACE_REGISTER) //
                 SET_SR_ENDED()                                                  //
                 "99:\n"                                                         //
                 "msr nzcv, " TMP_REG6 "\n"                                      //
                 SPEC_FENCE()                                                    //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// =====================================================================
// 故障处理宏 FAULT_HANDLER
//
// 当被测代码触发异常(如数据访问故障、指令故障)时，跳转到fault_handler继续执行
// 动态配置部分：更新x20/x21/SP为actor 0(主actor)的值，使故障处理代码能正确
// 访问主actor的数据区和工具区
// =====================================================================

/// @brief 故障处理宏的动态配置部分——设置fault_handler全局指针并恢复寄存器
///        故障处理必须由主actor(owner=0)拥有，确保测量结果正确归属
///        步骤：设置fault_handler地址 → 更新x20/SP → 更新x21
static inline size_t start_macro_fault_handler(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    ASSERT(args.owner == 0, "inject_macro_configurable_part");

    fault_handler = (char *)((uint64_t)dest + cursor);

    // 恢复x20、SP和x21为主actor的值，确保故障处理代码可正确寻址
    cursor += update_mem_base_and_sp(0, dest, cursor);
    cursor += update_util_base_reg(0, dest, cursor);

    return cursor;
}

// =====================================================================
// 带测量的故障处理宏 FAULT_HANDLER_WITH_MEASUREMENT
//
// 在故障处理的同时进行侧信道测量，将测量宏与故障处理组合
// 动态配置部分：更新x20和x21为故障发生actor(args.arg1)的地址，
// 以便后续的probe/reload测量宏能正确访问该actor的数据区
// =====================================================================

/// @brief 带测量的故障处理宏的动态配置部分
///        与纯故障处理不同，这里更新为故障发生actor的寄存器值
///        因为测量宏需要访问故障actor的数据区来检测缓存访问模式
static inline size_t start_macro_fault_handler_with_measurement(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_memory_base_reg(args.arg1, dest, cursor);
    cursor += update_util_base_reg(args.arg1, dest, cursor);
    return cursor;
}

// =====================================================================
// 通用域切换宏 MACRO_SWITCH
//
// 用于在同一特权级内不同actor之间的切换(如actor A的函数跳转到actor B的函数)
// 不涉及异常级别变化，仅更新寄存器值和跳转目标
// 动态配置部分：更新x20/SP为目标actor的值，通过B指令跳转到目标函数
// =====================================================================

/// @brief 通用切换宏的动态配置部分
///        步骤：更新x20/SP → 计算目标函数地址 → 生成B指令跳转
///        B指令的偏移量以4字节为单位，26位有符号偏移，范围±128MB
static inline size_t start_macro_switch(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_mem_base_and_sp(args.arg1, dest, cursor);

    uint64_t switch_target = get_function_addr(args.arg1, args.arg2);
    uint32_t relative_offset = switch_target - (uint64_t)dest - cursor;

    uint32_t opcode = b_imm(relative_offset);
    APPEND_U32_TO_DEST(opcode);

    return cursor;
}

// =====================================================================
// 内核→用户态切换宏 K2U (Kernel→User, EL2→EL0)
//
// ARM64的K2U切换通过eret指令实现：
//   1) 在set_k2u_target中配置ELR_EL2(返回地址)和SPSR_EL2(目标EL模式)
//   2) 在switch_k2u中执行eret，处理器恢复SPSR_EL2→PSTATE并跳转到ELR_EL2
//
// SPSR_EL2的M字段决定目标异常级别：
//   M[4:0]=0x0 → EL0t(用户态，使用SP_EL0)
//   M[4:0]=0x5 → EL1h(内核态)
//   M[4:0]=0x9 → EL2h(虚拟化管理态)
//
// eret执行后：PSTATE ← SPSR_EL2, PC ← ELR_EL2
// 处理器自动切换到目标EL，后续代码在目标EL执行
// =====================================================================

/// @brief K2U目标设置宏的动态配置部分
///        生成以下指令序列：
///        (1) msr ELR_EL2, x28 — 将目标函数地址写入异常链接寄存器
///            eret指令从ELR_EL2读取返回地址，跳转到该地址执行用户态代码
///        (2) isb — 确保ELR_EL2写入生效
///        (3) msr SPSR_EL2, x28 — 将EL0t模式值(0x0)写入保存的程序状态寄存器
///            M[4:0]=0x0表示目标为EL0t(用户态)，eret后处理器将在EL0执行
///        (4) isb — 确保SPSR_EL2写入生效
///        (5) 将目标地址存入util_vars.k2u_target_address(供着陆宏参考)
static inline size_t start_macro_set_k2u_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 计算用户态目标函数地址——eret后将在此地址开始执行
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);

    // 步骤1: 将目标地址写入ELR_EL2
    // ELR_EL2是eret的返回地址寄存器，eret后PC = ELR_EL2值
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_ELR_EL2_ENCODING, function_addr, dest, cursor);

    // 步骤2: 将EL0t模式值写入SPSR_EL2
    // SPSR_EL2值=0x0: M[4:0]=0x0(EL0t), NZCV=0, DAIF=0, 其他PSTATE位=0
    // eret后PSTATE ← SPSR_EL2，处理器将在EL0(用户态)执行
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_SPSR_EL2_ENCODING, 0x0, dest, cursor);

    // 步骤3: 将目标地址存入util_vars.k2u_target_address
    // util_vars中的k2u_target_address字段供着陆宏和异常处理参考
    // 地址 = UTIL_BASE_REGISTER + K2U_TARGET_OFFSET
    uint64_t util_k2u_addr = (uint64_t)sandbox->util + K2U_TARGET_OFFSET;
    cursor += mov_uint64_to_reg(TMP_REG1_ID, util_k2u_addr, dest, cursor);
    cursor += mov_uint64_to_reg(TMP_REG2_ID, function_addr, dest, cursor);
    // str x27, [x28] — 将目标地址写入util_vars的k2u_target_address字段
    uint32_t opcode = str_reg(TMP_REG2_ID, TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    return cursor;
}

/// @brief K2U切换宏的动态配置部分——无额外配置
///        所有配置已在set_k2u_target中完成(ELR_EL2和SPSR_EL2已设置)
///        body部分仅执行eret指令
static inline size_t start_macro_switch_k2u(macro_args_t UNUSED, uint8_t *UNUSED2) { return 0; }

/// @brief K2U切换宏的静态主体部分——执行eret指令
///        eret执行流程：
///          1) PSTATE ← SPSR_EL2 (恢复目标EL的模式、中断掩码、条件标志等)
///          2) PC ← ELR_EL2 (跳转到set_k2u_target设置的用户态目标地址)
///          3) 处理器切换到EL0(用户态)执行
///        eret后，着陆宏landing_k2u在目标地址处恢复x20/x21/SP
static void __attribute__((noipa)) body_macro_switch_k2u(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile("eret\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// =====================================================================
// 用户态→内核切换宏 U2K (User→Kernel, EL0→EL1)
//
// ARM64的U2K切换通过svc #0指令实现：
//   SVC(Supervisor Call)从EL0触发同步异常，处理器跳转到EL1/EL2的异常向量
//   跳转目标 = VBAR_ELx + offset(SVC from lower EL, AArch64 = 0x400)
//
// 实现方案：
//   1) set_u2k_target: 将目标地址存入util_vars.u2k_target_address，
//      并设置VBAR_EL1指向预构建的SVC异常向量表
//   2) switch_u2k: 执行svc #0，触发SVC异常
//   3) SVC异常向量处理器读取util_vars.u2k_target_address并跳转到目标
//   4) landing_u2k: 在目标地址处恢复x20/SP
//
// 注意：VBAR_EL1必须2KB对齐，SVC异常向量表在初始化阶段预构建
// =====================================================================

/// @brief U2K目标设置宏的动态配置部分
///        生成以下指令序列：
///        (1) 将目标函数地址存入util_vars.u2k_target_address
///            SVC异常处理器从该位置读取目标地址并跳转
///        (2) msr VBAR_EL1, x28 — 设置异常向量表基址
///            SVC从EL0触发时跳转到VBAR_EL1 + 0x400
///            VBAR_EL1必须2KB对齐
///        (3) isb — 确保VBAR_EL1写入生效
static inline size_t start_macro_set_u2k_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 计算内核态着陆函数地址——SVC异常处理后跳转到此地址
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);

    // 步骤1: 将目标地址存入util_vars.u2k_target_address
    // SVC异常处理器在EL1执行时从此位置读取跳转目标
    uint64_t util_u2k_addr = (uint64_t)sandbox->util + U2K_TARGET_OFFSET;
    cursor += mov_uint64_to_reg(TMP_REG1_ID, util_u2k_addr, dest, cursor);
    cursor += mov_uint64_to_reg(TMP_REG2_ID, function_addr, dest, cursor);
    // str x27, [x28] — 将目标地址写入util_vars
    uint32_t opcode = str_reg(TMP_REG2_ID, TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤2: 设置VBAR_EL1为预构建的SVC异常向量表基址
    // SVC从EL0触发时：PC ← VBAR_EL1 + 0x400
    // 向量表中的SVC handler读取util_vars.u2k_target_address并跳转
    // svc_vector_base在虚拟化管理初始化时设置，必须2KB对齐
    ASSERT(svc_vector_base != 0, "start_macro_set_u2k_target: SVC vector base not initialized");
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_VBAR_EL1_ENCODING,
                                svc_vector_base, dest, cursor);

    return cursor;
}

/// @brief U2K切换宏的静态主体部分——执行svc #0指令
///        SVC #0执行流程：
///          1) 处理器从EL0切换到EL1(或EL2，取决于VHE配置)
///          2) SPSR_EL1 ← PSTATE(保存EL0的状态，包括NZCV和EL信息)
///          3) ELR_EL1 ← PC+4(保存SVC指令的下一条指令地址，用于返回)
///          4) PC ← VBAR_EL1 + 0x400(跳转到SVC异常向量处理器)
///          5) SVC异常处理器读取util_vars.u2k_target_address并跳转到着陆宏
static void __attribute__((noipa)) body_macro_switch_u2k(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile("svc #0\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// =====================================================================
// 宿主机→客户机切换宏 H2G (Host→Guest, EL2→EL1)
//
// ARM64的H2G切换通过eret指令从EL2进入EL1客户机：
//   1) set_h2g_target: 配置VTTBR_EL2(Stage-2页表)、ELR_EL2(入口地址)、
//      SPSR_EL2(EL1h模式)
//   2) switch_h2g: 执行eret，处理器恢复SPSR_EL2→PSTATE并跳转到ELR_EL2
//
// VTTBR_EL2指向Stage-2页表(S2PT)的物理基址，控制guest的GPA→HPA翻译
// 每个guest VM有自己的S2PT，切换guest时必须更新VTTBR_EL2
//
// eret执行后：PSTATE ← SPSR_EL2(M=0x5→EL1h), PC ← ELR_EL2(guest入口)
// 处理器进入EL1h(客户机内核态)执行guest代码
//
// 注意：修改VTTBR_EL2后应执行TLB无效化(tlbi vmalle2is)以确保
// 新的S2PT翻译生效。当前实现中TLB维护通过ISB+DSB保证基本正确性，
// 完整的TLB无效化应在虚拟化管理模块中补充
// =====================================================================

/// @brief H2G目标设置宏的动态配置部分
///        生成以下指令序列：
///        (1) msr VTTBR_EL2, x28 — 设置Stage-2页表基址
///            每个guest VM有独立的S2PT，vttbr_hpas数组存储各guest的S2PT物理地址
///        (2) isb — 确保VTTBR_EL2写入生效
///        (3) dsb sy — 数据同步屏障，确保S2PT修改对所有观察者可见
///        (4) msr ELR_EL2, x28 — 设置guest入口地址
///        (5) isb — 确保ELR_EL2写入生效
///        (6) msr SPSR_EL2, x28 — 设置目标EL为EL1h(M=0x5)
///        (7) isb — 确保SPSR_EL2写入生效
static inline size_t start_macro_set_h2g_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 计算guest入口函数地址——eret后guest从此地址开始执行
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);

    // 步骤1: 设置VTTBR_EL2为该guest的Stage-2页表物理地址
    // VTTBR_EL2控制guest的GPA→HPA地址翻译，每个guest VM有独立的S2PT
    // vttbr_hpas[args.arg1]存储第args.arg1个guest的S2PT物理基址
    ASSERT(vttbr_hpas != NULL, "start_macro_set_h2g_target: vttbr_hpas not initialized");
    uint64_t vttbr_hpa = vttbr_hpas[args.arg1];
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_VTTBR_EL2_ENCODING, vttbr_hpa, dest, cursor);

    // 步骤2: DSB屏障——确保VTTBR_EL2修改对后续内存访问可见
    // 修改Stage-2翻译表基址后必须执行DSB，否则后续的内存访问可能
    // 使用旧的S2PT翻译，导致guest访问错误的物理地址
    APPEND_U32_TO_DEST(OPCODE_DSB_SY);

    // TODO: 完整的TLB无效化——应在VTTBR_EL2修改后添加以下指令：
    //   tlbi vmalle2is  — 无效化所有Stage-2 TLB条目(内部共享)
    //   tlbi vmalle1is  — 无效化所有Stage-1 TLB条目(内部共享)
    //   dsb ish         — 数据同步屏障(内部共享)
    //   isb             — 指令同步屏障
    // 这些指令的opcode编码需在虚拟化管理模块完善后添加

    // 步骤3: 将guest入口地址写入ELR_EL2
    // eret后PC = ELR_EL2值，guest从此地址开始执行
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_ELR_EL2_ENCODING, function_addr, dest, cursor);

    // 步骤4: 将EL1h模式值写入SPSR_EL2
    // SPSR_EL2值=0x5: M[4:0]=0x5(EL1h，内核态使用SP_EL1)
    // eret后处理器在EL1h(客户机内核态)执行
    // EL1h是ARM64内核的标准运行模式，使用SP_EL1而非SP_EL0
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_SPSR_EL2_ENCODING, 0x5, dest, cursor);

    return cursor;
}

/// @brief H2G切换宏的动态配置部分——无额外配置
///        所有配置已在set_h2g_target中完成(VTTBR/ELR/SPSR已设置)
static inline size_t start_macro_switch_h2g(macro_args_t UNUSED, uint8_t *UNUSED2) { return 0; }

/// @brief H2G切换宏的静态主体部分——执行eret指令进入guest VM
///        eret执行流程：
///          1) PSTATE ← SPSR_EL2 (M=0x5 → EL1h，客户机内核态)
///          2) PC ← ELR_EL2 (跳转到set_h2g_target设置的guest入口地址)
///          3) 处理器切换到EL1h执行，Stage-2翻译由VTTBR_EL2控制
///        eret后，着陆宏landing_h2g在guest入口处恢复x20/x21
static void __attribute__((noipa)) body_macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile("eret\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// =====================================================================
// 客户机→宿主机切换宏 G2H (Guest→Host, EL1→EL2)
//
// ARM64的G2H切换通过hvc #0指令实现：
//   HVC(Hypervisor Call)从EL1触发虚拟化异常，处理器跳转到EL2的异常向量
//   跳转目标 = VBAR_EL2 + 0x400(HVC from lower EL, AArch64)
//
// 实现方案：
//   1) set_g2h_target: 将宿主机着陆地址存入util_vars，设置VBAR_EL2
//   2) switch_g2h: 在guest EL1中执行hvc #0
//   3) HVC异常向量处理器读取util_vars中的目标地址并跳转
//   4) landing_g2h: 在EL2宿主机着陆点恢复x20/x21
//
// HVC异常执行流程：
//   SPSR_EL2 ← PSTATE(保存guest EL1状态)
//   ELR_EL2 ← PC+4(保存HVC指令后的guest指令地址，用于返回guest)
//   PC ← VBAR_EL2 + 0x400(跳转到宿主机HVC异常处理器)
// =====================================================================

/// @brief G2H目标设置宏的动态配置部分
///        生成以下指令序列：
///        (1) 将宿主机着陆函数地址存入util_vars
///            使用U2K_TARGET_OFFSET字段暂存(U2K和G2H不会同时使用)
///            HVC异常处理器从该位置读取宿主机着陆地址并跳转
///        (2) msr VBAR_EL2, x28 — 设置EL2异常向量表基址
///            HVC从EL1触发时跳转到VBAR_EL2 + 0x400
///        (3) isb — 确保VBAR_EL2写入生效
static inline size_t start_macro_set_g2h_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 计算宿主机着陆函数地址——HVC异常处理后跳转到此地址
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);

    // 步骤1: 将目标地址存入util_vars
    // 暂用U2K_TARGET_OFFSET存储(U2K和G2H不会同时活跃)
    // 未来可新增G2H_TARGET_OFFSET专用字段
    uint64_t util_target_addr = (uint64_t)sandbox->util + U2K_TARGET_OFFSET;
    cursor += mov_uint64_to_reg(TMP_REG1_ID, util_target_addr, dest, cursor);
    cursor += mov_uint64_to_reg(TMP_REG2_ID, function_addr, dest, cursor);
    uint32_t opcode = str_reg(TMP_REG2_ID, TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤2: 设置VBAR_EL2为预构建的HVC异常向量表基址
    // HVC从EL1触发时：PC ← VBAR_EL2 + 0x400
    // 向量表中的HVC handler读取util_vars中的目标地址并跳转到宿主机着陆点
    ASSERT(hvc_vector_base != 0, "start_macro_set_g2h_target: HVC vector base not initialized");
    cursor += msr_write_to_reg(TMP_REG1_ID, MSR_VBAR_EL2_ENCODING,
                                hvc_vector_base, dest, cursor);

    return cursor;
}

/// @brief G2H切换宏的静态主体部分——执行hvc #0指令
///        HVC #0执行流程：
///          1) 处理器从EL1(guest)切换到EL2(host/hypervisor)
///          2) SPSR_EL2 ← PSTATE(保存guest EL1的状态)
///          3) ELR_EL2 ← PC+4(保存HVC后的guest指令地址)
///          4) PC ← VBAR_EL2 + 0x400(跳转到宿主机HVC异常处理器)
///          5) HVC handler读取util_vars中的目标地址并跳转到landing_g2h
static void __attribute__((noipa)) body_macro_switch_g2h(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile("hvc #0\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// =====================================================================
// 着陆宏 LANDING MACROS
//
// 域切换完成后，处理器在新EL的目标地址开始执行。着陆宏在此目标地址处
// 恢复执行器寄存器(x20数据基址、x21工具基址、SP栈指针)，使新actor的
// 数据区和工具区可被正确访问。
//
// 每种域切换类型有对应的着陆宏：
//   landing_k2u: EL0着陆——更新x20/x21/SP为用户态actor的值
//   landing_u2k: EL1着陆——更新x20/SP为内核态actor的值
//   landing_h2g: EL1着陆(guest)——更新x20/x21为guest actor的值
//   landing_g2h: EL2着陆(host)——更新x20/x21为host actor的值
//
// args.owner参数指定着陆后所属的actor编号，用于确定正确的寄存器值
// =====================================================================

/// @brief K2U着陆宏——eret降至EL0后恢复用户态actor的寄存器
///        步骤：更新x20(数据基址) → 更新SP(栈指针) → 更新x21(工具基址)
///        注意：eret不破坏任何通用寄存器，但PSTATE已从SPSR_EL2恢复
///        用户态代码需要正确的x20/x21/SP才能访问actor数据和测量工具
static inline size_t start_macro_landing_k2u(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 更新x20和SP为用户态actor的值
    // x20指向用户态actor的数据区基址，SP指向数据区内的栈位置
    cursor += update_mem_base_and_sp(args.owner, dest, cursor);

    // 更新x21为工具区基址
    // 用户态测量宏(probe/reload)通过[x21+offset]访问L1D priming缓冲区
    cursor += update_util_base_reg(args.owner, dest, cursor);

    return cursor;
}

/// @brief U2K着陆宏——SVC升至EL1后恢复内核态actor的寄存器
///        步骤：更新x20(数据基址) → 更新SP(栈指针)
///        注意：SVC异常会自动设置EL1的SP(使用SP_EL1)，但执行器需要
///        将SP设置为actor数据区内的特定位置(LOCAL_RSP_OFFSET)
///        SVC异常也会将ELR_EL1设为SVC指令+4的地址，着陆宏不需要处理返回地址
static inline size_t start_macro_landing_u2k(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 更新x20和SP为内核态actor的值
    // 内核态actor的数据访问通过[x20+offset]寻址
    cursor += update_mem_base_and_sp(args.owner, dest, cursor);

    return cursor;
}

/// @brief H2G着陆宏——eret进入guest EL1后恢复guest actor的寄存器
///        步骤：更新x20(数据基址) → 更新x21(工具基址)
///        注意：guest EL1中的内存访问经过Stage-2翻译(VTTBR_EL2控制)
///        x20和x21指向host物理地址，guest通过S2PT映射访问
///        不更新SP——guest内核使用SP_EL1，eret已从SPSR_EL2恢复SP选择
///        TODO: 完整的guest内存映射后，x20/x21应指向guest虚拟地址
static inline size_t start_macro_landing_h2g(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 更新x20为guest actor的数据区基址
    cursor += update_memory_base_reg(args.owner, dest, cursor);

    // 更新x21为工具区基址
    cursor += update_util_base_reg(args.owner, dest, cursor);

    return cursor;
}

/// @brief G2H着陆宏——HVC返回EL2后恢复host actor的寄存器
///        步骤：更新x20(数据基址) → 更新x21(工具基址)
///        HVC异常从guest EL1返回host EL2，需要在EL2恢复host的寄存器
///        不更新SP——host EL2的SP在H2G切换前已保存，恢复时使用原始SP
static inline size_t start_macro_landing_g2h(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 更新x20为host actor的数据区基址
    cursor += update_memory_base_reg(args.owner, dest, cursor);

    // 更新x21为工具区基址
    cursor += update_util_base_reg(args.owner, dest, cursor);

    return cursor;
}

// =====================================================================
// 数据权限设置宏 MACRO_SET_DATA_PERMISSIONS
//
// 修改目标actor数据页的PTE(页表项)权限位，用于配置侧信道测量的访问权限
// ARM64 PTE(l3_descr_t)的关键权限位：
//   bit 0: Valid — 页面有效标志，=0时访问触发Translation Fault
//   bits[6:7]: AP(Access Permissions) — 访问权限控制
//     AP[1](bit6): 0=特权级只访问(EL1+), 1=用户级可访问(EL0+)
//     AP[2](bit7): 0=读写, 1=只读
//   bit 8: AF(Access Flag) — 访问标志，=0时首次访问触发Access Flag Fault
//   bit 54: XN(Execute Never) — 禁止执行标志
//   bit 53: PXN(Privileged Execute Never) — 特权级禁止执行标志
//
// MODIFIABLE_PTE_BITS = PTE_VALID | PTE_USER | PTE_RDONLY
//   = bit0 | bit6 | bit7 = 0xC1
//
// 动态配置部分：加载PTE指针 → 加载当前PTE值 → OR mask_set → AND mask_clear →
//   写回修改后的PTE → DSB+ISB屏障确保修改生效
// mask_set设置权限位(如Valid=1, User=1)，mask_clear清除权限位(如Valid=0)
// mask_clear中=0的位将被清除，=1的位保持不变
// =====================================================================

/// @brief 数据权限设置宏的动态配置部分
///        生成以下指令序列：
///        (1) movz+movk x28, ptep — 加载PTE指针到TMP_REG1
///        (2) ldr x26, [x28] — 从PTE指针加载当前64位PTE值到TMP_REG3
///        (3) movz+movk x27, mask_set — 加载OR掩码到TMP_REG2
///        (4) orr x26, x26, x27 — 对PTE应用OR掩码，设置指定权限位
///        (5) movz+movk x27, mask_clear — 加载AND掩码到TMP_REG2
///        (6) and x26, x26, x27 — 对PTE应用AND掩码，清除指定权限位
///            mask_clear中bit=0的位将被清除，bit=1的位保持不变
///        (7) str x26, [x28] — 将修改后的PTE写回内存
///        (8) dsb sy + isb — 确保PTE修改对后续内存访问生效
static inline size_t start_macro_set_data_permissions(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // 获取OR掩码(mask_set)和AND掩码(mask_clear)
    // mask_set: 要设置的权限位，如bit0(Valid)+bit6(User)=0x41
    // mask_clear: 要保持的权限位，清除位=0，保持位=1，如~bit0=~Valid=0xFFFE
    uint16_t mask_set = args.arg2;
    uint16_t mask_clear = args.arg3;

    // 获取目标PTE指针
    // PTE指向actor数据区的faulty页(faulty_area)的页表项
    // faulty页的权限可动态修改以触发不同类型的内存访问故障
    uint64_t actor_id = args.arg1;
    uint64_t page_id = (actor_id * N_DATA_PAGES_PER_ACTOR) + FAULTY_PAGE_ID;
    pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
    ASSERT(ptep != NULL, "start_macro_set_data_permissions");

    // 步骤1: 加载PTE指针到TMP_REG1(x28)
    cursor += mov_uint64_to_reg(TMP_REG1_ID, (uint64_t)ptep, dest, cursor);

    // 步骤2: 从PTE指针加载当前PTE值到TMP_REG3(x26)
    // ldr x26, [x28] — 读取当前64位PTE值
    uint32_t opcode = ldr_reg(TMP_REG3_ID, TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤3: 加载mask_set到TMP_REG2(x27)并OR到PTE
    // mask_set是16位值，零扩展为64位后OR到PTE的低16位
    // 这只影响PTE的低16位(Valid、AP等关键权限位都在低8位)
    cursor += mov_uint64_to_reg(TMP_REG2_ID, (uint64_t)mask_set, dest, cursor);
    // orr x26, x26, x27 — PTE |= mask_set
    opcode = orr_reg(TMP_REG3_ID, TMP_REG3_ID, TMP_REG2_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤4: 加载mask_clear到TMP_REG2(x27)并AND到PTE
    // mask_clear中=0的位将被清除，=1的位保持不变
    cursor += mov_uint64_to_reg(TMP_REG2_ID, (uint64_t)mask_clear, dest, cursor);
    // and x26, x26, x27 — PTE &= mask_clear
    opcode = and_reg(TMP_REG3_ID, TMP_REG3_ID, TMP_REG2_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤5: 将修改后的PTE写回内存
    // str x26, [x28] — 存储修改后的PTE值
    opcode = str_reg(TMP_REG3_ID, TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    // 步骤6: 内存屏障——确保PTE修改对后续内存访问生效
    // DSB SY: 数据同步屏障，确保PTE存储操作对所有观察者可见
    // ISB: 指令同步屏障，确保处理器使用更新后的PTE进行地址翻译
    // 注意：完整的TLB无效化(tlbi)应在此处添加，确保旧PTE的TLB缓存被刷新
    APPEND_U32_TO_DEST(OPCODE_DSB_SY);
    APPEND_U32_TO_DEST(OPCODE_ISB);

    // 清零临时寄存器，防止残留值泄露信息
    // movz x26, #0; movz x27, #0; movz x28, #0
    opcode = movz(TMP_REG3_ID, 0, 0);
    APPEND_U32_TO_DEST(opcode);
    opcode = movz(TMP_REG2_ID, 0, 0);
    APPEND_U32_TO_DEST(opcode);
    // 注意：不清零TMP_REG1(x28)，因为它可能在后续代码中作为通用临时寄存器使用

    return cursor;
}

// =====================================================================
// 宏描述符表 macro_descriptors
//
// 宏类型(TYPE_XXX)到具体实现函数的映射关系。
// 每个宏类型对应一个描述符，包含两个函数指针：
//   .start: 动态配置部分生成函数(根据宏参数动态生成机器码)，NULL表示无动态部分
//   .body:  静态主体部分函数(编译时固定的代码，通过MACRO_START/MACRO_END标记提取)，
//           NULL表示无静态部分
//
// 映射关系说明：
//   TYPE_PRIME/FAST_PRIME → Prime+Probe测量开始(填充L1D缓存集)
//   TYPE_PROBE → Prime+Probe测量结束(探测L1D缓存集访问模式)
//   TYPE_FLUSH → Flush+Reload测量开始(从L1D驱逐目标缓存行)
//   TYPE_EVICT → Evict+Reload测量开始(使用prime方式驱逐，与PRIME共用body)
//   TYPE_RELOAD → Flush+Reload/Evict+Reload测量结束(重载缓存行测量访问时间)
//   TYPE_FAULT_HANDLER → 纯故障处理(恢复寄存器，无测量)
//   TYPE_FAULT_AND_PROBE/RELOAD → 带测量的故障处理(故障处理+probe/reload)
//   TYPE_SWITCH → 同特权级actor切换(更新寄存器+跳转)
//   TYPE_SET_K2U_TARGET → K2U目标设置(写ELR_EL2+SPSR_EL2)
//   TYPE_SWITCH_K2U → K2U切换执行(eret降至EL0)
//   TYPE_SET_U2K_TARGET → U2K目标设置(写util_vars+VBAR_EL1)
//   TYPE_SWITCH_U2K → U2K切换执行(svc升至EL1)
//   TYPE_SET_H2G_TARGET → H2G目标设置(写VTTBR_EL2+ELR_EL2+SPSR_EL2)
//   TYPE_SWITCH_H2G → H2G切换执行(eret进入guest EL1)
//   TYPE_SET_G2H_TARGET → G2H目标设置(写util_vars+VBAR_EL2)
//   TYPE_SWITCH_G2H → G2H切换执行(hvc升至EL2)
//   TYPE_LANDING_K2U → K2U着陆(EL0恢复x20/x21/SP)
//   TYPE_LANDING_U2K → U2K着陆(EL1恢复x20/SP)
//   TYPE_LANDING_H2G → H2G着陆(guest EL1恢复x20/x21)
//   TYPE_LANDING_G2H → G2H着陆(host EL2恢复x20/x21)
//   TYPE_SET_DATA_PERMISSIONS → 修改数据页PTE权限位
// =====================================================================
macro_descr_t macro_descriptors[] = {
    [TYPE_UNDEFINED] = {.start = NULL, .body = NULL},
    [TYPE_PRIME] = {.start = NULL, .body = body_macro_prime},
    [TYPE_FAST_PRIME] = {.start = NULL, .body = body_macro_fast_prime},
    [TYPE_PARTIAL_PRIME] = {.start = NULL, .body = NULL},
    [TYPE_FAST_PARTIAL_PRIME] = {.start = NULL, .body = NULL},
    [TYPE_PROBE] = {.start = NULL, .body = body_macro_probe},
    [TYPE_FLUSH] = {.start = NULL, .body = body_macro_flush},
    [TYPE_EVICT] = {.start = NULL, .body = body_macro_prime},
    [TYPE_RELOAD] = {.start = NULL, .body = body_macro_reload},
    [TYPE_TSC_START] = {.start = NULL, .body = NULL},
    [TYPE_TSC_END] = {.start = NULL, .body = NULL},
    [TYPE_FAULT_HANDLER] = {.start = start_macro_fault_handler, .body = NULL},
    [TYPE_FAULT_AND_PROBE] = {.start = start_macro_fault_handler_with_measurement,
                              .body = body_macro_probe},
    [TYPE_FAULT_AND_RELOAD] = {.start = start_macro_fault_handler_with_measurement,
                               .body = body_macro_reload},
    [TYPE_FAULT_AND_TSC_END] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH] = {.start = start_macro_switch, .body = NULL},
    [TYPE_SET_K2U_TARGET] = {.start = start_macro_set_k2u_target, .body = NULL},
    [TYPE_SWITCH_K2U] = {.start = start_macro_switch_k2u, .body = body_macro_switch_k2u},
    [TYPE_SET_U2K_TARGET] = {.start = start_macro_set_u2k_target, .body = NULL},
    [TYPE_SWITCH_U2K] = {.start = NULL, .body = body_macro_switch_u2k},
    [TYPE_SET_H2G_TARGET] = {.start = start_macro_set_h2g_target, .body = NULL},
    [TYPE_SWITCH_H2G] = {.start = start_macro_switch_h2g, .body = body_macro_switch_h2g},
    [TYPE_SET_G2H_TARGET] = {.start = start_macro_set_g2h_target, .body = NULL},
    [TYPE_SWITCH_G2H] = {.start = NULL, .body = body_macro_switch_g2h},
    [TYPE_LANDING_K2U] = {.start = start_macro_landing_k2u, .body = NULL},
    [TYPE_LANDING_U2K] = {.start = start_macro_landing_u2k, .body = NULL},
    [TYPE_LANDING_H2G] = {.start = start_macro_landing_h2g, .body = NULL},
    [TYPE_LANDING_G2H] = {.start = start_macro_landing_g2h, .body = NULL},
    [TYPE_SET_DATA_PERMISSIONS] = {.start = start_macro_set_data_permissions, .body = NULL},
};

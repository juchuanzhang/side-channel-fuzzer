"""
文件：基于指令的简单推测器集合，用于 Unicorn 模型。

本模块实现了基于指令行为的推测执行模型，这些模型模拟 CPU 在
遇到特定指令时的推测行为（如分支误预测、存储旁路等）。

包含以下推测器：
- SeqSpeculator: 顺序执行推测器（不实现任何推测）
- X86CondSpeculator: x86 条件分支误预测推测器（Spectre v1）
- ARM64CondSpeculator: ARM64 条件分支误预测推测器
- StoreBpasSpeculator: 推测性存储旁路推测器（Spectre v4）
- X86CondBpasSpeculator: 组合条件分支误预测和存储旁路的推测器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Tuple, Callable, Final, Optional
from unicorn import UC_MEM_WRITE

import unicorn.x86_const as ucc  # type: ignore # no type hints for this library
import unicorn.arm64_const as aucc  # type: ignore # no type hints for this library

from .speculator_abc import UnicornSpeculator
from ..config import CONF

if TYPE_CHECKING:
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..target_desc import TargetDesc

# x86 标志位掩码定义
FLAGS_CF = 0b000000000001  # 进位标志
FLAGS_PF = 0b000000000100  # 奇偶标志
FLAGS_AF = 0b000000010000  # 辅助进位标志
FLAGS_ZF = 0b000001000000  # 零标志
FLAGS_SF = 0b000010000000  # 符号标志
FLAGS_TF = 0b000100000000  # 陷阱标志
FLAGS_IF = 0b001000000000  # 中断标志
FLAGS_DF = 0b010000000000  # 方向标志
FLAGS_OF = 0b100000000000  # 溢出标志

# ARM64 条件标志位掩码定义
FLAGS_N: Final[int] = 1 << 31  # 负标志
FLAGS_Z: Final[int] = 1 << 30  # 零标志
FLAGS_C: Final[int] = 1 << 29  # 进位标志
FLAGS_V: Final[int] = 1 << 28  # 溢出标志


class SeqSpeculator(UnicornSpeculator):
    """
    顺序执行推测器：不实现任何推测，模型所有指令按顺序执行。
    
    这是最简单的合约模型，用于建立无推测执行的基准：
    所有指令按程序顺序执行，没有分支误预测或故障推测。
    """

    is_sequential: bool = True


_CondBranchFlipper = Callable[[bytearray, int, int], Tuple[bytearray, bool, bool]]
""" 条件分支解码器回调函数类型：
    输入：(指令字节码, EFLAGS值, RCX值)
    输出：(目标偏移量字节码, 是否跳转, 是否为LOOP指令)
"""


# ==================================================================================================
# 条件分支误预测（Spectre v1）
# ==================================================================================================
class X86CondSpeculator(UnicornSpeculator):
    """
    x86 条件分支误预测推测器。

    强制所有条件分支推测性地走向错误的目标方向，
    模拟 Spectre v1 类型的攻击场景。

    解码方法使用 x86 条件跳转指令的操作码和 EFLAGS 值，
    确定分支的正常方向，然后将执行路径翻转到相反方向。

    支持的指令类型：
    - 单字节条件跳转 (0x70-0x7F)
    - 双字节条件跳转 (0x0F 0x80-0x8F)
    - LOOP 类指令 (0xE0-0xE3)
    """

    jumps = {
        # c - 指令字节码
        # f - EFLAGS 值
        # r - RCX 值（用于 LOOP 指令）
        0x70:
            lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71:
            lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72:
            lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73:
            lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74:
            lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75:
            lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76:
            lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77:
            lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78:
            lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79:
            lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A:
            lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B:
            lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C:
            lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D:
            lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E:
            lambda c, f, r: (
                c[1:],
                f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),
                False,
            ),
        0x7F:
            lambda c, f, r: (
                c[1:],
                f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),
                False,
            ),
        0xE0:
            lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1:
            lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2:
            lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3:
            lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F:
            lambda c, f, r: X86CondSpeculator.multibyte_jmp.get(c[1], (lambda _, __, ___:
                                                                        ([0], False, False)))
            (c, f, r),
    }

    multibyte_jmp: Final[Dict[int, _CondBranchFlipper]] = {
        """ 双字节条件跳转指令（0x0F 前缀）解码映射 """
        0x80:
            lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81:
            lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82:
            lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83:
            lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84:
            lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85:
            lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86:
            lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87:
            lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88:
            lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89:
            lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A:
            lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B:
            lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C:
            lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D:
            lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E:
            lambda c, f, r: (
                c[2:],
                f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),
                False,
            ),
        0x8F:
            lambda c, f, r: (
                c[2:],
                f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),
                False,
            ),
    }

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "x86-64"

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        对条件分支指令进行误预测推测。

        算法：
        1. 检查最大嵌套层级是否已达到
        2. 从内存读取指令字节码和当前标志位
        3. 解码指令，确定是否为条件跳转及其正常方向
        4. 如果是条件跳转，保存检查点
        5. 翻转分支方向（走向错误目标），模拟误预测

        :param address: 指令地址
        :param size: 指令大小
        """
        if self._max_nesting_reached():  # 已达最大推测窗口？跳过
            return

        # 如果指令未定义，Unicorn 会返回巨大的 size 值，跳过这些
        if size > 15:  # 15字节是 Intel 最大指令大小
            return

        # 解码指令
        code: bytearray = self._emulator.mem_read(address, size)
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        rcx: int = self._emulator.reg_read(ucc.UC_X86_REG_RCX)  # type: ignore
        target, will_jump, is_loop = self.decode(code, flags, rcx)

        # 不是条件跳转？忽略
        if not target:
            return

        # LOOP 指令需要递减 RCX
        if is_loop:
            self._emulator.reg_write(ucc.UC_X86_REG_RCX, rcx - 1)

        # 保存检查点：记录正常执行路径的下一条指令地址
        next_instr = address + size + target if will_jump else address + size
        self._checkpoint(next_instr)

        # 模拟误预测：翻转分支方向
        if will_jump:
            # 正常会跳转 -> 误预测为不跳转（走向 fall-through）
            self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)
        else:
            # 正常不跳转 -> 误预测为跳转（走向目标）
            self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size + target)

    def decode(self, code: bytearray, flags: int, rcx: int) -> Tuple[int, bool, bool]:
        """
        解码 `code` 中编码的指令。如果是条件跳转，
        返回其预期目标偏移量、是否跳转到目标（基于 `flags` 值）
        以及是否为 LOOP 指令。

        :param code: 指令字节码
        :param flags: 当前 EFLAGS 值
        :param rcx: 当前 RCX 值（LOOP 指令需要）
        :return: (目标偏移量, 是否跳转, 是否为LOOP)
        """
        calculate_target = \
            self.jumps.get(code[0], (lambda _, __, ___: ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)  # type: ignore
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little', signed=True), will_jump, is_loop


class ARM64CondSpeculator(UnicornSpeculator):
    """
    ARM64 条件分支误预测推测器。

    强制所有条件分支推测性地走向错误的目标方向，
    模拟 ARM64 CPU 的分支误预测行为。

    支持的指令类型：
    - B.cond 条件分支指令
    - CBZ/CBNZ 比较并分支指令
    - TBZ/TBNZ 测试位并分支指令
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "arm64"

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        对 ARM64 条件分支指令进行误预测推测。

        算法：
        1. 检查最大嵌套层级
        2. 从内存读取指令并解码
        3. 确定是否为条件分支及其正常方向
        4. 保存检查点
        5. 翻转分支方向

        :param address: 指令地址
        :param size: 指令大小
        """
        if self._max_nesting_reached():  # 已达最大推测窗口？跳过
            return

        # 解码指令
        code: bytearray = self._emulator.mem_read(address, size)
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        target_offset, will_jump = self.decode(code, flags)

        # 不是条件跳转？忽略
        if not target_offset:
            return

        # 保存检查点
        next_instr = address + size + target_offset if will_jump else address + size
        self._checkpoint(next_instr)

        # 模拟误预测：翻转分支方向
        target_addr = address + size if will_jump else address + size + target_offset
        self._emulator.reg_write(self._uc_target_desc.pc_register, target_addr)

    def decode(self, code: bytearray, flags: int) -> Tuple[int, bool]:
        """
        解码 `code` 中编码的指令。如果是条件跳转，
        返回其预期目标偏移量和是否跳转到目标（基于 `flags` 值）。

        ARM64 分支指令编码：
        - B.cond: 首字节 0x54，最低4位为条件码
        - CBZ/CBNZ: 首字节 0x34-0x37
        - TBZ/TBNZ: 首字节 0xb4-0xb7

        :param code: 指令字节码
        :param flags: 当前 NZCV 标志位值
        :return: (目标偏移量, 是否跳转)
        """
        instruction = int.from_bytes(code, byteorder='little')
        first_byte = instruction >> 24
        if first_byte == 0x54 and instruction & 0x10 == 0:
            # B.cond 条件分支指令
            return self._decode_b_cond(instruction, flags)

        if 0xb4 <= first_byte <= 0xb7 or 0x34 <= first_byte <= 0x37:
            # CBZ/CBNZ/TBZ/TBNZ 指令
            return self._decode_cb_tb(instruction, first_byte)
        return (0, False)

    def _decode_b_cond(self, instruction: int, flags: int) -> Tuple[int, bool]:
        """
        解码 B.cond 条件分支指令。

        根据条件码和 NZCV 标志位确定分支方向。
        条件码映射表参照 ARM 文档：
        https://community.arm.com/arm-community-blogs/b/
        architectures-and-processors-blog/posts/condition-codes-1-condition-flags-and-codes

        :param instruction: 指令的32位编码
        :param flags: NZCV 标志位值（高位到低位：N[31], Z[30], C[29], V[28]）
        :return: (目标偏移量, 是否跳转)
        """
        target = self._twos_complement(instruction >> 5, 19)
        condition = instruction & 0xf
        n = (flags & FLAGS_N) != 0
        z = (flags & FLAGS_Z) != 0
        c = (flags & FLAGS_C) != 0
        v = (flags & FLAGS_V) != 0
        # ARM64 条件码判断表
        will_jump = [
            z,  # 0 = b.eq "相等"
            not z,  # 1 = b.ne "不等"
            c,  # 2 = b.cs "进位设置"
            not c,  # 3 = b.cc "进位清除"
            n,  # 4 = b.mi "负数"
            not n,  # 5 = b.pl "正数或零"
            v,  # 6 = b.vs "溢出设置"
            not v,  # 7 = b.vc "溢出清除"
            c and not z,  # 8 = b.hi "高于"
            not c or z,  # 9 = b.ls "低于或等于"
            n == v,  # a = b.ge "大于或等于"
            n != v,  # b = b.lt "小于"
            not z and n == v,  # c = b.gt "大于"
            z or n != v,  # d = b.le "小于或等于"
            True,  # e = b.al "总是"
            False,  # f = b.nv "从不"
        ][condition]
        return (target, will_jump)

    def _decode_cb_tb(self, instruction: int, first_byte: int) -> Tuple[int, bool]:
        """
        解码 CBZ/CBNZ/TBZ/TBNZ 指令。

        CBZ: 如果寄存器为零则分支
        CBNZ: 如果寄存器非零则分支
        TBZ: 如果测试位为零则分支
        TBNZ: 如果测试位非零则分支

        :param instruction: 指令的32位编码
        :param first_byte: 指令首字节（用于区分指令类型和宽度）
        :return: (目标偏移量, 是否跳转)
        """
        register_index = instruction & 0x1f
        is_32bit = first_byte >> 4 == 0x3

        register_value: int
        if register_index < 31:
            # 注意：UC_ARM64_REG_X29 != UC_ARM64_REG_X0 + 29（Unicorn 的特殊编码）
            uc_reg_id = \
                (aucc.UC_ARM64_REG_X0 + register_index) if register_index <= 28 else \
                (aucc.UC_ARM64_REG_X29 + (register_index - 29))

            register_value = self._emulator.reg_read(uc_reg_id)  # type: ignore
        elif register_index == 31:
            # xzr "零寄存器"：始终为 0
            register_value = 0
        else:
            raise ValueError(f"Invalid register index {register_index} in CBZ/CBNZ/TBZ/TBNZ")

        if is_32bit:
            # 32位操作仅使用低32位
            register_value &= 0xffff_ffff
        if first_byte & 0xf <= 0x5:
            # CBZ/CBNZ 指令
            target = self._twos_complement(instruction >> 5, 19)
            if first_byte & 0xf == 4:
                # CBZ: 寄存器为零时跳转
                will_jump = register_value == 0
            else:
                # CBNZ: 寄存器非零时跳转
                will_jump = register_value != 0
        else:
            # TBZ/TBNZ 指令
            target = self._twos_complement(instruction >> 5, 14)
            bit_number = (instruction >> 19) & 0x1f
            if not is_32bit:
                # 64位操作：测试位编号 +32
                bit_number += 32
            bit = register_value & (1 << bit_number)
            if first_byte & 0xf == 6:
                # TBZ: 测试位为零时跳转
                will_jump = bit == 0
            else:
                # TBNZ: 测试位非零时跳转
                will_jump = bit != 0
        return (target, will_jump)

    @staticmethod
    def _twos_complement(n: int, n_bits: int) -> int:
        """
        将二进制补码编码的偏移量转换为有符号整数。

        :param n: 二进制补码编码的值
        :param n_bits: 位宽度
        :return: 有符号偏移量
        """
        n &= (1 << n_bits) - 1
        sign_bit = 1 << (n_bits - 1)
        if n & sign_bit:
            return n - 2 * sign_bit
        return n


# ==================================================================================================
# 推测性存储旁路（Spectre v4）
# ==================================================================================================
class StoreBpasSpeculator(UnicornSpeculator):
    """
    推测性存储旁路推测器。

    模拟 CPU 在推测执行期间跳过存储指令的效果：
    当一个存储操作后紧跟一个从同一地址的加载操作时，
    CPU 可能推测性地将加载的值返回为旧值（即存储旁路），
    而不是新写入的值。

    算法实现（由于 Unicorn 缺少后指令钩子，采用"脏"方式）：
    1. 在内存写入时保存存储信息（地址、大小、旧值、新值）
    2. 在下一条指令执行前：
       a. 保存检查点
       b. 取消存储效果（恢复旧值）
       c. 但保留新值在内存变更日志中（用于回滚恢复）
    """
    _previous_store: Optional[Tuple[int, int, int, int]] = None
    """ 上一个存储的信息：(地址, 大小, 旧值, 新值) """

    def rollback(self) -> None:
        """ 回滚时清除任何待处理的存储旁路推测。 """
        # 如果有待处理的存储旁路，取消它们
        self._previous_store = None
        return super().rollback()

    def reset(self) -> None:
        """ 重置时清除存储状态。 """
        self._previous_store = None
        super().reset()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        在内存写入时保存存储信息，等待下一条指令时执行旁路推测。

        由于 Unicorn 没有后指令钩子，存储旁路的实现方式是：
        在写入钩子中保存存储信息，在指令钩子中执行旁路逻辑。

        注意：不支持同一指令的多次存储或自覆写指令。

        :param access: 内存访问类型
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 写入的值
        """
        if access == UC_MEM_WRITE:
            # 检查重复调用（同一指令的多次存储）
            if self._previous_store is not None:
                end_addr = address + size
                prev_addr, prev_size = self._previous_store[0:2]
                if address >= prev_addr and end_addr <= (prev_addr + prev_size):
                    prev_val = self._previous_store[3].\
                        to_bytes(prev_size, byteorder='little', signed=self._previous_store[3] < 0)
                    sliced = prev_val[address - prev_addr:end_addr - prev_addr][0]
                    if sliced == value:
                        return  # 相同值，忽略重复
                    raise NotImplementedError("Self-overwriting instructions are not supported")
                raise NotImplementedError("Instructions with multiple stores are not supported")

            # 不是重复 - 发起推测：保存旧值用于旁路
            old_val: int = self._emulator.mem_read(address, size)  # type: ignore
            self._previous_store = (address, size, old_val, value)

    def _speculate_instruction(self, address: int, _: int) -> None:
        """
        在下一条指令前执行存储旁路推测。

        如果有待处理的存储：
        1. 保存检查点（不包含当前指令效果，因为推测由上一条指令触发）
        2. 取消存储效果（恢复旧值到内存）
        3. 在变更日志中记录新值（回滚时恢复）

        :param address: 当前指令地址
        :param _: 指令大小
        """
        if self._max_nesting_reached():  # 已达最大推测窗口？跳过
            self._previous_store = None  # 清除待处理推测请求
            return

        if self._previous_store is not None:
            store_addr = self._previous_store[0]
            old_value = bytes(self._previous_store[2])
            new_is_signed = self._previous_store[3] < 0
            new_value = (self._previous_store[3]). \
                to_bytes(self._previous_store[1], byteorder='little', signed=new_is_signed)

            # 保存检查点（不包含当前指令效果，因为推测由上一条存储指令触发）
            self._checkpoint(address, include_current_inst=False)

            # 取消存储效果但保留新值（用于回滚恢复）
            self._emulator.mem_write(store_addr, old_value)
            self._store_logs[-1].append((store_addr, new_value))
        self._previous_store = None


class X86CondBpasSpeculator(X86CondSpeculator, StoreBpasSpeculator):
    """
    组合条件分支误预测和推测性存储旁路的推测器。

    同时模拟 Spectre v1（分支误预测）和 Spectre v4（存储旁路）两种推测行为。
    内存访问使用 StoreBpasSpeculator 的逻辑，
    指令级推测使用 X86CondSpeculator 的逻辑。
    """

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 存储旁路推测逻辑（调用 StoreBpasSpeculator 的实现） """
        super(StoreBpasSpeculator, self)._speculate_mem_access(access, address, size, value)

    def _speculate_instruction(self, address: int, size: int) -> None:
        """ 条件分支误预测逻辑（调用 X86CondSpeculator 的实现） """
        super(X86CondSpeculator, self)._speculate_instruction(address, size)

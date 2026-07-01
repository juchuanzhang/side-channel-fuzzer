"""
文件：指令规范类的集合。
这些规范通常来源于 JSON ISA 规范文件。
用于描述微架构侧信道模糊测试框架中指令的操作数类型、操作数规范和指令规范。

File: Collection of classes that represent instruction specifications.
The specifications typically originate from a JSON ISA spec file.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Final, Tuple, Literal, Optional


class OT(Enum):
    """
    操作数类型（OT）枚举类，表示指令操作数的类型。
    Enumeration class representing an Operand Type (OT) of an instruction.
    """
    REG = 1  # 寄存器操作数 / Register Operand
    MEM = 2  # 内存操作数 / Memory Operand
    IMM = 3  # 立即数操作数 / Immediate Operand
    LABEL = 4  # 标号操作数 / Label Operand
    AGEN = 5  # LEA指令中的内存地址 / Memory address in LEA instructions
    FLAGS = 6  # 标志位操作数 / Flags Operand
    COND = 7  # 条件操作数 / Condition Operand

    def __str__(self) -> str:
        """返回枚举成员的名称字符串"""
        return str(self._name_)  # pylint: disable=no-member  # This is an intended private use


# 扩展操作数类型（XOT），提供操作数的额外信息（符号、数据类型等）
XOT = Literal["f64", "f32", "f16", "2f16", "bf16", "int", "i64", "i32", "i16", "i8", "u256", "u128",
              "u64", "u32", "u16", "u8"]
""" Extended Operand Type (XOT) provides extra information (sign, type) about the operand. """


@dataclass
class OperandSpec:
    """
    指令操作数的规范描述，通常与 InstructionSpec 配合使用。
    包含操作数的值、类型、宽度、是否为源/目的操作数等信息。

    Specification of an operand in an instruction.
    Typically used in connection with an InstructionSpec.
    """

    values: Final[Tuple[str, ...]]
    """ 操作数值列表（如寄存器名称、立即数值） / List of operand values (e.g., register names, immediate values). """

    type: Final[OT]
    """ 操作数类型（如寄存器、内存、立即数） / Type of the operand (e.g., register, memory, immediate). """

    xtype: Final[Optional[XOT]]
    """ SIMD寄存器操作数的扩展类型（如打包双精度浮点为f64） / Extended type of a SIMD register operand (e.g., packed double-precision FP is f64) """

    width: Final[int]
    """ 操作数位宽（如64位寄存器宽度为64） / Width of the operand in bits, if applicable (e.g., 64 for 64-bit register). """

    src: bool
    """ 是否为源操作数（即指令是否读取该操作数） / Indicates if the operand is a source; i.e., if it is read by the instruction. """

    dest: bool
    """ 是否为目的操作数（即指令是否写入该操作数） / Indicates if the operand is a destination; i.e., if it is written by the instruction. """

    is_signed: Final[bool]
    """ 操作数是否为有符号类型 / Indicates if the operand is signed. """

    has_magic_value: Final[bool]
    """ 操作数是否具有需要特殊处理的魔术值
    （例如当RAX为目的操作数时使用单独的操作码）
    Indicates if the operand has a special value that requires unique handling.
    (e.g., separate opcode when RAX is a destination)
    """

    def __init__(self,
                 values: List[str],
                 type_: OT,
                 src: bool,
                 dest: bool,
                 width: int = 0,
                 is_signed: bool = True,
                 has_magic_value: bool = False,
                 xtype: Optional[XOT] = None):
        """
        初始化操作数规范。
        参数:
            values: 操作数值列表
            type_: 操作数类型
            src: 是否为源操作数
            dest: 是否为目的操作数
            width: 操作数位宽，默认为0
            is_signed: 是否有符号，默认为True
            has_magic_value: 是否有魔术值，默认为False
            xtype: 扩展操作数类型，默认为None
        """
        self.values = tuple(values)  # 将列表转换为不可变元组 / Convert list to immutable tuple
        self.type = type_
        self.src = src
        self.dest = dest
        self.width = width
        self.is_signed = is_signed
        self.has_magic_value = has_magic_value
        self.xtype = xtype

    def __str__(self) -> str:
        """返回操作数值的字符串表示，格式为 (val1, val2, ...)"""
        return "(" + ", ".join(self.values) + ")"


@dataclass
class InstructionSpec:
    """
    指令规范描述，通常来源于 JSON 规范文件（如 base.json）。
    包含指令名称、类别、是否为控制流指令、操作数列表等信息。

    Specification of an instruction.
    Typically originates from a JSON specification file (base.json).
    """

    name: Final[str]
    """ 指令名称 / Name of the instruction. """

    category: Final[str]
    """ 指令类别，来源于JSON规范文件 / Category of the instruction. Originates from the JSON specification file. """

    is_control_flow: Final[bool]
    """ 是否为控制流指令（如跳转、调用指令） / Indicates if the instruction alters control flow (e.g., jumps, calls). """

    operands: List[OperandSpec]
    """ 指令的显式操作数列表 / List of explicit operands for the instruction. """

    implicit_operands: List[OperandSpec]
    """ 指令的隐式操作数列表 / List of implicit operands for the instruction. """

    has_mem_operand: bool = False
    """ 指令是否包含内存操作数 / Indicates if the instruction has a memory operand. """

    has_write: bool = False
    """ 指令是否写入目的操作数 / Indicates if the instruction writes to a destination operand. """

    has_magic_value: bool = False
    """ 指令是否包含需要特殊处理的魔术值 / Indicates if the instruction has a special value that requires unique handling. """

    def __init__(self, name: str, category: str, is_control_flow: bool = False):
        """
        初始化指令规范。
        参数:
            name: 指令名称
            category: 指令类别
            is_control_flow: 是否为控制流指令，默认为False
        """
        self.name = name
        self.category = category
        self.is_control_flow = is_control_flow

        self.operands = []  # 显式操作数列表初始化为空
        self.implicit_operands = []  # 隐式操作数列表初始化为空

    def __str__(self) -> str:
        """返回指令及其操作数的字符串表示"""
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"

    def __hash__(self) -> int:
        """基于字符串表示计算哈希值，用于去重和比较"""
        return hash(str(self))

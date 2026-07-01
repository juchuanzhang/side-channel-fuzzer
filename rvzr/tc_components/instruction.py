"""
文件：表示测试用例程序中指令及其组件的类集合。

本模块定义了指令的各种操作数类型（寄存器、内存、立即数、标签、地址生成、
标志位、条件码）以及指令本身的类，用于构建和操作测试用例中的指令序列。

File: Collection of classes to represent instructions in a test case program and their components.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import List, Optional, Final, Literal, Union, Type, Tuple, get_args, cast
from typing_extensions import assert_never

from ..instruction_spec import OT, InstructionSpec, OperandSpec

# 标志位类型：r(读取)、w(写入)、r/w(读写)、r/cw(条件写入)、undef(未定义)
FlagType = Literal['r', 'w', 'r/w', 'r/cw', 'undef']
# 寄存器大小（位宽）：8/16/32/64/128/256位
RegSize = Literal[8, 16, 32, 64, 128, 256]


# ==================================================================================================
# 操作数（Operands）
# ==================================================================================================
@dataclass
class Operand(ABC):
    """ 指令操作数的抽象基类。所有具体操作数类型（寄存器、内存等）都继承此类。

    Operand of an instruction """

    value: str
    """ 操作数的值，如寄存器名称、内存地址等 """

    src: Final[bool]
    """ 如果为True，该操作数是源操作数（被读取） """

    dest: Final[bool]
    """ 如果为True，该操作数是目的操作数（被写入） """

    has_magic_value: bool = False
    """
    如果为True，操作数的值对父指令有特殊含义。
    特殊含义通常是单独的操作码或编码，例如移位1是单独的操作码。

    If True, the operand value has special meaning for the parent instruction.
    Special meaning is normally a separate opcode or encoding,
    such as when shift by 1 is a separate opcode.
    """

    def __init__(self, value: str, src: bool, dest: bool):
        # 将操作数值转换为小写以统一格式
        self.value = value.lower()
        self.src = src
        self.dest = dest
        super().__init__()

    @classmethod
    def from_fixed_spec(cls, spec: OperandSpec) -> AnyOperand:  # pylint: disable=r1710,r0911
        """
        从固定操作数规范创建操作数实例。
        "固定"意味着规范没有多选项字段（例如只有一个可能的值）。

        :param spec: 操作数规范
        :return: 与规范对应的操作数类型实例

        Create an Operand instance from a fixed operand specification.
        Fixed means that the specification does not have any multiple-option fields
        (e.g., only one possible value).
        :param spec: The operand specification
        :return: The Operand instance of the type that corresponds to the specification
        """
        # NOTE on pylint disable above:
        # - r1710 - mitigates a false positive due to assert_never
        # - r0911 - the large number of returns is a good design choice here

        # 断言规范是固定的（最多一个值），除非是标志位类型
        assert len(spec.values) <= 1 or spec.type == OT.FLAGS, \
            f"Attempt to call from_fixed_spec with a non-fixed spec {spec.values}"
        # 获取操作数值，如果规范无值则为空字符串
        value = spec.values[0] if spec.values else ""
        # 根据操作数类型创建对应的操作数实例
        if spec.type == OT.REG:
            return RegisterOp(value, spec.width, spec.src, spec.dest)
        if spec.type == OT.MEM:
            return MemoryOp(value, spec.width, spec.src, spec.dest)
        if spec.type == OT.IMM:
            return ImmediateOp(value, spec.width)
        if spec.type == OT.LABEL:
            return LabelOp(value)
        if spec.type == OT.AGEN:
            return AgenOp(value, spec.width)
        if spec.type == OT.FLAGS:
            return FlagsOp(spec.values)
        if spec.type == OT.COND:
            return CondOp(value)
        assert_never(spec.type)
        # unreachable, hence no return


class RegisterOp(Operand):
    """ 寄存器操作数。表示指令中的寄存器引用，如rax、xmm0等。

    Register operand of an instruction """

    width: Final[RegSize]  # 寄存器位宽

    def __init__(self, value: str, width: int, src: bool, dest: bool):
        # 验证寄存器位宽是否合法
        assert width in get_args(RegSize), f"Invalid register width {width} for register {value}"
        self.width = cast(RegSize, width)
        super().__init__(value, src, dest)


class MemoryOp(Operand):
    """ 内存操作数。表示指令中的内存引用，如[rax + 8]等。

    Memory operand of an instruction """

    width: Final[int]  # 内存访问宽度（字节数）

    def __init__(self, address: str, width: int, src: bool, dest: bool) -> None:
        self.width = width
        super().__init__(address, src, dest)

    def get_base_register(self) -> Optional[RegisterOp]:
        """
        获取内存操作数的基址寄存器。
        例如，对于[rax + 8]，返回rax。

        :param address: 内存地址字符串
        :return: 基址寄存器，如果没有基址寄存器则返回None

        Get the base register of the memory operand, if any.
        E.g., for [rax + 8], return rax.
        :return: The base register, or None if there is no base register
        """
        addr = self.value.strip()

        # 用+分割地址表达式（将-替换为+以统一处理），找到基址寄存器
        # Split by + and - to find base register
        tokens = [t.strip() for t in addr.replace('-', '+').split('+')]

        # 过滤掉数字常量（十六进制和二进制）
        # Filter out numeric tokens
        tokens = [t for t in tokens if not t.replace('0x', '').isdigit()]
        tokens = [t for t in tokens if not t.replace('0b', '').isdigit()]

        for t in tokens:
            # 第一个非数字token即为基址寄存器
            # the first non-numeric token is the base register
            return RegisterOp(t.lower(), self.width, True, False)
        return None


class ImmediateOp(Operand):
    """ 立即数操作数。表示指令中的常量值，如0x1、42等。立即数总是源操作数。

    Immediate operand of an instruction """

    width: Final[int]  # 立即数宽度（位数）

    def __init__(self, value: str, width: int) -> None:
        self.width = width
        # 立即数总是源操作数，不可能是目的操作数
        super().__init__(value, True, False)


class LabelOp(Operand):
    """ 标签操作数。表示指令中的跳转标签，如.loop、.exit等。标签总是源操作数。

    Label operand of an instruction """

    def __init__(self, value: str) -> None:
        # 标签总是源操作数
        super().__init__(value, True, False)


class AgenOp(Operand):
    """ 地址生成操作数。用于LEA指令，计算有效地址但不实际访问内存。

    Address generation operand of an instruction (used by LEA instruction) """

    width: Final[int]  # 地址宽度（位数）

    def __init__(self, value: str, width: int) -> None:
        self.width = width
        # 地址生成操作数总是源操作数
        super().__init__(value, True, False)


class FlagsOp(Operand):
    """ 标志位操作数。表示x86指令影响的CPU标志位（CF/PF/AF/ZF/SF/TF/IF/DF/OF）。

    Flags operand of an instruction """

    _flag_values: Final[Tuple[str, ...]]  # 每个标志位的访问类型值
    _flag_names: Final[Tuple[str, ...]] = ("CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF")
    # x86标志位名称：进位/奇偶/辅助/零/符号/陷阱/中断/方向/溢出

    def __init__(self, value: Tuple[str, ...]) -> None:
        # 验证标志位值的数量与名称数量一致
        assert len(value) == len(self._flag_names)
        self._flag_values = value
        super().__init__("FLAGS", False, False)  # 标志位既不是源也不是目的

    def __str__(self) -> str:
        # 格式化输出所有标志位及其类型
        return "FLAGS: " \
               f"{self._flag_names[0]}{self._flag_values[0]}|" \
               f"{self._flag_names[1]}{self._flag_values[1]}|" \
               f"{self._flag_names[2]}{self._flag_values[2]}|" \
               f"{self._flag_names[3]}{self._flag_values[3]}|" \
               f"{self._flag_names[4]}{self._flag_values[4]}|" \
               f"{self._flag_names[5]}{self._flag_values[5]}|" \
               f"{self._flag_names[6]}{self._flag_values[6]}|" \
               f"{self._flag_names[7]}{self._flag_values[7]}|" \
               f"{self._flag_names[8]}{self._flag_values[8]}"

    def _get_flag_list(self, types: List[FlagType]) -> List[str]:
        """
        获取具有指定类型的标志位列表。

        :param types: 要包含的标志位类型列表
        :return: 标志位名称列表

        Get a list of flags with the specified types.
        :param types: A list of flag types to include
        :return: A list of flags
        """
        flags = []
        for i, type_ in enumerate(self._flag_values):
            if type_ in types:
                flags.append(self._flag_names[i])
        return flags

    def get_flags_by_type(self, type_: Literal['read', 'write', 'overwrite', 'undef']) -> List[str]:
        """
        根据类型分类获取标志位列表。

        :param type_: 标志位类型（read/write/overwrite/undef）
        :return: 标志位名称列表

        - read: 包含r、r/w、r/cw类型的标志位（被指令读取的标志位）
        - write: 包含w、r/w、r/cw类型的标志位（被指令写入的标志位）
        - overwrite: 仅包含w类型的标志位（被指令无条件写入的标志位）
        - undef: 仅包含undef类型的标志位（指令后值未定义的标志位）

        Get a list of flags with the specified types.
        :param types: Type of flags to include (read, write, overwrite, undef)
        :return: A list of flags
        """
        flag_types: List[FlagType]
        if type_ == "read":
            # 读取类型：包括所有被读取的标志位
            flag_types = ['r', 'r/w', 'r/cw']
        elif type_ == "write":
            # 写入类型：包括所有被写入的标志位
            flag_types = ['w', 'r/w', 'r/cw']
        elif type_ == "overwrite":
            # 无条件写入类型：仅包括被无条件写入的标志位
            flag_types = ['w']
        elif type_ == "undef":
            # 未定义类型：指令后值不确定的标志位
            flag_types = ['undef']
        else:
            assert_never(type_)

        return self._get_flag_list(flag_types)


@dataclass
class CondOp(Operand):
    """ 条件操作数。表示条件跳转指令的条件码，如e（等于）、ne（不等于）等。

    Condition operand of an instruction """

    def __init__(self, value: str) -> None:
        # 条件操作数总是源操作数
        super().__init__(value, True, False)


# ==================================================================================================
# 操作数修改接口
# Operand Modification Interface
# ==================================================================================================
# 可修改值的操作数类型联合
_ValueModifiableOperand = Union[RegisterOp, MemoryOp, ImmediateOp, LabelOp, AgenOp, CondOp]
# 可修改源/目的属性的操作数类型联合（仅寄存器和内存）
_SrcDestModifiableOperand = Union[RegisterOp, MemoryOp]
# 所有操作数类型的联合
AnyOperand = Union[RegisterOp, MemoryOp, ImmediateOp, LabelOp, AgenOp, CondOp, FlagsOp]


def copy_op_with_value_modification(op: _ValueModifiableOperand,
                                    value: str) -> _ValueModifiableOperand:
    """
    复制操作数并修改其值。创建一个新操作数，保留原操作数的其他属性，仅替换值。

    :param op: 要复制的操作数
    :param value: 操作数的新值
    :return: 修改后的操作数

    Make a copy of an operand with a modification to its value
    :param op: The operand to copy
    :param value: The new value of the operand
    :return: The modified operand
    """
    # 根据操作数类型创建对应的新操作数，保留原有属性
    if isinstance(op, RegisterOp):
        return RegisterOp(value, op.width, op.src, op.dest)
    if isinstance(op, MemoryOp):
        return MemoryOp(value, op.width, op.src, op.dest)
    if isinstance(op, ImmediateOp):
        return ImmediateOp(value, op.width)
    if isinstance(op, LabelOp):
        return LabelOp(value)
    if isinstance(op, AgenOp):
        return AgenOp(value, op.width)
    if isinstance(op, CondOp):
        return CondOp(value)
    assert_never(op)


def copy_op_with_flow_modification(op: _SrcDestModifiableOperand,
                                   src: Optional[bool] = None,
                                   dest: Optional[bool] = None) -> _SrcDestModifiableOperand:
    """
    复制操作数并修改其数据流属性（源/目的标志）。

    :param op: 要复制的操作数
    :param src: 如果不为None，操作数的新src属性
    :param dest: 如果不为None，操作数的新dest属性
    :return: 修改后的操作数

    Make a copy of an operand with modifications to its flow properties
    :param op: The operand to copy
    :param src: If not None, the new src property of the operand
    :param dest: If not None, the new dest property of the operand
    :return: The modified operand
    """
    # 如果未提供新值，保留原操作数的属性
    if src is None:
        src = op.src
    if dest is None:
        dest = op.dest

    if isinstance(op, RegisterOp):
        return RegisterOp(op.value, op.width, src, dest)
    if isinstance(op, MemoryOp):
        return MemoryOp(op.value, op.width, src, dest)
    assert_never(op)


# ==================================================================================================
# 指令和符号
# Instructions and Symbols
# ==================================================================================================
class Instruction:
    """ 测试用例程序中的指令类。封装指令名称、类别、操作数等信息。

    Instruction in a test case program """

    # pylint: disable=too-many-instance-attributes
    # NOTE: This is a data container class, so it is expected to have many attributes
    # pylint: disable=too-many-public-methods
    # NOTE: This contains separate accessors for each operand type,
    # so it is expected to have many methods

    name: Final[str]
    """ 指令名称，不含操作数，如'mov', 'add'等 """
    category: Final[str]
    """ 指令类别，如BASE-BINARY，与指令集描述文件中的类别关键字匹配

    The category of the instruction, e.g., BASE-BINARY. The keyword matches
    the category in the instruction set description file (typically called base.json)"""

    is_control_flow: Final[bool]
    """ 如果为True，该指令是控制流指令（分支、调用、返回等） """
    is_instrumentation: Final[bool]
    """ 如果为True，该指令是插桩指令，由生成器插入以防止故障或误报 """
    is_noremove: Final[bool]
    """ 如果为True，在最小化过程中应跳过该指令 """
    is_from_template: bool = False
    """ 如果为True，该指令直接从模板复制，而非由生成器自动创建 """
    is_macro_placeholder: bool = False
    """ 如果为True，该指令是占位符的一部分，将在执行器/模型中被宏调用替换；
    该指令预期为NOP。对于大多数指令，此属性始终为False。

    If True, this instruction is a part of a placeholder that will be
    replaced by a macro call in the executor/model; this instruction is expected to be a NOP.
    For most instructions, this is always False. """

    operands: Final[List[AnyOperand]]
    """ 指令的显式操作数列表 """
    implicit_operands: Final[List[AnyOperand]]
    """ 指令的隐式操作数列表，如x86指令中的标志位等不在指令中显式指定但被使用的操作数 """

    _line_num: int = -1      # 指令在源汇编文件中的行号；通过line_num()访问
    _section_id: int = -1    # 指令在目标文件中的段ID；通过section_id()访问
    _section_offset: int = -1 # 指令在段中的偏移量；通过section_offset()访问
    _size: int = -1          # 指令的字节大小；通过size()访问
    _inst_brief: str = ""    # 缓存的指令简要表示

    # ----------------------------------------------------------------------------------------------
    # 构造函数
    # Constructors

    def __init__(self,
                 name: str,
                 category: str = "",
                 is_control_flow: bool = False,
                 is_instrumentation: bool = False,
                 is_noremove: bool = False) -> None:
        """
        初始化指令对象。

        :param name: 指令名称
        :param category: 指令类别，默认为空
        :param is_control_flow: 是否为控制流指令，默认为False
        :param is_instrumentation: 是否为插桩指令，默认为False
        :param is_noremove: 是否不可移除（最小化时保留），默认为False
        """
        self.name = name
        self.category = category
        self.is_control_flow = is_control_flow
        self.is_instrumentation = is_instrumentation
        self.is_noremove = is_noremove

        self.operands = []
        self.implicit_operands = []

    @classmethod
    def from_spec(cls: Type[Instruction],
                  sp: InstructionSpec,
                  is_instrumentation: bool = False,
                  is_noremove: bool = False) -> Instruction:
        """
        从指令规范创建无操作数的指令对象。

        :param sp: 指令规范
        :param is_instrumentation: 是否为插桩指令
        :param is_noremove: 是否在最小化时保留
        :return: 指令对象

        Create an instruction with NO OPERANDS from an instruction specification.
        :param spec: The instruction specification
        :param is_instrumentation: If True, the instruction is an instrumentation instruction
        :param is_noremove: If True, the instruction be kept during minimization
        :return: The instruction
        """
        obj = cls(
            sp.name,
            sp.category,
            sp.is_control_flow,
            is_instrumentation=is_instrumentation,
            is_noremove=is_noremove)
        return obj

    # ----------------------------------------------------------------------------------------------
    # 打印输出
    # Printing

    def __str__(self) -> str:
        # 格式化指令字符串，内存操作数用方括号包围
        op_list = [
            "[" + o.value + "]" if isinstance(o, MemoryOp) else o.value for o in self.operands
        ]
        operands = ', '.join(op_list)
        return f"{self.name} {operands}"

    # ----------------------------------------------------------------------------------------------
    # 操作数管理
    # Operand Management

    def add_op(self, op: AnyOperand, implicit: bool = False) -> Instruction:
        """
        向指令添加操作数。返回指令本身以支持链式调用。

        :param op: 要添加的操作数
        :param implicit: 如果为True，操作数为隐式操作数
        :return: 指令对象（用于链式调用）

        Add operand to the instruction. Returns the instruction for chaining.
        :param op: Operand to add
        :param implicit: If True, the operand is implicit
        :return: The instruction
        """
        if not implicit:
            self.operands.append(op)
        else:
            self.implicit_operands.append(op)
        return self

    def has_mem_operand(self, include_implicit: bool) -> bool:
        """
        检查指令是否包含内存操作数。

        :param include_implicit: 如果为True，检查时包含隐式操作数
        :return: 如果包含内存操作数返回True，否则返回False

        Check if the instruction has a memory operand.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp):
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp):
                    return True
        return False

    def has_write(self, include_implicit: bool = False) -> bool:
        """
        检查指令是否包含写入内存的操作数。

        :param include_implicit: 如果为True，检查时包含隐式操作数
        :return: 如果包含写入内存的操作数返回True，否则返回False

        Check if the instruction has a memory operand that writes to memory.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand that writes to memory, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp) and o.dest:
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp) and o.dest:
                    return True
        return False

    def has_read(self, include_implicit: bool = False) -> bool:
        """
        检查指令是否包含读取内存的操作数。

        :param include_implicit: 如果为True，检查时包含隐式操作数
        :return: 如果包含读取内存的操作数返回True，否则返回False

        Check if the instruction has a memory operand that reads from memory.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand that reads memory, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp) and o.src:
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp) and o.src:
                    return True
        return False

    def get_all_operands(self) -> List[AnyOperand]:
        """
        获取指令的所有操作数，包括显式和隐式操作数。

        :return: 所有操作数列表

        Get a list of all operands of the instruction,
        including both explicit and implicit operands.
        :return: A list of all operands
        """
        return self.operands + self.implicit_operands

    def get_src_operands(self, include_implicit: bool = False) -> List[AnyOperand]:
        """
        获取指令的源操作数列表。

        :param include_implicit: 如果为True，包含隐式操作数
        :return: 源操作数列表

        Get a list of source operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of source operands
        """
        res = []
        for o in self.operands:
            if o.src:
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if o.src:
                    res.append(o)
        return res

    def get_dest_operands(self, include_implicit: bool = False) -> List[AnyOperand]:
        """
        获取指令的目的操作数列表。

        :param include_implicit: 如果为True，包含隐式操作数
        :return: 目的操作数列表

        Get a list of destination operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of destination operands
        """
        res = []
        for o in self.operands:
            if o.dest:
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if o.dest:
                    res.append(o)
        return res

    def get_mem_operands(self,
                         include_explicit: bool = True,
                         include_implicit: bool = False) -> List[MemoryOp]:
        """
        获取指令的内存操作数列表。

        :param include_explicit: 如果为True，包含显式操作数
        :param include_implicit: 如果为True，包含隐式操作数
        :return: 内存操作数列表

        Get a list of memory operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of memory operands
        """
        assert include_explicit or include_implicit, "At least one of include_explicit or " \
                                                     "include_implicit must be True"
        res = []
        if include_explicit:
            for o in self.operands:
                if isinstance(o, MemoryOp):
                    res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp):
                    res.append(o)
        return res

    def get_flags_operand(self) -> Optional[FlagsOp]:
        """
        获取指令的标志位操作数。

        :return: 标志位操作数，如果指令没有标志位操作数则返回None

        Get the flags operand of the instruction.
        :return: The flags operand, or None if the instruction does not have one
        """
        # 优先在隐式操作数中查找（标志位通常是隐式的）
        for o in self.implicit_operands:
            if isinstance(o, FlagsOp):
                return o
        for o in self.operands:
            if isinstance(o, FlagsOp):
                return o
        return None

    def get_reg_operands(self, include_implicit: bool = False) -> List[RegisterOp]:
        """
        获取指令的寄存器操作数列表。

        :param include_implicit: 如果为True，包含隐式操作数
        :return: 寄存器操作数列表

        Get a list of register operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of register operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, RegisterOp):
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, RegisterOp):
                    res.append(o)
        return res

    def get_cond_operand(self) -> Optional[CondOp]:
        """
        获取指令的条件操作数。

        :return: 条件操作数，如果指令没有条件操作数则返回None

        Get the condition operand of the instruction.
        :return: The condition operand, or None if the instruction does not have one
        """
        for o in self.operands:
            if isinstance(o, CondOp):
                return o
        # 条件操作数必须是显式的，不检查隐式操作数
        # not checking implicit operands -> conditions must be explicit
        return None

    def get_label_operand(self) -> Optional[LabelOp]:
        """
        获取指令的标签操作数。

        :return: 标签操作数，如果指令没有标签操作数则返回None

        Get the label operand of the instruction.
        :return: The label operand, or None if the instruction does not have one
        """
        for o in self.operands:
            if isinstance(o, LabelOp):
                return o
        # 标签操作数必须是显式的，不检查隐式操作数
        # not checking implicit operands -> labels must be explicit
        return None

    def get_imm_operands(self, include_implicit: bool = False) -> List[ImmediateOp]:
        """
        获取指令的立即数操作数列表。

        :param include_implicit: 如果为True，包含隐式操作数
        :return: 立即数操作数列表

        Get a list of immediate operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of immediate operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, ImmediateOp):
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, ImmediateOp):
                    res.append(o)
        return res

    def get_agen_operands(self) -> List[AgenOp]:
        """
        获取指令的地址生成操作数列表。

        :return: 地址生成操作数列表

        Get a list of address generation operands of the instruction.
        :return: A list of address generation operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, AgenOp):
                res.append(o)
        # 地址生成操作数必须是显式的
        # not checking implicit operands -> agen must be explicit
        return res

    # ----------------------------------------------------------------------------------------------
    # 指令在汇编中的位置信息
    # Instruction in Assembly
    def assign_line_num(self, line_num: int) -> None:
        """ 分配指令在源文件中的行号。只能分配一次。

        Assign the line number in the source file where the instruction is located. """
        assert self._line_num == -1, "Line number is already assigned"
        self._line_num = line_num

    def line_num(self) -> int:
        """ 获取指令在源文件中的行号。

        Get the line number in the source file where the instruction is located. """
        assert self._line_num != -1, "Line number is not assigned"
        return self._line_num

    # ----------------------------------------------------------------------------------------------
    # 指令在二进制文件中的属性
    # Instruction in Binary
    def assign_binary_properties(self, section_id: int, offset: int, size: int) -> None:
        """
        在汇编后分配指令在二进制文件中的属性。

        :param section_id: 指令所在段在目标文件中的段ID
        :param offset: 指令在段中的偏移量
        :param size: 汇编后指令的字节大小

        Assign properties of the instruction in the binary file after it has been assembled.
        :param section_id: The ID of the section in the object file where the instruction is located
        :param offset: The section offset of the instruction in the object file
        :param size: The size of the instruction in bytes, after it has been assembled
        """
        assert self._section_id == -1, "Instruction properties are already assigned \n" \
            "    (assign_binary_properties() can only be called once)"
        self._section_id = section_id
        self._section_offset = offset
        self._size = size

    def section_id(self) -> int:
        """ 获取指令在目标文件中的段ID。

        Get the ID of the section in the object file where the instruction is located. """
        assert self._section_id != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before section_id() can be used)"
        return self._section_id

    def section_offset(self) -> int:
        """ 获取指令在段中的偏移量。

        Get the section offset of the instruction in the object file. """
        assert self._section_offset != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before section_offset() can be used)"
        return self._section_offset

    def size(self) -> int:
        """ 获取指令的字节大小。

        Get the size of the instruction in bytes. """
        assert self._size != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before size() can be used)"
        return self._size


def copy_inst_with_modification(instruction: Instruction,
                                name: Optional[str] = None,
                                category: Optional[str] = None,
                                is_control_flow: Optional[bool] = None,
                                is_instrumentation: Optional[bool] = None,
                                is_noremove: Optional[bool] = None) -> Instruction:
    """
    复制指令并修改其属性。创建一个新指令，可选择性地替换原指令的某些属性。

    :param instruction: 要复制的指令
    :param name: 如果不为None，指令的新名称
    :param category: 如果不为None，指令的新类别
    :param is_control_flow: 如果不为None，指令的新控制流属性
    :param is_instrumentation: 如果不为None，指令的新插桩属性
    :param is_noremove: 如果不为None，指令的新不可移除属性
    :return: 修改后的新指令

    Make a copy of an instruction with modifications to its properties
    :param instruction: The instruction to copy
    :param name: If not None, the new name of the instruction
    :param category: If not None, the new category of the instruction
    :param is_control_flow: If not None, the new is_control_flow property of the instruction
    :param is_instrumentation: If not None, the new is_instrumentation property of the instruction
    :param is_noremove: If not None, the new is_noremove property of the instruction
    :return: The new modified instruction
    """
    # 如果未提供新值，保留原指令的属性
    if name is None:
        name = instruction.name
    if category is None:
        category = instruction.category
    if is_control_flow is None:
        is_control_flow = instruction.is_control_flow
    if is_instrumentation is None:
        is_instrumentation = instruction.is_instrumentation
    if is_noremove is None:
        is_noremove = instruction.is_noremove

    # 创建新指令并复制所有属性和操作数
    new_inst = Instruction(name, category, is_control_flow, is_instrumentation, is_noremove)
    new_inst.is_from_template = instruction.is_from_template
    new_inst.is_macro_placeholder = instruction.is_macro_placeholder
    new_inst.operands.extend(instruction.operands.copy())
    new_inst.implicit_operands.extend(instruction.implicit_operands.copy())
    # 复制二进制属性（段ID、偏移量、大小、行号）
    new_inst._section_id = instruction._section_id  # pylint: disable=protected-access
    new_inst._section_offset = instruction._section_offset  # pylint: disable=protected-access
    new_inst._size = instruction._size  # pylint: disable=protected-access
    new_inst._line_num = instruction._line_num  # pylint: disable=protected-access

    return new_inst

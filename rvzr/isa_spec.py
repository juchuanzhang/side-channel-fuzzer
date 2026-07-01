"""
文件：ISA（指令集架构）规范加载器。
负责从 JSON 规范文件中读取指令集定义，并对指令集进行过滤、去重和分类等后处理，
为微架构侧信道模糊测试框架提供可用的指令集。

File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import json
from copy import deepcopy
from typing import Dict, List, Optional, Any, get_args

from .instruction_spec import OT, XOT, OperandSpec, InstructionSpec
from .config import CONF
from .logs import ISALogger

# 操作数类型字符串到枚举的映射字典，用于JSON解析时将字符串转换为OT枚举值
_OT_STR_TO_ENUM = {
    "REG": OT.REG,
    "MEM": OT.MEM,
    "IMM": OT.IMM,
    "LABEL": OT.LABEL,
    "AGEN": OT.AGEN,
    "FLAGS": OT.FLAGS,
    "COND": OT.COND,
}

# 浮点扩展操作数类型列表（不支持FP SIMD）
_FP_XOT = ["f64", "f32", "f16", "2f16"]
# BF16扩展操作数类型列表（不支持）
_BFP_XOT = ["bf16"]


class InstructionSet:
    """
    指令集类，表示给定架构的指令集。
    包含 InstructionSpec 对象列表以及按类型分类的指令子列表。
    在初始化时从JSON文件加载指令规范，并进行过滤、属性设置、去重和分类。

    Class representing an instruction set of a given architecture.
    Contains a list of InstructionSpec objects as well as type-based lists of instructions.
    """

    instructions: List[InstructionSpec]  # 经过过滤后的指令列表
    instructions_unfiltered: List[InstructionSpec]  # 未过滤的原始指令列表
    logger: ISALogger  # ISA日志记录器

    has_unconditional_branch: bool = False  # 是否包含无条件分支指令
    has_conditional_branch: bool = False  # 是否包含条件分支指令
    has_indirect_branch: bool = False  # 是否包含间接分支指令
    has_reads: bool = False  # 是否包含内存读取指令
    has_writes: bool = False  # 是否包含内存写入指令

    control_flow_specs: List[InstructionSpec]  # 控制流指令列表
    non_control_flow_specs: List[InstructionSpec]  # 非控制流指令列表
    non_memory_access_specs: List[InstructionSpec]  # 无内存访问的指令列表
    load_instruction: List[InstructionSpec]  # 内存加载指令列表
    store_instructions: List[InstructionSpec]  # 内存存储指令列表
    cond_branches: List[InstructionSpec]  # 条件分支指令列表

    def __init__(self, filename: str, include_categories: Optional[List[str]] = None):
        """
        初始化指令集。
        参数:
            filename: JSON ISA规范文件路径
            include_categories: 要包含的指令类别列表，可选
        流程: 加载JSON -> 过滤 -> 设置属性 -> 去重 -> 分类
        """
        self.instructions = []
        _read_json_spec(self, filename)  # 从JSON文件读取指令规范
        self.instructions_unfiltered = deepcopy(self.instructions)  # 保存未过滤的副本
        _reduce(self, include_categories)  # 过滤不支持的指令和操作数
        _set_isa_properties(self)  # 设置指令集属性标志
        _dedup(self)  # 去除重复指令
        _set_categories(self)  # 按类别分类指令

    def get_return_spec(self) -> InstructionSpec:
        """
        返回当前架构的RET指令规范。
        根据配置的指令集架构（x86-64或arm64）返回对应的返回指令。
        Return the instruction spec for the RET instruction on the given architecture
        """
        if CONF.instruction_set == "x86-64":
            return InstructionSpec("ret", "BASE-RET", is_control_flow=True)
        if CONF.instruction_set == "arm64":
            return InstructionSpec("ret", "general-ret", is_control_flow=True)
        raise NotImplementedError(f"Unsupported instruction set: {CONF.instruction_set}")

    def get_unconditional_jump_spec(self) -> InstructionSpec:
        """
        返回当前架构的无条件跳转指令规范。
        x86-64架构返回jmp指令，arm64架构返回b指令。
        两种架构都附带一个LABEL操作数。

        Return the instruction spec for the unconditional jump instruction
        on the given architecture
        """
        if CONF.instruction_set == "x86-64":
            spec = InstructionSpec("jmp", "BASE-UNCOND_BR", is_control_flow=True)
            spec.operands.append(OperandSpec([], OT.LABEL, src=True, dest=False, width=64))
            return spec
        if CONF.instruction_set == "arm64":
            spec = InstructionSpec("b", "general-uncond_branch", is_control_flow=True)
            spec.operands.append(OperandSpec([], OT.LABEL, src=True, dest=False, width=64))
            return spec
        raise NotImplementedError(f"Unsupported instruction set: {CONF.instruction_set}")


# ==================================================================================================
# 本地服务函数：对指令集进行后处理
# Local service functions that post-process the instruction set
# ==================================================================================================
def _read_json_spec(isa: InstructionSet, filename: str) -> None:
    """
    从JSON文件读取指令集规范并解析为InstructionSpec对象列表。
    遍历JSON中的每个指令节点，解析其显式操作数和隐式操作数。
    """
    with open(filename, "r") as f:
        root = json.load(f)
    for instruction_node in root:
        # 创建指令规范对象
        instruction = InstructionSpec(instruction_node["name"], instruction_node["category"],
                                      instruction_node["is_control_flow"])

        # 解析显式操作数
        for op_node in instruction_node["operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.operands.append(op)
            if op.has_magic_value:
                instruction.has_magic_value = True  # 标记指令含有魔术值

        # 解析隐式操作数
        for op_node in instruction_node["implicit_operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.implicit_operands.append(op)

        isa.instructions.append(instruction)


def _parse_json_operand(op: Dict[str, Any], parent: InstructionSpec) -> OperandSpec:
    """
    解析JSON操作数节点为OperandSpec对象。
    对于寄存器操作数，会对值进行排序；
    对于内存操作数，会更新父指令的has_mem_operand和has_write标志。

    参数:
        op: JSON操作数节点字典
        parent: 所属的InstructionSpec对象
    返回:
        OperandSpec对象
    """
    op_type = _OT_STR_TO_ENUM[op["type_"]]  # 将字符串类型转换为OT枚举
    op_values = op.get("values", [])
    if op_type == OT.REG:
        op_values = sorted(op_values)  # 寄存器值按字母排序，便于后续处理

    spec = OperandSpec(
        values=op_values,
        type_=op_type,
        src=op["src"],
        dest=op["dest"],
        width=op["width"],
        is_signed=op.get("is_signed", True),
        xtype=op.get("xtype", None),
    )

    # 内存操作数需要更新父指令的相关标志
    if op_type == OT.MEM:
        parent.has_mem_operand = True  # 标记指令包含内存操作数
        if spec.dest:
            parent.has_write = True  # 如果内存操作数是目的操作数，标记指令有写操作

    return spec


def _reduce(isa: InstructionSet, include_categories: Optional[List[str]]) -> None:
    """
    过滤（裁减）指令集，移除不支持的指令和操作数值。
    过滤规则包括：
    - 类别过滤：仅保留指定类别中的指令
    - 指令白名单/黑名单过滤
    - 寄存器黑名单过滤（内存操作数和隐式操作数中的寄存器）
    - FP/BF16 SIMD寄存器过滤（当前不支持浮点SIMD）
    - 操作数值过滤：移除黑名单中的寄存器值；若操作数无可用值则移除整个指令

    Remove unsupported instructions and operand values
    """

    def is_supported(spec: InstructionSpec) -> bool:
        """
        判断指令规范是否被支持。
        白名单优先于黑名单。
        """
        # pylint: disable=too-many-return-statements
        # This is justified as it is a filtering function

        if not CONF.is_generation_enabled():
            # 如果使用现有测试用例，指令过滤无关
            return True

        # 白名单优先于黑名单 / allowlist has priority over blocklist
        if spec.name in CONF.instruction_allowlist:
            return True

        if include_categories and spec.category not in include_categories:
            logger.dbg_dump_filtering_reason(spec, "category not in include_categories")
            return False

        if spec.name in CONF.instruction_blocklist:
            logger.dbg_dump_filtering_reason(spec, "in instruction_blocklist")
            return False

        # 检查显式操作数中的内存操作数是否使用黑名单寄存器
        for operand in spec.operands:
            if operand.type == OT.MEM and operand.values \
                    and operand.values[0] in register_blocklist:
                logger.dbg_dump_filtering_reason(spec, "mem operand uses blocked register")
                return False

        # FP SIMD不被支持 / FP SIMD is not supported
        for operand in spec.operands:
            if operand.type != OT.REG or operand.xtype is None:
                continue
            assert operand.xtype in get_args(XOT), f"Unknown xtype value: {operand.xtype}"
            if operand.xtype in _FP_XOT or operand.xtype in _BFP_XOT:
                logger.dbg_dump_filtering_reason(spec, "uses unsupported FP/SIMD registers")
                return False

        # 检查隐式操作数
        for implicit_operand in spec.implicit_operands:
            assert implicit_operand.type != OT.LABEL  # 目前不存在此类指令
            if implicit_operand.type == OT.MEM \
                    and implicit_operand.values[0] in register_blocklist:
                logger.dbg_dump_filtering_reason(spec, "implicit mem operand uses blocked register")
                return False

            if implicit_operand.type == OT.REG \
                    and implicit_operand.values[0] in register_blocklist:
                assert len(implicit_operand.values) == 1
                logger.dbg_dump_filtering_reason(spec, "implicit reg operand uses blocked register")
                return False
        return True

    logger = ISALogger()

    # 确定不应使用的寄存器集合（黑名单减去白名单）
    register_blocklist = set(CONF.register_blocklist) - set(CONF.register_allowlist)

    # 第一轮过滤：移除不支持的指令
    skip_list = []
    for s in isa.instructions:
        if not is_supported(s):
            skip_list.append(s)
    for s in skip_list:
        isa.instructions.remove(s)

    # 第二轮过滤：移除操作数值中不支持的寄存器；
    # 如果操作数没有可用值，则移除整个指令
    skip_list = []
    for s in isa.instructions:
        operands = list(s.operands)  # 制作副本 / make a copy
        for op_id, op in enumerate(operands):
            # 过滤仅适用于寄存器操作数 / filtering applies only to registers
            if op.type != OT.REG:
                continue

            # 识别支持的寄存器值（移除黑名单中的寄存器）
            op_values = sorted(list(set(op.values) - register_blocklist))

            # FIXME: 临时禁用x86高字节寄存器生成 / temporary disabled generation of higher reg. bytes for x86
            for i, reg in enumerate(op_values):
                if reg[-1] == 'h':
                    op_values[i] = reg.replace('h', 'l')  # 将高字节寄存器替换为低字节寄存器

            # 没有可用值则跳过该指令 / no supported values -> skip this instruction
            if not op_values:
                skip_list.append(s)
                break

            # 否则更新操作数规范 / otherwise, update the operand
            s.operands[op_id] = OperandSpec(op_values, op.type, op.src, op.dest, op.width,
                                            op.is_signed, op.has_magic_value, op.xtype)
    for s in skip_list:
        isa.instructions.remove(s)


def _set_isa_properties(isa: InstructionSet) -> None:
    """
    设置指令集的属性标志，用于指导测试用例生成过程。
    根据指令类型设置：是否有无条件分支、条件分支、内存读取、内存写入等。

    Set properties of the instruction set that are used in the generation process.
    """
    for inst in isa.instructions:
        if inst.is_control_flow:
            # 控制流指令：区分无条件分支和条件分支
            if inst.category in ["BASE-UNCOND_BR", "general-uncond_branch"]:
                isa.has_unconditional_branch = True
            else:
                isa.has_conditional_branch = True
        elif inst.has_mem_operand:
            # 内存访问指令：区分读取和写入
            if inst.has_write:
                isa.has_writes = True
            else:
                isa.has_reads = True


def _dedup(isa: InstructionSet) -> None:
    """
    去除指令集中的重复指令。
    JSON规范文件可能包含同一指令的多个副本，通过比较指令名称、
    操作数数量、类型、值和宽度来识别并移除重复项。

    Instruction set spec may contain several copies of the same instruction.
    Remove them.
    """
    skip_list = set()
    n_instructions = len(isa.instructions)
    # 两两比较所有指令，寻找重复项
    for i in range(n_instructions):
        for j in range(i + 1, n_instructions):
            inst1 = isa.instructions[i]
            inst2 = isa.instructions[j]
            # 名称和操作数数量必须相同才算可能重复
            if inst1.name == inst2.name and len(inst1.operands) == len(inst2.operands):
                match = True
                for k, op1 in enumerate(inst1.operands):
                    op2 = inst2.operands[k]

                    # 操作数类型必须相同
                    if op1.type != op2.type:
                        match = False
                        continue

                    # 操作数值必须相同
                    if op1.values != op2.values:
                        match = False
                        continue

                    # 操作数宽度必须相同（立即数除外，因为宽度不影响立即数语义）
                    if op1.width != op2.width and op1.type != OT.IMM:
                        match = False
                        continue

                    # assert op1.src == op2.src
                    # assert op1.dest == op2.dest

                if match:
                    skip_list.add(inst1)  # 将重复指令加入跳过列表

    for s in skip_list:
        isa.instructions.remove(s)


def _set_categories(isa: InstructionSet) -> None:
    """
    按类别对指令进行分类，构建各种子列表供测试用例生成使用。
    包括：控制流/非控制流、内存/非内存访问、加载/存储指令等。
    同时根据可用指令集调整配置参数。
    """
    isa.control_flow_specs = [i for i in isa.instructions if i.is_control_flow]
    # 如果没有控制流指令，调整配置使每个基本块只有1个后继
    if len(isa.control_flow_specs) == 0:
        CONF.min_successors_per_bb = 1
        CONF.max_successors_per_bb = 1

    isa.non_control_flow_specs = [i for i in isa.instructions if not i.is_control_flow]
    assert isa.non_control_flow_specs, \
        "The instruction set is insufficient to generate a test case"  # 指令集不足以生成测试用例

    # 无内存访问的非控制流指令
    isa.non_memory_access_specs = \
        [i for i in isa.non_control_flow_specs if not i.has_mem_operand]
    if CONF.avg_mem_accesses != 0:
        # 有内存访问的非控制流指令
        memory_access_instructions = \
            [i for i in isa.non_control_flow_specs if i.has_mem_operand]
        # 加载指令：有内存操作数但无写操作
        isa.load_instruction = [i for i in memory_access_instructions if not i.has_write]
        # 存储指令：有内存操作数且有写操作
        isa.store_instructions = [i for i in memory_access_instructions if i.has_write]
        assert isa.load_instruction or isa.store_instructions, \
               "The instruction set does not have memory accesses while `avg_mem_accesses > 0`"
    else:
        isa.load_instruction = []
        isa.store_instructions = []

    # 条件分支指令：排除无条件跳转指令
    uncond_name = isa.get_unconditional_jump_spec().name.lower()
    isa.cond_branches = \
        [i for i in isa.control_flow_specs if i.name.lower() != uncond_name]

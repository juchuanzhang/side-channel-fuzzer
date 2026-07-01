"""
文件: 将汇编文件解析为内部表示(TestCaseCode)的x86特定代码
File: Parsing of assembly files into our internal representation (TestCaseCode).
      This file contains x86-specific code.

本模块实现了x86 Intel语法汇编文件的解析器，负责：
- 将汇编源文件中的指令解析为内部的InstructionSpec和Instruction对象
- 处理x86指令前缀（lock, rep, rex等）和指令同义词（如je/jz）
- 匹配指令操作数类型（寄存器、内存、立即数、标签、标志位）
- 处理内存操作数的大小前缀（byte/word/dword/qword等）

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import re
from typing import TYPE_CHECKING, List

from rvzr.asm_parser import AsmParser, AsmLineParser, asm_parser_assert
from rvzr.instruction_spec import OT, InstructionSpec

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc

# ==================================================================================================
# 私有模块: Intel语法汇编行解析器
# ==================================================================================================

# 常量值匹配的正则表达式模式
_PATTERN_CONST_INT = re.compile("^-?[0-9]+$")      # 十进制整数
_PATTERN_CONST_HEX = re.compile("^-?0x[0-9abcdef]+$")  # 十六进制数
_PATTERN_CONST_BIN = re.compile("^-?0b[01]+$")      # 二进制数
_PATTERN_CONST_SUM = re.compile("^-?[0-9]+ *[+-] *[0-9]+$")  # 算术表达式

# x86指令前缀列表：这些前缀需与指令名合并处理
_ASM_PREFIXES = ["lock", "rex", "rep", "repe", "repne"]

# x86指令同义词映射表：将别名指令名映射到规范名
# 例如je和jz是同一指令的不同名称，统一映射为jz
_ASM_SYNONYMS = {
    "je": "jz",
    "jne": "jnz",
    "jnae": "jb",
    "jc": "jb",
    "jae": "jnb",
    "jnc": "jnb",
    "jna": "jbe",
    "ja": "jnbe",
    "jnge": "jl",
    "jge": "jnl",
    "jng": "jle",
    "jg": "jnle",
    "jpe": "jp",
    "jpo": "jnp",
    "cmove": "cmovz",
    "cmovne": "cmovnz",
    "cmovnae": "cmovb",
    "cmovc": "cmovb",
    "cmovae": "cmovnb",
    "cmovnc": "cmovnb",
    "cmovna": "cmovbe",
    "cmova": "cmovnbe",
    "cmovnge": "cmovl",
    "cmovge": "cmovnl",
    "cmovng": "cmovle",
    "cmovg": "cmovnle",
    "cmovpe": "cmovp",
    "cmovpo": "cmovnp",
    "sete": "setz",
    "setne": "setnz",
    "setnae": "setb",
    "setc": "setb",
    "setae": "setnb",
    "setnc": "setnb",
    "setna": "setbe",
    "seta": "setnbe",
    "setnge": "setl",
    "setge": "setnl",
    "setng": "setle",
    "setg": "setnle",
    "setpe": "setp",
    "setpo": "setnp",
    "movabs": "mov",
    "repe": "repz",
    "repne": "repnz",
    "repnz": "repne",
    "repz": "repe",
}

# 内存操作数大小关键字到位宽的映射
_MEMORY_SIZES = {
    "byte": 8,
    "word": 16,
    "dword": 32,
    "qword": 64,
    "tbyte": 80,
    "xmmword": 128,
    "ymmword": 256,
    "zmmword": 512
}


class _X86IntelLineParser(AsmLineParser):
    """
    x86 Intel语法汇编行解析器。

    继承自AsmLineParser，实现x86 Intel语法特有的解析逻辑：
    - 提取指令名称（包括前缀如lock, rep等）
    - 提取操作数列表
    - 查找候选指令规格
    - 匹配操作数与指令规格
    """

    _curr_ln: int

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        """
        初始化x86 Intel语法行解析器。

        :param isa_spec: 指令集规格，提供指令映射表
        :param target_desc: 目标架构描述，提供寄存器信息
        """
        super().__init__(isa_spec, target_desc)
        self._comment_char = "#"

    # ----------------------------------------------------------------------------------------------
    # ISA特定钩子方法的实现
    def _tokenize(self, line: str) -> List[str]:
        """
        对汇编行进行词法分析（分词）。

        :param line: 汇编行文本
        :return: 词法单元列表（本实现中不需要分词，返回空列表）
        """
        return []  # 本实现中不需要分词

    def _get_instruction_name(self, line: str, _: List[str]) -> str:
        """
        从汇编行提取指令名称，包括前缀。

        处理x86指令前缀（如lock, rep, rex等），将前缀与指令名合并。
        例如 "lock cmpxchg" 会被完整提取。

        :param line: 汇编行文本
        :param _: 词法单元列表（未使用）
        :return: 包含前缀的完整指令名称
        """
        name = ""
        for word in line.split():
            if word in _ASM_PREFIXES:
                name += word + " "
                continue
            name += word
            break
        return name

    def _get_instruction_operands(self, line: str, name: str, tokens: List[str]) -> List[str]:
        """
        从汇编行提取操作数列表。

        移除指令名称后，按逗号分隔操作数，并去除多余空格。

        :param line: 汇编行文本
        :param name: 指令名称（用于从行中移除）
        :param tokens: 词法单元列表（未使用）
        :return: 操作数字符串列表
        """
        operands_raw = line.removeprefix(name).split(",")
        if operands_raw == [""]:  # 无操作数
            return []
        operands_raw = [o.strip() for o in operands_raw]  # 去除空格
        return operands_raw

    def _get_initial_candidate_specs(self, line: str, _: str) -> List[InstructionSpec]:
        """
        根据指令名称查找候选指令规格列表。

        处理指令前缀和同义词，在指令映射表中查找匹配的规格。
        例如将"je"转换为"jz"后再查找。

        :param line: 汇编行文本
        :param _: 指令名称（未使用）
        :return: 候选指令规格列表
        """
        key = ""
        for word in line.split():
            # 将前缀包含在查找键中
            if word in _ASM_PREFIXES:
                key += word + " "
                continue

            # 修复跳转指令名称（使用同义词映射）
            if word in _ASM_SYNONYMS:
                key += _ASM_SYNONYMS[word]
            else:
                key += word
            return self._instruction_map.get(key, [])
        return []

    def _check_if_spec_matches(self, spec: InstructionSpec, operands_raw: List[str]) -> bool:
        """
        检查给定的指令规格是否与操作数列表匹配。

        对每个操作数依次匹配其类型：
        - 标签：以"."开头的标识符
        - 内存地址：包含"[]"的操作数，检查大小前缀
        - 立即数：匹配十进制/十六进制/二进制/算术表达式
        - 寄存器：与规格中允许的寄存器值列表匹配

        :param spec: 待匹配的指令规格
        :param operands_raw: 原始操作数字符串列表
        :return: 若规格与操作数完全匹配返回True，否则False
        """
        # pylint: disable=too-many-return-statements  # 选择器中多返回语句是合理的

        if len(spec.operands) != len(operands_raw):
            return False

        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]

            # 匹配标签操作数：以"."开头的标识符
            if op_raw[0] == ".":
                if op_spec.type != OT.LABEL:
                    return False
                continue

            # 匹配内存地址操作数：包含"[]"的表示
            if "[" in op_raw:
                if op_spec.type not in [OT.AGEN, OT.MEM]:
                    return False

                # 匹配地址大小前缀（如byte ptr, dword ptr等）
                access_size = op_raw.split()[0]
                if access_size == "ptr":
                    # 内部约定："ptr"前缀匹配任意大小
                    continue

                asm_parser_assert(access_size in _MEMORY_SIZES, self._curr_ln,
                                  f"Pointer size must be declared explicitly: {op_raw}")
                if op_spec.width != _MEMORY_SIZES[access_size]:
                    return False
                continue

            # 匹配立即数操作数：匹配二进制/十六进制/十进制/算术表达式
            if _PATTERN_CONST_BIN.match(op_raw) or \
                    _PATTERN_CONST_HEX.match(op_raw) or \
                    _PATTERN_CONST_INT.match(op_raw) or \
                    _PATTERN_CONST_SUM.match(op_raw):
                if op_spec.type != OT.IMM:
                    return False
                continue

            # 匹配寄存器操作数：检查寄存器名是否在规格允许值列表中
            if op_spec.type == OT.REG:
                if op_raw not in op_spec.values:
                    return False
                continue
            return False
        return True


# ==================================================================================================
# 公共接口: x86汇编文件解析器
# ==================================================================================================
class X86AsmParser(AsmParser):
    """
    x86汇编文件解析器的实现。

    继承自通用AsmParser接口，使用_X86IntelLineParser作为行级解析器，
    并设置宏占位指令为"nop qword ptr [rax + 0xff]"。
    """

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        """
        初始化x86汇编解析器。

        :param isa_spec: 指令集规格对象
        :param target_desc: 目标架构描述对象
        """
        super().__init__(isa_spec, target_desc)
        self._line_parser = _X86IntelLineParser(isa_spec, target_desc)
        # 设置宏占位指令，用于在宏展开时替代宏体
        self._asm_patcher.set_macro_placeholder(" nop qword ptr [rax + 0xff]")

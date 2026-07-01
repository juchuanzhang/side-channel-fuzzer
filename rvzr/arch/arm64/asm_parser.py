"""
文件：ARM64汇编文件解析器
本文件实现了将ARM64汇编代码解析为内部测试用例表示（TestCaseCode）的功能，
包含ARM64特定的语法处理逻辑：
1. _ARM646LineParser：ARM64单行汇编指令解析器，处理ARM64特有的条件码、
   内存寻址语法、方括号合并等
2. ARM64AsmParser：ARM64汇编文件解析器的公共接口类

注意：当前实现较为脆弱，未来应使用正式解析器（如keystone）重写。

File: Parsing of assembly files into our internal representation (TestCaseCode).
      This file contains arm64-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# FIXME: this implementation is quite brittle; rewrite it using a proper parser (keystone ?)

from __future__ import annotations
import re
from typing import TYPE_CHECKING, List

from rvzr.asm_parser import AsmParser, AsmLineParser, AsmParserError
from rvzr.instruction_spec import OT, InstructionSpec

from .target_desc import ARM64TargetDesc

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc


# ==================================================================================================
# Private: Parser of assembly lines in ARM64 syntax（私有模块：ARM64汇编行解析器）
# ==================================================================================================
class _ARM646LineParser(AsmLineParser):
    """
    ARM64汇编行解析器。
    负责将单行ARM64汇编代码解析为指令名和操作数列表，
    处理ARM64特有的语法特征：条件码后缀、方括号内存寻址、
    #前缀立即数等。

    Parser of assembly lines in ARM64 syntax
    """
    _target_desc: ARM64TargetDesc
    _curr_ln: int  # 当前解析的行号

    def __init__(self, isa_spec: InstructionSet, target_desc: ARM64TargetDesc) -> None:
        """
        初始化ARM64汇编行解析器。

        参数:
            isa_spec: 指令集规范，用于查找指令定义
            target_desc: ARM64目标描述对象，提供寄存器和条件码信息
        """
        super().__init__(isa_spec, target_desc)
        # ARM64汇编使用//作为注释前缀
        self._comment_char = "//"
        # ARM64指令分词正则表达式：捕获指令名+条件码、操作数列表和注释
        # 格式：指令名(可能带条件后缀) + 操作数1 + 操作数2 + ... + 注释
        self._re_tokenize = re.compile(
            r"^([^ .]+\.?)([^ ]+)? ([^ ,]+)(,[^,]+)?(,[^,]+)?(,[^,]+)?( //.*)?")
        # 简化版分词正则：仅捕获指令名和条件码（用于无操作数指令如nop）
        self._re_tokenize_nops = re.compile(r"^([^ .]+\.?)([^ ]+)?")
        # ARM64条件码列表，用于识别和匹配条件操作数
        self._condition_code = list(target_desc.branch_conditions.keys())

    # ----------------------------------------------------------------------------------------------
    # Implementation of ISA-specific hooks（ISA特定钩子的实现）
    def _tokenize(self, line: str) -> List[str]:
        """
        将ARM64汇编行文本分词为操作数token列表。
        使用正则表达式提取指令名、条件码和操作数，
        然后合并被正则拆散的方括号内存寻址操作数（如[x0, #8]）。

        参数:
            line: 待分词的ARM64汇编行文本
        返回值:
            合并后的token列表

        异常:
            AsmParserError: 当无法分词时抛出
        """
        # 使用主正则或简化正则提取tokens
        matches = self._re_tokenize.findall(line)
        if matches == []:
            matches = self._re_tokenize_nops.findall(line)
        if not matches:
            raise AsmParserError(self._curr_ln, "Could not tokenize the line")
        # 去除操作数前的逗号前缀
        tokens = [t.removeprefix(",") for t in matches[0] if t]
        # print(tokens)

        # the regex above splits memory address operands into multiple tokens
        # we need to merge them back
        # 上方正则会将方括号内存地址操作数拆分为多个token，
        # 需要将它们合并回完整的内存操作数格式
        tokens_merged = []
        mem_started = False  # 标记是否正在收集方括号内的token
        mem_token = ""      # 临时存储方括号内的部分token
        for token in tokens:
            if not token:
                continue
            # 完整的方括号操作数（如[x0]），直接添加
            if token[0] == "[" and token[-1] == "]":
                tokens_merged.append(token)
                continue
            # 方括号开始（如[x0,），开始收集内存操作数
            if token[0] == "[":
                mem_started = True
                mem_token = token
                continue
            # 方括号结束（如#8]），合并所有部分并结束收集
            if token[-1] == "]":
                tokens_merged.append(mem_token + "," + token)
                mem_started = False
                mem_token = ""
                continue
            # 方括号内部的中间token（如#8,），追加到临时存储
            if mem_started:
                mem_token += "," + token
                continue
            # 非内存操作数的普通token，直接添加
            tokens_merged.append(token)

        # print(tokens_merged)
        return tokens_merged

    def _get_instruction_name(self, line: str, tokens: List[str]) -> str:
        """
        从token列表中获取指令名称。
        ARM64中指令名是token列表的第一个元素。

        参数:
            line: 原始汇编行文本（未使用）
            tokens: 分词后的token列表
        返回值:
            指令名称字符串
        """
        return tokens[0]

    def _get_instruction_operands(self, _: str, __: str, tokens: List[str]) -> List[str]:
        """
        从token列表中获取指令操作数列表。
        ARM64中操作数是token列表中除指令名外的所有元素。

        参数:
            _: 原始行文本（未使用）
            __: 指令名称（未使用）
            tokens: 分词后的token列表
        返回值:
            操作数字符串列表

        Get the list of operand strings from the tokens
        """
        return tokens[1:]

    def _get_initial_candidate_specs(self, _: str, name: str) -> List[InstructionSpec]:
        """
        根据指令名称获取候选的指令规范列表。
        从指令映射表中查找与给定名称匹配的所有指令规范。

        参数:
            _: 原始行文本（未使用）
            name: 指令名称
        返回值:
            匹配的指令规范列表（可能为空）

        Get the list of candidate specs for an instruction with the given name
        """
        return self._instruction_map.get(name, [])

    def _check_if_spec_matches(self, spec: InstructionSpec, operands_raw: List[str]) -> bool:
        """
        检查给定的指令规范是否与原始操作数字符串列表匹配。
        按ARM64语法规则逐一验证每个操作数的类型：
        - 条件码（OT.COND）：必须在ARM64条件码列表中
        - 标号（OT.LABEL）：以.开头的字符串
        - 地址（OT.AGEN/OT.MEM）：包含方括号的表达式
        - 立即数（OT.IMM）：以#开头的值或在允许值列表中的关键字
        - 寄存器（OT.REG）：必须在规范的允许值列表中

        参数:
            spec: 待匹配的指令规范
            operands_raw: 原始操作数字符串列表
        返回值:
            True表示规范与操作数匹配，False表示不匹配

        Check if the given spec matches the given list of operand strings
        """
        # pylint: disable=too-many-return-statements  # justified for selectors
        # pylint: disable=too-many-branches  # justified for selectors
        # print(spec.name, operands_raw, spec.operands)

        # 操作数数量必须一致
        if len(spec.operands) != len(operands_raw):
            return False

        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]

            # match condition
            # 匹配条件码操作数：检查是否在ARM64条件码列表中
            if op_spec.type == OT.COND:
                if op_raw not in self._condition_code:
                    return False
                continue

            # match label
            # 匹配标号操作数：以.开头的字符串必须是LABEL类型
            if op_raw[0] == ".":
                if op_spec.type != OT.LABEL:
                    return False
                continue

            # match address
            # 匹配地址操作数：包含方括号的必须是AGEN或MEM类型
            if "[" in op_raw:
                if op_spec.type not in [OT.AGEN, OT.MEM]:
                    return False
                continue

            # match immediate value
            # 匹配立即数操作数：以#开头必须是IMM类型
            if op_raw[0] == "#":
                if op_spec.type != OT.IMM:
                    return False
                continue

            # match register
            # 匹配寄存器操作数：值必须在规范允许的寄存器列表中
            if op_spec.type == OT.REG:
                if op_raw not in op_spec.values:
                    return False
                continue

            # match keyword immediate
            # 匹配关键字立即数：非#开头的IMM操作数必须在允许值列表中
            if op_spec.type == OT.IMM:
                if op_raw not in op_spec.values:
                    return False
                continue

            # no match
            # 所有匹配规则都不满足，返回不匹配
            return False
        return True


# ==================================================================================================
# Public Interface: Parser of ARM64 assembly files（公共接口：ARM64汇编文件解析器）
# ==================================================================================================
class ARM64AsmParser(AsmParser):
    """
    ARM64汇编文件解析器的公共接口实现。
    继承通用AsmParser，使用_ARM646LineParser处理ARM64特有的语法，
    并设置宏指令的占位符为ARM64的nop指令序列。

    Implementation of the AsmParser interface for ARM64 assembly files
    """

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        """
        初始化ARM64汇编解析器。

        参数:
            isa_spec: 指令集规范对象
            target_desc: 目标架构描述对象（必须是ARM64TargetDesc）
        """
        super().__init__(isa_spec, target_desc)
        assert isinstance(target_desc, ARM64TargetDesc)
        # 创建ARM64单行解析器实例
        self._line_parser = _ARM646LineParser(isa_spec, target_desc)
        # 设置宏指令占位符为3个ARM64 nop指令
        self._asm_patcher.set_macro_placeholder("nop; nop; nop")

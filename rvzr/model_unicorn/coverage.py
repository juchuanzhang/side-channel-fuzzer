"""
文件：基于 Unicorn 后端的模糊测试中指令覆盖率跟踪类。

本模块实现了 InstructionCoverage 类，用于在模糊测试过程中跟踪
模型执行的指令覆盖率。覆盖率以指令签名（名称+操作数类型）为粒度，
记录每个指令签名被多少个测试用例覆盖。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import defaultdict

from typing import Dict, Optional
from typing_extensions import assert_never

from ..tc_components.instruction import Instruction, RegisterOp, MemoryOp, \
    ImmediateOp, LabelOp, AgenOp, FlagsOp, CondOp
from ..config import CONF

_SIGNATURE_CACHE: Dict[int, str] = {}
""" 指令签名缓存，避免重复计算 """


def _get_instruction_signature(instruction: Instruction) -> str:
    """
    获取指令的简短字符串表示，用作覆盖率跟踪时的唯一标识。

    签名格式为：指令名 + 操作数类型缩写（R=寄存器, M=内存, I=立即数,
    L=标签, A=地址生成, F=标志位, C=条件码）及操作数宽度。

    :param instruction: 要生成签名的指令
    :return: 指令的签名字符串
    """
    inst_identifier = id(instruction)

    # 从缓存中获取签名，避免重复计算
    if inst_identifier in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[inst_identifier]

    # 计算指令签名
    brief = instruction.name
    for o in instruction.operands:
        if isinstance(o, RegisterOp):
            brief += f" R{o.width}"
        elif isinstance(o, MemoryOp):
            brief += f" M{o.width}"
        elif isinstance(o, ImmediateOp):
            brief += f" I{o.width}"
        elif isinstance(o, LabelOp):
            brief += " L"
        elif isinstance(o, AgenOp):
            brief += f" A{o.width}"
        elif isinstance(o, FlagsOp):
            brief += " F"
        elif isinstance(o, CondOp):
            brief += " C"

        else:
            assert_never(o)

    _SIGNATURE_CACHE[inst_identifier] = brief
    return brief


class InstructionCoverage:
    """
    指令覆盖率跟踪类：在模糊测试过程中跟踪模型执行的指令覆盖率。

    覆盖率分两层记录：
    - _cov: 整个模糊测试会话的累计覆盖率（每个指令签名被多少测试用例覆盖）
    - _local_cov: 当前测试用例的覆盖率（每个指令签名被执行的次数）

    覆盖率类型由 CONF.coverage_type 控制：
    - "model_instructions": 启用模型指令级覆盖率跟踪
    - 其他值: 禁用覆盖率跟踪
    """
    _cov: Dict[str, int]
    """ 整个模糊测试会话的累计指令覆盖率 """

    _local_cov: Optional[Dict[str, int]] = None
    """ 当前测试用例的指令覆盖率（仅在启用跟踪时有效）"""

    def __init__(self) -> None:
        """ 初始化覆盖率跟踪器，创建空的累计覆盖率字典 """
        self._cov = defaultdict(int)

    def start_test_case(self) -> None:
        """
        开始跟踪新测试用例的覆盖率。
        当 CONF.coverage_type == "model_instructions" 时启用跟踪，
        否则禁用覆盖率跟踪。
        """
        if CONF.coverage_type == "model_instructions":
            self._local_cov = defaultdict(int)
            return

        self._local_cov = None

    def add_instruction(self, inst: Instruction) -> None:
        """ 记录给定指令为已覆盖（仅在覆盖率跟踪启用时）。
        跳过仪器指令（instrumentation），因为它们不属于测试用例本身。
        :param inst: 已执行的指令
        """
        if self._local_cov is None:
            return
        if inst.is_instrumentation:
            return
        self._local_cov[_get_instruction_signature(inst)] += 1

    def finish_test_case(self) -> None:
        """ 结束当前测试用例的覆盖率跟踪，将局部覆盖率合并到累计覆盖率中 """
        if self._local_cov is None:
            return

        # 将当前测试用例的覆盖指令合并到累计覆盖率中
        for inst_name in self._local_cov.keys():
            self._cov[inst_name] += 1

    def report(self, path: str) -> None:
        """ 将覆盖率数据写入文件。
        先确保最后一个测试用例的覆盖率被合并，
        然后按覆盖次数降序排列写入文件。
        :param path: 输出文件路径
        """
        # 确保最后一个测试用例的覆盖率被包含在报告中
        self.finish_test_case()

        # 按覆盖次数降序排列指令，写入文件
        inst_names = sorted(self._cov.items(), key=lambda x: x[1], reverse=True)
        with open(path, "w") as f:
            for inst_name, count in inst_names:
                f.write(f"{inst_name:<20} {count}\n")
            if not inst_names:
                f.write("    No coverage data available")

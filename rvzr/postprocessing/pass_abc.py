"""
文件：最小化pass的抽象接口和公共功能。

该模块定义了所有最小化pass的基类BaseMinimizationPass，
提供了公共功能包括：
- 从指令列表创建测试用例对象
- 检查测试用例是否触发违规
- 设置忽略列表
- 根据指令集架构确定注释符号和基地址寄存器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
import tempfile
from typing import TYPE_CHECKING, List, Final

from ..config import CONF

if TYPE_CHECKING:
    from ..fuzzer import Fuzzer
    from ..isa_spec import InstructionSet
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData
    from .progress_printer import ProgressPrinter


class BaseMinimizationPass(abc.ABC):
    """
    所有最小化pass的基类，提供公共功能。
    
    包括：
    - 模糊测试器实例引用，用于执行验证
    - 指令集规范引用，用于指令处理
    - 进度打印器，用于输出最小化进度
    - 忽略列表，指定验证时应忽略的输入ID
    - 注释符号和基地址寄存器，根据指令集架构自动确定
    """
    name: str = ""
    _fuzzer: Final[Fuzzer]  # 模糊测试器实例
    _instruction_set_spec: Final[InstructionSet]  # 指令集规范
    _progress: Final[ProgressPrinter]  # 进度打印器
    _ignore_list: List[int]  # 验证时应忽略的输入ID列表

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet,
                 progress: ProgressPrinter):
        """
        初始化最小化pass基类。
        :param fuzzer: 模糊测试器实例
        :param instruction_set_spec: 指令集规范
        :param progress: 进度打印器
        """
        self._fuzzer = fuzzer
        self._instruction_set_spec = instruction_set_spec
        self._progress = progress
        self._ignore_list = []

        # 根据指令集架构确定注释符号和基地址寄存器
        self._comment_symbol = "#" if CONF.instruction_set == "x86-64" else "//"  # x86用#，arm64用//
        self._base_register = "r14" if CONF.instruction_set == "x86-64" else "x20"  # x86用r14，arm64用x20

    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """ 设置验证时应忽略的输入ID列表 """
        self._ignore_list = ignore_list

    def _get_test_case_from_instructions(self,
                                         instructions: List[str],
                                         path: str = "") -> TestCaseProgram:
        """
        从指令列表创建测试用例对象。
        指令被写入文件，然后通过汇编解析器解析为测试用例对象。
        :param instructions: 指令列表（每行一条指令）
        :param path: 存储测试用例的文件路径；如果为空，创建临时文件
        :return: 解析后的测试用例对象
        """
        # 如果未指定路径，创建临时文件
        if not path:
            with tempfile.NamedTemporaryFile(dir="/tmp/rvzr_minimize", delete=False) as fp:
                path = fp.name
        # print(path)

        # 将指令写入文件
        with open(path, "w+") as f:
            for line in instructions:
                f.write(line)
        tc = self._fuzzer.asm_parser.parse_file(path, self._fuzzer.code_gen,
                                                self._fuzzer.elf_parser)
        return tc

    def _check_for_violation(self, test_case: TestCaseProgram, inputs: List[InputData],
                             local_ignore_list: List[int]) -> bool:
        """
        检查测试用例是否触发违规。
        多次重试以提高检测的可靠性。
        :param test_case: 待检查的测试用例
        :param inputs: 用于验证的输入列表
        :param local_ignore_list: 验证时应忽略的输入ID列表
        :return: True表示违规被触发，False表示未触发
        """
        for _ in range(CONF.minimizer_retries):  # 多次重试
            violation = self._fuzzer.fuzzing_round(test_case, inputs, local_ignore_list)
            if violation is not None:
                return True
        return False
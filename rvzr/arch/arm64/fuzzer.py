"""
文件：ARM64架构模糊测试器的实现
本文件实现了ARM64架构上的模糊测试器，包括：
1. ARM64Fuzzer：标准模糊测试模式，扩展通用Fuzzer类，
   增加了推测过滤器和观测过滤器以筛除无价值的测试用例
2. ARM64ArchitecturalFuzzer：架构级模糊测试器（ARM64特定实现，暂无额外逻辑）
3. ARM64ArchDiffFuzzer：架构差异模糊测试器，检测不同架构行为差异
4. 辅助函数：快速模式上下文管理器、带屏障测试用例创建

File: arm64 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Generator
from contextlib import contextmanager
import tempfile
import os

from rvzr.fuzzer import Fuzzer, ArchitecturalFuzzer, ArchDiffFuzzer
from rvzr.traces import HTrace
from rvzr.tc_components.test_case_data import InputData
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.stats import FuzzingStats
from rvzr.config import CONF
from .executor import ARM64Executor

if TYPE_CHECKING:
    from rvzr.asm_parser import AsmParser
    from rvzr.elf_parser import ELFParser
    from rvzr.code_generator import CodeGenerator
    from rvzr.executor import Executor

# 模糊测试统计信息收集器
STAT = FuzzingStats()


# ==================================================================================================
# ARM64-specific Implementation of the Fuzzer（ARM64特定模糊测试器实现）
# ==================================================================================================
class ARM64Fuzzer(Fuzzer):
    """
    ARM64架构标准模糊测试模式的实现。
    扩展通用Fuzzer类，增加了：
    1. 指令集兼容性检查（确保指令集支持所需的异常类型）
    2. 推测过滤器（Speculation Filter）和观测过滤器（Observation Filter）
       用于筛除不会产生有趣侧信道信号的测试用例

    Implementation of the standard fuzzing mode for the arm64 architecture.

    Extends the generic Fuzzer class with:
    1. Checking of the instruction set for compatibility with the required faults
    2. Filtering of non-useful test cases with a Speculation Filter and an Observation Filter
    """

    executor: ARM64Executor

    # ----------------------------------------------------------------------------------------------
    # Private Methods（私有方法）
    def _filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        多阶段过滤算法，逐步筛除无价值的测试用例。
        当前实现了观测过滤器：将原始测试用例的硬件追踪与
        添加内存屏障后的追踪进行比较，如果两者等效则说明
        侧信道信号不是由推测执行产生的，应过滤掉。

        参数:
            test_case: 待过滤的测试用例程序
            inputs: 待测试的输入数据列表
        返回值:
            True表示应过滤掉该测试用例；False表示保留

        This function implements a multi-stage algorithm that gradually filters out
        uninteresting test cases

        :param test_case: the target test case
        :param inputs: list of inputs to be tested
        :return: True if the test case should be filtered out; False otherwise
        """
        # Exit if all filters are disabled
        # 如果观测过滤器被禁用，直接返回False（不过滤）
        if not CONF.enable_observation_filter:
            return False

        # Number of repetitions for each input
        # 每个输入的重复执行次数
        reps = CONF.executor_filtering_repetitions

        with _quick_and_dirty_mode(self.executor):  # Speed up the execution by disabling checks
            # 使用快速模式执行，禁用部分检查以加速过滤过程
            # Collect hardware traces for the test case
            # 收集测试用例的硬件追踪数据
            try:
                self.executor.load_test_case(test_case)
                org_htraces = self.executor.trace_test_case(inputs, reps)
            except IOError:
                return True  # IO错误时过滤掉该测试用例

            # 执行观测过滤器检查
            if self._observation_filter(test_case, inputs, reps, org_htraces):
                return True

            return False

    def _observation_filter(self, test_case: TestCaseProgram, inputs: List[InputData], reps: int,
                            org_htraces: List[HTrace]) -> bool:
        """
        观测过滤器：检测硬件追踪中是否包含推测性缓存驱逐信号。
        方法：创建一个带内存屏障（dsb SY + isb）的测试用例版本，
        收集其硬件追踪，与原始追踪比较。
        如果两者等效，说明侧信道信号不是由推测执行产生的，
        该测试用例没有研究价值，应过滤掉。

        参数:
            test_case: 原始测试用例程序
            inputs: 待测试的输入数据列表
            reps: 每个输入的重复执行次数
            org_htraces: 原始测试用例的硬件追踪列表
        返回值:
            True表示应过滤掉；False表示保留（追踪不同，说明有推测行为差异）

        Check if any of the htraces contain a speculative cache eviction
        for this create a fenced version of the test case and collect traces for it
        :param test_case: the target test case
        :param inputs: list of inputs to be tested
        :param reps: number of repetitions for each input
        :param org_htraces: list of HTrace objects collected while executing the test case
        :return: True if the test case should be filtered out; False otherwise
        """
        if not CONF.enable_observation_filter:
            return False

        # 创建临时文件用于存储带屏障的测试用例汇编代码
        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_name = fenced.name
        # 生成带内存屏障的测试用例版本
        fenced_test_case = _create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                    self.asm_parser, self.code_gen, self.elf_parser)
        try:
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, reps)
        except IOError:
            return True  # skip the test case if there is an error
        os.remove(fenced.name)

        # 比较原始追踪和带屏障追踪是否等效
        # 如果所有输入的追踪都等效，说明侧信道信号不是推测执行产生的
        traces_match = True
        for i, _ in enumerate(inputs):
            if not self.analyser.htraces_are_equivalent(fenced_htraces[i], org_htraces[i]):
                traces_match = False
                break
        if traces_match:
            # 追踪匹配：侧信道信号在添加屏障后消失，说明不是推测执行产生的
            STAT.observ_filter += 1
            return True

        # 追踪不匹配：侧信道信号在屏障版本中不同，说明有推测行为差异，保留
        return False


# ==================================================================================================
# Non-standard Fuzzers（非标准模糊测试器）
# ==================================================================================================
class ARM64ArchitecturalFuzzer(ArchitecturalFuzzer):
    """
    ARM64架构特定的架构级模糊测试器。
    目前无需ARM64特定的实现，直接继承通用ArchitecturalFuzzer。

    ARM64-specific implementation of the ArchitecturalFuzzer.
    """
    # No ARM64-specific implementation is needed


class ARM64ArchDiffFuzzer(ArchDiffFuzzer):
    """
    ARM64架构特定的架构差异模糊测试器。
    检测不同微架构实现之间的行为差异。

    ARM64-specific implementation of the ArchDiffFuzzer.
    """

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        """
        创建带内存屏障的测试用例版本。
        调用辅助函数_create_fenced_test_case实现。

        参数:
            original_asm: 原始汇编文件路径
            fenced_asm: 带屏障的汇编文件输出路径
            asm_parser: 汇编解析器
            generator: 代码生成器
            elf_parser: ELF解析器
        返回值:
            带屏障的测试用例程序对象
        """
        return _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)


# ==================================================================================================
# Helper functions（辅助函数）
# ==================================================================================================
@contextmanager
def _quick_and_dirty_mode(executor: Executor) -> Generator[None, None, None]:
    """
    快速模式上下文管理器，用于临时启用快速执行模式。
    在with语句块内禁用部分检查以加速执行，退出语句块后恢复正常模式。
    这在过滤阶段特别有用，因为过滤只需快速判断是否需要保留测试用例。

    参数:
        executor: 执行器对象，用于设置快速模式状态

    Context manager that enables us to use quick and dirty mode in the form of `with` statement
    """
    try:
        executor.set_quick_and_dirty(True)  # 启用快速模式
        yield
    finally:
        executor.set_quick_and_dirty(False)  # 恢复正常模式


def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                             generator: CodeGenerator, elf_parser: ELFParser) -> TestCaseProgram:
    """
    创建带内存屏障的测试用例版本。
    遍历原始汇编文件的每一行，在每条非特殊指令（非注释、非伪指令、
    非标签、非宏定义）后面插入ARM64全系统数据同步屏障（dsb SY）和
    指令同步屏障（isb），以消除推测执行的影响。

    参数:
        original_asm: 原始汇编文件路径
        fenced_asm: 带屏障的汇编文件输出路径
        asm_parser: 汇编解析器，用于解析生成的汇编代码
        generator: 代码生成器，用于代码生成流程
        elf_parser: ELF解析器，用于解析编译后的二进制
    返回值:
        带屏障的测试用例程序对象

    Add fences to all instructions in the test case
    """
    with open(original_asm, 'r') as f:
        with open(fenced_asm, 'w') as fenced_file:
            for line in f:
                fenced_file.write(line)
                line = line.strip().lower()
                # 跳过注释(//)、伪指令(.)、标签(b开头)和宏定义行
                if line and line[0] not in ["/", ".", "b"] \
                        and "macro" not in line:
                    # 在每条指令后插入ARM64全系统屏障指令
                    fenced_file.write('dsb SY\n isb\n')
    # 解析带屏障的汇编文件为测试用例程序对象
    fenced_test_case = asm_parser.parse_file(fenced_asm, generator, elf_parser)
    return fenced_test_case

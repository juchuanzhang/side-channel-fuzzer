"""
文件: x86架构模糊测试器(Fuzzer)的实现
File: x86 implementation of the test case generator

本模块实现了x86架构特有的模糊测试器，包括：
- X86Fuzzer: 标准模糊测试模式，带有推测过滤器(Speculation Filter)和观测过滤器(Observation Filter)
- X86ArchitecturalFuzzer: 架构级模糊测试器
- X86ArchDiffFuzzer: 架构差异模糊测试器（对比有/无fence的执行差异）
- 辅助函数：指令列表检查、fence测试用例创建、快速执行模式管理

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import List, Generator, TYPE_CHECKING
from contextlib import contextmanager
import tempfile
import os

from rvzr.fuzzer import Fuzzer, ArchitecturalFuzzer, ArchDiffFuzzer, FuzzingMode
from rvzr.traces import HTrace
from rvzr.executor import Executor
from rvzr.tc_components.test_case_data import InputData
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.logs import warning
from rvzr.stats import FuzzingStats
from rvzr.config import CONF
from .config import _buggy_instructions
from .executor import X86IntelExecutor

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.asm_parser import AsmParser
    from rvzr.elf_parser import ELFParser
    from rvzr.code_generator import CodeGenerator

STAT = FuzzingStats()


# ==================================================================================================
# x86特定模糊测试器实现
# ==================================================================================================
class X86Fuzzer(Fuzzer):
    """
    x86架构的标准模糊测试器实现。

    扩展了通用Fuzzer类，增加以下功能：
    1. 检查指令集是否兼容所需的异常类型
    2. 通过推测过滤器(Speculation Filter)过滤无推测执行的测试用例
    3. 通过观测过滤器(Observation Filter)过滤无可观测侧信道泄漏的测试用例

    推测过滤器：若硬件追踪显示无分支预测错误（misprediction），则跳过该测试用例，
    因为无推测执行的情况下不太可能产生侧信道漏洞。

    观测过滤器：创建一个带lfence的测试用例版本，若其硬件追踪与原始版本相同，
    则说明原始测试用例无可观测的缓存驱逐行为，跳过该测试用例。
    """

    executor: X86IntelExecutor

    # ----------------------------------------------------------------------------------------------
    # 公共接口
    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        """
        启动模糊测试。

        在开始前先检查指令集是否包含所需的异常相关指令。

        :param num_test_cases: 要生成的测试用例数量
        :param num_inputs: 每个测试用例的输入数量
        :param timeout: 超时时间（秒）
        :param nonstop: 是否在发现违规后继续测试
        :param save_violations: 是否保存违规测试用例
        :param type_: 模糊测试模式
        :return: 是否成功完成测试
        """
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)

    # ----------------------------------------------------------------------------------------------
    # 私有方法
    def _filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        多阶段过滤算法，逐步过滤掉无价值的测试用例。

        过滤流程：
        1. 若两个过滤器都禁用，直接返回（不过滤）
        2. 在快速模式下执行测试用例，收集硬件追踪
        3. 运行推测过滤器：检查是否有分支预测错误
        4. 运行观测过滤器：检查是否有可观测的缓存驱逐

        :param test_case: 目标测试用例
        :param inputs: 待测试的输入列表
        :return: True表示应过滤掉该测试用例；False表示应保留
        """
        # 若所有过滤器都禁用则直接退出
        if not CONF.enable_speculation_filter and not CONF.enable_observation_filter:
            return False

        # 每个输入的重复次数
        reps = CONF.executor_filtering_repetitions

        with _quick_and_dirty_mode(self.executor):  # 通过禁用某些功能加速执行
            # 收集测试用例的硬件追踪
            try:
                self.executor.load_test_case(test_case)
                org_htraces = self.executor.trace_test_case(inputs, reps)
            except IOError:
                return True

            # 运行推测过滤器
            if self._speculation_filter(org_htraces):
                return True

            # 运行观测过滤器
            if self._observation_filter(test_case, inputs, reps, org_htraces):
                return True

            return False

    @staticmethod
    def _speculation_filter(htraces: List[HTrace]) -> bool:
        """
        推测过滤器：检查硬件追踪中是否存在分支预测错误。

        若所有追踪中均无预测错误（PFC值无差异），则该测试用例
        不太可能产生推测执行相关的侧信道漏洞，应被过滤掉。

        判断逻辑：
        - pfc_values[0]为0表示错误，不进行过滤
        - pfc_values[0] > pfc_values[1] 或 pfc_values[2] > 0 表示有预测错误，保留

        :param htraces: 执行测试用例时收集的HTrace对象列表
        :return: True表示应过滤掉；False表示有推测执行行为，应保留
        """
        if not CONF.enable_speculation_filter:
            return False

        for _, htrace in enumerate(htraces):
            pfc_values = htrace.get_max_pfc()
            if pfc_values[0] == 0:  # 0表示错误；无法进行过滤
                return False
            if pfc_values[0] > pfc_values[1] or pfc_values[2] > 0:
                return False
        STAT.spec_filter += 1
        return True

    def _observation_filter(self, test_case: TestCaseProgram, inputs: List[InputData], reps: int,
                            org_htraces: List[HTrace]) -> bool:
        """
        观测过滤器：检查硬件追踪中是否包含推测性的缓存驱逐。

        创建一个带lfence屏障的测试用例版本，收集其硬件追踪。
        若带fence版本的追踪与原始版本相同，说明原始测试用例中
        没有可观测的推测性缓存驱逐行为，应被过滤掉。

        :param test_case: 目标测试用例
        :param inputs: 待测试的输入列表
        :param reps: 每个输入的重复次数
        :param org_htraces: 原始测试用例的HTrace列表
        :return: True表示应过滤掉；False表示有可观测的泄漏行为，应保留
        """
        if not CONF.enable_observation_filter:
            return False

        # 创建带lfence的测试用例临时文件
        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_name = fenced.name
        fenced_test_case = _create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                    self.asm_parser, self.code_gen, self.elf_parser)
        try:
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, reps)
        except IOError:
            return True  # 出现错误时跳过该测试用例
        os.remove(fenced.name)

        # 比较带fence版本与原始版本的硬件追踪
        traces_match = True
        for i, _ in enumerate(inputs):
            if not self.analyser.htraces_are_equivalent(fenced_htraces[i], org_htraces[i]):
                traces_match = False
                break
        # 若追踪相同，说明无可观测泄漏，应过滤掉
        if traces_match:
            STAT.observ_filter += 1
            return True

        return False

    def _adjust_config(self, existing_test_case: str) -> None:
        """
        根据现有测试用例调整配置，并更新指令列表（移除触发未处理异常的指令）。

        :param existing_test_case: 现有测试用例的路径
        """
        super()._adjust_config(existing_test_case)
        _update_instruction_list()


# ==================================================================================================
# 非标准模糊测试器
# ==================================================================================================
class X86ArchitecturalFuzzer(ArchitecturalFuzzer):
    """
    x86特定的架构级模糊测试器实现。

    与通用ArchitecturalFuzzer基本相同，但增加了对指令集的额外检查，
    确保指令集包含所需的异常相关指令。
    """

    def _adjust_config(self, existing_test_case: str) -> None:
        """
        调整配置并更新指令列表。

        :param existing_test_case: 现有测试用例的路径
        """
        super()._adjust_config(existing_test_case)
        _update_instruction_list()

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        """
        启动架构级模糊测试，先检查指令集兼容性。

        :param num_test_cases: 测试用例数量
        :param num_inputs: 输入数量
        :param timeout: 超时时间
        :param nonstop: 是否持续测试
        :param save_violations: 是否保存违规
        :param type_: 测试模式
        :return: 是否成功完成
        """
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)


class X86ArchDiffFuzzer(ArchDiffFuzzer):
    """
    架构差异模糊测试器。

    比较测试用例在有/无fence屏障情况下的执行差异。
    若结果不同，则报告一个违规(violation)。
    用于检测由推测执行引起的架构级错误。
    """

    executor: X86IntelExecutor

    def _adjust_config(self, existing_test_case: str) -> None:
        """
        调整配置并更新指令列表。

        :param existing_test_case: 现有测试用例的路径
        """
        super()._adjust_config(existing_test_case)
        _update_instruction_list()

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        """
        启动架构差异模糊测试，先检查指令集兼容性。

        :param num_test_cases: 测试用例数量
        :param num_inputs: 输入数量
        :param timeout: 超时时间
        :param nonstop: 是否持续测试
        :param save_violations: 是否保存违规
        :param type_: 测试模式
        :return: 是否成功完成
        """
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        """
        创建带lfence屏障的测试用例版本。

        :param original_asm: 原始汇编文件路径
        :param fenced_asm: 带fence的汇编文件输出路径
        :param asm_parser: 汇编解析器
        :param generator: 代码生成器
        :param elf_parser: ELF解析器
        :return: 带fence的测试用例程序对象
        """
        return _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)


# ==================================================================================================
# 辅助函数
# ==================================================================================================
def _update_instruction_list() -> None:
    """
    移除触发未处理异常的指令。

    根据配置中的异常白名单(faults_allowlist)，将触发未允许异常的指令
    添加到指令阻止列表(instruction_blocklist)中：
    - 未允许opcode-undefined异常时，移除ud/ud2
    - 未允许breakpoint异常时，移除int3
    - 未允许debug-register异常时，移除int1

    此功能作为模块级函数实现，以避免X86Fuzzer和X86ArchitecturalFuzzer之间的代码重复。
    """
    if 'opcode-undefined' not in CONF.faults_allowlist:
        CONF.instruction_blocklist.extend(["ud", "ud2"])
    if 'breakpoint' not in CONF.faults_allowlist:
        CONF.instruction_blocklist.extend(["int3"])
    if 'debug-register' not in CONF.faults_allowlist:
        CONF.instruction_blocklist.extend(["int1"])


def _check_instruction_list(instruction_set: InstructionSet) -> None:
    """
    检查指令集是否包含所需异常类型对应的指令。

    若配置中启用了某异常类型但指令集中缺少对应指令，
    则发出警告。同时检查已知会导致误报的问题指令。

    :param instruction_set: 当前指令集对象
    """
    all_instruction_names = {i.name for i in instruction_set.instructions}
    # 检查除法异常相关指令
    if 'div-by-zero' in CONF.faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            warning("fuzzer", "div-by-zero enabled, but DIV/IDIV instructions are missing")
    if 'div-overflow' in CONF.faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            warning("fuzzer", "div-overflow enabled, but DIV/IDIV instructions are missing")
    # 检查断点异常相关指令
    if 'breakpoint' in CONF.faults_allowlist:
        if 'int3' not in all_instruction_names:
            warning("fuzzer", "breakpoint enabled, but INT3 instruction is missing")
    # 检查调试寄存器异常相关指令
    if 'debug-register' in CONF.faults_allowlist:
        if 'int1' not in all_instruction_names:
            warning("fuzzer", "debug-register enabled, but INT1 instruction is missing")

    # 若指令集中包含已知问题指令，发出警告
    for inst_name in _buggy_instructions:
        if inst_name in all_instruction_names and CONF.is_generation_enabled():
            warning(
                "fuzzer", f"Instruction {inst_name} is known to cause false positives\n"
                "Consider adding it to instruction_blocklist")


@contextmanager
def _quick_and_dirty_mode(executor: Executor) -> Generator[None, None, None]:
    """
    快速执行模式的上下文管理器。

    在with语句块内启用快速执行模式（禁用部分执行器功能以加速执行），
    退出时恢复正常模式。

    :param executor: 执行器对象
    :yield: 无返回值
    """
    try:
        executor.set_quick_and_dirty(True)
        yield
    finally:
        executor.set_quick_and_dirty(False)


def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                             generator: CodeGenerator, elf_parser: ELFParser) -> TestCaseProgram:
    """
    在测试用例的所有指令后添加lfence屏障，创建带fence版本。

    逐行读取原始汇编文件，在每条非特殊指令后插入lfence指令。
    跳过以下情况不插入fence：
    - 空行和注释行
    - 跳转指令（j*和loop，因为fence会破坏跳转逻辑）
    - 汇编器指令（section, syntax, function, macro）
    - test_case_exit标记之后的指令
    - landing pad之前的指令

    :param original_asm: 原始汇编文件路径
    :param fenced_asm: 带fence的汇编文件输出路径
    :param asm_parser: 汇编解析器
    :param generator: 代码生成器
    :param elf_parser: ELF解析器
    :return: 带fence的测试用例程序对象
    """
    with open(original_asm, 'r') as f:
        with open(fenced_asm, 'w') as fenced_file:
            lines = f.readlines()
            n_lines = len(lines)

            for i, line in enumerate(lines):
                fenced_file.write(line)
                line = line.strip().lower()

                # 空行和注释行不需要添加fence
                if not line or line[0] == "#":
                    continue

                # 跳转指令后添加fence会破坏汇编解析器的假设，这是一个解析器的缺陷，
                # 此检查是临时解决方案
                if line[0] == "j" or "loop" in line:
                    continue

                # 汇编器指令后不添加fence
                if "section" in line \
                   or "syntax" in line \
                   or "function" in line \
                   or "macro" in line:
                    continue

                # test_case_exit之后不再添加fence
                if "test_case_exit" in line:
                    break

                # 在landing pad之前添加fence会干扰解析算法，
                # 而且也不会有任何有意义的效果，所以跳过
                if i < n_lines and "landing" in lines[i + 1]:
                    continue

                # 在所有其他指令后添加lfence屏障
                fenced_file.write('lfence\n')

    fenced_test_case = asm_parser.parse_file(fenced_asm, generator, elf_parser)
    return fenced_test_case

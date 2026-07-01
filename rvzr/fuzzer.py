"""
文件：模糊测试编排（Fuzzing Orchestration）
核心模糊测试逻辑，包含测试用例生成、输入准备、迹收集、违例检测的完整流程。
实现多阶段检测算法：先进行快速检测，再逐步过滤各类假阳性。

主要类：
- _RoundState: 一轮模糊测试的配置状态管理
- _RoundManager: 一轮模糊测试的执行管理器
- Fuzzer: 模糊测试主类，编排所有模块的调用
- ArchitecturalFuzzer: 架构不一致检测的简化模糊器
- ArchDiffFuzzer: 对比有无推测屏障执行的模糊器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import shutil
import os
import tempfile
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List, Callable, Literal, Final
from typing_extensions import assert_never
import numpy as np

from . import factory

from .traces import HTrace, CTrace, Violation, RawHTraceSample, ArrayOfSamples, CTraceEntry, \
    TraceBundle
from .tc_components.actor import ActorMode
from .tc_components.test_case_code import TestCaseProgram
from .tc_components.test_case_data import InputData
from .isa_spec import InstructionSet
from .analyser import Analyser
from .config import CONF
from .stats import FuzzingStats
from .logs import FuzzLogger, warning, update_logging_after_config_change

if TYPE_CHECKING:
    from .code_generator import CodeGenerator
    from .data_generator import DataGenerator
    from .asm_parser import AsmParser
    from .elf_parser import ELFParser
    from .model import Model
    from .executor import Executor

FuzzingMode = Literal["random", "template", "asm"]  # 模糊测试模式：随机生成、模板生成、汇编文件
RoundStage = Literal["fast", "nesting", "taint_mistake", "priming", "noise", "arch_mismatch",
                     "priming_large"]  # 模糊测试轮次阶段类型

STAT = FuzzingStats()


# ==================================================================================================
# 私有类：轮次状态管理
# ==================================================================================================
class _RoundState:
    """
    一轮模糊测试的配置状态集合。
    跟踪Revizor各模块在模糊测试轮次中使用的配置选项，
    这些配置随着轮次的推进而动态更新。
    """
    executor_n_reps: int
    """ 执行器使用的测量重复次数 """

    _start_nesting: int
    max_nesting: int
    model_nesting: int
    """ 模型使用的推测嵌套层级 """

    enable_fast_contract_tracing: bool
    """ 是否在_boost_inputs函数中使用快速boosting特性 """

    enable_priming: bool
    """ 是否使用模糊测试轮次的priming阶段 """

    record_stats: bool = True
    """ 是否在分析器中记录统计数据 """

    update_ignore_list: bool = False
    """ 是否更新执行器的忽略列表 """

    reuse_boosts: bool = False
    """ 是否复用上一阶段收集到的boosted输入 """

    reuse_ctraces: bool = False
    """ 是否复用上一阶段收集到的合约迹 """

    extend_htraces: bool = False
    """ 若为True，新收集的硬件迹将追加到已有的硬件迹中而非替换 """

    is_initial: bool = True
    """ 是否为模糊测试过程的第一个轮次 """

    def __init__(self, is_speculative: bool) -> None:
        """
        初始化轮次状态。
        :param is_speculative: 是否为推测执行模式（影响嵌套层级的初始值）
        """
        self.executor_n_reps = CONF.executor_sample_sizes[0]  # 使用配置中的第一个样本大小

        # 推测模式下使用配置的最小/最大嵌套层级；非推测模式下嵌套层级固定为1
        self._start_nesting = CONF.model_min_nesting if is_speculative else 1
        self.max_nesting = CONF.model_max_nesting if is_speculative else 1
        assert self._start_nesting <= self.max_nesting
        self.model_nesting = self._start_nesting

        self.enable_fast_contract_tracing = CONF.enable_fast_path_model
        self.enable_priming = CONF.enable_priming


class _RoundManager:
    """
    一轮模糊测试的执行管理器。
    负责维护轮次中的配置一致性，以及将测试用例分发给模型和执行器。
    
    管理器跟踪原始输入、boosted输入、硬件迹、合约迹和违例等核心数据，
    并协调各阶段的执行顺序和数据传递。
    """
    test_case: TestCaseProgram           # 当前测试用例
    org_inputs: List[InputData]          # 原始输入列表
    boosted_inputs: List[InputData]      # 经污点boosting扩展后的输入列表

    htraces: List[HTrace]                # 收集到的硬件迹列表
    _reference_htraces: List[HTrace]     # 快速路径的参考硬件迹（用于对比）

    ctraces: List[CTrace]                # 收集到的合约迹列表
    _non_boosted_ctraces: List[CTrace]   # 未经boosting的合约迹（用于快速路径复用）

    violations: List[Violation]          # 检测到的合约违例列表
    arch_violations: List[Violation]     # 检测到的架构不一致违例列表

    fuzzer: Final[Fuzzer]                # 所属的模糊器实例
    conf: Final[_RoundState]             # 当前轮次的配置状态

    def __init__(self, fuzzer: Fuzzer, test_case: TestCaseProgram, inputs: List[InputData]) -> None:
        """
        初始化轮次管理器，将测试用例加载到模型和执行器。
        :param fuzzer: 所属的模糊器实例
        :param test_case: 本轮要测试的测试用例
        :param inputs: 本轮使用的原始输入列表
        """
        self.test_case = test_case
        self.org_inputs = inputs
        self.boosted_inputs = []

        self.htraces = []
        self.ctraces = []
        self.violations = []
        self.arch_violations = []

        self.fuzzer = fuzzer
        self.conf = _RoundState(fuzzer.model.is_speculative)

        # 将测试用例同时加载到模型和执行器
        self.fuzzer.model.load_test_case(self.test_case)
        self.fuzzer.executor.load_test_case(self.test_case)

    def execute_stage(self, stage: RoundStage) -> None:
        """
        执行模糊测试轮次中的指定阶段。
        每个阶段有不同的配置调整策略和检测逻辑。
        
        :param stage: 要执行的阶段类型
        """
        # pylint: disable=too-many-return-statements
        # pylint: disable=too-many-branches
        # 注：这是一个选择器函数，大量return语句是合理的

        if stage == "fast":
            # 快速路径：仅在第一轮执行，使用最小嵌套层级和最少重复次数
            assert self.conf.is_initial, "Fast path can be run only in the first round"
            self._normal_stage()
            self.conf.is_initial = False  # 确保快速路径仅执行一次
            self.conf.record_stats = False  # 仅在快速路径中记录统计
            self._reference_htraces = self.htraces  # 使用快速路径迹作为参考
            return

        if stage == "nesting":
            # 嵌套层级提升阶段：将模型嵌套层级提升到最大值，重新检测
            if self.conf.model_nesting != self.conf.max_nesting:
                self.conf.model_nesting = self.conf.max_nesting
                self._normal_stage()

            # 此阶段后，boosted输入列表已稳定，可以开始复用它们
            # 同时可以开始忽略无违例的输入
            self.conf.reuse_boosts = True
            self.conf.update_ignore_list = True
            return

        if stage == "taint_mistake":
            # 污点追踪检查阶段：仅在启用快速合约追踪时才需要此阶段
            if self.conf.enable_fast_contract_tracing:  # 仅在快速追踪之后适用

                self.conf.enable_fast_contract_tracing = False
                self._normal_stage()

            # 在nesting和taint_mistake阶段之后，合约迹已可信，可以开始复用
            assert self.conf.model_nesting == self.conf.max_nesting, "Invalid stage order"
            self.conf.reuse_ctraces = True
            return

        if stage == "priming":
            # Priming检查阶段：通过交换输入来排除跨输入干扰导致的假阳性
            if not self.conf.enable_priming:
                return
            self._priming_check()
            return

        if stage == "noise":
            # 噪声过滤阶段：增大样本量以减少噪声对结果的影响
            if len(CONF.executor_sample_sizes) == 1:
                return  # 配置中只有一个样本大小，无法增大
            self.conf.extend_htraces = True  # 新迹追加到已有迹而非替换

            # 逐级增大样本量，每级检查违例是否消失
            for sample_size in CONF.executor_sample_sizes[1:]:
                self.fuzzer.log.sample_size_increase(sample_size)
                self.conf.executor_n_reps = sample_size - len(self.htraces[0])
                self._normal_stage()
                if not self.violations:
                    return  # 违例消失，说明是噪声导致的假阳性
            return

        if stage == "priming_large":
            # 大样本priming阶段：使用最大样本量重新执行priming检查
            if not self.conf.enable_priming or len(CONF.executor_sample_sizes) == 1:
                return
            self.conf.executor_n_reps = CONF.executor_sample_sizes[-1]
            self._priming_check()
            return

        if stage == "arch_mismatch":
            # 架构不一致检查阶段：检测模型与执行器之间的架构不一致
            self._check_for_architectural_mismatch()
            return

    def finalize(self) -> None:
        """完成模糊测试轮次，输出调试信息"""
        self.fuzzer.log.dbg_dump_traces(self.boosted_inputs, self.htraces, self._reference_htraces,
                                        self.ctraces)

    def _normal_stage(self) -> None:
        """
        执行一轮标准检测流程：
        1. 对输入进行污点boosting
        2. 收集合约迹
        3. 收集硬件迹
        4. 检查违例
        5. 更新忽略列表
        """
        self._boost_inputs()
        self._collect_ctraces()
        try:
            self._collect_htraces()
        except IOError:
            self.violations = []
            return
        if len(self.org_inputs) > 0:
            self._check_violations()
            if not self.violations:
                return
            self._update_ignore_list()

    def _boost_inputs(self) -> None:
        """
        对原始输入进行污点追踪和boosting扩展。
        使用模型的污点追踪功能，基于合约迹中的依赖关系，
        生成与原始输入具有相同合约迹但不同数据值的boosted输入。
        
        Boosting的目的是：在等价类内提供多样化的输入，
        以检测相同合约迹是否产生不同的硬件迹（即合约违例）。
        """
        # 若每个类只需1个输入，无需污点追踪和boosting
        if CONF.inputs_per_class == 1:
            self._non_boosted_ctraces = \
                self.fuzzer.model.trace_test_case(self.org_inputs, self.conf.model_nesting)
            self.boosted_inputs = self.org_inputs
            return

        # 正常情况：先收集污点信息，再基于污点生成boosted输入
        self._non_boosted_ctraces, taints = \
            self.fuzzer.model.trace_test_case_with_taints(self.org_inputs, self.conf.model_nesting)
        self.boosted_inputs = self.fuzzer.data_gen.generate_boosted(self.org_inputs, taints,
                                                                    CONF.inputs_per_class)

    def _collect_ctraces(self) -> None:
        """
        为boosted输入收集合约迹。
        根据配置选择不同的收集策略：
        - 复用已有合约迹（reuse模式）
        - 快速模式：同一类内的所有boosted输入共用一条合约迹
        - 完整模式：为每个boosted输入单独计算合约迹
        """
        # 合约迹已收集完毕，直接复用
        if self.conf.reuse_ctraces:
            assert len(self.ctraces) == len(self.boosted_inputs), "No ctraces to reuse"
            return

        # 快速模式：同一类的所有成员共享同一合约迹
        # 原理：同一类内的boosted输入应产生相同的合约迹，因此复用原始合约迹即可
        if self.conf.enable_fast_contract_tracing:
            self.ctraces = self._non_boosted_ctraces * CONF.inputs_per_class
            return

        # 完整模式：为每个boosted输入单独计算合约迹
        self.ctraces = \
            self.fuzzer.model.trace_test_case(self.boosted_inputs, self.conf.model_nesting)

    def _collect_htraces(self) -> None:
        """
        为boosted输入收集硬件迹。
        根据配置选择替换或追加模式：
        - 替换模式：新的硬件迹完全替换旧的
        - 追加模式：新的硬件迹与旧的合并（用于噪声过滤阶段）
        """
        new_htraces = self.fuzzer.executor.trace_test_case(self.boosted_inputs,
                                                           self.conf.executor_n_reps)
        if not self.conf.extend_htraces:
            self.htraces = new_htraces
            return

        # 追加模式：将新硬件迹与已有硬件迹合并
        assert len(self.htraces) == len(new_htraces), "Number of htraces does not match"
        for i, htrace in enumerate(new_htraces):
            self.htraces[i] = htrace.merge(self.htraces[i])

    def _check_violations(self) -> None:
        """
        检查收集到的迹是否存在合约违例。
        调用分析器的filter_violations方法，基于等价类分析检测违例。
        """
        assert self.ctraces and len(self.ctraces) == len(self.htraces), \
            f"Invalid number of c- or htraces: {len(self.ctraces)} vs {len(self.htraces)}"
        self.violations = self.fuzzer.analyser.filter_violations(
            ctraces=self.ctraces,
            htraces=self.htraces,
            test_case_code=self.test_case,
            inputs=self.boosted_inputs,
            stats_=self.conf.record_stats)

    def _update_ignore_list(self) -> None:
        """
        将所有未产生违例的输入标记为忽略。
        目的：避免测量结果不确定性时引发假阳性的连锁反应。
        当执行器的测量结果不确定时，忽略非违例输入可以防止它们
        在后续阶段中被误判为违例。
        """
        if self.conf.update_ignore_list:
            violating_ids = [m.input_id for v in self.violations for m in v.measurements]
            ignored_input_ids = [
                i for i in range(len(self.boosted_inputs)) if i not in violating_ids
            ]
            self.fuzzer.executor.extend_ignore_list(ignored_input_ids)

    def _priming_check(self) -> None:
        """
        执行Priming检查，用于区分真违例和假阳性。
        
        目标：区分由输入数据差异导致的违例（真违例）和由输入间
        微架构状态干扰导致的违例（假阳性）。
        
        方法：交换产生违例的输入位置，检查违例是否仍然存在。
        若违例消失则为假阳性，若违例仍然存在则为真违例。
        
        示例：假设违例由输入序列 (i1, i2, i1', i2') 产生，
        其中 i2 和 i2' 产生相同的合约迹但不同的硬件迹。
        违例可能由 i2 vs i2' 的数据差异（真违例）引起，
        也可能由 i1 vs i1' 的微架构状态差异（假阳性）引起。
        
        为区分两者，priming检查创建两个新序列：
        (i1, i2', i1', i2') 和 (i1, i2, i1', i2)。
        
        若第一个序列中 i2' 的迹与原始序列中 i2' 的迹一致，且
        第二个序列中 i2 的迹与原始序列中 i2 的迹一致，
        则违例是真违例。
        """

        while self.violations:
            self.fuzzer.log.priming(len(self.violations))

            violation: Violation = self.violations.pop()
            n_reps = violation.measurements[0].htrace.sample_size()
            measurements_to_test = [hc[0] for hc in violation.get_hw_classes()]

            for current_measurement in measurements_to_test:
                current_input_id = current_measurement.input_id
                htrace_to_reproduce = current_measurement.htrace
                other_measurements = [m for m in measurements_to_test if m != current_measurement]

                # 产生不同硬件迹的输入ID列表
                input_ids_to_test: List[int] = [m.input_id for m in other_measurements]

                # 遍历违例中的输入，将它们与current_input_id交换
                for input_id in input_ids_to_test:
                    self.fuzzer.log.dbg_priming_progress(input_id, current_input_id)

                    # 将被测试的输入插入到新位置（交换输入）
                    primer = list(self.boosted_inputs)
                    primer[current_input_id] = self.boosted_inputs[input_id]

                    # 尝试新输入序列，检查观察到的迹是否与原始迹等价
                    htraces: List[HTrace] = self.fuzzer.executor.trace_test_case(primer, n_reps)
                    new_htrace = htraces[current_input_id]

                    # 迹收集错误时快速退出
                    if new_htrace.is_empty() or new_htrace.is_corrupted_or_ignored():
                        warning("fuzzer", "Tracing error during priming. "
                                "Skipping this test case")
                        self.violations = []
                        return

                    # 新迹与原始迹等价 -> 交换后违例消失，可能是假阳性
                    if self.fuzzer.analyser.htraces_are_equivalent(new_htrace, htrace_to_reproduce):
                        continue

                    self.fuzzer.log.dbg_priming_fail(input_id, current_input_id,
                                                     htrace_to_reproduce, new_htrace)

                    # 无法复现 -> 这是真违例
                    self.violations = [violation]
                    return

            # 所有迹都能复现 -> 这是假阳性
            self.violations = []
            return

    def _check_for_architectural_mismatch(self) -> None:
        """
        检查测试用例是否导致模型与执行器之间的架构不一致。
        例如，模型可能因模拟器bug而错误地模拟指令执行，导致架构状态不一致。
        
        方法：比较模型和执行器在相同输入下产生的架构级（寄存器值）迹，
        若不一致则报告架构违例。
        """
        hardware_regs: List[List[int]] = []  # 执行器收集的寄存器值
        model_regs: List[List[int]] = []     # 模型计算出的寄存器值

        self.fuzzer.arch_model.load_test_case(self.test_case)
        self.fuzzer.arch_executor.load_test_case(self.test_case)

        # 此函数可能独立调用（见ArchitecturalFuzzer），
        # 此时boosted_inputs尚未设置，使用原始输入代替
        if not self.boosted_inputs:
            self.boosted_inputs = self.org_inputs

        # 收集架构级硬件迹（寄存器值）
        try:
            htraces = self.fuzzer.arch_executor.trace_test_case(self.boosted_inputs, n_reps=1)
        except IOError:
            warning("fuzz", "Error during architectural mismatch check. Skipping this test case")
            self.arch_violations = []  # 迹收集出错时跳过该测试用例
            return
        for htrace_obj in htraces:
            raw_traces = htrace_obj.get_raw_readings()
            assert len(raw_traces) == 1, "Expected only one hardware trace"
            raw_trace_int = [int(v) for v in raw_traces[0]]
            hardware_regs.append(raw_trace_int)

        # 收集架构级模型迹（寄存器值，取前6个值并模2^64）
        ctraces = self.fuzzer.arch_model.trace_test_case(self.boosted_inputs,
                                                         CONF.model_max_nesting)
        for ctrace in ctraces:
            model_regs.append([v % (2**64) for v in ctrace.get_untyped()[:6]])

        # 调试输出
        self.fuzzer.log.dbg_dump_architectural_traces(hardware_regs, model_regs)

        # 检查违例：逐个输入对比模型和硬件的寄存器值
        # 注：此处直接检查迹的相等性，无需调用分析器
        for i, input_ in enumerate(self.boosted_inputs):
            if model_regs[i] == hardware_regs[i]:
                continue
            measurement = TraceBundle(i, input_, ctraces[i], htraces[i])
            violation = Violation([measurement], self.boosted_inputs, self.test_case)
            violation.set_trivial_hw_classes()
            self.arch_violations = [violation]
            return
        return


# ==================================================================================================
# 公共类：模糊器
# ==================================================================================================
class Fuzzer:
    """
    模糊测试主类：编排整个模糊测试流程。
    创建所有必要模块，并按正确顺序调用它们、传递数据。
    
    主要接口是 start 方法，实现多阶段违例检测算法。
    start方法实现了核心模糊测试循环：生成测试用例、准备输入、收集迹、检查违例。
    
    该类还提供一组独立接口用于：
    - 生成测试用例（standalone_generate）
    - 分析迹文件（standalone_analyse）
    - 过滤无用测试用例（standalone_filter）
    """

    model: Model               # 模型（合约迹生成器）
    executor: Executor          # 执行器（硬件迹收集器）
    asm_parser: AsmParser       # 汇编解析器
    code_gen: CodeGenerator     # 代码生成器
    data_gen: DataGenerator     # 数据生成器
    analyser: Analyser          # 分析器（违例检测器）
    elf_parser: ELFParser       # ELF解析器

    arch_executor: Executor     # 架构不一致检查模式的执行器
    arch_model: Model           # 架构不一致检查模式的模型
    log: FuzzLogger             # 模糊测试日志记录器

    _isa_spec: InstructionSet   # 指令集规格
    _existing_test_case: str    # 已有测试用例路径（用于asm模式）
    _work_dir: str              # 工作目录
    _input_paths: List[str]     # 输入文件路径列表
    _generation_function: Callable[[str], TestCaseProgram]  # 测试用例生成函数

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 input_paths: Optional[List[str]] = None):
        """
        初始化模糊器，创建所有核心模块。
        :param instruction_set_spec: 指令集规格文件路径
        :param work_dir: 工作目录路径
        :param existing_test_case: 已有测试用例路径（用于asm模式）
        :param input_paths: 输入文件路径列表（若提供则使用而非生成）
        """
        self._adjust_config(existing_test_case)

        self._existing_test_case = existing_test_case
        self._input_paths = input_paths if input_paths is not None else []
        self._work_dir = work_dir

        # 创建所有核心模块
        self.log = FuzzLogger()
        self._isa_spec = InstructionSet(instruction_set_spec, CONF.instruction_categories)
        self.code_gen = factory.get_program_generator(CONF.program_generator_seed, self._isa_spec)
        self.data_gen = factory.get_data_generator(CONF.data_generator_seed)
        self.executor = factory.get_executor()
        self.model = factory.get_model(self.executor.read_base_addresses())
        self.analyser = factory.get_analyser()
        self.asm_parser = factory.get_asm_parser(self._isa_spec)
        self.elf_parser = factory.get_elf_parser()

        # 创建架构不一致检查的专用执行器和模型
        self.arch_executor = factory.get_executor(enable_mismatch_check_mode=True)
        self.arch_model = factory.get_model(
            self.arch_executor.read_base_addresses(), enable_mismatch_check_mode=True)

    # ==============================================================================================
    # 模糊测试接口
    # ==============================================================================================
    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        """
        启动模糊测试流程。
        
        :param num_test_cases: 要生成的测试用例数量
        :param num_inputs: 每个测试用例的输入数量
        :param timeout: 最大运行时间（秒）
        :param nonstop: 是否在检测到第一个违例后继续运行
        :param save_violations: 是否存储违例产物
        :param type_: 模糊测试模式（random/template/asm）
        :return: 若检测到至少一个违例返回True，否则返回False
        """
        # 打印头部信息
        start_time = datetime.today()
        self.log.start(num_test_cases, start_time)

        # 根据模糊测试模式设置生成函数
        self._set_generation_function(type_)

        # 开始模糊测试循环
        for i in range(num_test_cases):
            self.log.start_round(i)

            # 生成测试用例
            test_case: TestCaseProgram = self._generation_function(self._existing_test_case)
            STAT.test_cases += 1

            # 准备输入
            inputs: List[InputData]
            if self._input_paths:
                inputs = self.data_gen.load(self._input_paths)  # 从文件加载输入
            else:
                inputs = self.data_gen.generate(num_inputs, n_actors=test_case.n_actors())  # 生成输入
            STAT.num_inputs += len(inputs) * CONF.inputs_per_class

            # 检查测试用例是否有效（过滤无用测试用例）
            if self._filter(test_case, inputs):
                continue

            # 执行模糊测试轮次
            violation = self.fuzzing_round(test_case, inputs, [])
            if violation:
                self.log.report_violations(violation)
                self.log.dbg_violation(violation, self.model)
                if save_violations:
                    self._store_violation_artifact(violation, self._work_dir)
                STAT.violations += 1
                if not nonstop:
                    break  # 非持续模式下，检测到一个违例即停止

            # 超时检查
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    self.log.timeout()
                    break

        self.log.finish()
        self.log.report_model_coverage(self.model)
        return STAT.violations > 0

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      starting_ignore_list: List[int]) -> Optional[Violation]:
        """
        执行一轮模糊测试：为给定测试用例和输入收集合约迹和硬件迹，并检查合约违例。
        
        此函数通常作为模糊测试循环的一部分（由.start调用），
        但也可由其他类独立使用。
        
        函数实现多阶段检测方法：第一次测量快速但可能有假阳性，
        后续阶段逐级过滤各类潜在假阳性。具体阶段数量取决于配置。
        
        多阶段流程：
        1. 快速路径（fast）- 最小嵌套和重复次数
        2. 嵌套提升（nesting）- 模型使用最大嵌套层级
        2.1 排除因嵌套不足导致的假阳性
        3. 污点检查（taint_mistake）- 完整收集合约迹
        3.1 排除因污点追踪错误导致的假阳性
        4. Priming检查 - 交换输入排除跨输入干扰
        4.1 排除因输入间微架构干扰导致的假阳性
        5. 噪声过滤（noise）- 增大样本量减少噪声影响
        5.1 排除因测量噪声导致的假阳性
        6. 大样本Priming（priming_large）- 使用最大样本量重新priming
        7. 架构不一致检查（arch_mismatch）- 检测模型bug
        
        :param test_case: 要执行的测试用例
        :param inputs: 待测试的输入列表
        :param starting_ignore_list: 执行器应忽略的输入ID列表
        :return: 第一个检测到的违例，若无违例返回None
        """
        # pylint: disable=too-many-return-statements

        # 初始化轮次管理器并加载测试用例
        round_manager = _RoundManager(self, test_case, inputs)

        # 若提供了忽略列表，在执行器中设置
        if starting_ignore_list:
            self.executor.set_ignore_list(starting_ignore_list)

        # 1. 快速路径：使用最小嵌套和重复次数收集迹
        round_manager.execute_stage("fast")
        if not round_manager.violations:
            STAT.fast_path += 1
            round_manager.finalize()
            return None

        # 2. 慢速路径：逐步检查快速路径中可能的假阳性来源
        self.log.slow_path()

        # 2.1 假阳性可能因模型推测嵌套深度不足。
        #     为排除此类假阳性，使用最大嵌套重新追踪模型。
        #     由于污点依赖合约迹，必须重新boost输入并重新收集硬件迹
        round_manager.execute_stage("nesting")
        if not round_manager.violations:
            STAT.fp_nesting += 1
            round_manager.finalize()
            return None

        # 2.2 假阳性可能因污点追踪不完美（如污点追踪器bug）。
        #     为排除此类假阳性，为所有boosted输入单独收集合约迹，检查违例是否仍存在
        prev_ctraces = list(round_manager.ctraces)
        round_manager.execute_stage("taint_mistake")
        if not round_manager.violations:
            if round_manager.ctraces != prev_ctraces:  # 正常情况下不应发生
                self._report_bug_tainting(round_manager)
            STAT.fp_taint_mistakes += 1
            round_manager.finalize()
            return None

        # 2.3 假阳性可能因输入间干扰。使用priming测试排除：
        #     交换产生违例的输入，检查违例是否仍存在
        round_manager.execute_stage("priming")
        if not round_manager.violations:
            STAT.fp_priming += 1
            round_manager.finalize()
            return None

        # 2.4 假阳性可能因测量噪声。增大样本量以减少噪声影响
        round_manager.execute_stage("noise")
        if not round_manager.violations:
            STAT.fp_large_sample += 1
            return None

        # 2.5 Priming可能因样本量太小而失败（导致不确定性）。
        #     使用最大样本量重新执行priming检查
        round_manager.execute_stage("priming_large")
        if not round_manager.violations:
            STAT.fp_priming += 1
            round_manager.finalize()
            return None

        # 2.6 假阳性可能因模型与执行器之间的架构不一致。
        #     此类情况罕见，因此最后检查。
        #     检查违例是否由架构不一致引起
        round_manager.execute_stage("arch_mismatch")
        if round_manager.arch_violations:
            self._report_bug_arch(round_manager)
            round_manager.finalize()
            return None

        # 违例通过了所有检查，报告为真违例
        round_manager.finalize()
        return round_manager.violations[0]

    # ==============================================================================================
    # 独立接口（不需要完整模糊测试循环）
    # ==============================================================================================
    def standalone_filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """检查给定测试用例是否应被过滤掉（即无测试价值）"""
        return self._filter(test_case, inputs)

    def standalone_generate(self, program_generator_seed: int, num_test_cases: int, num_inputs: int,
                            permit_overwrite: bool) -> None:
        """
        独立运行测试用例生成，将生成的测试用例程序和输入存储到工作目录中。
        :param program_generator_seed: 程序生成器种子
        :param num_test_cases: 要生成的测试用例数量
        :param num_inputs: 每个测试用例的输入数量
        :param permit_overwrite: 是否允许覆盖已存在的目录
        """
        self.log.start(0, datetime.today())

        # 准备生成
        STAT.test_cases = num_test_cases
        CONF.program_generator_seed = program_generator_seed
        program_gen = factory.get_program_generator(CONF.program_generator_seed, self._isa_spec)
        data_gen = factory.get_data_generator(CONF.data_generator_seed)

        # 生成测试用例和输入
        Path(self._work_dir).mkdir(exist_ok=True)
        for i in range(0, num_test_cases):
            test_case_dir = self._work_dir + "/tc" + str(i)
            try:
                Path(test_case_dir).mkdir(exist_ok=permit_overwrite)
            except FileExistsError:
                raise FileExistsError(f"Directory '{test_case_dir}' already exists\n"
                                      "       Use --permit-overwrite to overwrite the test case")

            program_gen.create_test_case(test_case_dir + "/" + "program.asm", True)
            inputs = data_gen.generate(num_inputs, n_actors=1)
            for j, input_ in enumerate(inputs):
                input_.save(f"{test_case_dir}/input{j}.bin")

        self.log.finish()

    def standalone_analyse(self, ctrace_file: str, htrace_file: str) -> None:
        """
        检查给定文件中的合约迹和硬件迹是否存在合约违例。
        :param ctrace_file: 合约迹文件路径
        :param htrace_file: 硬件迹文件路径
        """
        if "dbg_violation" in CONF.logging_modes:
            CONF.logging_modes.remove("dbg_violation")
            update_logging_after_config_change()

        self.log.start(0, datetime.today())
        STAT.test_cases = 1

        # 从文件读取迹
        ctraces: List[CTrace] = []
        htraces: List[HTrace] = []

        with open(ctrace_file, 'r') as f:
            for line in f:
                ctraces.append(CTrace([CTraceEntry("val", int(line))]))
        with open(htrace_file, 'r') as f:
            for line in f:
                sample: ArrayOfSamples = np.ndarray(1, dtype=RawHTraceSample)
                sample[0]['trace'] = int(line)
                htraces.append(HTrace(sample))

        assert len(ctraces) == len(htraces), \
            "The number of hardware traces does not match the number of contract traces"

        # 使用虚拟输入和测试用例（仅用于分析）
        dummy_inputs = factory.get_data_generator(0).generate(len(ctraces), n_actors=1)
        dummy_tc = TestCaseProgram("generated.asm", 0)

        # 检查违例
        analyser = factory.get_analyser()
        violations = analyser.filter_violations(ctraces, htraces, dummy_tc, dummy_inputs, True)

        # 输出结果
        if violations:
            self.log.report_violations(violations[0])

        self.log.finish()

    # ==============================================================================================
    # 私有方法
    # ==============================================================================================
    def _set_generation_function(self, type_: FuzzingMode) -> None:
        """
        根据模糊测试模式设置测试用例生成函数。
        :param type_: 模糊测试模式（random/template/asm）
        """
        if type_ == "random":
            # 随机模式：使用代码生成器随机创建测试用例
            self._generation_function = self.code_gen.create_test_case
        elif type_ == "template":
            # 模板模式：基于模板生成测试用例
            self._generation_function = self.code_gen.create_test_case_from_template
        elif type_ == "asm":
            # 汇编模式：从汇编文件解析测试用例
            self._generation_function = self._asm_parser_adapter
        else:
            assert_never(f"Unknown fuzzing mode: {type_}")

    @staticmethod
    def _create_timestamped_dir(path: str) -> str:
        """创建带时间戳的子目录，用于存储违例产物或bug报告"""
        timestamp = datetime.today().strftime('%y%m%d-%H%M%S')
        violation_dir = f"{path}/violation-{timestamp}"
        Path(path).mkdir(exist_ok=True)
        Path(violation_dir).mkdir()
        return violation_dir

    def _store_violation_artifact(self, violation: Violation, path: str) -> None:
        """
        将违例产物存储到指定目录。
        
        违例产物包含：
        - 导致违例的测试用例（program.asm）
        - 导致违例的输入（input_*.bin）
        - 原始配置文件（org-config.yaml）
        - 用于复现违例的配置文件（reproduce.yaml）
        - 用于最小化的配置文件（minimize.yaml）
        - 违例报告（report.txt）

        :param violation: 要存储的违例对象
        :param path: 存储目录路径；若为空则存储到当前目录
        """
        # 若路径为空，存储到当前目录
        if not path:
            path = "."

        # 创建违例产物子目录
        violation_dir = self._create_timestamped_dir(path)

        # 存储违例：测试用例和输入
        test_case = violation.test_case_code
        test_case.save(f"{violation_dir}/program.asm")
        for i, input_ in enumerate(violation.input_sequence):
            input_.save(f"{violation_dir}/input_{i:04}.bin")

        # 存储原始配置文件
        if CONF._config_path:
            shutil.copy2(CONF._config_path, f"{violation_dir}/org-config.yaml")
        else:
            with open(f"{violation_dir}/org-config.yaml", "w") as f:
                f.write("# Original violation used a default config, hence this file is empty\n")

        # 创建用于复现和最小化违例的配置文件
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/reproduce.yaml")
        with open(f"{violation_dir}/reproduce.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"data_generator_seed: {violation.input_sequence[0].seed}\n")
            f.write("inputs_per_class: 1\n")
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/minimize.yaml")
        with open(f"{violation_dir}/minimize.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"data_generator_seed: {violation.input_sequence[0].seed}\n")

        # 将统计数据写入文件前，禁用颜色输出（避免ANSI转义序列污染文件）
        color_on = CONF.color
        CONF.color = False

        # 存储违例报告
        with open(f"{violation_dir}/report.txt", "w") as f:
            f.write("# Violation Report\n\n")
            f.write(f"* Test Case ID: {STAT.test_cases - 1}\n")
            f.write(f"* Detected: {datetime.today().strftime('%d.%m.%y at %H:%M:%S')}\n\n")
            f.write("* Time to detection:"
                    f" {(datetime.today() - self.log.start_time).total_seconds()}\n")
            f.write("* Statistics:\n")
            f.write(str(STAT) + "\n")

            f.write("\n## Generation Properties\n")
            f.write(f"* Program seed: {test_case.generator_seed}\n")
            f.write(f"* Input seed: {violation.input_sequence[0].seed}\n")
            f.write("* Faulty page properties:\n")
            target_desc = self.code_gen._target_desc
            # 输出每个actor的页表项（PTE）属性
            for actor in test_case.get_actors(sorted_=True):
                actor_id = actor.get_id()
                f.write(f"  - Actor {actor_id}:\n")

                pte_fields = []
                for field in target_desc.pte_bits:
                    offset, default = target_desc.pte_bits[field]
                    value = bool(actor.data_properties & (1 << offset))
                    if value != default:
                        pte_fields.append(f"{field}={value}")
                f.write(f"    * PTE: {'; '.join(pte_fields)}\n")

                if actor.mode != ActorMode.GUEST:
                    continue
                # 对于Guest模式的actor，输出扩展页表项（EPTE）属性
                vm_pte_fields = []
                for field in target_desc.vm_pte_bits:
                    offset, default = target_desc.vm_pte_bits[field]
                    value = bool(actor.data_ept_properties & (1 << offset))
                    if value != default:
                        vm_pte_fields.append(f"{field}={value}")
                f.write(f"    * EPTE: {'; '.join(vm_pte_fields)}\n")

            f.write("\n## Counterexample Inputs\n")
            for m in violation.measurements:
                f.write(f"\nInput #{m.input_id}\n")
                f.write(f"* Hardware trace:\n {m.htrace.full_str()}\n")
                f.write(f"* Contract trace (hash): {m.ctrace}\n")
                f.write(f"* Contract trace (detailed): {m.ctrace.full_str()}\n")

        # 重新启用颜色输出
        CONF.color = color_on

    def _report_bug_tainting(self, round_manager: _RoundManager) -> None:
        """
        报告污点追踪bug：快速路径的合约迹与完整追踪的合约迹不一致。
        将bug相关的测试用例和输入存储到bugs目录。
        """
        warning("fuzzer", "Fast path contract traces do not match the full traces")
        if self._work_dir and CONF.is_generation_enabled():
            warning("fuzzer", f"Storing the bug into {self._work_dir}/bugs/")

            # 注意：此处不使用_store_violation_artifact，因为没有实际违例
            # 仅存储测试用例和输入以供调试
            violation_dir = self._create_timestamped_dir(f"{self._work_dir}/bugs/")
            round_manager.test_case.save(f"{violation_dir}/program.asm")
            for i, input_ in enumerate(round_manager.org_inputs):
                input_.save(f"{violation_dir}/input_{i:04}.bin")

    def _report_bug_arch(self, round_manager: _RoundManager) -> None:
        """
        报告架构不一致bug：模型与执行器的架构级行为不一致。
        将违例产物存储到bugs目录。
        """
        warning("fuzzer", "Architectural mismatch between model and executor detected")
        if self._work_dir and CONF.is_generation_enabled():
            warning("fuzzer", f"Storing the bug into {self._work_dir}/bugs/")
            self._store_violation_artifact(round_manager.violations[0], f"{self._work_dir}/bugs/")

    # ----------------------------------------------------------------------------------------------
    # 私有：子类钩子方法（用于ISA特定定制）
    # ----------------------------------------------------------------------------------------------
    def _filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        过滤函数：检查测试用例是否无测试价值。
        
        此函数通常作为模糊测试循环的一部分（由self.start_*方法调用），
        但也可由其他类独立使用。

        :param test_case: 待检查的测试用例
        :param inputs: 与测试用例配合使用的输入
        :return: True表示应过滤掉（无价值），False表示有价值（不应过滤）
        """
        return False  # 由架构特定子类实现

    def _adjust_config(self, _: str) -> None:
        """根据给定测试用例调整配置（由架构特定子类实现）"""

    def _asm_parser_adapter(self, asm: str) -> TestCaseProgram:
        """汇编解析适配器：将汇编文件路径传递给解析器以生成测试用例"""
        # FIXME: 这是一个hack以适配接口；需要重构
        return self.asm_parser.parse_file(asm, self.code_gen, self.elf_parser)


class ArchitecturalFuzzer(Fuzzer):
    """
    架构不一致检测模糊器：检查模型与执行器之间的架构级不一致。
    此模糊器用于检测Revizor本身的bug，但不能检测合约违例。
    
    该模糊器借用Fuzzer的_check_for_architectural_mismatch方法来检查不一致性。
    """

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: Optional[List[str]] = None):
        """
        初始化架构不一致检测模糊器。
        :param instruction_set_spec: 指令集规格文件路径
        :param work_dir: 工作目录路径
        :param existing_test_case: 已有测试用例路径
        :param inputs: 输入文件路径列表
        """
        super().__init__(instruction_set_spec, work_dir, existing_test_case, inputs)
        warning("fuzzer", "Running in architectural mode. "
                "Contract violations can't be detected!")

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      _: List[int]) -> Optional[Violation]:
        """
        执行一轮架构不一致检测：为给定测试用例和输入收集迹并检查架构不一致。
        :param test_case: 要执行的测试用例
        :param inputs: 待测试的输入列表
        :return: 第一个检测到的架构违例，若无违例返回None
        """
        round_manager = _RoundManager(self, test_case, inputs)
        round_manager.execute_stage("arch_mismatch")
        return round_manager.arch_violations[0] if round_manager.arch_violations else None


class ArchDiffFuzzer(Fuzzer):
    """
    架构差异模糊器：对比测试用例在有无推测屏障（speculation fences）情况下的执行结果。
    若结果不同，则报告违例。
    
    用于检测因推测执行导致的架构级bug。
    """

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      _: List[int]) -> Optional[Violation]:
        """
        执行一轮架构差异检测：对比有无推测屏障的执行结果。
        :param test_case: 要执行的测试用例
        :param inputs: 待测试的输入列表
        :return: 若检测到差异返回伪违例，否则返回None
        """
        # 收集无屏障的迹（正常执行结果）
        self.arch_executor.load_test_case(test_case)
        reg_values: List[List[int]] = []
        try:
            htraces: List[HTrace] = self.arch_executor.trace_test_case(inputs, 1)
        except IOError:
            return None
        for htrace in htraces:
            reg_values.append(htrace.get_raw_readings()[0].tolist())

        # 收集有屏障的迹（插入推测屏障后的执行结果）
        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_name = fenced.name
        fenced_test_case = self._create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                         self.asm_parser, self.code_gen,
                                                         self.elf_parser)
        self.arch_executor.load_test_case(fenced_test_case)
        fenced_reg_values: List[List[int]] = []
        try:
            htraces = self.arch_executor.trace_test_case(inputs, 1)
        except IOError:
            return None
        for htrace in htraces:
            fenced_reg_values.append(htrace.get_raw_readings()[0].tolist())
        os.remove(fenced_name)

        # 对比每个输入的无屏障和有屏障执行结果
        for i, input_ in enumerate(inputs):
            if fenced_reg_values[i] == reg_values[i]:
                # 无差异：推测执行未影响架构级结果
                if "dbg_dump_htraces" in CONF.logging_modes:
                    print(f"Input #{i}")
                    print(f"Fenced:       {list(fenced_reg_values[i])}")
                    print(f"Non-fenced:   {list(reg_values[i])}")
                continue

            # 有差异：推测执行改变了架构级结果 -> 报告违例
            if "dbg_violation" in CONF.logging_modes:
                print(f"Input #{i}")
                print(f"Fenced:       {list(fenced_reg_values[i])}")
                print(f"Non-fenced:   {list(reg_values[i])}")

            return Violation.pseudo_violation_from_inputs([input_], test_case)
        return None

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        """
        钩子函数：创建带推测屏障的测试用例。
        必须由ISA特定子类实现，因为不同架构的屏障指令不同。
        :param original_asm: 原始汇编文件路径
        :param fenced_asm: 带屏障的汇编文件输出路径
        :param asm_parser: 汇编解析器
        :param generator: 代码生成器
        :param elf_parser: ELF解析器
        :return: 带屏障的测试用例对象
        """

        raise NotImplementedError("This method should be implemented by the subclass")

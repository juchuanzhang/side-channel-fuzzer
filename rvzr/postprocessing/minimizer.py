"""
文件：后处理模块的入口点。
根据命令行参数选择适当的最小化pass，然后依次执行它们。

执行顺序：
1. 重现违规
2. 运行输入最小化pass（减少输入数量和差异）
3. 运行指令最小化pass（移除/简化指令）
4. 运行分析pass（添加注释等）
5. 存储结果

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import shutil
import os

from copy import deepcopy
from typing import List, NamedTuple, Dict, TYPE_CHECKING, Any, Type, Optional
from ..traces import Violation
from ..tc_components.test_case_code import TestCaseProgram
from ..tc_components.test_case_data import InputData
from ..config import CONF
from ..logs import warning, error, update_logging_after_config_change
from ..fuzzer import Fuzzer

from .instruction_passes import BaseInstructionMinimizationPass, InstructionRemovalPass, \
    InstructionSimplificationPass, NopReplacementPass, ConstantSimplificationPass, \
    MaskSimplificationPass, LabelRemovalPass, FenceInsertionPass
from .input_passes import BaseInputMinimizationPass, InputSequenceMinimizationPass, \
    DifferentialInputMinimizerPass
from .analysis_passes import AddViolationCommentsPass
from .progress_printer import ProgressPrinter

if TYPE_CHECKING:
    from ..isa_spec import InstructionSet

TMP_DIR = "/tmp/rvzr_minimize"  # 临时文件目录


class PassDesc(NamedTuple):
    """ 存储最小化pass描述的命名元组，包含pass类和是否为分析pass的标记 """
    cls_: Type[BaseInstructionMinimizationPass | BaseInputMinimizationPass]
    is_analysis_pass: bool


class Minimizer:
    """
    后处理模块的主类。根据命令行参数选择适当的最小化pass并执行它们。

    支持的pass包括：
    - 指令pass：移除、简化、NOP替换、常数简化、掩码简化、标签移除、屏障插入
    - 输入pass：输入序列最小化、差异输入最小化
    - 分析pass：违规注释插入

    执行流程：重现违规 -> 输入pass -> 指令pass -> 分析pass -> 存储结果
    """

    ignore_list: List[int]
    """ 最小化过程中忽略的输入ID列表 """

    pass_map: Dict[str, PassDesc]
    """ pass名称到其类的映射字典 """

    _instruction_passes: List[Type[BaseInstructionMinimizationPass]]
    _input_passes: List[Type[BaseInputMinimizationPass]]
    _analysis_passes: List[Type[BaseInstructionMinimizationPass]]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet):
        """
        初始化最小化器。
        :param fuzzer: 模糊测试器实例
        :param instruction_set_spec: 指令集规范
        """
        self._fuzzer = fuzzer
        self._progress = ProgressPrinter()
        self.instruction_set_spec = instruction_set_spec
        self.ignore_list = []

        # 创建临时目录
        if not os.path.exists(TMP_DIR):
            os.makedirs(TMP_DIR)

        # 初始化pass映射表
        self.pass_map = {
            "instruction_pass": PassDesc(InstructionRemovalPass, False),      # 指令移除pass
            "simplification_pass": PassDesc(InstructionSimplificationPass, False),  # 指令简化pass
            "nop_pass": PassDesc(NopReplacementPass, False),                  # NOP替换pass
            "constant_pass": PassDesc(ConstantSimplificationPass, False),     # 常数简化pass
            "mask_pass": PassDesc(MaskSimplificationPass, False),             # 掩码简化pass
            "label_pass": PassDesc(LabelRemovalPass, False),                  # 标签移除pass
            "fence_pass": PassDesc(FenceInsertionPass, True),                 # 屏障插入pass（分析pass）
            "input_seq_pass": PassDesc(InputSequenceMinimizationPass, False), # 输入序列最小化pass
            "input_diff_pass": PassDesc(DifferentialInputMinimizerPass, False),  # 差异输入最小化pass
            "comment_pass": PassDesc(AddViolationCommentsPass, True),         # 违规注释插入pass（分析pass）
        }

    def __del__(self) -> None:
        """ 析构函数：删除临时目录 """
        if os.path.exists(TMP_DIR):
            shutil.rmtree(TMP_DIR)

    def run(self, test_case_asm: str, n_inputs: int, test_case_outfile: str, input_outdir: str,
            n_attempts: int, **enabled_passes: Any) -> None:
        """
        根据命令行参数运行最小化pass。
        首先重现违规，然后运行输入pass，再运行指令pass，最后运行分析pass。
        最小化后的程序存储到test_case_outfile，输入序列存储到input_outdir。

        :param test_case_asm: 测试用例汇编文件路径
        :param n_inputs: 最小化过程中使用的输入数量
        :param test_case_outfile: 存储最小化测试用例的路径
        :param input_outdir: 存储最小化输入的路径
        :param n_attempts: 指令最小化pass的运行次数
        :param enabled_passes: 启用/禁用pass的参数字典。
               支持的键：
               - enable_instruction_pass
               - enable_simplification_pass
               - enable_nop_pass
               - enable_constant_pass
               - enable_mask_pass
               - enable_label_pass
               - enable_fence_pass
               - enable_input_seq_pass
               - enable_input_diff_pass
               - enable_comment_pass
        :return: None
        """
        self._reset(enabled_passes)

        # 解析测试用例和生成输入
        test_case = self._fuzzer.asm_parser.parse_file(test_case_asm, self._fuzzer.code_gen,
                                                       self._fuzzer.elf_parser)
        inputs = self._fuzzer.data_gen.generate(n_inputs, n_actors=test_case.n_actors())

        # 检查违规是否可以重现
        violation = self._reproduce_org_violation(test_case, inputs)
        if not violation:
            return

        # 运行输入最小化pass
        if self._input_passes:
            new_inputs = self._run_input_passes(test_case, inputs, violation, input_outdir)

            # 检查使用新输入后违规是否仍可重现
            new_violation = self._fuzzer.fuzzing_round(test_case, inputs, [])
            if new_violation:
                # 使用新输入进行后续pass
                inputs = new_inputs
                violation = new_violation

                # 从现在起禁用输入增强：最小化后的输入序列已保证被增强
                CONF.inputs_per_class = 1
            else:
                warning("postprocessor", "Non-reproducible input sequence minimization. Reverting")

        # 设置非违规输入为忽略列表
        violating_ids = [m.input_id for m in violation.measurements]
        self.ignore_list = \
            [i for i in range(len(violation.input_sequence)) if i not in violating_ids]
        self._progress.pass_msg(f"Violating input IDs: {violating_ids}")

        # 运行指令最小化pass（可多次迭代）
        for attempt in range(n_attempts):
            self._progress.global_msg(f"Minimization attempt {attempt + 1}/{n_attempts}")
            old_tc = deepcopy(test_case)
            test_case = self._run_instruction_passes(test_case, inputs, violation,
                                                     test_case_outfile)
            if test_case == old_tc:  # 如果没有进展则停止
                break

        # 运行分析pass
        test_case = self._run_analysis_passes(test_case, inputs, violation, test_case_outfile)

        # 清除未使用的标签
        if enabled_passes.get("enable_label_pass", False):
            self._instruction_passes = [LabelRemovalPass]
            test_case = self._run_instruction_passes(test_case, inputs, violation,
                                                     test_case_outfile)

        # 存储结果
        self._progress.pass_start("Storing the results")
        test_case.save(test_case_outfile)

    def _reset(self, enabled_passes: Dict[str, Any]) -> None:
        """ 重置最小化器状态：设置启用的pass、清空忽略列表、调整采样大小和日志配置 """
        # 获取启用的pass列表
        self._set_passes(enabled_passes)

        # 清空忽略列表
        self.ignore_list = []

        # 调整采样大小以减少不可重现性
        CONF.executor_sample_sizes = [CONF.executor_sample_sizes[-1]]

        # 禁用模糊测试进度信息的打印
        if "info" in CONF.logging_modes:
            CONF.logging_modes.remove("info")
            update_logging_after_config_change()

    def _reproduce_org_violation(self, test_case: TestCaseProgram,
                                 inputs: List[InputData]) -> Optional[Violation]:
        """
        尝试重现原始违规。多次重试以提高成功率。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 重现的违规对象，如果无法重现则返回None
        """
        self._progress.pass_start("Reproducing the violation")
        for _ in range(CONF.minimizer_retries):
            violation = self._fuzzer.fuzzing_round(test_case, inputs, [])
            if violation:
                self._progress.pass_msg("Violation reproduced. Proceeding with minimization")
                return violation
        self._progress.pass_msg("Could not reproduce the violation. Exiting")
        return None

    def _set_passes(self, enabled_passes: Dict[str, Any]) -> None:
        """
        根据启用参数设置输入pass、指令pass和分析pass列表。
        :param enabled_passes: 启用/禁用pass的参数字典
        """
        passes: List[PassDesc] = \
            [v for k, v in self.pass_map.items() if enabled_passes.get(f"enable_{k}", False)]
        self._input_passes = [
            p.cls_ for p in passes if issubclass(p.cls_, BaseInputMinimizationPass)
        ]
        self._instruction_passes = [
            p.cls_
            for p in passes
            if issubclass(p.cls_, BaseInstructionMinimizationPass) and not p.is_analysis_pass
        ]
        self._analysis_passes = [
            p.cls_
            for p in passes
            if issubclass(p.cls_, BaseInstructionMinimizationPass) and p.is_analysis_pass
        ]

    def _run_input_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                          org_violation: Violation, outdir: str) -> List[InputData]:
        """
        运行所有启用的输入最小化pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :param org_violation: 原始违规对象
        :param outdir: 输入输出目录
        :return: 最小化后的输入列表
        """
        violation = org_violation

        for pass_cls in self._input_passes:
            # 创建pass对象
            pass_ = pass_cls(self._fuzzer, self.instruction_set_spec, self._progress)
            self._progress.pass_start(pass_.name)

            # 运行pass
            new_inputs = pass_.run(test_case, inputs, violation)

            # 用新输入序列重新验证违规
            new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
            if new_violation:
                violation = new_violation
                inputs = new_inputs
            else:
                self._progress.pass_msg("[WARNING] Non-reproducible sequence minimization"
                                        ". Rolling back to the previous state")

        # 创建输出目录（如果不存在）
        if outdir and not os.path.exists(outdir):
            try:
                os.makedirs(outdir)
            except OSError:
                error(f"Creation of the directory {outdir} failed")
            outdir = os.path.abspath(outdir)

        # 存储最小化后的输入
        self._progress.pass_msg(f"Saving new inputs in '{outdir}'")
        for i, input_ in enumerate(inputs):
            input_.save(f"{outdir}/min_input_{i:04}.bin")

        return inputs

    def _run_instruction_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                                org_violation: Violation, outfile: str) -> TestCaseProgram:
        """
        运行所有启用的指令最小化pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :param org_violation: 原始违规对象
        :param outfile: 输出文件路径
        :return: 最小化后的测试用例
        """
        # 创建pass对象
        passes = self._instruction_passes
        pass_objs = [c(self._fuzzer, self.instruction_set_spec, self._progress) for c in passes]
        for pass_obj in pass_objs:
            pass_obj.set_ignore_list(self.ignore_list)
            pass_obj.set_violation(org_violation)

        # 运行每个pass
        for pass_obj in pass_objs:
            self._progress.pass_start(pass_obj.name)
            test_case = pass_obj.run(test_case, inputs)
            test_case.save(outfile)

        return test_case

    def _run_analysis_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                             org_violation: Violation, outfile: str) -> TestCaseProgram:
        """
        运行所有启用的分析pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :param org_violation: 原始违规对象
        :param outfile: 输出文件路径
        :return: 分析后的测试用例
        """
        # 创建pass对象
        passes = self._analysis_passes
        pass_objs = [c(self._fuzzer, self.instruction_set_spec, self._progress) for c in passes]
        for pass_obj in pass_objs:
            pass_obj.set_ignore_list(self.ignore_list)
            pass_obj.set_violation(org_violation)

        # 运行每个分析pass
        for pass_obj in pass_objs:
            self._progress.pass_start(pass_obj.name)
            test_case = pass_obj.run(test_case, inputs)
            test_case.save(outfile)

        return test_case
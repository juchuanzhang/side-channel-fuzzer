"""
文件：分析类后处理pass集合——对测试用例进行分析但不修改代码。

该模块包含在最小化过程中用于分析违规（violation）的pass，
例如在汇编代码中插入违规相关的内存访问地址注释，
帮助用户理解导致侧信道泄露的具体内存操作。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List
from typing_extensions import assert_never

from ..model_unicorn import model as uc_model, speculators_basic as uc_speculator, \
    tracer as uc_tracer, interpreter as uc_interpreter
from ..sandbox import CodeArea
from ..arch.x86.target_desc import X86TargetDesc
from ..arch.arm64.target_desc import ARM64TargetDesc
from ..config import CONF

from .instruction_passes import BaseInstructionMinimizationPass

if TYPE_CHECKING:
    from ..traces import Violation, CTraceEntry
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_code import TestCaseProgram
    from ..target_desc import TargetDesc


def _get_seq_model(data_start: int, code_start: int) -> uc_model.UnicornModel:
    """
    获取顺序执行模型（UnicornModel）的辅助函数。
    这是factory.py中代码的部分重复，但由于循环导入问题无法直接引用factory.py。
    根据配置的指令集架构（x86-64或arm64）创建对应的顺序执行模型。
    :param data_start: 数据区起始地址
    :param code_start: 代码区起始地址
    :return: 顺序执行的UnicornModel实例
    """
    model_cls: type[uc_model.UnicornModel]
    target_desc: TargetDesc
    interpreter: type[uc_interpreter.ExtraInterpreter]
    if CONF.instruction_set == "x86-64":
        model_cls = uc_model.X86UnicornModel
        target_desc = X86TargetDesc()
        interpreter = uc_interpreter.X86ExtraInterpreter
    elif CONF.instruction_set == "arm64":
        model_cls = uc_model.ARM64UnicornModel
        target_desc = ARM64TargetDesc()
        interpreter = uc_interpreter.ARMExtraInterpreter
    else:
        assert_never(CONF.instruction_set)

    bases = (data_start, code_start)
    model = model_cls(bases, target_desc, uc_speculator.SeqSpeculator,
                      uc_tracer.CTTracer, interpreter)
    return model


class AddViolationCommentsPass(BaseInstructionMinimizationPass):
    """
    违规注释插入pass——遍历测试用例并在汇编代码中添加注释，
    标注导致违规的内存加载/存储地址。

    该pass通过重新执行测试用例收集PC和内存追踪，
    然后将每个指令对应的内存访问地址（包括缓存行号和偏移）写入汇编文件。
    """
    name = "Violation Comment Insertion"
    violation: Violation

    def set_violation(self, violation: Violation) -> None:
        """ 设置当前正在最小化的违规对象 """
        self.violation = violation

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行违规注释插入pass的主逻辑。
        1. 获取违规的两个输入ID
        2. 使用顺序模型重新执行以收集PC和内存追踪
        3. 构建每条指令对应的内存访问地址映射
        4. 在汇编文件中为相关指令添加内存访问注释
        :param test_case: 测试用例对象
        :param inputs: 输入数据列表
        :return: 添加注释后的测试用例对象
        """
        # pylint: disable=too-many-locals
        # pylint: disable=too-many-branches
        # FIXME: this function was written in a hurry and needs to be refactored

        # 重新执行违规以获取违规输入ID
        v_inputs = [m.input_ for m in self.violation.measurements[:2]]
        v_input_ids = [m.input_id for m in self.violation.measurements[:2]]

        # 创建收集PC和内存追踪的模型
        data_start, code_start = 0x2000000, 0x1000000
        model = _get_seq_model(data_start, code_start)

        # 收集追踪
        model.tracer.enable_tracing = True  # 从最开始启用追踪
        model.load_test_case(test_case)
        ctraces_obj = model.trace_test_case(v_inputs, 30)
        ctraces: List[List[CTraceEntry]] = [t.get_typed() for t in ctraces_obj]

        # 从追踪中选择加载和存储操作
        ctrace_maps = []
        for ctrace in ctraces:
            ctrace_map = {}
            for v1, v2, v3 in zip(ctrace, ctrace[1:], ctrace[2:]):
                if v1.type_ == 'pc' and v2.type_ == 'mem':
                    pc = v1.value
                    ld_addr = v2.value  # 加载地址
                    st_addr = v3.value if v3.type_ == 'mem' else 0  # 存储地址（可能不存在）
                    ctrace_map[pc] = (ld_addr, st_addr)
            ctrace_maps.append(ctrace_map)

        # 获取汇编文件内容
        lines = []
        with open(test_case.asm_path(), "r") as f:
            lines = list(enumerate(f))

        # 为简化后续步骤，建立汇编行号到PC的映射字典
        line_num_to_pc = {}
        for func in test_case.iter_functions():
            actor_id = func.get_owner().get_id()
            actor_start_pc = model.layout.get_code_addr(CodeArea.MAIN, actor_id)
            for bb in func:
                for inst in list(bb) + bb.terminators:
                    pc = actor_start_pc + inst.section_offset() - code_start
                    line_num = inst.line_num()
                    if line_num != 0:
                        line_num_to_pc[line_num] = pc

        # 在汇编代码中添加加载/存储地址注释
        with open(test_case.asm_path(), 'w') as f:
            for i, line in lines:
                f.write(line)
                if i not in line_num_to_pc:
                    continue
                pc = line_num_to_pc[i]
                if pc not in ctrace_maps[0] or pc not in ctrace_maps[1]:
                    continue

                ld, st, cl, of = [0, 0], [0, 0], [0, 0], [0, 0]
                iid = v_input_ids
                for i in range(2):
                    ld[i], st[i] = ctrace_maps[i][pc]
                    cl[i] = (ld[i] % 0x1000) // 64  # 计算缓存行号
                    of[i] = (ld[i] % 0x1000) % 64   # 计算缓存行内偏移

                if st[0] != 0 or st[1] != 0:
                    f.write(
                        f"{self._comment_symbol} "
                        f"mem access: [{iid[0]}] {hex(ld[0])}-{hex(st[0])} CL {cl[0]}:{of[0]} | "
                        f"[{iid[1]}] {hex(ld[1])}-{hex(st[1])} CL {cl[1]}:{of[1]}\n")
                else:
                    f.write(f"{self._comment_symbol} "
                            f"mem access: [{iid[0]}] {hex(ld[0])} CL {cl[0]}:{of[0]} | "
                            f"[{iid[1]}] {hex(ld[1])} CL {cl[1]}:{of[1]}\n")

                if st[0] == 0xff8 or st[1] == 0xff8:
                    f.write(f"{self._comment_symbol} exception?\n")

        return test_case

    def modify_instruction(self, _: List[str], __: int) -> List[str]:
        return []  # 未使用（分析pass不需要修改指令）

    def verify_modification(self, _: TestCaseProgram, __: List[InputData]) -> bool:
        return True  # 未使用（分析pass不需要验证修改）
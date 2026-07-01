"""
文件：基于 Unicorn 的合约模型后端实现。

本模块实现了微架构侧信道模糊测试框架的核心模型，使用 Unicorn CPU 模拟器引擎
来模拟推测执行行为。模型通过状态机方式管理执行流程，支持：
- 顺序执行和推测执行两种模式
- x86-64 和 ARM64 两种架构
- 故障处理、权限检查和回滚机制
- 污点追踪、覆盖率统计和合约轨迹收集

核心类：
- _Dispatcher: 调度器，将 Unicorn 事件分发到各服务模块
- UnicornModel: 架构无关的模型基类（抽象类）
- X86UnicornModel: x86-64 架构的模型实现
- ARM64UnicornModel: ARM64 架构的模型实现

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Set, TYPE_CHECKING, Final, Dict, Type

import numpy as np

import unicorn as uc
import unicorn.x86_const as x86ucc  # type: ignore # no type hints for unicorn.x86_const
import unicorn.arm64_const as armucc  # type: ignore # no type hints for unicorn.arm_const
from unicorn import Uc, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, \
    UC_HOOK_MEM_UNMAPPED, UcError, UC_MEM_WRITE, UC_PROT_NONE, UC_PROT_READ

from ..model import Model
from ..sandbox import SandboxLayout, DataArea
from ..config import CONF
from ..logs import ModelLogger, BLUE, COL_RESET, error
from ..traces import CTraceEntry

from .taint_tracker import UnicornTaintTracker
from .coverage import InstructionCoverage
from .execution_context import ModelExecutionState

if TYPE_CHECKING:
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_data import InputTaint
    from ..tc_components.test_case_code import TestCaseProgram
    from ..traces import CTrace
    from .tracer import UnicornTracer
    from .speculator_abc import UnicornSpeculator
    from .interpreter import ExtraInterpreter
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..sandbox import BaseAddrTuple


_UC_FAULT_MAPPING: Final[Dict[str, List[int]]] = {  # 故障名称到 Unicorn 故障 ID 的映射
    "DE": [21],    # 除法错误 (Division Error)
    "DB": [10],    # 调试异常 (Debug Exception)
    "BP": [21],    # 断点 (Breakpoint)
    "BR": [13],    # 范围超出 (Bound Range)
    "UD": [10],    # 未定义指令 (Undefined Instruction)
    "PF": [12, 13], # 页故障 (Page Fault) - 12 为读取, 13 为写入
    "GP": [6, 7],  # 一般保护故障 (General Protection) - 6 为非规范, 7 为其他
    "assist": [12, 13], # 微代码辅助 (Microcode Assist)
}


# ==================================================================================================
# 私有类和函数
# ==================================================================================================
class _Dispatcher:
    """
    调度器类：负责在 Unicorn 中发生事件时调用各服务模块的回调函数。

    调度器协调以下服务模块：
    - taint_tracker: 污点追踪器
    - tracer: 执行追踪器
    - speculator: 推测器
    - interpreter: 额外解释器
    - coverage: 覆盖率统计

    各回调的调用顺序是重要的，因为某些模块依赖于其他模块的先处理结果。
    """
    coverage: InstructionCoverage
    _taint_tracker: UnicornTaintTracker
    _tracer: UnicornTracer
    _speculator: UnicornSpeculator
    _interpreter: ExtraInterpreter

    def __init__(self, taint_tracker: UnicornTaintTracker, speculator: UnicornSpeculator,
                 tracer: UnicornTracer, interpreter: ExtraInterpreter,
                 coverage: InstructionCoverage) -> None:
        """
        初始化调度器，建立与各服务模块的连接。
        """
        self._taint_tracker = taint_tracker
        self._tracer = tracer
        self._speculator = speculator
        self._interpreter = interpreter
        self.coverage = coverage

    def test_case_load_dispatch(self, test_case: TestCaseProgram) -> None:
        """ 在加载测试用例时调用各服务模块的回调。
        通知解释器和追踪器加载测试用例，并管理覆盖率的测试用例边界。 """
        self._interpreter.load_test_case(test_case)
        self._tracer.load_test_case(test_case)
        self.coverage.finish_test_case()
        self.coverage.start_test_case()

    def execution_start_dispatch(self, input_: InputData) -> None:
        """ 在模型执行开始前调用各服务模块的回调。
        重置追踪器、推测器和污点追踪器，加载输入到解释器。 """
        self._tracer.reset(input_)
        self._speculator.reset()
        self._taint_tracker.reset()
        self._interpreter.load_input(input_)

    def instruction_dispatch(self, address: int, size: int, _: UnicornModel,
                             state: ModelExecutionState) -> None:
        """ 在每条指令执行时调用各服务模块的回调。

        调用顺序（重要）：
        1. 污点追踪器：追踪指令操作数
        2. 追踪器：记录指令事件
        3. 推测器：处理推测机制
        4. 解释器：额外解释逻辑
        5. 覆盖率：记录指令覆盖

        :param address: 指令地址
        :param size: 指令大小
        :param state: 模型执行状态
        """

        if state.current_instruction.is_macro_placeholder:
            # 跳过宏占位符，它们不是真正的指令
            return

        # 注意：以下调用顺序是重要的
        self._taint_tracker.track_instruction(state.current_instruction)
        self._tracer.observe_instruction(address, size)
        self._speculator.handle_instruction(address, size)
        self._interpreter.interpret_instruction(address, state)
        self.coverage.add_instruction(state.current_instruction)

    def mem_access_dispatch(self, access: int, address: int, size: int, value: int,
                            state: ModelExecutionState) -> None:
        """ 在每次内存访问时调用各服务模块的回调。

        调用顺序（重要）：
        1. 污点追踪器：追踪内存访问操作数
        2. 推测器：处理内存访问级推测机制
        3. 追踪器：记录内存访问事件
        4. 解释器：额外解释逻辑（如故障权限检查）

        :param access: 内存访问类型
        :param address: 内存地址
        :param size: 访问大小
        :param value: 访问的值
        :param state: 模型执行状态
        """

        if state.current_instruction.is_macro_placeholder:
            # 跳过宏占位符
            return

        # 注意：以下调用顺序是重要的
        self._taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        self._speculator.handle_mem_access(access, address, size, value)
        self._tracer.observe_mem_access(access, address, size, value)
        self._interpreter.interpret_mem_access(access, address, size, value)


def _instruction_hook(_: Uc, address: int, size: int, model: UnicornModel) -> None:
    """ 将 Unicorn 指令钩子分发到模型。 """
    model.instruction_callback(address, size)


def _mem_access_hook(_: Uc, access: int, address: int, size: int, value: int,
                     model: UnicornModel) -> None:
    """ 将 Unicorn 内存访问钩子分发到模型。 """
    model.mem_access_callback(access, address, size, value)


def _mem_unmapped_hook(_: Uc, access: int, address: int, size: int, value: int,
                       model: UnicornModel) -> None:
    """ 将 Unicorn 未映射内存访问钩子分发到模型。 """
    model.mem_access_callback(access, address, size, value)


_ERR_DECODE = {
    """ Unicorn 错误码到描述字符串的映射 """
    uc.UC_ERR_OK: "OK (UC_ERR_OK)",
    uc.UC_ERR_NOMEM: "No memory available or memory not present (UC_ERR_NOMEM)",
    uc.UC_ERR_ARCH: "Invalid/unsupported architecture (UC_ERR_ARCH)",
    uc.UC_ERR_HANDLE: "Invalid handle (UC_ERR_HANDLE)",
    uc.UC_ERR_MODE: "Invalid mode (UC_ERR_MODE)",
    uc.UC_ERR_VERSION: "Different API version between core & binding (UC_ERR_VERSION)",
    uc.UC_ERR_READ_UNMAPPED: "Invalid memory read (UC_ERR_READ_UNMAPPED)",
    uc.UC_ERR_WRITE_UNMAPPED: "Invalid memory write (UC_ERR_WRITE_UNMAPPED)",
    uc.UC_ERR_FETCH_UNMAPPED: "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)",
    uc.UC_ERR_HOOK: "Invalid hook type (UC_ERR_HOOK)",
    uc.UC_ERR_INSN_INVALID: "Invalid instruction (UC_ERR_INSN_INVALID)",
    uc.UC_ERR_MAP: "Invalid memory mapping (UC_ERR_MAP)",
    uc.UC_ERR_WRITE_PROT: "Write to write-protected memory (UC_ERR_WRITE_PROT)",
    uc.UC_ERR_READ_PROT: "Read from non-readable memory (UC_ERR_READ_PROT)",
    uc.UC_ERR_FETCH_PROT: "Fetch from non-executable memory (UC_ERR_FETCH_PROT)",
    uc.UC_ERR_ARG: "Invalid argument (UC_ERR_ARG)",
    uc.UC_ERR_READ_UNALIGNED: "Read from unaligned memory (UC_ERR_READ_UNALIGNED)",
    uc.UC_ERR_WRITE_UNALIGNED: "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)",
    uc.UC_ERR_FETCH_UNALIGNED: "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)",
    uc.UC_ERR_RESOURCE: "Insufficient resource (UC_ERR_RESOURCE)",
    uc.UC_ERR_EXCEPTION: "Misc. CPU exception (UC_ERR_EXCEPTION)",
}


def _err_to_str(errno: int) -> str:
    """ 将 Unicorn 错误码转换为描述字符串。
    :param errno: Unicorn 错误码
    :return: 错误描述字符串
    """
    if errno in _ERR_DECODE:
        return _ERR_DECODE[errno]
    return "Unknown error code"


# ==================================================================================================
# 公共接口：架构无关模型
# ==================================================================================================
class UnicornModel(Model, ABC):
    """
    基于 Unicorn 的架构无关模型基础实现。

    该模型管理 CPU 模拟器的执行流程，通过状态机方式处理正常执行、
    故障处理和推测执行回滚等场景。它作为协调者连接多个服务模块：
    - 推测器(speculator): 控制推测执行行为
    - 追踪器(tracer): 收集合约轨迹
    - 污点追踪器(taint_tracker): 追踪数据依赖
    - 解释器(interpreter): 提供额外的指令解释逻辑
    - 覆盖率(coverage): 统计指令覆盖率

    该基类不直接支持推测执行；推测行为由推测器子类实现。

    完整的状态机图见：docs/assets/unicorn-model-state-machine.drawio.png
    """

    # pylint: disable=too-many-instance-attributes
    # 这是一个管理类，连接多个服务模块，因此有许多属性是必要的

    # 服务对象
    emulator: Uc
    """ Unicorn 模拟器实例 """
    tracer: Final[UnicornTracer]
    """ 执行追踪器 """
    speculator: Final[UnicornSpeculator]
    """ 推测器 """
    _taint_tracker: UnicornTaintTracker
    """ 污点追踪器 """
    _log: Final[ModelLogger]
    """ 模型日志记录器 """
    _dispatcher: Final[_Dispatcher]
    """ 事件调度器 """

    # 模型状态
    state: ModelExecutionState
    """ 当前执行状态 """
    layout: SandboxLayout
    """ 沙箱内存布局 """

    # 描述符
    _bases: BaseAddrTuple
    """ 沙箱基地址元组 """
    _target_desc: Final[TargetDesc]
    """ 目标架构描述 """
    _uc_target_desc: Final[UnicornTargetDesc]
    """ Unicorn 特定的目标架构描述 """
    _architecture: Optional[Tuple[int, int]] = None  # (UC_ARCH, UC_MODE)
    """ Unicorn 架构和模式配置 """
    _handled_faults: Set[int]
    """ 不终止执行的故障类型集合 """

    # ----------------------------------------------------------------------------------------------
    # 构造函数和服务模块初始化
    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:
        """
        初始化 Unicorn 模型及其服务模块。

        :param bases: 沙箱基地址元组
        :param target_desc: 目标架构描述
        :param speculator_cls: 推测器类
        :param tracer_cls: 追踪器类
        :param interpreter_cls: 额外解释器类
        :param enable_mismatch_check_mode: 是否启用不匹配检查模式（用于调试）
        """

        assert self._architecture is not None, \
            "Subclasses must define the `architecture` attribute before calling super().__init__"

        # 初始化服务模块
        self.emulator = Uc(*self._architecture)
        self._taint_tracker = UnicornTaintTracker(bases, target_desc)
        self.tracer = tracer_cls(target_desc, self, self._taint_tracker)
        self.speculator = speculator_cls(target_desc, self, self._taint_tracker)
        self._dispatcher = _Dispatcher(self._taint_tracker, self.speculator, self.tracer,
                                       interpreter_cls(target_desc, self), InstructionCoverage())
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc
        self._log = ModelLogger()

        # 设置基地址和不匹配检查模式
        self._bases = bases
        self._enable_mismatch_check_mode = enable_mismatch_check_mode
        self.is_speculative = not self.speculator.is_sequential

        # 设置处理的故障类型列表（这些故障不终止执行）
        self._handled_faults = set()
        for fault in CONF._handled_faults:
            if fault in _UC_FAULT_MAPPING:
                self._handled_faults.update(_UC_FAULT_MAPPING[fault])
            else:
                raise NotImplementedError(f"Fault type {fault} is not supported")

    # ----------------------------------------------------------------------------------------------
    # 默认公共接口
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        加载测试用例到模型。必须在追踪测试用例之前调用。

        步骤：
        1. 计算沙箱布局
        2. 创建执行状态
        3. 通知各服务模块加载测试用例
        4. 创建新的 Unicorn 模拟器实例
        5. 将测试用例二进制代码写入模拟器内存
        6. 设置内存访问和指令执行钩子

        :param test_case: 要加载的测试用例
        :return: None
        :raises UcError: 如果加载过程中发生错误
        """
        test_case_obj = test_case.get_obj()

        # 通知各服务模块加载测试用例
        self.layout = SandboxLayout(self._bases, test_case.n_actors())
        self._log.set_model_layout(self.layout)
        self.state = ModelExecutionState(test_case, self.layout, self._target_desc)
        self._dispatcher.test_case_load_dispatch(test_case)

        # 创建新的模拟器实例（每次加载测试用例都需要重建）
        assert self._architecture is not None, "_architecture must be set by subclass"
        self.emulator = Uc(*self._architecture)

        # 获取测试用例的二进制表示
        code = test_case_obj.to_bytes(
            padded_section_size=self.layout.code_size_per_actor(), padding_byte=b'\x90')

        # 分配内存并写入二进制代码
        # 注意：数据将在 _load_input 方法中写入
        try:
            self.emulator.mem_map(self.layout.code_start(), self.layout.code_size)
            self.emulator.mem_map(self.layout.data_start(), self.layout.data_size)
            self.emulator.mem_write(self.layout.code_start(), code)
        except UcError as e:
            error(f"[UnicornModel:load_test_case] {e}")

        # 设置回调钩子（指令执行、内存访问、未映射内存）
        try:
            self.emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, _mem_access_hook, self)
            self.emulator.hook_add(UC_HOOK_MEM_UNMAPPED, _mem_unmapped_hook, self)
            self.emulator.hook_add(UC_HOOK_CODE, _instruction_hook, self)
        except UcError as e:
            error(f"[UnicornModel:load_test_case] {e}")

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        使用给定输入执行测试用例并收集合约轨迹（不启用污点追踪）。

        :param inputs: 用于测试用例的输入列表
        :param nesting: 推测执行的最大嵌套层级
        :return: 收集的合约轨迹列表，每个输入对应一条轨迹
        """
        self._taint_tracker.set_enable_tracking(False)
        self.speculator.set_max_nesting(nesting)
        ctraces, _ = self._execute_test_case_with_inputs(inputs)
        return ctraces

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        使用给定输入执行测试用例，同时收集合约轨迹和污点信息。

        :param inputs: 用于测试用例的输入列表
        :param nesting: 推测执行的最大嵌套层级
        :return: 合约轨迹列表和污点列表，每个输入各一条
        """
        self._taint_tracker.set_enable_tracking(True)
        self.speculator.set_max_nesting(nesting)
        ctraces, taints = self._execute_test_case_with_inputs(inputs)
        return ctraces, taints

    # ----------------------------------------------------------------------------------------------
    # Unicorn 特定的公共接口
    def instruction_callback(self, address: int, size: int) -> None:
        """
        Unicorn 执行指令时的回调函数。

        处理逻辑：
        1. 如果到达退出指令地址，停止模拟器
        2. 否则，更新执行上下文（保存 Unicorn 状态，更新当前指令引用）
        3. 将事件分发到各服务模块

        :param address: 指令地址
        :param size: 指令大小
        :return: None
        """
        # 如果到达退出指令，终止执行
        if self.state.is_exit_addr(address):
            self.emulator.emu_stop()
            return

        # 更新上下文（保存 Unicorn 上下文用于 bug 修补，更新当前指令）
        self.state.update_context(self.emulator, address)
        self._log.dbg_instruction(address, self, self.state, self.speculator)

        # 将指令事件分发到各服务模块
        self._dispatcher.instruction_dispatch(address, size, self, self.state)

    def mem_access_callback(self, access: int, address: int, size: int, value: int) -> None:
        """
        Unicorn 访问内存时的回调函数。

        :param access: 内存访问类型
        :param address: 内存地址
        :param size: 访问大小
        :param value: 访问的值
        """
        self._log.dbg_mem_access(access == UC_HOOK_MEM_WRITE, value, address, size, self,
                                 self.layout)
        self._dispatcher.mem_access_dispatch(access, address, size, value, self.state)

    def do_soft_fault(self, errno: int) -> None:
        """
        向模型发出故障信号并停止模拟器（不抛出异常）。

        这是一种"软故障"机制：通过设置 pending_fault 标志和停止模拟器，
        让 _run_state_machine 方法在模拟器停止后处理故障。
        不抛出异常，避免了 Unicorn 内部的错误处理问题。

        :param errno: 故障的错误号
        """
        assert self.state, "Function called before load_test_case"
        self.state.pending_fault = errno
        self.emulator.emu_stop()

    def set_faulty_area_rw(self, actor_id: int, r: bool, w: bool) -> None:
        """ 设置给定 actor 的故障区域的读写权限属性。

        通过修改 Unicorn 的内存保护来模拟页表权限：
        - 不可读和不可写: UC_PROT_NONE
        - 可读但不可写: UC_PROT_READ
        - 可读和可写: 默认权限

        :param actor_id: actor 的 ID（-1 表示当前 actor）
        :param r: 是否可读
        :param w: 是否可写
        """
        if actor_id == -1:
            actor_id = self.state.current_actor.get_id()
        faulty_base = self.layout.get_data_addr(DataArea.FAULTY, actor_id)
        faulty_size = self.layout.data_area_size(DataArea.FAULTY)
        if not r:
            self.emulator.mem_protect(faulty_base, faulty_size, UC_PROT_NONE)
        elif not w:
            self.emulator.mem_protect(faulty_base, faulty_size, UC_PROT_READ)
        else:
            self.emulator.mem_protect(faulty_base, faulty_size)

    def report_coverage(self, path: str) -> None:
        """ 将覆盖率数据写入文件。
        :param path: 输出文件路径
        """
        self._dispatcher.coverage.report(path)

    @abstractmethod
    def print_registers(self, oneline: bool = False) -> None:
        """ 打印所有通用寄存器的当前值（抽象方法，由架构子类实现）。 """

    # ----------------------------------------------------------------------------------------------
    # 私有方法
    def _execute_test_case_with_inputs(
            self, inputs: List[InputData]) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        使用给定输入序列执行加载的测试用例，收集轨迹和污点。

        对每个输入：
        1. 重置模型状态和服务模块
        2. 加载输入数据到模拟器
        3. 运行状态机
        4. 收集合约轨迹和污点信息

        不匹配检查模式：
        - 正常模式：存储合约轨迹
        - 不匹配检查模式：存储寄存器值作为轨迹（用于验证模型与实际执行的一致性）

        :param inputs: 输入数据列表
        :return: 收集的轨迹和污点
        """
        traces, taints = [], []
        for index, input_ in enumerate(inputs):
            self._log.dbg_header(index)
            self.state.full_reset()
            self._dispatcher.execution_start_dispatch(input_)

            # 使用给定输入执行测试用例
            self._load_input(input_)
            self._run_state_machine()

            # 记录轨迹（两种选项）：
            if not self._enable_mismatch_check_mode:  # 选项1：正常模式 - 存储轨迹
                traces.append(self.tracer.get_trace())
            else:  # 选项2：不匹配检查模式 - 存储寄存器值
                register_list = self._uc_target_desc.usable_registers
                registers = register_list[:-2]  # 排除 RSP 和 EFLAGS
                reg_values = [int(self.emulator.reg_read(reg)) for reg in registers]  # type: ignore
                self.tracer.trace = [CTraceEntry("reg", val) for val in reg_values]
                traces.append(self.tracer.get_trace())

            # 记录污点
            n_actors = self.state.current_test_case().n_actors()
            taints.append(self._taint_tracker.get_taint(n_actors))

        return traces, taints

    def _run_state_machine(self) -> None:
        """
        在模型上使用加载的输入执行测试用例。

        该方法实现了状态机，反复执行测试用例直到在非推测状态下到达退出指令。

        状态机保证：
        - 当模拟器退出但未到达退出指令时：
          如果在推测中则回滚，如果不在推测中则退出
        - 当故障触发时：
          如果不在推测中则跳转到故障处理程序，
          如果在推测中则回滚

        完整状态机图见：docs/assets/unicorn-model-state-machine.drawio.png
        """
        code_start = self.layout.code_start()
        pc = code_start
        while True:
            self.state.reset_after_em_stop(pc)

            # 处理故障和回滚后的重新进入
            if pc != code_start:
                in_speculation = self.speculator.in_speculation()

                # 进入新循环迭代时的选项：
                # 1. 到达退出且不在推测中 -> 正常结束
                if self.state.is_exit_addr(pc) and not in_speculation:
                    return

                # 2. 到达退出但在推测中 -> 回滚到检查点
                if self.state.is_exit_addr(pc) and in_speculation:
                    pc = self.speculator.rollback()
                    self._log.dbg_rollback(pc)
                    continue

                # 3. 进入故障处理程序但在推测中 -> 需要再次回滚
                if pc == self.state.fault_handler_addr and in_speculation:
                    # 这表示回滚本应终止推测，所以再回滚一次
                    pc = self.speculator.rollback()
                    self._log.dbg_rollback(pc)
                    continue
                # 4. 其他情况 -> 正常继续执行

            # 执行测试用例
            try:
                self.emulator.emu_start(pc, self.layout.code_end(), timeout=10 * uc.UC_SECOND_SCALE)
            except UcError as e:
                self.state.pending_fault = int(e.errno)  # type: ignore  # missing type annotation

            # 处理故障
            if self.state.pending_fault:
                self._patch_context_after_fault()
                pc = self._handle_fault()
                if pc and pc != self.state.exit_addr:
                    continue

            # 如果模型不在推测状态，故障终止执行
            if not self.speculator.in_speculation():
                return

            # 否则（在推测状态），故障导致推测回滚
            pc = self.speculator.rollback()
            self._log.dbg_rollback(pc)
            continue

    def _handle_fault(self) -> int:
        """
        处理执行期间触发的故障。

        故障处理场景（按优先级）：
        1. 有注册的推测机制处理此故障 -> 使用推测机制
        2. 无推测机制但已在推测中 -> 回滚
        3. 不在推测中且之前已有故障 -> 报错（嵌套故障）
        4. 非嵌套非推测故障，在预期故障列表中 -> 跳转到故障处理程序
        5. 非嵌套非推测故障，不在预期列表中 -> 报错（意外故障）

        :param errno: 故障的错误号
        :return: 下一条要执行的指令地址，或 0 表示触发回滚
        """
        errno = self.state.pending_fault
        self._log.dbg_exception(errno, _err_to_str(errno))

        # 清除待处理故障
        self.state.pending_fault = 0

        # 故障触发时，CPU 将 PC 和故障类型压入栈 - 需要在合约层面镜像
        rsp = self.layout.get_data_addr(DataArea.RSP_INIT, 0)
        self.tracer.observe_mem_access(UC_MEM_WRITE, rsp, 8, errno)

        # 故障处理场景：
        # 1. 有注册的推测机制 -> 使用它
        next_addr = self.speculator.handle_fault(errno)
        if next_addr:
            return next_addr

        # 2. 无推测机制但在推测中 -> 回滚
        if self.speculator.in_speculation():
            return 0

        # 3. 不在推测中且之前已有故障 -> 嵌套故障错误
        if self.state.had_arch_fault:
            self.print_registers()
            error(f"Nested fault {errno} {_err_to_str(errno)}", print_last_tb=True)
        self.state.had_arch_fault = True

        # 4. 非嵌套非推测故障，在预期列表中 -> 跳转到故障处理程序
        if errno in self._handled_faults:
            return self.state.fault_handler_addr

        # 5. 非嵌套非推测故障，不在预期列表中 -> 意外故障错误
        self.print_registers()
        error(f"Unexpected exception {errno} {_err_to_str(errno)}", print_last_tb=True)

    def _patch_context_after_fault(self) -> None:
        """
        在故障后修补上下文以避免 Unicorn bug。

        Unicorn 在捕获异常后存在已知 bug：模拟器内部状态会被破坏。
        解决方法是恢复预异常时保存的上下文，并重新写入标志位寄存器。
        """
        if not self.state.previous_context:
            error("Fault triggered without a previous context")

        # Unicorn bug 的 workaround：捕获异常后恢复预异常上下文，
        # 否则模拟器内部状态会损坏
        self.emulator.context_restore(self.state.previous_context)
        # 另一个 workaround，专门针对标志位
        flags_id = self._target_desc.uc_target_desc.reg_norm_to_constant["FLAGS"]
        self.emulator.reg_write(flags_id, self.emulator.reg_read(flags_id))

    @abstractmethod
    def _load_input(self, input_: InputData) -> None:
        """ 加载寄存器和内存的给定输入：此方法是架构特定的。 """


# ==================================================================================================
# 公共：x86 实现
# ==================================================================================================
class X86UnicornModel(UnicornModel):
    """
    x86 架构的模型实现。

    使用 Unicorn 的 x86-64 模式，处理 x86 特定的输入加载和寄存器初始化。
    """

    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:
        """
        初始化 x86 模型。

        :param bases: 沙箱基地址元组
        :param target_desc: 目标架构描述
        :param speculator_cls: 推测器类
        :param tracer_cls: 追踪器类
        :param interpreter_cls: 额外解释器类
        :param enable_mismatch_check_mode: 是否启用不匹配检查模式
        """
        self._architecture = (uc.UC_ARCH_X86, uc.UC_MODE_64)
        self._flags_id = x86ucc.UC_X86_REG_EFLAGS

        # 初始化溢出/下溢填充区（全零）
        self.underflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.UNDERFLOW_PAD))
        self.overflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.OVERFLOW_PAD))

        super().__init__(bases, target_desc, speculator_cls, tracer_cls, interpreter_cls,
                         enable_mismatch_check_mode)

    def _load_input(self, input_: InputData) -> None:
        """
        根据输入对象设置模拟器中的内存和寄存器值，
        同时设置每个 actor 的内存权限。

        x86-64 输入加载步骤：
        1. 为每个 actor 写入内存区域（溢出区、主数据区、故障区、GPR区、SIMD区）
        2. 修补 EFLAGS 值（确保保留的有效位正确）
        3. 初始化通用寄存器（GPR）
        4. 初始化 SIMD 寄存器（128位 XMM，YMM 上128位忽略）
        5. 设置特殊寄存器（RSP、RBP、R14指向沙箱数据区）

        :param input_: 输入对象，包含每个 actor 的内存和寄存器值
        """

        def patch_flags(flags: np.uint64) -> np.uint64:
            """ 修补 EFLAGS 值：保留有效位（0x2263 = CF,PF,AF,ZF,SF,OF,TF,IF,DF）
            并强制设置 bit 1（_RESERVED，x86 规范要求为 1）"""
            return (flags & np.uint64(2263)) | np.uint64(2)

        def write_area(area: DataArea, actor_id: int, data: bytes) -> None:
            """ 将数据写入指定 actor 的指定数据区域 """
            em.mem_write(self.layout.get_data_addr(area, actor_id), data)

        # 快捷变量
        em = self.emulator
        regs = self._uc_target_desc.usable_registers

        # 为每个 actor 初始化内存：
        n_actors = self.state.current_test_case().n_actors()
        for actor_id in range(n_actors):
            input_fragment = input_[actor_id]

            # - 初始化溢出区为零
            write_area(DataArea.OVERFLOW_PAD, actor_id, self.overflow_pad_values)
            write_area(DataArea.UNDERFLOW_PAD, actor_id, self.underflow_pad_values)

            # - 沙箱数据页
            write_area(DataArea.MAIN, actor_id, input_fragment['main'].tobytes())
            write_area(DataArea.FAULTY, actor_id, input_fragment['faulty'].tobytes())

            # - GPR 区域
            # 注意：执行器使用 GPR 区域初始化 EFLAGS，需要修补以确保一致性
            input_fragment['gpr'][6] = patch_flags(input_fragment['gpr'][6])
            write_area(DataArea.GPR, actor_id, input_fragment['gpr'].tobytes())

            # - SIMD 区域
            write_area(DataArea.SIMD, actor_id, input_fragment['simd'].tobytes())

        # 寄存器使用主 actor 的输入初始化
        input_fragment = input_[0]

        # - 初始化通用寄存器
        value: np.uint64
        for i, value in enumerate(input_fragment['gpr']):
            em.reg_write(regs[i], int(value))

        # 同样修补 EFLAGS 寄存器值
        em.reg_write(x86ucc.UC_X86_REG_EFLAGS, int(patch_flags(input_fragment['gpr'][6])))
        # 设置特殊寄存器：栈指针、基指针、数据区基址
        em.reg_write(x86ucc.UC_X86_REG_RSP, self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(x86ucc.UC_X86_REG_RBP, self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(x86ucc.UC_X86_REG_R14, self.layout.get_data_addr(DataArea.MAIN, 0))

        # - 初始化 SIMD 寄存器
        # Unicorn 不完全支持 YMM（256位），因此只初始化 XMM（128位）
        # 两个连续的 64 位值组合为一个 128 位 XMM 值
        simd_values: List[int] = []
        for i, val in enumerate(input_fragment['simd']):
            if i % 4 == 0:
                simd_values.append(int(val))  # XMM 低64位
            elif i % 4 == 1:
                simd_values[-1] |= int(val) << 64  # XMM 高64位（与低64位组合）
            else:
                # YMM 的上128位被忽略（Unicorn 不支持）
                continue
        for i, simd_value in enumerate(simd_values):
            em.reg_write(self._uc_target_desc.usable_simd128_registers[i], simd_value)

    def print_registers(self, oneline: bool = False) -> None:
        """ 打印当前 x86-64 寄存器值。

        地址值被压缩显示：沙箱数据区地址显示为 base+offset，
        其他地址显示为完整十六进制值。

        :param oneline: 是否单行显示（支持彩色输出）
        """

        def compressed(val: int) -> str:
            """ 压缩地址显示：数据区地址显示为偏移量，其他显示完整值 """
            if self.layout.is_data_addr(val):
                return f"base+0x{self.layout.data_addr_to_offset(val):<9x}"
            return f"0x{val:016x}"

        em = self.emulator
        rax = compressed(em.reg_read(x86ucc.UC_X86_REG_RAX))  # type: ignore
        rbx = compressed(em.reg_read(x86ucc.UC_X86_REG_RBX))  # type: ignore
        rcx = compressed(em.reg_read(x86ucc.UC_X86_REG_RCX))  # type: ignore
        rdx = compressed(em.reg_read(x86ucc.UC_X86_REG_RDX))  # type: ignore
        rsi = compressed(em.reg_read(x86ucc.UC_X86_REG_RSI))  # type: ignore
        rdi = compressed(em.reg_read(x86ucc.UC_X86_REG_RDI))  # type: ignore

        if not oneline:
            print("\n\nRegisters:")
            print(f"rax: {rax}")
            print(f"rbx: {rbx}")
            print(f"rcx: {rcx}")
            print(f"rdx: {rdx}")
            print(f"rsi: {rsi}")
            print(f"rdi: {rdi}")
        else:
            if CONF.color:
                print(f"  {BLUE}rax={COL_RESET}{rax} "
                      f"{BLUE}rbx={COL_RESET}{rbx} "
                      f"{BLUE}rcx={COL_RESET}{rcx}\n"
                      f"  {BLUE}rdx={COL_RESET}{rdx} "
                      f"{BLUE}rsi={COL_RESET}{rsi} "
                      f"{BLUE}rdi={COL_RESET}{rdi}\n"
                      f"  {BLUE}flags={COL_RESET}0b{em.reg_read(x86ucc.UC_X86_REG_EFLAGS):012b}\n"
                      f"  {BLUE}xmm0={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM0):032x} "
                      f"{BLUE}xmm1={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM1):032x} \n"
                      f"  {BLUE}xmm2={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM2):032x} "
                      f"{BLUE}xmm3={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM3):032x} \n"
                      f"  {BLUE}xmm4={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM4):032x} "
                      f"{BLUE}xmm5={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM5):032x} \n"
                      f"  {BLUE}xmm6={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM6):032x} "
                      f"{BLUE}xmm7={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM7):032x} \n")
            else:
                print(f"  rax={rax} "
                      f"rbx={rbx} "
                      f"rcx={rcx} "
                      f"rdx={rdx}\n"
                      f"  rsi={rsi} "
                      f"rdi={rdi} "
                      f"flags=0b{em.reg_read(x86ucc.UC_X86_REG_EFLAGS):012b}\n"
                      f"  xmm0=0x{em.reg_read(x86ucc.UC_X86_REG_XMM0):032x} "
                      f"xmm1=0x{em.reg_read(x86ucc.UC_X86_REG_XMM1):032x} \n"
                      f"  xmm2=0x{em.reg_read(x86ucc.UC_X86_REG_XMM2):032x} "
                      f"xmm3=0x{em.reg_read(x86ucc.UC_X86_REG_XMM3):032x} \n"
                      f"  xmm4=0x{em.reg_read(x86ucc.UC_X86_REG_XMM4):032x} "
                      f"xmm5=0x{em.reg_read(x86ucc.UC_X86_REG_XMM5):032x} \n"
                      f"  xmm6=0x{em.reg_read(x86ucc.UC_X86_REG_XMM6):032x} "
                      f"xmm7=0x{em.reg_read(x86ucc.UC_X86_REG_XMM7):032x} \n")


# ==================================================================================================
# 公共：ARM64 实现
# ==================================================================================================
class ARM64UnicornModel(UnicornModel):
    """
    ARM64 架构的模型实现。

    使用 Unicorn 的 ARM64 模式，处理 ARM64 特定的输入加载和寄存器初始化。
    """

    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:
        """
        初始化 ARM64 模型。

        :param bases: 沙箱基地址元组
        :param target_desc: 目标架构描述
        :param speculator_cls: 推测器类
        :param tracer_cls: 追踪器类
        :param interpreter_cls: 额外解释器类
        :param enable_mismatch_check_mode: 是否启用不匹配检查模式
        """
        self._architecture = (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        self._flags_id = armucc.UC_ARM64_REG_NZCV

        # 初始化溢出/下溢填充区（全零）
        self.underflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.UNDERFLOW_PAD))
        self.overflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.OVERFLOW_PAD))

        super().__init__(bases, target_desc, speculator_cls, tracer_cls, interpreter_cls,
                         enable_mismatch_check_mode)

    def _load_input(self, input_: InputData) -> None:
        """
        根据输入对象设置模拟器中的内存和寄存器值，
        同时设置每个 actor 的内存权限。

        ARM64 输入加载步骤：
        1. 为每个 actor 写入内存区域
        2. 修补 NZCV 标志位值（左移28位到标志位位置）
        3. 初始化通用寄存器
        4. 设置特殊寄存器（SP、actor基址寄存器）

        :param input_: 输入对象，包含每个 actor 的内存和寄存器值
        """

        # FIXME: 与 x86 的代码去重

        def patch_flags(flags: np.uint64) -> np.uint64:
            """ 修补 NZCV 标志位：将值左移28位到 ARM64 标志位位置
            （N[31], Z[30], C[29], V[28]）"""
            return (flags << np.uint64(28)) % np.uint64(pow(2, 64) - 1)

        def write_area(area: DataArea, actor_id: int, data: bytes) -> None:
            """ 将数据写入指定 actor 的指定数据区域 """
            em.mem_write(self.layout.get_data_addr(area, actor_id), data)

        # 快捷变量
        em = self.emulator
        regs = self._uc_target_desc.usable_registers

        # 为每个 actor 初始化内存：
        n_actors = self.state.current_test_case().n_actors()
        init_gpr: List[np.uint64]
        for actor_id in range(n_actors):
            input_fragment = input_[actor_id].copy()

            # - 初始化溢出区为零
            write_area(DataArea.OVERFLOW_PAD, actor_id, self.overflow_pad_values)
            write_area(DataArea.UNDERFLOW_PAD, actor_id, self.underflow_pad_values)

            # - 沙箱数据页
            write_area(DataArea.MAIN, actor_id, input_fragment['main'].tobytes())
            write_area(DataArea.FAULTY, actor_id, input_fragment['faulty'].tobytes())

            # - GPR 区域
            # 注意：执行器使用 GPR 区域初始化 NZCV，需要修补以确保一致性
            input_fragment['gpr'][6] = patch_flags(input_fragment['gpr'][6])
            write_area(DataArea.GPR, actor_id, input_fragment['gpr'].tobytes())

            # - SIMD 区域
            write_area(DataArea.SIMD, actor_id, input_fragment['simd'].tobytes())

            # 保存主 actor 的 GPR 区域用于寄存器初始化
            if actor_id == 0:
                init_gpr = input_fragment['gpr']

        # - 初始化通用寄存器
        value: np.uint64
        for i, value in enumerate(init_gpr):
            em.reg_write(regs[i], int(value))

        # 同样修补 NZCV 标志位寄存器值
        em.reg_write(self._uc_target_desc.flags_register, int(init_gpr[6]))
        # 设置特殊寄存器：栈指针、actor数据区基址
        em.reg_write(self._uc_target_desc.sp_register,
                     self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(self._uc_target_desc.actor_base_register,
                     self.layout.get_data_addr(DataArea.MAIN, 0))

    def print_registers(self, oneline: bool = False) -> None:
        """ 打印当前 ARM64 寄存器值。
        :param oneline: 是否单行显示（支持彩色输出）
        """

        def compressed(val: int) -> str:
            """ 压缩地址显示 """
            if self.layout.is_data_addr(val):
                return f"base+0x{self.layout.data_addr_to_offset(val):<9x}"
            return f"0x{val:016x}"

        em = self.emulator
        x0 = compressed(em.reg_read(armucc.UC_ARM64_REG_X0))  # type: ignore
        x1 = compressed(em.reg_read(armucc.UC_ARM64_REG_X1))  # type: ignore
        x2 = compressed(em.reg_read(armucc.UC_ARM64_REG_X2))  # type: ignore
        x3 = compressed(em.reg_read(armucc.UC_ARM64_REG_X3))  # type: ignore
        x4 = compressed(em.reg_read(armucc.UC_ARM64_REG_X4))  # type: ignore
        x5 = compressed(em.reg_read(armucc.UC_ARM64_REG_X5))  # type: ignore
        flags = f"{em.reg_read(armucc.UC_ARM64_REG_NZCV) >> 28:04b}"  # type: ignore

        if not oneline:
            print("\n\nRegisters:")
            print(f"x0: {x0}")
            print(f"x1: {x1}")
            print(f"x2: {x2}")
            print(f"x3: {x3}")
            print(f"x4: {x4}")
            print(f"x5: {x5}")
        else:
            if CONF.color:
                print(f"  {BLUE}x0={COL_RESET}{x0} "
                      f"{BLUE}x1={COL_RESET}{x1} "
                      f"{BLUE}x2={COL_RESET}{x2}\n"
                      f"  {BLUE}x3={COL_RESET}{x3} "
                      f"{BLUE}x4={COL_RESET}{x4} "
                      f"{BLUE}x5={COL_RESET}{x5}\n"
                      f"  {BLUE}flags={COL_RESET}0b{flags}\n")
            else:
                print(f"  x0={x0} "
                      f"x1={x1} "
                      f"x2={x2} "
                      f"x3={x3}\n"
                      f"  x4={x4} "
                      f"x5={x5} "
                      f"flags=0b{flags}\n")

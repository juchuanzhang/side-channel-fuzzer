"""
文件：额外解释器的抽象接口和架构特定实现。

额外解释器(extra interpreter)是提供 Unicorn 之外额外解释逻辑的组件。
Unicorn 本身只能模拟指令的基本执行效果，但某些场景需要额外的解释：

1. 宏指令解释：测试用例中的宏指令（如 actor 切换、权限设置）不是真实 CPU 指令，
   需要额外解释器来模拟其效果
2. VM 客户模式模拟：在虚拟机客户模式下，某些指令会导致 VMEXIT，
   需要解释器来模拟这种行为
3. 用户空间执行模拟：在用户空间模式下，特权指令会导致异常，
   需要解释器来判断和触发故障
4. 故障权限检查：页表权限检查需要额外的解释逻辑

模块结构：
- ExtraInterpreter: 抽象基类
- X86ExtraInterpreter: x86 架构的实现
- ARMExtraInterpreter: ARM 架构的实现
- _MacroInterpreterCommon: 宏指令解释的通用逻辑
- _X86MacroInterpreter: x86 特定的宏解释
- _ARM64MacroInterpreter: ARM64 特定的宏解释
- _X86VMInterpreter: VM 客户模式模拟
- _X86UserspaceInterpreter: 用户空间模式模拟
- _FaultInterpreterCommon: 故障权限检查通用逻辑
- _X86FaultInterpreter: x86 页权限检查
- _ARM64FaultInterpreter: ARM64 页权限检查

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Tuple, Dict, Callable, Set, Optional, List, Final

from unicorn import UC_ERR_NOMEM, UcError, UC_ERR_EXCEPTION, UC_MEM_WRITE, UC_ERR_INSN_INVALID, \
    UC_ERR_READ_PROT, UC_ERR_WRITE_PROT
import unicorn.x86_const as x86ucc  # type: ignore  # no type hints available

from ..tc_components.actor import ActorMode, ActorPL, Actor, ActorID, PTEMask
from ..sandbox import CodeArea, DataArea
from ..logs import warning

if TYPE_CHECKING:
    from .model import UnicornModel
    from .execution_context import ModelExecutionState
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..tc_components.instruction import Instruction
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_binary import SymbolTableEntry
    from ..tc_components.test_case_data import InputData

CRITICAL_ERROR = UC_ERR_NOMEM  # 模型永不处理此错误，因此总是会导致崩溃


# ==================================================================================================
# 公共接口
# ==================================================================================================
class ExtraInterpreter(ABC):
    """
    额外解释器：实现 Unicorn 之外的额外解释逻辑。

    主要功能包括：
    - 宏指令的解释执行（如 actor 切换、权限设置等测试框架专用指令）
    - VM 客户模式下的指令模拟（触发 VMEXIT 的指令）
    - 用户空间模式下的特权指令检测（触发异常的指令）

    该类提供通用接口，由 ISA 特定的子类实例化。
    """
    _model: Final[UnicornModel]
    """ 模型实例 """
    _target_desc: Final[TargetDesc]
    """ 目标架构描述 """
    _uc_target_desc: Final[UnicornTargetDesc]
    """ Unicorn 特定的目标架构描述 """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        """
        初始化额外解释器。
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        """
        self._target_desc = target_desc
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ 加载测试用例到解释器 """

    @abstractmethod
    def load_input(self, input_: InputData) -> None:
        """ 加载输入到解释器 """

    def interpret_instruction(self, address: int, state: ModelExecutionState) -> None:
        """
        解释当前指令（存储在 state.current_instruction 中）。

        处理逻辑：
        1. 如果是宏指令，调用宏解释器
        2. 如果当前 actor 是 VM 客户模式，模拟 VM 执行行为
        3. 如果当前 actor 是用户空间模式，模拟用户空间执行行为

        :param address: 指令地址
        :param state: 模型执行状态
        """
        instruction = state.current_instruction

        if instruction.name == "macro":
            self._interpret_macro(instruction, address)

        # 在 VM 客户模式下模拟无效操作码
        if state.current_actor.mode == ActorMode.GUEST:
            self._emulate_vm_execution(address)
        elif state.current_actor.privilege_level == ActorPL.USER:
            self._emulate_userspace_execution(address)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 解释给定的内存访问。默认不做额外处理。 """

    @abstractmethod
    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        """ 模拟宏指令的执行效果（抽象方法，由子类实现）"""

    @abstractmethod
    def _emulate_vm_execution(self, address: int) -> None:
        """ 模拟 VM 客户模式下的指令执行（抽象方法，由子类实现）"""

    @abstractmethod
    def _emulate_userspace_execution(self, address: int) -> None:
        """ 模拟用户空间模式下的指令执行（抽象方法，由子类实现）"""


# ==================================================================================================
# 架构特定实现
# ==================================================================================================
class X86ExtraInterpreter(ExtraInterpreter):
    """
    x86 架构的额外解释器实现。

    组合了四个子解释器：
    - _macro_interpreter: x86 宏指令解释
    - _vm_interpreter: VM 客户模式模拟
    - _userspace_interpreter: 用户空间模式模拟
    - _fault_interpreter: x86 故障权限检查
    """

    _macro_interpreter: _X86MacroInterpreter
    _vm_interpreter: _X86VMInterpreter
    _userspace_interpreter: _X86UserspaceInterpreter
    _fault_interpreter: _X86FaultInterpreter

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        """
        初始化 x86 额外解释器，创建各子解释器实例。
        """
        super().__init__(target_desc, model)
        self._macro_interpreter = _X86MacroInterpreter(model, target_desc)
        self._vm_interpreter = _X86VMInterpreter(model, target_desc)
        self._userspace_interpreter = _X86UserspaceInterpreter(model, target_desc)
        self._fault_interpreter = _X86FaultInterpreter(model, target_desc)

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ 加载测试用例到各子解释器，重置 VM 和用户空间解释器状态。 """
        self._macro_interpreter.load_test_case(test_case)
        self._fault_interpreter.load_test_case(test_case)
        self._vm_interpreter.reset()
        self._userspace_interpreter.reset()

    def load_input(self, input_: InputData) -> None:
        """ 加载输入到故障解释器（设置页权限）。 """
        self._fault_interpreter.load_input(input_)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 解释内存访问：调用故障解释器检查用户/内核访问权限。 """
        super().interpret_mem_access(access, address, size, value)
        self._fault_interpreter.induce_user_faults(self._model.state.current_actor, address)

    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        """ 通过宏解释器解释宏指令。 """
        self._macro_interpreter.interpret(macro, pc)

    def _emulate_vm_execution(self, address: int) -> None:
        """ 通过 VM 解释器模拟 VM 客户模式执行。 """
        self._vm_interpreter.interpret(self._model.state.current_instruction, address)

    def _emulate_userspace_execution(self, address: int) -> None:
        """ 通过用户空间解释器模拟用户空间执行。 """
        self._userspace_interpreter.interpret(self._model.state.current_instruction, address)


class ARMExtraInterpreter(ExtraInterpreter):
    """
    ARM 架构的额外解释器实现。

    ARM 架构目前不需要 VM 和用户空间模拟，
    仅使用宏解释器和故障解释器。
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        """ 初始化 ARM 额外解释器。 """
        super().__init__(target_desc, model)
        self._macro_interpreter = _ARM64MacroInterpreter(model, target_desc)
        self._fault_interpreter = _ARM64FaultInterpreter(model, target_desc)

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ 加载测试用例到宏和故障解释器。 """
        self._macro_interpreter.load_test_case(test_case)
        self._fault_interpreter.load_test_case(test_case)

    def load_input(self, input_: InputData) -> None:
        """ 加载输入到故障解释器。 """
        self._fault_interpreter.load_input(input_)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 解释内存访问：调用 ARM64 故障解释器处理跨页故障。 """
        super().interpret_mem_access(access, address, size, value)
        self._fault_interpreter.emulate_crossing_fault(access, address, size)

    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        """ 通过 ARM64 宏解释器解释宏指令。 """
        self._macro_interpreter.interpret(macro, pc)

    def _emulate_vm_execution(self, address: int) -> None:
        """ ARM64 不支持 VM 模式模拟（空实现）。 """
        pass

    def _emulate_userspace_execution(self, address: int) -> None:
        """ ARM64 目前不支持用户空间模拟（空实现）。 """
        pass


# ==================================================================================================
# 私有：宏指令解释
# ==================================================================================================

_MacroCallback = Callable[[int, int, int, int], None]
""" 宏回调函数类型：接受4个参数（从宏符号表解码）"""


class _MacroInterpreterCommon:
    """
    架构无关宏指令解释和通用逻辑的实现。

    宏指令是测试框架专用的伪指令，不是真实 CPU 指令。
    它们用于控制测试用例的执行流程，如切换 actor、设置权限等。

    支持的通用宏指令：
    - measurement_start: 开始测量（启用追踪）
    - measurement_end: 结束测量（禁用追踪）
    - switch: 切换到另一个 actor 的函数
    - fault_handler: 故障处理宏（空实现，仅占位）

    宏参数从符号表中解码，每个参数占16位：
    arg & 0xFFFF, (arg >> 16) & 0xFFFF, (arg >> 32) & 0xFFFF, (arg >> 48) & 0xFFFF
    """
    _model: UnicornModel
    _uc_target_desc: UnicornTargetDesc

    _test_case: Optional[TestCaseProgram] = None
    _function_table: List[SymbolTableEntry]
    """ 函数符号表（type_ == 0 的符号），按 arg 排序 """
    _macro_table: List[SymbolTableEntry]
    """ 宏符号表（type_ != 0 的符号）"""
    _macro_callbacks: Dict[str, _MacroCallback]
    """ 宏名称到回调函数的映射 """

    _curr_targets: Dict[str, int]
    """ 当前存储的切换目标地址（用于 k2u, u2k, h2g, g2h 切换）"""
    _sid_to_actor: Dict[int, Actor]
    """ section ID 到 actor 对象的映射 """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        """
        初始化宏解释器，设置通用宏回调。
        """
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self._function_table = []
        self._macro_table = []
        self._curr_targets = {
            "h2g": 0,  # hypervisor 到 guest 切换目标
            "g2h": 0,  # guest 到 hypervisor 切换目标
            "k2u": 0,  # kernel 到 user 切换目标
            "u2k": 0,  # user 到 kernel 切换目标
        }
        self._macro_callbacks = {
            "measurement_start": self._macro_measurement_start,
            "measurement_end": self._macro_measurement_end,
            "switch": self._macro_switch,
            "fault_handler": lambda *_: None,
        }

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        加载测试用例到宏解释器。

        从测试用例的符号表中提取函数表和宏表，
        建立 section ID 到 actor 的映射。

        :param test_case: 测试用例程序
        """
        self._test_case = test_case
        test_case_obj = test_case.get_obj()
        symbol_table = test_case_obj.symbol_table()

        self._function_table = [sym for sym in symbol_table if sym.type_ == 0]
        self._function_table.sort(key=lambda s: [s.arg])
        self._macro_table = [sym for sym in symbol_table if sym.type_ != 0]
        self._sid_to_actor = {actor.get_id(): actor for actor in test_case.get_actors()}

    def interpret(self, macro: Instruction, pc: int) -> None:
        """
        解释给定的宏指令并在模型上执行对应的逻辑。

        步骤：
        1. 根据 PC 地址和 actor ID 计算宏偏移量
        2. 从符号表中查找宏参数
        3. 从宏名称获取回调函数
        4. 执行回调

        :param macro: 宏指令对象
        :param pc: 宏指令的地址
        """
        actor_id = self._model.state.current_actor.get_id()
        macro_start = self._model.layout.get_code_addr(CodeArea.MAIN, actor_id)
        macro_offset = pc - macro_start
        macro_args = self._get_macro_args(actor_id, macro_offset)
        macro_name = macro.operands[0].value.lower()[1:]  # 去掉前缀 '$' 或 '.'
        if macro_name not in self._macro_callbacks:
            warning("interpret", f"unknown macro: {macro_name}")
            raise UcError(CRITICAL_ERROR)

        interpreter_func = self._macro_callbacks[macro_name]
        interpreter_func(*macro_args)

    def _get_macro_args(self, section_id: int, section_offset: int) -> Tuple[int, int, int, int]:
        """
        从符号表中获取宏参数。

        每个宏在符号表中有一个条目，arg 字段编码了4个16位参数：
        - arg & 0xFFFF: 第1个参数
        - (arg >> 16) & 0xFFFF: 第2个参数
        - (arg >> 32) & 0xFFFF: 第3个参数
        - (arg >> 48) & 0xFFFF: 第4个参数

        :param section_id: 代码段 ID（actor ID）
        :param section_offset: 宏在代码段内的偏移量
        :return: 4个解码后的参数
        """
        for symbol in self._macro_table:
            if symbol.sid == section_id and symbol.offset == section_offset:
                args = symbol.arg
                return args & 0xFFFF, (args >> 16) & 0xFFFF, (args >> 32) & 0xFFFF, \
                    (args >> 48) & 0xFFFF
        warning("get_macro_args", "macro not found in symbol table")
        raise UcError(CRITICAL_ERROR)

    def _find_function_by_id(self, function_id: int) -> SymbolTableEntry:
        """
        根据函数 ID 在函数表中查找对应的符号表条目。

        :param function_id: 函数 ID（函数表的索引）
        :return: 符号表条目
        """
        if function_id < 0 or function_id >= len(self._function_table):
            warning("find_function_by_id", "function not found in symbol table")
            raise UcError(CRITICAL_ERROR)
        return self._function_table[function_id]

    def _macro_measurement_start(self, _: int, __: int, ___: int, ____: int) -> None:
        """ measurement_start 宏：开始测量（仅在非推测状态下启用追踪）。
        推测状态下不启用追踪，因为推测观测不应被记录。 """
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = True

    def _macro_measurement_end(self, _: int, __: int, ___: int, ____: int) -> None:
        """ measurement_end 宏：结束测量（仅在非推测状态下禁用追踪）。 """
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = False

    def _macro_switch(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        switch 宏：切换到另一个 actor 的指定函数。

        步骤：
        1. 计算目标函数地址
        2. 设置 PC 寄存器跳转到目标函数
        3. 更新数据区基址和栈指针寄存器
        4. 更新当前 actor 引用

        :param section_id: 目标 actor 的 ID
        :param function_id: 目标函数的 ID
        """
        model = self._model
        layout = model.layout

        # PC 更新：跳转到目标函数
        section_addr = layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        model.emulator.reg_write(self._uc_target_desc.pc_register, function_addr)

        # 数据区基址和栈指针更新
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(self._uc_target_desc.sp_register, new_sp)

        # actor 更新
        model.state.current_actor = self._sid_to_actor[section_id]


class _X86MacroInterpreter(_MacroInterpreterCommon):
    """
    x86 特定宏指令的解释实现。

    支持的 x86 特定宏指令：
    - switch_k2u/u2k: 内核/用户空间切换（模拟 syscall/sysret）
    - switch_h2g/g2h: hypervisor/guest 切换（模拟 VMRUN/VMEXIT）
    - set_k2u_target/set_u2k_target: 设置切换目标地址
    - set_h2g_target/set_g2h_target: 设置 VM 切换目标地址
    - landing_k2u/u2k/h2g/g2h: 切换后的着陆点（清零寄存器）
    - set_data_permissions: 手动设置数据权限

    AMD CPU 的特殊处理：
    - VMRUN 会清零 RAX（模拟 AMD 行为）
    - VMEXIT 会清零 RAX（模拟 AMD 行为）
    """
    _pseudo_lstar: int
    """ 伪 LSTAR 寄存器值（模拟 MSR_LSTAR，用于 u2k 切换目标）"""
    _is_amd: bool
    """ 是否为 AMD CPU """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        """ 初始化 x86 宏解释器，注册 x86 特定宏回调。 """
        super().__init__(model, target_desc)
        self._is_amd = target_desc.cpu_desc.vendor == "AMD"
        self._macro_callbacks.update({
            "switch_k2u": self._macro_switch_k2u,
            "switch_u2k": self._macro_switch_u2k,
            "set_k2u_target": self._macro_set_k2u_target,
            "set_u2k_target": self._macro_set_u2k_target,
            "switch_h2g": self._macro_switch_h2g,
            "switch_g2h": self._macro_switch_g2h,
            "set_h2g_target": self._macro_set_h2g_target,
            "set_g2h_target": self._macro_set_g2h_target,
            "landing_k2u": self._macro_landing_k2u,
            "landing_u2k": self._macro_landing_u2k,
            "landing_h2g": self._macro_landing_h2g,
            "landing_g2h": self._macro_landing_g2h,
            "set_data_permissions": self._macro_set_data_permissions,
        })

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ 加载测试用例，初始化伪 LSTAR 为退出地址。 """
        super().load_test_case(test_case)
        self._pseudo_lstar = self._model.state.exit_addr

    def _macro_set_k2u_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        set_k2u_target 宏：解码参数并将目标地址存储到 _curr_targets["k2u"]。

        :param section_id: 目标 actor 的 section ID
        :param function_id: 目标函数的 ID
        """
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["k2u"] = function_addr

    def _macro_switch_k2u(self, section_id: int, _: int, __: int, ___: int) -> None:
        """
        switch_k2u 宏：从内核切换到用户空间。

        步骤：
        1. 从 _curr_targets["k2u"] 读取目标地址并设置 PC
        2. 更新数据区基址和栈指针
        3. 更新当前 actor

        :param section_id: 目标 actor 的 section ID
        """
        model = self._model
        layout = model.layout

        # PC 更新：跳转到预设的 k2u 目标地址
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["k2u"])

        # 数据区基址和栈指针更新
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor 更新
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_set_u2k_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        set_u2k_target 宏：设置 LSTAR 为目标地址（仅在内核模式下）。
        用户模式下调用会触发异常。

        :param section_id: 目标 actor 的 section ID
        :param function_id: 目标函数的 ID
        """
        if self._model.state.current_actor.privilege_level != ActorPL.KERNEL:
            # 用户模式下设置 LSTAR 是特权操作，触发异常
            self._model.do_soft_fault(UC_ERR_EXCEPTION)
            return
        model = self._model

        # 更新伪 LSTAR（模拟 MSR_LSTAR）
        section_addr = model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._pseudo_lstar = function_addr

    def _macro_switch_u2k(self, section_id: int, _: int, __: int, ___: int) -> None:
        """
        switch_u2k 宏：从用户空间切换到内核。

        步骤：
        1. 从伪 LSTAR 读取目标地址并设置 PC
        2. 更新数据区基址和栈指针
        3. 更新当前 actor

        :param section_id: 目标 actor 的 section ID
        """
        model = self._model

        # PC 更新：跳转到伪 LSTAR 地址（模拟 SYSCALL 目标）
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._pseudo_lstar)

        # 数据区基址和栈指针更新
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor 更新
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_switch_h2g(self, section_id: int, _: int, __: int, ___: int) -> None:
        """
        switch_h2g 宏：从 hypervisor 切换到 guest。

        步骤：
        1. 跳转到预设的 h2g 目标地址
        2. 更新数据区基址和栈指针
        3. 重置标志位（模拟 VMRUN 行为）
        4. 更新当前 actor
        5. AMD CPU 清零 RAX（模拟 VMRUN 副作用）

        :param section_id: 目标 actor 的 section ID
        """
        model = self._model

        # PC 更新
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["h2g"])

        # 数据区基址和栈指针更新
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # 重置标志位
        model.emulator.reg_write(x86ucc.UC_X86_REG_EFLAGS, 0b10)

        # actor 更新
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMRUN 清零 RAX（模拟 AMD VMRUN 副作用）
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_switch_g2h(self, section_id: int, _: int, __: int, ___: int) -> None:
        """
        switch_g2h 宏：从 guest 切换到 hypervisor。

        步骤：
        1. 跳转到预设的 g2h 目标地址
        2. 更新数据区基址和栈指针
        3. 更新当前 actor
        4. AMD CPU 清零 RAX（模拟 VMEXIT 副作用）

        :param section_id: 目标 actor 的 section ID
        """
        model = self._model

        # PC 更新
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["g2h"])

        # 数据区基址和栈指针更新
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor 更新
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMEXIT 清零 RAX（模拟 AMD VMEXIT 副作用）
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_set_h2g_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """ set_h2g_target 宏：设置 hypervisor 到 guest 的切换目标地址。 """
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["h2g"] = function_addr

    def _macro_set_g2h_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """ set_g2h_target 宏：设置 guest 到 hypervisor 的切换目标地址。 """
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["g2h"] = function_addr

    def _macro_landing_k2u(self, _: int, __: int, ___: int, ____: int) -> None:
        """ landing_k2u 宏：内核到用户切换的着陆点，清零 RCX。 """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_u2k(self, _: int, __: int, ___: int, ____: int) -> None:
        """ landing_u2k 宏：用户到内核切换的着陆点，清零 RCX。 """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_h2g(self, _: int, __: int, ___: int, ____: int) -> None:
        """ landing_h2g 宏：hypervisor 到 guest 切换的着陆点（无操作）。 """

    def _macro_landing_g2h(self, _: int, __: int, ___: int, ____: int) -> None:
        """ landing_g2h 宏：guest 到 hypervisor 切换的着陆点（无操作）。 """

    def _macro_set_data_permissions(self, actor_id: int, must_set: int, must_clear: int,
                                    _: int) -> None:
        """ set_data_permissions 宏：手动设置 actor 的数据权限。 """


class _ARM64MacroInterpreter(_MacroInterpreterCommon):
    """
    ARM64 特定宏指令的解释实现。

    目前 ARM64 仅使用通用宏回调，没有额外特有宏指令。
    fault_handler 宏在 ARM64 中为空实现（lambda）。
    """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        """ 初始化 ARM64 宏解释器。 """
        super().__init__(model, target_desc)
        self._is_amd = target_desc.cpu_desc.vendor == "AMD"
        self._macro_callbacks.update({
            "fault_handler": lambda *_: None,
        })


# ==================================================================================================
# 私有：VM 模式和用户空间模拟
# ==================================================================================================
class _X86VMInterpreter:
    """
    为 Unicorn 模拟器添加 VM 客户模式执行模拟能力。

    在 VM 客户模式下，某些指令会导致 VMEXIT（退出虚拟机），
    需要模拟器来检测和触发这些故障。

    实现方式：
    - always_exit_instructions: 始终导致 VMEXIT 的指令集合
    - always_exiting_registers: 始终导致 VMEXIT 的控制寄存器集合
    - safe_address_cache: 已确认安全的指令地址缓存（加速检测）
    - 对于 MOV 指令到控制寄存器：检查是否写入 VMEXIT 寄存器
    """

    safe_address_cache: Set[int]
    """ 已确认安全的指令地址缓存，避免重复检测 """
    always_exit_instructions: Set[str] = {
        # 始终导致 VMEXIT 的指令列表（VMX 非根操作模式下的指令）
        "cpuid", "getsec", "xgetbv", "xsetbv", "xrstors", "xsaves", "invd", "invept", "invvpid",
        "vmptrld", "vmptrst", "vmclear", "vmxon", "vmxoff", "vmlaunch", "vmresume", "vmcall",
        "vmfunc", "hlt", "invlpg", "invpcid", "lgdt", "lidt", "lldt", "ltr", "sgdt", "sidt", "sldt",
        "str", "loadiwkey", "monitor", "mwait", "rdpmc", "rdrand", "rdseed", "rdtsc", "rdtscp",
        "rsm", "tpause", "umwait", "vmread", "vmwrite", "wbinvd", "wbnoinvd", "wrmsr", "fxsave",
        "fxsave64", "in", "ins", "insb", "insw", "insd", "out", "outs", "outsb", "outsw", "outsd",
        "pause", "rdmsr", "swapgs"
    }
    always_exiting_registers = ["cr0", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"]
    """ 写入这些寄存器始终导致 VMEXIT """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc) -> None:
        """
        初始化 VM 解释器。
        :param model: Unicorn 模型实例
        :param target_desc: 目标架构描述
        """
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self.safe_address_cache = set()

    def reset(self) -> None:
        """ 重置解释器状态；必须在每个新测试用例时调用。
        清空安全地址缓存。
        """
        self.safe_address_cache.clear()

    def interpret(self, inst: Instruction, address: int) -> None:
        """
        解释 VM 客户模式下的指令。

        处理逻辑：
        1. 如果地址在安全缓存中，跳过检测
        2. 如果指令在 always_exit_instructions 集合中，触发 VMEXIT（软故障）
           - 对于有内存操作数的指令，先暴露内存访问
        3. 如果是 MOV 指令，检查是否写入 VMEXIT 寄存器
        4. 其他指令标记为安全（加入缓存）

        :param inst: 指令对象
        :param address: 指令地址
        """
        if address in self.safe_address_cache:
            return  # 已确认安全，跳过
        stripped_name = inst.name.split()[-1]

        # 始终导致 VMEXIT 的指令
        if stripped_name in self.always_exit_instructions:
            # 确保内存访问在故障前被暴露到轨迹中
            if inst.has_mem_operand(True):
                ops = inst.get_mem_operands(True)
                for op in ops:
                    words = op.value.split("+")
                    for word in words:
                        reg = self._uc_target_desc.reg_str_to_constant.get(word.lower(), 0)
                        if reg:
                            value = int(self._model.emulator.reg_read(reg))  # type: ignore
                            self._model.tracer.observe_mem_access(UC_MEM_WRITE, value, 8, 0)
            # 触发 VMEXIT（以无效指令故障的形式）
            self._model.do_soft_fault(UC_ERR_INSN_INVALID)
            return

        # 条件性 VMEXIT：MOV 到控制/调试寄存器
        if stripped_name == "mov":
            if not self._emulate_move(inst, address):
                return

        # 安全指令：加入缓存以加速后续检测
        self.safe_address_cache.add(address)

    def _emulate_move(self, inst: Instruction, _: int) -> bool:
        """
        检查 MOV 指令是否写入 VMEXIT 寄存器。

        如果写入 always_exiting_registers 中的寄存器，触发 VMEXIT。
        否则返回 True 表示指令安全。

        :param inst: MOV 指令对象
        :return: True 表示安全，False 表示触发了 VMEXIT
        """
        for operand in inst.operands:
            if operand.value in self.always_exiting_registers:
                self._model.do_soft_fault(UC_ERR_INSN_INVALID)
                return False
        return True


class _X86UserspaceInterpreter(_X86VMInterpreter):
    """
    为 Unicorn 模拟器添加用户空间模式执行模拟能力。

    在用户空间模式下，更多指令会导致异常（特权指令）。
    用户空间的 always_exit_instructions 集合比 VM 模式更大，
    因为用户空间不能执行大多数系统管理指令。
    """
    always_exit_instructions: Set[str] = {
        # 用户空间模式下始终导致异常的指令列表
        "cpuid", "rdmsr", "wrmsr", "rdtsc", "rdtscp", "clac", "stac", "clgi", "stgi", "clts", "htl",
        "invd", "invlpg", "invlpga", "invlpgb", "invpcid", "lgdt", "lldt", "lidt", "ltr", "sgdt",
        "sidt", "sldt", "str", "psmash", "pvalidate", "rmpadjust", "rmpquery", "rmpupdate",
        "skinit", "sysretq", "sysexitq", "tlbsync", "vmmcall", "vmload", "vmsave", "vmrun",
        "wbinvd", "wbnoinvd", "smsw", "lmsw", "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase",
        "swapgs", "vmclear", "vmlaunch", "vmptrld", "vmptrst", "vmread", "vmresume", "vmwrite",
        "vmxoff", "invvpid", "getsec", "loadiwkey", "pconfig", "encls", "enclv", "hlt", "xgetbv",
        "xsetbv"
    }
    always_exiting_registers = [
        # 用户空间模式下写入即异常的寄存器（控制寄存器和调试寄存器）
        "cr0", "cr2", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
    ]


# ==================================================================================================
# 私有：故障处理和权限
# ==================================================================================================
class _FaultInterpreterCommon(ABC):
    """
    故障解释器通用基类：处理模拟器中的页故障和权限检查。

    负责管理每个 actor 的故障区域页权限，并在内存访问时
    检查是否应触发用户/内核访问权限故障。

    页权限信息来自 actor 的 PTE (Page Table Entry) 和 EPTE
    (Extended Page Table Entry，用于 VM 模式) 配置。
    """
    _model: UnicornModel
    _target_desc: TargetDesc
    _uc_target_desc: UnicornTargetDesc
    _test_case: Optional[TestCaseProgram] = None

    _faulty_page_readable: Dict[ActorID, bool]
    """ 每个 actor 的故障区域是否可读 """
    _faulty_page_writable: Dict[ActorID, bool]
    """ 每个 actor 的故障区域是否可写 """
    _faulty_page_user_accessible: Dict[ActorID, bool]
    """ 每个 actor 的故障区域是否用户可访问 """
    _main_page_user_accessible: Dict[ActorID, bool]
    """ 每个 actor 的主数据区域是否用户可访问 """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        """ 初始化故障解释器。 """
        self._model = model
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        加载测试用例到故障解释器。

        从每个 actor 的 PTE/EPTE 配置中提取页权限信息，
        并将这些信息提供给模型的其他组件使用。

        :param test_case: 测试用例程序
        """
        self._test_case = test_case
        self._faulty_page_readable = {}
        self._faulty_page_writable = {}
        self._faulty_page_user_accessible = {}
        self._main_page_user_accessible = {}
        for actor in test_case.get_actors(sorted_=True):
            aid = actor.get_id()

            # 从 PTE 位提取权限信息
            pte: PTEMask = actor.data_properties
            self._faulty_page_readable[aid] = self._page_is_readable(pte)
            self._faulty_page_writable[aid] = self._page_is_writable(pte)
            self._faulty_page_user_accessible[aid] = self._page_is_user_accessible(pte)
            # 主数据区域的用户可访问性取决于 actor 的特权级别
            self._main_page_user_accessible[aid] = actor.privilege_level == ActorPL.USER

            # VM 客户模式下还需考虑 EPTE 权限
            if actor.mode == ActorMode.GUEST:
                epte: PTEMask = actor.data_ept_properties
                self._faulty_page_readable[aid] &= self._extended_page_is_readable(epte)
                self._faulty_page_writable[aid] &= self._extended_page_is_writable(epte)
                # 注意：EPTE 用户可访问位目前不支持

        # 将页权限提供给模型的其他组件
        self._model.state.page_permissions = {}
        for actor_id in range(test_case.n_actors()):
            self._model.state.page_permissions[actor_id] = (self._faulty_page_readable[actor_id],
                                                            self._faulty_page_writable[actor_id])

    def load_input(self, _: InputData) -> None:
        """
        设置内存权限：根据页权限配置修改 Unicorn 的内存保护。

        不可读/不可写的故障区域被设置为 UC_PROT_NONE，
        可读但不可写的区域被设置为 UC_PROT_READ。

        :param _: 输入数据（此处不直接使用，仅作为接口参数）
        """
        assert self._test_case is not None

        # 设置内存权限
        for actor_id in range(self._test_case.n_actors()):
            if not self._faulty_page_readable[actor_id]:
                self._model.set_faulty_area_rw(actor_id, False, False)
            elif not self._faulty_page_writable[actor_id]:
                self._model.set_faulty_area_rw(actor_id, True, False)

    def induce_user_faults(self, current_actor: Actor, address: int) -> None:
        """
        根据页权限和当前执行模式引发用户/内核访问权限故障。

        故障触发逻辑：
        1. 确定目标页的用户可访问性
        2. 用户 actor 访问内核数据 -> 触发故障(#GP, errno=13)
        3. 内核 actor 访问用户数据（SMAP） -> 触发故障(#GP, errno=13)

        注意：SMAP(Supervisor Mode Access Prevention) 假设为启用状态。

        :param current_actor: 当前正在执行的 actor
        :param address: 内存访问地址
        """
        # 确定目标页的特权级别
        if not self._model.layout.is_data_addr(address):
            return
        target_aid = self._model.layout.data_addr_to_actor_id(address)
        faulty_area_start = self._model.layout.get_data_addr(DataArea.FAULTY, target_aid)
        is_faulty_page = (address & 0xFFFFFFFFFFFFF000) == faulty_area_start
        target_page_is_user = self._faulty_page_user_accessible[target_aid] \
            if is_faulty_page else self._main_page_user_accessible[target_aid]

        # 用户 actor 访问内核空间数据 -> 故障
        if current_actor.privilege_level == ActorPL.USER and not target_page_is_user:
            self._model.do_soft_fault(13)
            return

        # 内核 actor 访问用户空间数据 -> SMAP 故障
        # 注意：此代码假设 SMAP 已启用
        if current_actor.privilege_level == ActorPL.KERNEL and target_page_is_user:
            self._model.do_soft_fault(13)

    @abstractmethod
    def _page_is_readable(self, pet: PTEMask) -> bool:
        """ 根据 PTE 位检查页是否可读（抽象方法，由 ISA 子类实现）"""

    @abstractmethod
    def _page_is_writable(self, pet: PTEMask) -> bool:
        """ 根据 PTE 位检查页是否可写（抽象方法，由 ISA 子类实现）"""

    @abstractmethod
    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        """ 根据 PTE 位检查页是否用户可访问（抽象方法，由 ISA 子类实现）"""

    @abstractmethod
    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        """ 根据 EPTE 位检查扩展页是否可读（抽象方法，由 ISA 子类实现）"""

    @abstractmethod
    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        """ 根据 EPTE 位检查扩展页是否可写（抽象方法，由 ISA 子类实现）"""


class _X86FaultInterpreter(_FaultInterpreterCommon):
    """
    x86 架构的页故障处理和权限检查实现。

    x86 PTE 位检查规则：
    - 可读：Present 位 + Accessed 位必须为1，Reserved 位必须为0
    - 可写：Writable 位 + Dirty 位必须为1
    - 用户可访问：User/Supervisor 位必须为1

    x86 EPTE 位检查规则类似 PTE。
    """

    def _page_is_readable(self, pet: PTEMask) -> bool:
        """
        x86 PTE 可读检查：Present + Accessed = 1, Reserved = 0。

        :param pet: PTE 位掩码
        :return: 是否可读
        """
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["present"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["accessed"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["reserved_bit"][0])) != 0:
            return False
        return True

    def _page_is_writable(self, pet: PTEMask) -> bool:
        """
        x86 PTE 可写检查：Writable + Dirty = 1。

        :param pet: PTE 位掩码
        :return: 是否可写
        """
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["writable"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["dirty"][0])) == 0:
            return False
        return True

    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        """
        x86 PTE 用户可访问检查：User/Supervisor 位 = 1。

        :param pet: PTE 位掩码
        :return: 是否用户可访问
        """
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["user"][0])) == 0:
            return False
        return True

    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        """
        x86 EPTE 可读检查：Present + Accessed = 1, Reserved = 0。

        :param epet: EPTE 位掩码
        :return: 是否可读
        """
        epte_desc = self._target_desc.vm_pte_bits
        if (epet & (1 << epte_desc["present"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["accessed"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["reserved_bit"][0])) != 0:
            return False
        return True

    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        """
        x86 EPTE 可写检查：Writable + Dirty = 1。

        :param epet: EPTE 位掩码
        :return: 是否可写
        """
        epte_desc = self._target_desc.vm_pte_bits
        if (epet & (1 << epte_desc["writable"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["dirty"][0])) == 0:
            return False
        return True


class _ARM64FaultInterpreter(_FaultInterpreterCommon):
    """
    ARM64 架构的页故障处理和权限检查实现。

    ARM64 PTE 位检查规则：
    - 可读：Valid 位必须为1
    - 可写：NonWritable 位必须为0
    - 用户可访问：目前总是返回 True（FIXME: 需实现 User/Supervisor 位检查）
    - EPTE 可读/可写：目前总是返回 True（ARM64 EPT 检查尚未实现）
    """

    def _page_is_readable(self, pet: PTEMask) -> bool:
        """
        ARM64 PTE 可读检查：Valid 位 = 1。

        :param pet: PTE 位掩码
        :return: 是否可读
        """
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["valid"][0])) == 0:
            return False
        return True

    def _page_is_writable(self, pet: PTEMask) -> bool:
        """
        ARM64 PTE 可写检查：NonWritable 位 = 0。

        :param pet: PTE 位掩码
        :return: 是否可写
        """
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["non_writable"][0])) != 0:
            return False
        return True

    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        """ ARM64 PTE 用户可访问检查（FIXME: 目前总是返回 True）。 """
        return True  # FIXME: 实现 User/Supervisor 位检查

    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        """ ARM64 EPTE 可读检查（尚未实现，总是返回 True）。 """
        return True

    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        """ ARM64 EPTE 可写检查（尚未实现，总是返回 True）。 """
        return True

    def emulate_crossing_fault(self, access: int, address: int, size: int) -> None:
        """
        Unicorn 的 workaround：当内存访问跨页边界且第一页可访问但第二页不可访问时，
        Unicorn 不会触发故障。此方法检测这种情况并手动触发故障。

        适用条件：
        - 访问跨越了页边界（4KB对齐）
        - 跨越的目标页是故障区域

        :param access: 内存访问类型
        :param address: 内存访问地址
        :param size: 内存访问大小
        """
        # 如果访问不跨页边界，无需 workaround
        if address % 0x1000 + size < 0x1000:
            return

        # 如果跨越的目标不是故障区域，也不适用
        layout = self._model.layout
        access_end = address + size - 1
        actor_id = layout.data_addr_to_actor_id(address)
        if actor_id == -1:
            return
        faulty_base = layout.get_data_addr(DataArea.FAULTY, actor_id)
        faulty_end = faulty_base + layout.data_area_size(DataArea.FAULTY)
        if access_end < faulty_base or access_end >= faulty_end:
            return

        # 如果故障区域不可读/不可写，模拟故障
        if not self._faulty_page_readable[actor_id]:
            self._model.do_soft_fault(UC_ERR_READ_PROT)
            return
        if access == UC_MEM_WRITE and not self._faulty_page_writable[actor_id]:
            self._model.do_soft_fault(UC_ERR_WRITE_PROT)
            return

"""
文件：模型在单个测试用例执行期间的执行状态

本模块定义了 ModelExecutionState 类，用于跟踪 Unicorn 模型在执行测试用例时的
内部状态，包括当前指令、当前执行者(actor)、退出地址、故障处理地址、
待处理异常、页权限等。它是模型执行状态机的核心数据结构。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final, Optional, Dict, Tuple

from unicorn import Uc
from ..sandbox import SandboxLayout, CodeArea
from ..tc_components.actor import ActorID

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.instruction import Instruction
    from ..tc_components.actor import Actor
    from ..target_desc import TargetDesc

PAGE_PERMISSION_MAP = Dict[ActorID, Tuple[bool, bool]]
""" 页权限映射数据类型：每个 actor 的故障区域是否可读和可写 """


class ModelExecutionState:
    """
    模型执行状态类：跟踪测试用例程序在给定输入下的一次执行的所有状态变量。

    该类维护执行过程中的关键状态信息：
    - current_instruction: 当前正在执行的指令
    - current_actor: 当前正在执行代码的 actor（执行者）
    - exit_addr: 退出指令的地址
    - fault_handler_addr: 故障处理程序的地址
    - pending_fault: 待处理的软故障 ID
    - previous_context: Unicorn 上下文（用于修复 Unicorn bug）
    - had_arch_fault: 是否已发生过非推测性故障
    - page_permissions: 各 actor 故障区域的页权限
    """

    current_instruction: Instruction
    """ 模型当前正在执行的指令 """

    current_actor: Actor
    """ 当前正在由模型执行其代码的 actor """

    exit_addr: int
    """ 当前测试用例中退出指令的地址 """

    fault_handler_addr: int
    """ 当前测试用例中故障处理程序的地址 """

    pending_fault: int = 0
    """ 用于向模型发出待处理软故障信号的接口；
    如果故障已触发但尚未处理，其 ID 存储于此 """

    previous_context: Optional[object] = None
    """ 当前指令执行前的模拟器上下文；
    用于修补 Unicorn 的一个 bug（异常后上下文恢复） """

    had_arch_fault: bool = False
    """ 标识模型在当前运行中是否已发生过非推测性故障 """

    page_permissions: Optional[PAGE_PERMISSION_MAP] = None
    """ 执行开始时各 actor 的页权限字典。
    仅包含故障区域的权限，因为其他区域始终为 RW。"""

    _test_case: Final[TestCaseProgram]  # 模型当前正在执行的测试用例
    _layout: Final[SandboxLayout]  # 沙箱布局

    def __init__(self, test_case: TestCaseProgram, layout: SandboxLayout, target_desc: TargetDesc):
        """
        初始化模型执行状态。
        :param test_case: 要执行的测试用例程序
        :param layout: 沙箱内存布局
        :param target_desc: 目标架构描述
        """
        self._test_case = test_case
        self._layout = layout

        self.exit_addr = self._layout.get_exit_addr(test_case)
        self._set_fault_handler_addr(target_desc.macro_specs["fault_handler"].type_)
        self.full_reset()

    def full_reset(self) -> None:
        """ 完整重置模型状态；必须在每次测试用例执行前调用 """
        self.had_arch_fault = False
        self.pending_fault = 0
        self.current_actor = self._test_case.find_actor(name="main")

    def reset_after_em_stop(self, start_pc: int) -> None:
        """
        在模拟器停止后重置模型状态；
        必须在每次模拟器迭代开始前调用。
        :param start_pc: 模拟器将开始执行的地址
        :return: None
        """
        self.pending_fault = 0
        # 根据 PC 地址确定当前 actor
        aid = self._layout.code_addr_to_actor_id(start_pc)
        self.current_actor = self._test_case.find_actor(actor_id=aid)

    def is_exit_addr(self, address: int) -> bool:
        """ 检查给定地址是否为退出地址。
        对于主 actor，任何超过退出地址的地址也算作退出（因为代码区连续）。
        :param address: 要检查的地址
        :return: 是否为退出地址
        """
        return address == self.exit_addr or \
            (self.current_actor.is_main and address > self.exit_addr)

    def update_context(self, em: Uc, address: int) -> None:
        """ 在每条指令执行后更新模型状态。
        保存 Unicorn 上下文（用于故障后的 bug 修补），
        并根据地址和代码偏移量更新当前指令引用。
        :param em: Unicorn 模拟器实例
        :param address: 当前指令地址
        """
        self.previous_context = em.context_save()
        aid = self.current_actor.get_id()
        section_start = self._layout.get_code_addr(CodeArea.MAIN, aid)
        instruction_map = self._test_case.get_obj().instruction_map()
        self.current_instruction = instruction_map[aid][address - section_start]

    def current_test_case(self) -> TestCaseProgram:
        """ 返回当前正在执行的测试用例 """
        return self._test_case

    def _set_fault_handler_addr(self, fh_id: int) -> None:
        """
        设置故障处理程序地址。
        根据宏符号表中的偏移量计算地址；如果不存在故障处理宏，
        则将地址设为退出地址。
        :param fh_id: 故障处理宏的类型 ID
        """
        test_case_obj = self._test_case.get_obj()
        code_start = self._layout.code_start()
        offset = test_case_obj.get_macro_offset(fh_id)
        if offset == -1:
            # 没有故障处理宏时，使用退出地址作为替代
            self.fault_handler_addr = self.exit_addr
            return

        self.fault_handler_addr = code_start + offset

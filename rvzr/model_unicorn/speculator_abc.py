"""
文件：所有推测器(speculator)必须实现的抽象接口。

具体推测器的实现请参见 speculators_*.py 文件。

推测器是修改测试用例在合约模型上执行过程的组件（例如，它可以模拟分支误预测）。
因此，推测器实现了不同合约的执行条款(execution clause)。

核心功能：
- 检查点(checkpoint)和回滚(rollback)：保存和恢复模拟器状态
- 推测窗口(speculation window)：控制推测执行的持续时间
- 嵌套层级(nesting)：控制推测的最大嵌套深度
- 内存变更日志(store log)：在推测期间记录内存写入以便回滚时恢复

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, List, Final, Tuple

from unicorn import UC_MEM_WRITE

from ..config import CONF

if TYPE_CHECKING:
    from unicorn import Uc
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..target_desc import TargetDesc, UnicornTargetDesc

_UnicornContext = object
_InstrAddress = int
_Flags = int
_SpecWindow = int
_Checkpoint = Tuple[_UnicornContext, _InstrAddress, _Flags, _SpecWindow]
""" 检查点数据类型：(模拟器上下文, 下一条指令地址, 标志位, 推测窗口计数器) """

_MemoryAddress = int
_MemoryValue = bytes
_StoreLogEntry = Tuple[_MemoryAddress, _MemoryValue]
""" 内存变更日志条目：(写入地址, 写入前的原始值) """


class UnicornSpeculator(ABC):
    """
    所有推测器必须实现的接口定义，以及通用功能的实现。

    推测器通过以下核心机制工作：
    1. 检查点(checkpoint)：在开始推测前保存完整的模拟器状态
    2. 推测执行：模拟器继续执行但状态可能不正确
    3. 回滚(rollback)：当推测窗口到期或遇到序列化指令时，
       恢复到检查点状态，撤销所有推测期间的内存和寄存器变更

    子类通过实现 _speculate_instruction、_speculate_mem_access 和 _speculate_fault
    来定义具体的推测机制（如分支误预测、故障推测等）。
    """

    is_sequential: bool = False
    """ 标识推测器是否不实现推测（即顺序执行模型）"""

    # 检查点管理
    _checkpoints: List[_Checkpoint]
    """ 检查点栈，每个检查点保存模拟器上下文、回滚地址、标志位和推测窗口 """
    _store_logs: List[List[_StoreLogEntry]]
    """ 内存变更日志栈，每层推测对应一个日志列表 """

    # 推测控制
    _max_nesting: int = 0
    """ 最大推测嵌套层级 """
    _speculation_window: int = 0
    """ 当前推测窗口计数器（从开始推测后执行的指令数）"""
    _max_spec_window: int = 0
    """ 推测窗口的最大长度 """
    _in_speculation: bool = False
    """ 是否当前处于推测执行状态 """

    # 与其他模块的连接
    _emulator: Uc
    _model: Final[UnicornModel]
    _target_desc: Final[TargetDesc]
    _uc_target_desc: Final[UnicornTargetDesc]
    _taint_tracker: UnicornTaintTracker

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化推测器，建立与模型和其他服务模块的连接。
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__()
        self._model = model
        self._taint_tracker = taint_tracker
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc
        self.reset()

    # ----------------------------------------------------------------------------------------------
    # 公共接口
    def in_speculation(self) -> bool:
        """ 返回模型当前是否处于推测执行状态。 """
        return self._in_speculation

    def set_max_nesting(self, max_nesting: int) -> None:
        """ 设置模型的最大推测嵌套层级。
        :param max_nesting: 最大嵌套层级数
        """
        self._max_nesting = max_nesting

    def nesting(self) -> int:
        """ 返回当前的推测嵌套层级（等于检查点栈的长度）。 """
        return len(self._checkpoints)

    def reset(self) -> None:
        """ 重置推测器到初始状态。
        刷新模拟器引用（因为模型可能在加载测试用例时重新创建模拟器），
        清空检查点和内存日志，重置推测状态。
        """
        self._emulator = self._model.emulator  # 刷新模拟器引用
        self._checkpoints = []
        self._store_logs = []
        self._in_speculation = False
        self._speculation_window = 0
        self._max_spec_window = CONF.model_max_spec_window

    def rollback(self) -> int:
        """ 将模型及其服务模块回滚到最后一个检查点。

        回滚步骤：
        1. 从检查点栈弹出最后一个检查点
        2. 恢复模拟器上下文（寄存器值）
        3. 恢复推测窗口计数器
        4. 恢复内存变更（将推测期间写入的内存恢复为原始值）
        5. 恢复标志位寄存器（在其他操作之后，避免被破坏）
        6. 回滚污点追踪器
        7. 返回回滚后的下一条指令地址

        :return: 回滚后应执行的指令地址
        """
        # 恢复寄存器值
        state, next_instr, flags, spec_window = self._checkpoints.pop()
        if not self._checkpoints:
            self._in_speculation = False

        # 恢复推测状态
        self._emulator.context_restore(state)
        self._speculation_window = spec_window

        # 回滚内存变更：将推测期间写入的所有内存恢复为原始值
        mem_changes = self._store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self._emulator.mem_write(addr, val)

        # 最后恢复标志位，避免被其他操作破坏
        self._emulator.reg_write(self._uc_target_desc.flags_register, flags)

        # 恢复污点追踪状态
        self._taint_tracker.rollback()

        # 回滚后从正确路径重新开始执行（不再误预测）
        return next_instr

    def handle_instruction(self, address: int, size: int) -> None:
        """
        推测器在每条指令上执行的钩子函数。
        根据具体推测器（子类），可能为某些指令实现不同的推测机制
        （如分支误预测）。

        在推测状态下，该方法还：
        - 增加推测窗口计数器
        - 在遇到序列化指令(barrier)时停止模拟器（触发回滚）
        - 在推测窗口超期时停止模拟器（触发回滚）

        :param address: 当前指令地址
        :param size: 当前指令大小
        :return: None
        """

        if self._in_speculation:
            self._speculation_window += 1
            # 在序列化指令上回滚（如 lfence、sfence 等）
            if self._model.state.current_instruction.name in self._uc_target_desc.barriers:
                self._emulator.emu_stop()

            # 在推测窗口超期时回滚
            if self._speculation_window > self._max_spec_window:
                self._emulator.emu_stop()

        self._speculate_instruction(address, size)

    def handle_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        推测器在每次内存访问上执行的钩子函数。
        根据具体推测器（子类），可能为某些内存访问实现不同的推测机制
        （如存储到加载转发）。

        在推测状态下，该方法还记录所有内存写入的原始值（用于回滚时恢复）。

        :param access: 内存访问类型（UC_MEM_READ 或 UC_MEM_WRITE）
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 内存访问的值
        :return: None
        """
        # 在推测状态下，记录所有内存变更以便回滚时恢复
        if access == UC_MEM_WRITE and self._store_logs:
            prev_value = bytes(self._emulator.mem_read(address, 8))
            self._store_logs[-1].append((address, prev_value))

        self._speculate_mem_access(access, address, size, value)

    def handle_fault(self, errno: int) -> int:
        """
        推测器在每次故障上执行的钩子函数。
        根据具体推测器（子类），可能为某些故障实现不同的推测机制
        （如 Meltdown 类型的故障推测）。

        :param errno: 故障的错误号
        :return: 推测性执行的下一条指令地址；0 表示不触发推测
        """
        return self._speculate_fault(errno)

    # ----------------------------------------------------------------------------------------------
    # 私有方法
    def _checkpoint(self, next_instruction_addr: int, include_current_inst: bool = True) -> None:
        """
        为模型及其服务模块的当前状态保存检查点。

        检查点保存内容：
        - Unicorn 模拟器的完整上下文（所有寄存器值）
        - 回滚后应执行的下一条指令地址
        - 标志位寄存器的值
        - 当前推测窗口计数器
        - 空的内存变更日志列表（后续会填充）

        同时调用污点追踪器的 checkpoint 方法保存污点状态。

        :param next_instruction_addr: 推测回滚后应执行的指令地址
        :param include_current_inst: 是否将当前指令的效果包含在检查点中
                                     （用于污点追踪；例如存储旁路推测时设为 False）
        """
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        context = self._emulator.context_save()
        spec_window = self._speculation_window
        self._checkpoints.append((context, next_instruction_addr, flags, spec_window))
        self._store_logs.append([])
        self._in_speculation = True
        self._taint_tracker.checkpoint(include_current_inst=include_current_inst)

    def _max_nesting_reached(self) -> bool:
        """ 检查是否已达到最大推测嵌套层级。 """
        return len(self._checkpoints) >= self._max_nesting

    def _speculate_instruction(self, address: int, size: int) -> None:
        """ 子类可覆写此方法以实现指令级推测机制（如分支误预测）。
        默认实现不做任何推测。
        :param address: 当前指令地址
        :param size: 当前指令大小
        """
        pass

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 子类可覆写此方法以实现内存访问级推测机制（如存储旁路）。
        默认实现不做任何推测。
        :param access: 内存访问类型
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 内存访问值
        """
        pass

    def _speculate_fault(self, _: int) -> int:
        """
        在故障发生时实现推测。默认实现不触发推测。
        子类可覆写此方法以实现故障级推测机制（如 Meltdown）。

        :param errno: 故障的 ID
        :return: 推测性执行的第一条指令地址，或 0 表示不触发推测
        """
        return 0

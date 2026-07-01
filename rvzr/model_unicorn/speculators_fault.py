"""
文件：基于故障的推测器（即 Meltdown 类型）集合，用于 Unicorn 后端。

本模块实现了多种基于异常/故障的推测执行模型，这些模型模拟 CPU 在
遇到异常时的推测行为（如 Meltdown、Faultyload、DEH 等）。

包含以下推测器：
- FaultSpeculator: 所有故障推测器的基类
- SequentialAssistSpeculator: 顺序处理内存微代码辅助
- UnicornDEH: 延迟异常处理(DEH)基类（乱序 CPU 中的延迟故障处理）
- X86UnicornDEH: x86-64 的 DEH 实现（含 ISA 特殊情况处理）
- ARMUnicornDEH: ARM64 的 DEH 实现
- X86UnicornNull: 零注入推测（故障时注入零值并重新执行）
- X86UnicornNullAssist: 零注入辅助变体（回滚后无故障重新执行）
- X86Meltdown: Meltdown 推测（故障时直接读取内存值）
- X86NonCanonicalAddress: 非规范地址推测

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Set, Tuple, List
from copy import copy
import re

from unicorn import UC_MEM_WRITE
import unicorn.x86_const as ucc  # type: ignore # no type hints for this library

from .speculator_abc import UnicornSpeculator
from ..tc_components.instruction import Instruction, RegisterOp, FlagsOp, MemoryOp, ImmediateOp

if TYPE_CHECKING:
    from ..target_desc import TargetDesc
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..tc_components.actor import ActorID


# ==================================================================================================
# 所有故障推测器的基类
# ==================================================================================================
class FaultSpeculator(UnicornSpeculator, ABC):
    """
    所有故障推测器的通用功能基类。

    提供的功能：
    - 通用方法判断给定故障是否应触发推测
    - 配置推测回滚地址的方法
    - 记录当前指令地址（用于子类确定推测起点）
    - 恢复故障页权限的方法（用于需要重新执行故障指令的场景）

    子类通过设置 _errno_that_trigger_speculation 指定哪些故障类型触发推测。
    """

    _errno_that_trigger_speculation: Set[int]  # 由子类设置
    """ 触发推测的故障错误号集合 """
    _curr_instruction_addr: int = 0
    """ 当前指令的地址 """

    def _fault_triggers_speculation(self, errno: int) -> bool:
        """
        检查故障是否应触发推测。

        推测仅在以下条件满足时触发：
        1. 故障类型在预设的触发集合中
        2. 未达到最大推测嵌套层级

        :param errno: 故障的错误号
        :return: 是否应触发推测
        """
        # 只对预定义的故障类型子集进行推测
        if errno not in self._errno_that_trigger_speculation:
            return False

        # 达到最大嵌套层级后不再推测
        if self._max_nesting_reached():
            return False
        return True

    def _get_rollback_address(self) -> int:
        """ 返回推测回滚后的目标地址（默认为故障处理程序地址）。
        子类可覆写此方法以指定不同的回滚目标。
        """
        return self._model.state.fault_handler_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """ 记录当前指令地址，供子类在故障推测时使用。 """
        self._curr_instruction_addr = address

    def _restore_faulty_page_permissions(self, actor_id: ActorID) -> None:
        """
        恢复故障区域的页权限到初始状态。
        在推测期间可能临时修改了权限（如设为 RW），回滚后需要恢复。
        :param actor_id: actor 的 ID
        """
        assert (self._model.state.page_permissions
                is not None), "Page permissions were not initialized"
        org_permissions = self._model.state.page_permissions[actor_id]
        self._model.set_faulty_area_rw(actor_id, org_permissions[0], org_permissions[1])


# ==================================================================================================
# 微代码辅助
# ==================================================================================================
class SequentialAssistSpeculator(FaultSpeculator):
    """
    顺序处理内存微代码辅助的推测器。

    模拟 CPU 在遇到 A/D 位缺失的页故障时的正常处理：
    不进行推测，而是临时修改页权限为 RW，让故障指令重新执行，
    然后恢复权限并继续顺序执行。

    适用于 modeling 顺序辅助处理（不涉及推测执行）。
    """

    def __init__(
        self,
        target_desc: TargetDesc,
        model: UnicornModel,
        taint_tracker: UnicornTaintTracker,
    ) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # 触发推测的故障类型：A/D 位缺失（errno 12, 13）
        self._errno_that_trigger_speculation = {12, 13}

    def _speculate_fault(self, errno: int) -> int:
        """
        顺序辅助处理：不推测，仅重置权限以允许访问。

        :param errno: 故障错误号
        :return: 重新执行的指令地址（当前指令地址）
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 不推测 - 仅仅重置权限以允许访问，然后重新执行
        self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return self._curr_instruction_addr


# ==================================================================================================
# 简单乱序异常处理
# ==================================================================================================
class UnicornDEH(FaultSpeculator, ABC):
    """
    延迟异常处理(DEH)推测器的基类。

    模型乱序 CPU 中的延迟故障处理：非数据依赖的指令可能在故障指令
    被退休之前执行。

    示例：
        mov rax, [faulty_addr]  ; 从故障地址加载（可能故障）
        mov rbx, [non-faulty_addr] ; 独立加载（可能在故障处理之前执行）
        mov [some_addr], rax    ; 存储加载值（如果加载故障应跳过）

    DEH 算法：
    1. 在故障发生时保存检查点并开始推测
    2. 记录故障指令的目标操作数为"依赖"
    3. 在推测期间，跳过所有依赖于故障指令的操作数的指令
    4. 不依赖的指令正常执行（模拟乱序 CPU 的行为）
    5. 在回滚时恢复所有状态
    """

    _dependencies: Set[str]
    """ 当前依赖集合（故障指令的目标操作数及其传播）"""
    _dependency_checkpoints: List[Set[str]]
    """ 依赖集合的检查点栈（与推测嵌套对应）"""
    _next_instruction_addr: int = 0
    """ 下一条指令的地址（用于在故障时跳过当前指令）"""

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # DEH 触发的故障类型：GP(6,7), UD(10), PF(12,13), DE(21)
        self._errno_that_trigger_speculation = {6, 10, 12, 13, 21}
        self._dependencies = set()
        self._dependency_checkpoints = []

    def _checkpoint(self, next_instruction_addr: int, include_current_inst: bool = True) -> None:
        """ 保存检查点，包括依赖集合状态。 """
        self._dependency_checkpoints.append(copy(self._dependencies))
        return super()._checkpoint(next_instruction_addr, include_current_inst=include_current_inst)

    def rollback(self) -> int:
        """ 回滚时恢复依赖集合状态。 """
        self._dependencies = self._dependency_checkpoints.pop()
        return super().rollback()

    def _speculate_fault(self, errno: int) -> int:
        """
        在故障发生时开始推测执行。

        步骤：
        1. 检查故障是否触发推测
        2. 保存检查点（回滚地址为故障处理程序或退出地址）
        3. 将故障指令的目标操作数添加到依赖集合
        4. 推测性地跳过故障指令（返回下一条指令地址）

        :param errno: 故障错误号
        :return: 推测性执行的下一条指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 开始推测：设置回滚地址
        # 故障终止执行，因此回滚地址设为测试用例末尾
        self._checkpoint(self._get_rollback_address())

        # 将故障指令的目标操作数添加到依赖列表
        for op in self._model.state.current_instruction.get_dest_operands(True):
            if isinstance(op, RegisterOp):
                self._dependencies.add(self._target_desc.reg_normalized[op.value])
            elif isinstance(op, FlagsOp):
                for flag in op.get_flags_by_type("write"):
                    self._dependencies.add(flag)

        # 推测性地跳过故障指令
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0  # 已到末尾，无需推测

        self._arm64_emulate_fault_with_post_increment()
        return self._next_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        在推测期间跟踪指令依赖，跳过依赖于故障指令的指令。

        算法：
        1. 解析指令的源和目标操作数
        2. 检查源操作数是否在依赖集合中（数据依赖）
        3. 如果依赖，将目标操作数也添加到依赖集合（传播）
        4. 如果不依赖，正常执行
        5. 对于依赖的指令，通过修改 RIP 来跳过执行

        特殊处理：
        - 被覆写的依赖从集合中移除（除非源也是依赖的）
        - 内存存储指令即使依赖也不完全跳过（因为微操作分裂）
        """
        # FIXME: 重构此方法以降低复杂度
        super()._speculate_instruction(address, size)

        # 校正指令大小（无效指令可能有错误的大小）
        if self._model.state.current_instruction.size() not in [0, size]:
            size = self._model.state.current_instruction.size()
        self._next_instruction_addr = address + size

        instruction = self._model.state.current_instruction

        # 仅在推测且存在依赖时进行跟踪
        if not self._in_speculation or not self._dependencies:
            return

        # 解析指令操作数，区分源/目标和内存地址寄存器
        reg_src_operands = []
        reg_dest_operands = []
        address_regs = []
        for op in instruction.get_all_operands():
            if isinstance(op, RegisterOp):
                if op.src:
                    reg_src_operands.append(self._target_desc.reg_normalized[op.value])
                if op.dest:
                    reg_dest_operands.append(self._target_desc.reg_normalized[op.value])
            elif isinstance(op, MemoryOp):
                for sub_op in re.split(r"\+|-|\*| ", op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        reg_src_operands.append(normalized)
                        address_regs.append(normalized)
            elif isinstance(op, FlagsOp):
                reg_src_operands.extend(op.get_flags_by_type("read"))
                reg_dest_operands.extend(op.get_flags_by_type("write"))

        # 检查指令是否依赖于故障指令
        is_dependent = False
        is_dependent_addr = False
        for reg in reg_src_operands:
            if reg in self._dependencies:
                is_dependent = True
                break
        for reg in address_regs:
            if reg in self._dependencies:
                is_dependent_addr = True

        # 移除被覆写的过期依赖
        old_dependencies = list(self._dependencies)  # 强制复制
        for reg in reg_dest_operands:
            if reg not in reg_src_operands and reg in self._dependencies:
                self._dependencies.remove(reg)

        if not is_dependent:
            return

        # 传播依赖：将目标操作数添加到依赖集合
        for reg in reg_dest_operands:
            self._dependencies.add(reg)

        # ISA 特定特殊情况处理
        self._handle_isa_specific_corner_cases(instruction, old_dependencies, reg_dest_operands)

        # 特殊情况：许多内存操作实现为两个微操作，
        # 其中一个可能正常执行即使另一个数据依赖
        # 近似处理：不跳过依赖的存储指令（仅跳过依赖的加载/计算）
        if instruction.has_mem_operand(True) and not is_dependent_addr:
            return

        # 此指令依赖于故障指令 -> 通过修改 RIP 跳过它
        self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)

    @abstractmethod
    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        """处理 ISA 特定的依赖跟踪特殊情况"""

    def _arm64_emulate_fault_with_post_increment(self) -> None:
        """ ARM64 后增量加载/存储触发页故障的工作around """


class X86UnicornDEH(UnicornDEH):
    """
    x86-64 延迟异常处理(DEH)的实现。

    扩展了基类 DEH，添加了 x86 特定的依赖跟踪特殊情况：
    - cmpxchg 不总是污染 RAX（仅在目标已被污染时）
    - xchg 指令交换依赖（源和目标的依赖互换）
    - xadd 指令用目标依赖覆盖源依赖
    - 清零模式（如 xor rax, rax）移除所有目标依赖

    这些特殊情况反映了 x86 指令的语义对依赖传播的影响。
    """

    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        """ 处理 x86-64 特定的依赖跟踪特殊情况。 """

        # 特殊情况 1 - cmpxchg 不总是污染 RAX
        name = instruction.name
        if "cmpxchg" in name:
            dest = instruction.operands[0]
            if (isinstance(dest, MemoryOp)
                    or self._target_desc.reg_normalized[dest.value] not in old_dependencies):
                # 只有目标已被污染时，RAX 才被污染
                self._dependencies.remove(self._target_desc.reg_normalized["rax"])
                flags = instruction.get_flags_operand()
                assert flags
                for flag in flags.get_flags_by_type("write"):
                    self._dependencies.remove(flag)
            return

        # 特殊情况 2 - xchg 指令交换依赖关系
        if "xchg" in name:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if isinstance(op1, RegisterOp):
                # 两个寄存器之间的交换：依赖互换
                op1_val, op2_val = [self._target_desc.reg_normalized[op.value] for op in [op1, op2]]
                if op1_val in old_dependencies and op2_val not in old_dependencies:
                    self._dependencies.remove(op1_val)
                elif op1_val not in old_dependencies and op2_val in old_dependencies:
                    self._dependencies.remove(op2_val)
            else:
                # 寄存器与内存交换：内存无依赖，覆盖源依赖
                op2_val = self._target_desc.reg_normalized[op2.value]
                if op2_val in old_dependencies:
                    self._dependencies.remove(op2_val)
            return

        # 特殊情况 3 - xadd 用目标依赖覆盖源依赖
        if "xadd" in name:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if (isinstance(op1, MemoryOp)
                    or self._target_desc.reg_normalized[op1.value] not in old_dependencies):
                self._dependencies.remove(self._target_desc.reg_normalized[op2.value])
            return

        # 特殊情况 4 - 清零和重置模式（如 xor rax, rax 结果为 0）
        if name in ["sub", "lock sub", "sbb", "lock sbb", "xor", "lock xor", "cmp"]:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if op1.value == op2.value:
                # 同一寄存器自身操作，结果确定（通常为0），移除依赖
                for reg in reg_dest_operands:
                    self._dependencies.remove(reg)
            return


class ARMUnicornDEH(UnicornDEH):
    """
    ARM64 延迟异常处理(DEH)的实现。
    目前没有已知的 ARM64 依赖跟踪特殊情况。
    """

    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        pass  # ARM64 目前没有已知的特殊情况

    def _arm64_emulate_fault_with_post_increment(self) -> None:
        """
        ARM64 故障处理的工作around：
        如果后增量加载/存储触发页故障，地址寄存器仍然被立即值增量。

        例如，指令 `ldr x0, [x1], #8` 故障时，x1 仍然被增量 8，
        即使加载未完成。这模拟了 ARM64 CPU 的推测行为。
        """
        instr = self._model.state.current_instruction
        if "ldr" not in instr.name and "str" not in instr.name:
            return  # 该指令不可能有后增量

        # 检查指令是否有后增量操作数
        operands = instr.get_all_operands()
        if not isinstance(operands[-1], ImmediateOp):
            return

        # 找到被增量的寄存器
        mem_addr_op = operands[-2]
        assert isinstance(mem_addr_op, MemoryOp)
        addr_reg = mem_addr_op.get_base_register()
        if addr_reg is None:
            return

        # 增量寄存器值
        increment_str = operands[-1].value
        increment = int(increment_str[1:]) if increment_str.startswith("#") else int(increment_str)
        uc_reg = self._target_desc.uc_target_desc.reg_str_to_constant[addr_reg.value]
        curr_value = int(self._emulator.reg_read(uc_reg))  # type: ignore
        new_value = curr_value + increment
        self._emulator.reg_write(uc_reg, new_value)


# ==================================================================================================
# 值注入推测
# ==================================================================================================
class X86UnicornNull(FaultSpeculator):
    """
    描述故障时零注入的合约。

    算法：
    - 在故障加载时：
        * 保存检查点
        * 将加载值覆写为零
        * 将故障页权限改为 RW
        * 重新执行指令
    - 在回滚时：
        * 恢复故障页的原始权限
        * 回滚内存和寄存器值
        * 跳转到回滚地址

    这种合约模拟了某些 CPU 在遇到故障时返回零值而不是触发异常的行为，
    允许后续指令基于零值继续推测执行。
    """

    _curr_load: Tuple[int, int]
    """ 当前加载的地址和大小 """
    _pending_re_execution: bool = False
    """ 是否需要重新执行故障指令（在权限修改后）"""
    _pending_restore_permissions: bool = False
    """ 是否需要恢复故障页权限（在重新执行后）"""

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # 仅对页故障（PF errno 12, 13）触发推测
        self._errno_that_trigger_speculation = {12, 13}

    def reset(self) -> None:
        """ 重置推测器状态。
        检查测试用例是否包含 REP 指令（此合约不支持 REP 指令）。
        """
        if not getattr(self._model, "state", None):
            super().reset()
            return

        # 此合约不正确处理 REP 指令（已知 bug）
        # 显式检测 REP 指令并报错
        for bb in self._model.state.current_test_case().iter_basic_blocks():
            for instr in bb:
                if "rep" in instr.name:
                    raise ValueError(
                        "REP instructions are not supported by this contract\n"
                        "Exclude all REP instructions from the instruction set, or change contract")
        super().reset()

    def rollback(self) -> int:
        """ 回滚时恢复故障页权限为 RW（确保后续执行可访问），然后执行标准回滚。 """
        actor_id = self._model.state.current_actor.get_id()
        self._model.set_faulty_area_rw(actor_id, True, True)
        return super().rollback()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 在故障前保存加载地址（此方法在 _speculate_fault 之前调用）。 """

        if access == UC_MEM_WRITE:
            return
        # 保存加载地址，以防此指令可能故障
        self._curr_load = (address, size)

    def _speculate_fault(self, errno: int) -> int:
        """ 在故障时注入零值并重新执行指令。

        步骤：
        1. 检查故障是否触发推测
        2. 保存检查点
        3. 在加载地址注入零值（覆写内存）
        4. 将故障页权限改为 RW
        5. 设置重新执行标志，返回当前指令地址

        :param errno: 故障错误号
        :return: 重新执行的指令地址；0 表示不推测
        """
        # (此方法在 _speculate_mem_access 之后调用)

        # 检查故障是否触发推测
        if not self._fault_triggers_speculation(errno):
            return 0

        # 保存检查点
        self._checkpoint(self._get_rollback_address())

        # 在加载地址注入零值
        address, size = self._curr_load
        if address != 0:
            # 记录原始值（用于回滚恢复）
            prev_value = bytes(self._emulator.mem_read(address, 8))
            self._store_logs[-1].append((address, prev_value))

            # 注入零值
            self._emulator.mem_write(address, bytes([0 for _ in range(size)]))

        # 启用故障页访问权限并重新执行指令
        self._pending_re_execution = True
        actor_id = self._model.state.current_actor.get_id()
        self._model.set_faulty_area_rw(actor_id, True, True)
        return self._curr_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """ 在推测期间管理重新执行和权限恢复的状态机。

        三种状态：
        1. 重新执行状态（_pending_re_execution）：故障后第一次重新执行，
           标记下一步需要恢复权限
        2. 恢复权限状态（_pending_restore_permissions）：重新执行后恢复原始权限
        3. 正常状态：不做特殊处理
        """
        super()._speculate_instruction(address, size)

        # 状态 1：故障后重新执行指令
        if self._pending_re_execution:
            self._pending_re_execution = False
            self._pending_restore_permissions = True
            self._curr_load = (0, 0)
            return

        # 状态 2：重新执行后恢复故障页权限
        if self._pending_restore_permissions:
            self._pending_restore_permissions = False
            self._restore_faulty_page_permissions(self._model.state.current_actor.get_id())
            self._curr_load = (0, 0)
            return

        # 状态 3：其他情况不做特殊处理
        self._curr_load = (0, 0)


class X86UnicornNullAssist(X86UnicornNull):
    """
    X86UnicornNull 的变体，在推测结束后不终止执行，
    而是回滚到故障指令地址并以无故障方式重新执行。

    这模拟了微代码辅助（assist）场景：故障处理后指令正常完成，
    推测窗口中的观测仍然有效（因为辅助最终会完成操作）。
    """

    def _get_rollback_address(self) -> int:
        """ 回滚地址为当前指令地址（而非故障处理程序），
        以便在回滚后无故障地重新执行该指令。
        """
        return self._curr_instruction_addr


class X86Meltdown(FaultSpeculator):
    """
    Meltdown 推测器：从故障区域的加载推测性地返回内存中的实际值。

    这模拟了某些 Intel CPU 在遇到页故障时的行为：
    故障加载的数据仍然被推测性地传递到后续指令，
    即使权限检查最终会阻止该访问。

    算法：
    1. 在页故障时保存检查点
    2. 移除页保护（使故障区域可访问）
    3. 重新执行故障指令（此时能成功读取内存值）
    4. 推测窗口到期后回滚，恢复保护
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # 仅对页故障触发推测
        self._errno_that_trigger_speculation = {12, 13}

    def _speculate_fault(self, errno: int) -> int:
        """
        在页故障时移除保护并重新执行指令。

        :param errno: 故障错误号
        :return: 重新执行的指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 保存检查点
        self._checkpoint(self._get_rollback_address())

        # 移除页保护，使故障区域可访问
        self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return self._curr_instruction_addr


class X86NonCanonicalAddress(FaultSpeculator):
    """
    非规范地址推测器：模拟从非规范地址的加载。

    在 x86-64 中，地址必须为规范形式（高16位与第47位相同）。
    非规范地址访问会触发 General Protection Fault(#GP)。
    此推测器模拟某些 CPU 在推测执行中将非规范地址转换为规范地址的行为，
    允许后续指令基于转换后的值继续执行。
    """

    faulty_instruction_addr: int = -1
    """ 故障指令的地址 """
    address_register: int = -1
    """ 使用非规范地址的寄存器 ID """
    register_value: int = -1
    """ 寄存器的原始值（用于恢复）"""

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # GP 故障触发推测（errno 6, 7）
        self._errno_that_trigger_speculation = {6, 7}

    def _speculate_fault(self, errno: int) -> int:
        """
        在 GP 故障时保存检查点并记录故障指令地址。
        推测性地从故障指令地址重新执行（后续会将非规范地址转为规范地址）。

        :param errno: 故障错误号
        :return: 当前指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        self._checkpoint(self._model.state.fault_handler_addr)
        self.faulty_instruction_addr = self._curr_instruction_addr
        return self._curr_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        在推测期间将非规范地址转换为规范地址。

        步骤：
        1. 如果地址寄存器已转换，恢复原始值并继续
        2. 如果当前指令是故障指令，找到使用非规范地址的内存操作数
        3. 将非规范地址转换为最接近的规范地址
        4. 写入转换后的地址到寄存器，模拟 CPU 的推测行为

        非规范地址转换规则：
        - 如果第48位为1（高位地址），高16位设为全1
        - 如果第48位为0（低位地址），高16位设为全0
        """
        super()._speculate_instruction(address, size)

        if not self._in_speculation:
            return

        model = self._model
        # 如果地址寄存器已转换，恢复原始值
        if self.address_register != -1:
            model.emulator.reg_write(self.address_register, self.register_value)
            self.address_register = -1
            return

        if self.faulty_instruction_addr != address:
            return

        # 修复非规范地址
        for mem_op in model.state.current_instruction.get_mem_operands(True):
            registers = re.split(r"\+|-|\*| ", mem_op.value)
            if len(registers) > 1:
                continue  # 复合地址表达式，无法简单转换

            uc_reg = self._target_desc.uc_target_desc.reg_str_to_constant[registers[0]]
            load_address: int = model.emulator.reg_read(uc_reg)  # type: ignore
            # 检查是否为规范地址
            is_canonical: bool = (
                load_address > 0xFFFF800000000000 or load_address < 0x00007FFFFFFFFFFF)
            if not is_canonical:
                # 保存原始寄存器值用于后续恢复
                self.address_register = uc_reg
                self.register_value = load_address

                # 将非规范地址转换为规范地址
                if load_address & (1 << 47):  # 第48位为1 -> 高位地址
                    load_address = load_address | 0xFFFF800000000000
                else:  # 第48位为0 -> 低位地址
                    load_address = load_address & 0x00007FFFFFFFFFF
                model.emulator.reg_write(uc_reg, load_address)
                return
        return

    def reset(self) -> None:
        """ 重置推测器状态，包括故障指令地址和寄存器信息。 """
        self.faulty_instruction_addr = -1
        self.address_register = -1
        self.register_value = -1
        return super().reset()

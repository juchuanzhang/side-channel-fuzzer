"""
文件：Unicorn 模型的污点追踪实现

本模块实现了 UnicornTaintTracker 类，用于追踪影响合约轨迹的输入数据。
污点追踪是侧信道分析的关键技术，它通过跟踪数据从输入到观测的传播路径，
确定哪些输入字节会影响模型输出的合约轨迹，从而指导模糊测试的变异策略。

算法流程：
1. track_instruction: 解析指令的静态源和目标操作数
2. track_memory_access: 收集动态源和目标内存地址
3. taint: 收集本指令在合约轨迹中暴露的标签（寄存器名或内存地址）
4. finalize_instruction:
   - 将源操作数的依赖传播到目标操作数
   - 用 taint_* 方法收集的标签的依赖更新污点标签列表
5. get_taint: 根据所有污点标签生成 InputTaint 对象

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import copy
import re
from typing import List, Optional, Set, Dict, TYPE_CHECKING, Literal, Final
from typing_extensions import assert_never

from ..tc_components.instruction import Instruction, RegisterOp, FlagsOp, \
    MemoryOp, AgenOp, ImmediateOp, LabelOp, CondOp
from ..tc_components.test_case_data import InputTaint
from ..target_desc import TargetDesc
from ..sandbox import SandboxLayout, DataArea
from ..config import CONF

if TYPE_CHECKING:
    from ..target_desc import UnicornTargetDesc
    from ..sandbox import BaseAddrTuple, DataAddr

TAINTED_VALUE_TYPE = Literal["pc", "mem", "ld_val"]
""" 污点值类型：PC（程序计数器）、mem（内存地址）、ld_val（加载值）"""
_ARCH_INITIAL_OBSERVATIONS_X86_64 = [
    "A", "B", "C", "D", "SI", "DI", "RSP", "CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF",
    "AC"
]
""" x86-64 架构的初始观测标签列表（arch/ctr 合约预设观测）"""
_ARCH_INITIAL_OBSERVATIONS_ARM64 = ["R0", "R1", "R2", "R3", "R4", "R5", "N", "Z", "C", "V"]
""" ARM64 架构的初始观测标签列表 """


# ==================================================================================================
# 公共接口：污点追踪器
# ==================================================================================================
class UnicornTaintTracker:
    """
    追踪影响合约轨迹的输入数据。

    污点追踪算法基于数据依赖传播：
    - 每个标签（寄存器名或内存地址）维护一个依赖集合
    - 源操作数的依赖被传播到目标操作数
    - 当观测到某个标签时（通过 taint 方法），其依赖被添加到污点标签集合
    - 最终污点标签集合被转换为 InputTaint 对象，指导模糊测试变异

    该类还支持检查点/回滚机制，与推测器协同工作：
    - checkpoint: 保存当前依赖状态
    - rollback: 恢复到检查点时的依赖状态
    """
    _enable_tracking: bool = True
    """ 是否启用污点追踪（由 trace_test_case/trace_test_case_with_taints 控制）"""
    _tracking_in_progress: bool = False
    """ 是否正在追踪过程中（防止在追踪过程中切换启用/禁用）"""

    _initial_observations: List[str]
    """ 初始观测标签列表（由合约观测条款决定）"""
    _data_start: Final[DataAddr]
    """ 数据区起始地址（用于计算内存污点的偏移量）"""
    _uc_target_desc: Final[UnicornTargetDesc]
    _target_desc: Final[TargetDesc]

    _checkpoints: List[_Dependencies]
    """ 依赖状态检查点栈（与推测器的检查点协同工作）"""
    _tainted_labels: Set[str]
    """ 当前已标记为污点的标签集合 """
    _pending_taint: Set[str]
    """ 当前指令的待处理污点标签（由 taint 方法添加，在 finalize 时传播）"""

    _instruction: Optional[_TrackedInstruction] = None
    """ 当前正在追踪的指令 """
    _dependencies: _Dependencies
    """ 当前依赖状态映射 """

    def __init__(self, bases: BaseAddrTuple, target_desc: TargetDesc):
        """
        初始化污点追踪器。
        :param bases: 基地址元组（用于确定数据区起始地址）
        :param target_desc: 目标架构描述
        """
        assert CONF.instruction_set in ["x86-64", "arm64"], \
               "Taint tracking is only supported for x86_64 and arm64"

        self._data_start = bases[0]
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc

        # 某些合约类型有预设观测（如 arch/ctr 合约暴露所有寄存器）
        if CONF.contract_observation_clause in ('ctr', 'arch'):
            if CONF.instruction_set == "x86-64":
                self._initial_observations = _ARCH_INITIAL_OBSERVATIONS_X86_64
            elif CONF.instruction_set == "arm64":
                self._initial_observations = _ARCH_INITIAL_OBSERVATIONS_ARM64
        else:
            self._initial_observations = []

        self.reset()
        self._tracking_in_progress = False

    # ----------------------------------------------------------------------------------------------
    # 状态管理方法
    def set_enable_tracking(self, enable: bool) -> None:
        """ 启用或禁用污点追踪。
        必须在追踪未进行时调用（即在 get_taint() 之后）。
        :param enable: 是否启用追踪
        """
        assert self._tracking_in_progress is False, \
            "Cannot change tracking mode before get_taint() is called"
        self._enable_tracking = enable

    def reset(self) -> None:
        """ 重置污点追踪器到初始状态。
        清空检查点栈，用初始观测标签初始化污点标签集合，
        创建新的依赖映射。
        """
        self._checkpoints = []
        self._tainted_labels = set(self._initial_observations)
        self._pending_taint = set()
        self._instruction = None
        self._dependencies = _Dependencies()
        self._tracking_in_progress = True

    def checkpoint(self, include_current_inst: bool) -> None:
        """
        保存污点追踪器的当前状态（用于推测器的检查点机制）。
        :param include_current_inst: 是否将当前指令的效果包含在检查点中
                                    （某些推测机制如存储旁路需要在指令之前保存）
        """
        if not self._enable_tracking:
            return

        # 如果需要包含当前指令，先完成依赖传播
        if include_current_inst and self._instruction is not None:
            self._finalize_instruction()
        self._checkpoints.append(copy.deepcopy(self._dependencies))

    def rollback(self) -> None:
        """
        从最顶层的检查点恢复污点追踪器的状态（用于推测器的回滚机制）。
        :raises AssertionError: 如果没有可用的检查点
        """
        if not self._enable_tracking:
            return

        assert self._checkpoints, "There are no more checkpoints"
        # 先完成当前指令的依赖传播（因为回滚会清除当前指令状态）
        if self._instruction is not None:
            self._finalize_instruction()
        self._dependencies = copy.deepcopy(self._checkpoints.pop())

    # ----------------------------------------------------------------------------------------------
    # 依赖传播方法
    def track_instruction(self, instruction: Instruction) -> None:
        """
        解析指令并记录其静态源和目标操作数。
        "静态"指不需要执行指令就能识别的操作数。
        剩余的动态操作数由 track_memory_access 方法收集。

        :param instruction: 要解析的指令
        """
        if not self._enable_tracking:
            return

        # 确保前一条指令的依赖传播已完成
        if self._instruction:
            self._finalize_instruction()

        # 开始追踪新指令
        self._instruction = _TrackedInstruction(instruction)
        self._instruction.parse_static_operands(self._target_desc.reg_normalized)
        self._pending_taint = set()

        # 覆写过期的标志位依赖
        # FIXME: 这可能应该在 _finalize_instruction 中处理？
        flag_op = self._instruction.inst.get_flags_operand()
        if flag_op:
            for flag_label in flag_op.get_flags_by_type('overwrite'):
                self._dependencies.flag[flag_label] = {flag_label}

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        """
        将内存访问地址添加到当前指令的依赖列表。
        地址被掩码为8字节粒度（与 InputTaint 的粒度匹配）。

        :param address: 内存访问地址
        :param size: 内存访问大小
        :param is_write: True 表示写入（存储），False 表示读取（加载）
        """
        if not self._enable_tracking:
            return

        assert self._instruction, "track_memory_access called before track_instruction"

        # 对地址进行掩码处理 - 污点追踪以8字节为粒度
        address -= self._data_start
        masked_start_addr = address & 0xffff_ffff_ffff_fff8
        end_addr = address + (size - 1)
        masked_end_addr = end_addr & 0xffff_ffff_ffff_fff8

        # 将所有掩码后的地址添加到追踪
        for i in range(masked_start_addr, masked_end_addr + 1, 8):
            if is_write:
                self._instruction.dest_mems.add(hex(i))
            else:
                self._instruction.src_mems.add(hex(i))

    def _finalize_instruction(self) -> None:
        """
        传播依赖并记录追踪指令的污点。
        这是污点追踪的核心步骤：

        1. 将源操作数的依赖传播到目标操作数
        2. 将待处理污点标签的依赖添加到污点标签集合
        3. 清除被覆写的寄存器依赖（如 MOV 指令完全覆写目标寄存器）

        :raises AssertionError: 如果在 track_instruction 之前调用
        """
        assert self._instruction, "_finalize_instruction called before track_instruction"
        inst = self._instruction.inst
        inst_name = inst.name.lower()

        # 提取追踪指令的依赖传播
        self._dependencies.add_dependencies(self._instruction)

        # REP 指令的隐式 RCX 依赖的工作around
        if self._pending_taint and "rep" in inst_name and "C" in self._instruction.src_regs:
            self._pending_taint.add('C')

        # 更新污点标签集合：将待处理污点标签的依赖添加到全局污点集合
        for label in self._pending_taint:
            if label.startswith("0x"):
                # 内存地址标签：从 mem 依赖映射中查找其依赖集合
                tainted_values = self._dependencies.mem.get(label, {label})
            else:
                # 寄存器/标志位标签：从 reg 依赖映射中查找其依赖集合
                tainted_values = self._dependencies.reg.get(label, {label})
            self._tainted_labels.update(tainted_values)

        # 清除被覆写寄存器的过期依赖
        # 注意：必须在污点更新之后执行，否则污点会丢失
        self._dependencies.remove_overwritten_dependencies(self._instruction, self._target_desc)

        # 重置指令追踪状态
        self._instruction = None

    # ----------------------------------------------------------------------------------------------
    # 污点回调
    def taint(self, value_type: TAINTED_VALUE_TYPE) -> None:
        """
        对追踪指令的给定类型操作数进行污点标记。
        追踪指令是最后一次调用 track_instruction 的指令。

        污点类型：
        - "pc": 标记程序计数器为污点（仅对控制流指令）
        - "mem": 标记内存地址寄存器为污点
        - "ld_val": 标记加载的内存地址为污点

        :param value_type: 要污点标记的值类型
        """
        if not self._enable_tracking:
            return

        if not self._instruction:
            return

        # 污点标记程序计数器
        if value_type == "pc":
            if self._instruction and self._instruction.inst.is_control_flow:
                self._pending_taint.add("RIP")
            return

        # 污点标记内存地址（使用的寄存器）
        if value_type == "mem":
            for reg in self._instruction.mem_address_regs:
                self._pending_taint.add(reg)
            return

        # 污点标记加载的值（内存地址本身）
        if value_type == "ld_val":
            for addr in self._instruction.src_mems:
                self._pending_taint.add(addr)
            return
        assert_never(value_type)

    def taint_actors(self, actor_ids: List[int]) -> None:
        """
        对列表中所有 actor 的内存地址进行污点标记。
        这用于 actor 非干扰追踪器，需要将 observer actor 的全部数据标记为污点。
        :param actor_ids: actor ID 列表
        """
        data_size_per_actor = SandboxLayout.data_size_per_actor()
        for actor_id in actor_ids:
            actor_offset = actor_id * data_size_per_actor
            for i in range(actor_offset, actor_offset + data_size_per_actor, 8):
                self._tainted_labels.add(hex(i))

    # ----------------------------------------------------------------------------------------------
    # 污点输出
    def get_taint(self, n_actors: int) -> InputTaint:
        """
        根据模型执行期间收集的污点生成 InputTaint 对象。
        InputTaint 指示哪些输入字节影响了合约轨迹，
        用于指导模糊测试的变异策略（仅变异有影响的字节）。

        转换过程：
        1. 污点标签（寄存器名/内存地址）被映射到沙箱地址
        2. 沙箱地址被转换为 InputTaint 偏移量
        3. 每个 actor 的污点偏移量被单独记录

        :param n_actors: 测试用例中的 actor 数量
        :return: InputTaint 对象
        """
        # pylint: disable=too-many-locals
        # NOTE: 合理的，因为需要多个变量定义区域边界

        if not self._enable_tracking:
            self._tracking_in_progress = False
            return InputTaint(n_actors)

        # 完成最后一条指令的依赖传播
        if self._instruction:
            self._finalize_instruction()

        taint = InputTaint(n_actors)
        tainted_sandbox_addresses: List[int] = []
        register_start = SandboxLayout.data_area_offset(DataArea.GPR)
        simd_start = SandboxLayout.data_area_offset(DataArea.SIMD)

        # 将每个污点标签映射到沙箱地址
        for label in self._tainted_labels:
            # 内存地址标签 -> 沙箱地址
            if label.startswith('0x'):
                sandbox_address = int(label, 16)
                tainted_sandbox_addresses.append(sandbox_address)
                continue

            # 通用寄存器标签 -> GPR 区域中的沙箱地址
            reg = self._uc_target_desc.reg_norm_to_constant[label]
            registers = self._uc_target_desc.usable_registers
            if reg in registers:
                sandbox_address = register_start + registers.index(reg) * 8
                tainted_sandbox_addresses.append(sandbox_address)
                continue

            # SIMD 寄存器标签 -> SIMD 区域中的沙箱地址
            simd_registers = self._uc_target_desc.usable_simd128_registers
            if reg in simd_registers:
                sandbox_address = simd_start + simd_registers.index(reg) * 16
                tainted_sandbox_addresses.append(sandbox_address)
                tainted_sandbox_addresses.append(sandbox_address + 1)

        # 将沙箱地址转换为 InputTaint 偏移量，并按 actor 分配
        tainted_sandbox_addresses.sort()
        taint_offsets = [
            InputTaint.taint_offset_from_sandbox_address(pos) for pos in tainted_sandbox_addresses
        ]

        for actor_id in range(0, n_actors):
            actor_area_start = actor_id * InputTaint.per_actor_taint_size
            actor_area_end = (actor_id + 1) * InputTaint.per_actor_taint_size
            # 提取属于当前 actor 的污点偏移量
            actor_taints = [
                pos - actor_area_start
                for pos in taint_offsets
                if actor_area_start <= pos < actor_area_end
            ]
            taint.taint_actor_offsets(actor_id, actor_taints)

        self._tracking_in_progress = False
        return taint


# ==================================================================================================
# 私有：服务类
# ==================================================================================================
class _TrackedInstruction:
    """
    私有数据类：保存追踪指令的源和目标操作数。

    操作数分为静态和动态两类：
    - 静态操作数（parse_static_operands 收集）：寄存器、标志位、内存地址寄存器
    - 动态操作数（track_memory_access 收集）：实际的内存读写地址
    """

    def __init__(self, instruction: Instruction) -> None:
        """
        :param instruction: 要追踪的指令
        """
        self.inst = instruction

        self.src_regs: Set[str] = set()
        """ 源寄存器集合（归一化后的名称）"""
        self.dest_regs: Set[str] = set()
        """ 目标寄存器集合（归一化后的名称）"""

        self.src_flags: Set[str] = set()
        """ 源标志位集合 """
        self.dest_flags: Set[str] = set()
        """ 目标标志位集合 """

        self.src_mems: Set[str] = set()
        """ 源内存地址集合（hex格式，8字节对齐）"""
        self.dest_mems: Set[str] = set()
        """ 目标内存地址集合（hex格式，8字节对齐）"""

        self.mem_address_regs: Set[str] = set()
        """ 内存地址中使用的寄存器集合 """

    def parse_static_operands(self, reg_normalizer: Dict[str, str]) -> None:
        """
        设置指令的源和目标操作数（静态解析）。
        将操作数中的寄存器名归一化并分类到源/目标集合。

        :param reg_normalizer: 寄存器名称到归一化名称的映射字典
        :return: None
        """
        for op in self.inst.get_all_operands():
            # 寄存器操作数：归一化名称并记录到源/目标集合
            if isinstance(op, RegisterOp):
                value = reg_normalizer[op.value]
                if op.src:
                    self.src_regs.add(value)
                if op.dest:
                    self.dest_regs.add(value)
                continue

            # 标志位操作数：记录读/写/未定义标志
            if isinstance(op, FlagsOp):
                self.src_flags = set(op.get_flags_by_type('read'))
                self.src_flags.update(op.get_flags_by_type('undef'))
                self.dest_flags = set(op.get_flags_by_type('write'))
                continue

            # 内存操作数：记录地址中使用的寄存器名
            if isinstance(op, MemoryOp):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in reg_normalizer:
                        self.mem_address_regs.add(reg_normalizer[sub_op])
                continue

            # 地址生成(LEA)操作数：记录到源寄存器（非内存访问）
            if isinstance(op, AgenOp):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in reg_normalizer:
                        self.src_regs.add(reg_normalizer[sub_op])
                continue

            # 立即数、标签、条件码操作数：不做处理
            if isinstance(op, (ImmediateOp, LabelOp, CondOp)):
                continue

            assert_never(op)


class _Dependencies:
    """
    私有数据类：追踪 UnicornTaintTracker 收集的所有依赖关系。

    依赖映射维护三类依赖：
    - reg: 寄存器 -> 依赖集合
    - flag: 标志位 -> 依赖集合
    - mem: 内存地址 -> 依赖集合

    每个依赖集合记录了该标签所依赖的所有源标签（传播链）。
    """
    _cached_src_dependencies: Optional[Set[str]]

    def __init__(self) -> None:
        """ 初始化空的依赖映射 """
        self.reg: Dict[str, Set[str]] = {}
        """ 寄存器依赖映射：寄存器名 -> 其依赖的标签集合 """
        self.flag: Dict[str, Set[str]] = {}
        """ 标志位依赖映射：标志位名 -> 其依赖的标签集合 """
        self.mem: Dict[str, Set[str]] = {}
        """ 内存依赖映射：内存地址(hex) -> 其依赖的标签集合 """

    def add_dependencies(self, tracked_inst: _TrackedInstruction) -> None:
        """
        用追踪指令的源和目标操作数更新依赖映射。

        算法步骤：
        1. 收集所有源操作数的依赖（合并源寄存器、标志位、内存的依赖集合）
        2. 将源操作数的依赖传播到所有目标操作数
        3. 每个目标操作数还保留自身的标签（形成完整的传播链）

        :param tracked_inst: 追踪的指令
        """

        # 获取源操作数的依赖集合
        src_dependencies = set()
        for reg in tracked_inst.src_regs:
            src_dependencies.update(self.reg.get(reg, {reg}))
        for flag in tracked_inst.src_flags:
            src_dependencies.update(self.flag.get(flag, {flag}))
        for addr in tracked_inst.src_mems:
            src_dependencies.update(self.mem.get(addr, {addr}))
        self._cached_src_dependencies = src_dependencies

        # 将源依赖传播到目标操作数
        for reg in tracked_inst.dest_regs:
            if reg in self.reg:
                self.reg[reg].update(src_dependencies)
            else:
                self.reg[reg] = copy.copy(src_dependencies)
                self.reg[reg].add(reg)
        for flg in tracked_inst.dest_flags:
            if flg in self.flag:
                self.flag[flg].update(src_dependencies)
            else:
                self.flag[flg] = copy.copy(src_dependencies)
                self.flag[flg].add(flg)
        for mem in tracked_inst.dest_mems:
            if mem in self.mem:
                self.mem[mem].update(src_dependencies)
            else:
                self.mem[mem] = copy.copy(src_dependencies)
                self.mem[mem].add(mem)

    def remove_overwritten_dependencies(self, tracked_inst: _TrackedInstruction,
                                        target_desc: TargetDesc) -> None:
        """
        移除被完全覆写的目标操作数的过期依赖。

        对于 MOV 和 LEA 指令（64位宽度的单目标寄存器），其目标寄存器的
        旧依赖被完全覆写，只保留源操作数的依赖和自身标签。
        这是依赖传播优化：避免寄存器依赖集合无限增长。

        :param tracked_inst: 追踪的指令
        :param target_desc: 目标架构描述（用于确定寄存器大小）
        """
        assert self._cached_src_dependencies is not None, \
            "remove_overwritten_dependencies must be called after add_dependencies"
        src_dependencies = self._cached_src_dependencies
        self._cached_src_dependencies = None

        # 判断指令是否覆写了之前的依赖（目前仅考虑 MOV 和 LEA）
        # FIXME: 这是 x86 特定的实现，应移至 x86 模型
        override: bool = False
        inst_name = tracked_inst.inst.name.lower()
        if (inst_name.startswith("mov") or inst_name == "lea") \
           and len(tracked_inst.dest_regs) == 1:
            reg = tracked_inst.inst.get_reg_operands(True)[0].value
            if target_desc.register_sizes.get(reg, 0) == 64:
                override = True

        # 如果指令覆写了之前的依赖，移除不在源依赖中的旧依赖
        if override:
            assert len(tracked_inst.dest_regs) == 1, "MOV instruction with multiple destinations"
            reg = tracked_inst.dest_regs.pop()
            for dep in list(self.reg[reg]):
                if dep not in src_dependencies:
                    self.reg[reg].remove(dep)

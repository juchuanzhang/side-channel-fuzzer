"""
文件：未知值推测推测器集合，用于 Unicorn 后端。

本模块实现了基于值推测(value speculation, vspec)的推测执行模型，
这些模型模拟 CPU 在遇到异常时推测性地使用未知值继续执行的行为。

核心算法是 VSOps（Value Speculation with Unknown Operand Values），
详见论文 "Speculation at Fault: Modeling and Testing Microarchitectural
Leakage of CPU Exceptions" (Hofmann et al.) 第6节。

注意：此模块当前不再维护。如需此功能，请联系维护者。
已知问题请参见文件中的 FIXME 注释。

包含以下推测器：
- _VspecBaseSpeculator: 值推测基类（实现 VSOps 算法）
- VspecDIVSpeculator: 除法错误上的操作数值推测
- VspecMemoryFaultsSpeculator: 页故障上的操作数值推测
- VspecMemoryAssistsSpeculator: 微代码辅助上的操作数值推测
- VspecGPSpeculator: 一般保护故障上的操作数值推测
- VspecAllSpeculator: 最宽松合约（vspec-unknown，目标操作数依赖完整架构状态）
- VspecAllDIVSpeculator: 除法错误上的任意值推测
- VspecAllMemoryFaultsSpeculator: 页故障上的任意值推测
- VspecAllMemoryAssistsSpeculator: 微代码辅助上的任意值推测

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# FIXME: pylint 对此文件被禁用，因为当前不再维护
# pylint: disable=too-many-instance-attributes, too-many-locals
# pylint: disable=too-many-branches, too-many-statements

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Set, Tuple, List, NamedTuple, Dict, Final

import re
from copy import copy

from unicorn import UC_MEM_WRITE

from .speculators_basic import FLAGS_CF, FLAGS_PF, FLAGS_AF, FLAGS_ZF, FLAGS_SF, FLAGS_TF, \
    FLAGS_IF, FLAGS_DF, FLAGS_OF
from .speculators_fault import FaultSpeculator, X86NonCanonicalAddress
from ..tc_components.instruction import RegisterOp, FlagsOp, MemoryOp, AgenOp

if TYPE_CHECKING:
    from ..tc_components.test_case_data import InputData
    from ..target_desc import TargetDesc
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker


class _TaintedValue(NamedTuple):
    """
    污点值数据结构：记录被污点标记的值的来源信息。

    属性：
    - po: 程序偏移量（指令在代码中的位置）
    - label: 标签ID（寄存器ID或内存地址）
    - value: 实际的值（在模拟器中读取的值）
    """
    po: int
    label: int
    value: int


Taint = Set[_TaintedValue]
""" 污点集合类型：一组 _TaintedValue 的集合 """

_FLAG_NAME_TO_BITMASK: Final[Dict[str, int]] = {
    """ x86 标志位名称到 EFLAGS 位掩码的映射 """
    "CF": FLAGS_CF,
    "PF": FLAGS_PF,
    "AF": FLAGS_AF,
    "ZF": FLAGS_ZF,
    "SF": FLAGS_SF,
    "TF": FLAGS_TF,
    "IF": FLAGS_IF,
    "DF": FLAGS_DF,
    "OF": FLAGS_OF
}


class _VspecBaseSpeculator(FaultSpeculator, ABC):
    """
    未知值推测的基类，实现 VSOps 算法。

    VSOps 算法追踪污点(taint)在系统中的传播：
    - 当故障发生时，故障指令的源操作数被标记为污点
    - 污点从源操作数传播到目标操作数
    - 当使用污点值的内存访问被观测到时，其污点被记录到合约轨迹
    - 如果使用污点寄存器作为内存地址，则整个内存被标记为污点（因为地址未知）

    污点类型：
    - 正常污点(_TaintedValue): 记录具体的值和来源
    - 完整输入污点(_full_input_taint): 表示依赖完整架构状态（最宽松的合约）

    注意：此类当前不再维护。如需此功能，请联系维护者。
    """
    _input_hash: int = 0
    """ 输入数据的哈希值，用于表示完整架构状态的污点 """
    _full_input_taint: _TaintedValue
    """ 表示完整输入依赖的污点值 """
    _reg_taints: Dict[str, Taint]
    """ reg_taints: 寄存器的污点映射 """
    _reg_taints_checkpoints: List[Dict[str, Taint]]
    """ 寄存器污点的检查点栈 """
    _mem_taints: Dict[int, Taint]
    """ mem_taints: 内存地址的污点映射 """
    _mem_taints_checkpoints: List[Dict[int, Taint]]
    """ 内存污点的检查点栈 """
    _whole_memory_tainted: bool = False
    """ whole_memory_tainted: 过近似标记，记录整个内存是否被污点/损坏 """
    _whole_memory_tainted_checkpoints: List[bool]
    """ 整体内存污点标记的检查点栈 """
    _curr_observation: Taint = set()
    """ _curr_observation: 如果当前指令是内存访问，
        需要泄漏的污点+值集合 """
    _curr_mem_load: Tuple[int, int] = (-1, -1)
    """ _curr_mem_load: 最后一次内存加载的地址和大小（异常时需要）"""
    _curr_mem_store: Tuple[int, int] = (-1, -1)
    """ _curr_mem_store: 最后一次内存存储的地址和大小（异常时需要）"""
    _curr_dest_regs: List[str] = []
    """ _curr_dest_regs: 当前目标寄存器列表 """
    _curr_dest_regs_sizes: Dict[str, int]
    """ curr_dest_regs_sizes: 当前目标寄存器的宽度，
        即是否只有寄存器的一部分被覆写 """
    _curr_taint: Taint
    """ curr_taint: 当前从 _speculate_instruction() 传播到 trace_mem_access() 的污点+值 """
    _curr_src_tainted: bool = False
    """ 记录在 _speculate_instruction 中是否有任何源操作数被污点标记 """
    _next_instruction_addr: int = 0
    """ 下一条指令的地址 """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化值推测基类。
        注意：此构造函数会抛出 NotImplementedError，因为此类不再维护。

        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        # 默认触发推测的故障类型：GP(6,7) 和 PF(12,13)
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

        self._reg_taints = {}
        self._reg_taints_checkpoints = []
        self._mem_taints = {}
        self._mem_taints_checkpoints = []
        self._whole_memory_tainted_checkpoints = []
        self._curr_dest_regs_sizes = {}
        self._curr_taint = set()
        self._full_input_taint = _TaintedValue(0, 0, self._input_hash)\

        raise NotImplementedError("This class and its subclasses are no longer maintained."
                                  "If you need this functionality, please contact the maintainers")
        # NOTE: 搜索 FIXME 注释以查看此类中的已知问题列表

    def _load_input(self, input_: InputData) -> None:
        """
        加载输入数据并初始化污点状态。
        FIXME: _load_input 接口已不存在；此功能应移至其他方法（reset() 是好的候选）

        :param input_: 输入数据
        """
        self._input_hash = hash(input_)
        self._full_input_taint = _TaintedValue(0, 0, self._input_hash)
        self._curr_observation = set()
        self._curr_dest_regs = []
        self._curr_dest_regs_sizes = {}
        self._curr_mem_load = (-1, -1)
        self._curr_mem_store = (-1, -1)
        self._curr_taint = set()
        self._curr_src_tainted = False
        assert len(self._reg_taints) == 0
        assert len(self._reg_taints_checkpoints) == 0
        assert len(self._mem_taints) == 0
        assert len(self._mem_taints_checkpoints) == 0
        assert not self._whole_memory_tainted
        assert len(self._whole_memory_tainted_checkpoints) == 0

    def _assemble_reg_values(self, regs: Set[str]) -> Tuple[Taint, bool]:
        """
        聚合 regs 中所有寄存器的值。
        如果寄存器被污点标记，使用污点代替实际值。
        设置 _curr_src_tainted 为 True 如果有寄存器被污点标记。

        返回：寄存器值集合（可用作污点）和布尔标志
        标识是否有寄存器被污点标记。

        :param regs: 要聚合的寄存器名称集合
        :return: (污点值集合, 是否有寄存器被污点标记)
        """

        reg_values = set()
        reg_values_tainted = False

        for reg in regs:
            if reg in self._reg_taints:
                # 寄存器已被污点标记：使用污点值集合
                reg_values.update(self._reg_taints[reg])
                # 记住有寄存器被污点标记
                reg_values_tainted = True
            else:
                # 寄存器未被污点标记：使用模拟器中的实际值
                reg_id = self._uc_target_desc.reg_norm_to_constant[reg]
                reg_value: int = self._emulator.reg_read(reg_id)  # type: ignore
                # 如果寄存器是标志位，从 EFLAGS 中投影出对应标志
                if reg in {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"}:
                    reg_value = int((reg_value & _FLAG_NAME_TO_BITMASK[reg]) != 0)
                pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                reg_values.add(_TaintedValue(pc, reg_id, reg_value))
                print(f"reg: {reg_id}, value: {reg_value}, pc: {pc}")

        return reg_values, reg_values_tainted

    def _set_taint(self, reg: str, taint: Taint) -> None:
        """
        将寄存器 reg 的污点设置为 taint。
        如果污点集合包含 _full_input_taint，则简化为仅包含 _full_input_taint
        （因为完整输入污点代表最大权限，不需要额外的具体污点值）。

        :param reg: 寄存器名称
        :param taint: 污点集合
        """
        if self._full_input_taint in taint:
            self._reg_taints[reg] = {self._full_input_taint}
        else:
            self._reg_taints[reg] = taint

    def _update_reg_taints(self) -> None:
        """
        根据当前污点更新目标寄存器的污点。

        特殊情况：
        1) 仅更新寄存器的低位（如写入32位到64位寄存器），
           保留高位部分的旧污点
        2) 源未被污点标记但目标已被污点标记，
           用寄存器的当前值更新目标的污点（保留旧污点+添加新值）

        一般规则：
        - 如果目标未被污点标记且源被污点标记：传播源污点到目标
        - 如果目标未被污点标记且源未被污点标记：清除目标的旧污点
        - 如果目标已被污点标记：合并源污点和旧污点
        """
        for reg in self._curr_dest_regs:
            # 检查目标寄存器是否已被污点标记
            if reg in self._reg_taints:
                # 检查是否仅覆写低位部分
                if reg in self._curr_dest_regs_sizes and self._curr_dest_regs_sizes[reg] < 64:
                    # 仅低位被更新：保留旧污点并合并新污点
                    new_taint = self._reg_taints[reg] | self._curr_taint
                    self._set_taint(reg, new_taint)
                # 否则，旧污点在源被污点标记时被覆写
                elif self._curr_src_tainted:
                    self._set_taint(reg, self._curr_taint)
                # 如果源未被污点标记且目标被覆写，移除旧污点
                else:
                    self._reg_taints.pop(reg, None)
            # 如果目标未被污点标记，仅传播源污点
            elif self._curr_src_tainted:
                # 检查是否仅覆写低位部分
                if reg in self._curr_dest_regs_sizes and self._curr_dest_regs_sizes[reg] < 64:
                    # 低位被覆写：保留寄存器当前值作为污点并合并新污点
                    reg_id = self._uc_target_desc.reg_norm_to_constant[reg]
                    reg_value: int = self._emulator.reg_read(reg_id)  # type: ignore
                    pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                    new_taint = {_TaintedValue(pc, reg_id, reg_value)} | self._curr_taint
                    self._set_taint(reg, new_taint)
                else:
                    self._set_taint(reg, self._curr_taint)

    def _get_curr_load_taint(self) -> _TaintedValue:
        """
        获取当前内存加载的污点值。
        记录加载地址、大小和从模拟器读取的值。

        :return: 加载操作的污点值
        """
        address = self._curr_mem_load[0]
        size = self._curr_mem_load[1]
        mem_value = self._emulator.mem_read(address, size)
        mem_value_int = int.from_bytes(mem_value, 'little')
        pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
        return _TaintedValue(pc, address, mem_value_int)

    def _speculate_fault(self, errno: int) -> int:
        """
        在故障发生时进行值推测。

        算法步骤：
        1. 检查故障是否触发推测
        2. 保存检查点（回滚地址为故障处理程序）
        3. 如果源操作数未被污点标记（避免重复传播）：
           a. 收集故障指令的源和目标操作数
           b. 聚合源操作数的值/污点
           c. 如果有内存读取，添加加载污点
           d. 如果有内存写入，将污点传播到存储地址
           e. 将源污点传播到目标寄存器
        4. 返回下一条指令地址（推测性地跳过故障指令）

        :param errno: 故障错误号
        :return: 推测性执行的下一条指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 开始推测：保存检查点，回滚地址设为故障处理程序
        self._checkpoint(self._get_rollback_address())

        # 仅在源操作数未被污点标记时收集新污点
        # 如果源已被污点标记，污点已正确传播，无需重复处理
        if not self._curr_src_tainted:

            # 收集故障指令的操作数
            src_regs = set()
            for op in self._model.state.current_instruction.get_all_operands():
                if isinstance(op, RegisterOp):
                    if op.src:
                        op_normalized = self._target_desc.reg_normalized[op.value]
                        src_regs.add(op_normalized)
                    if op.dest:
                        op_normalized = self._target_desc.reg_normalized[op.value]
                        self._curr_dest_regs.append(op_normalized)
                        self._curr_dest_regs_sizes[op_normalized] = op.width
                elif isinstance(op, FlagsOp):
                    src_regs.update(op.get_flags_by_type('read'))
                    self._curr_dest_regs.extend(op.get_flags_by_type('write'))

            # 聚合源操作数的值/污点
            self._curr_taint, _ = self._assemble_reg_values(src_regs)

            # 如果有内存读取操作，添加加载污点
            if self._model.state.current_instruction.has_read():
                self._curr_taint.add(self._get_curr_load_taint())

            # 如果有内存写入操作，将污点传播到存储地址
            if self._model.state.current_instruction.has_write():
                address = self._curr_mem_store[0]
                size = self._curr_mem_store[1]
                for i in range(size):
                    self._mem_taints[address + i] = self._curr_taint

            # 设置 _curr_src_tainted 使 _update_reg_taints 正确工作
            self._curr_src_tainted = True
            self._update_reg_taints()

        return self._get_next_instruction()

    def _get_next_instruction(self) -> int:
        """
        返回推测性执行的下一条指令地址。
        如果下一条指令是退出地址，则不需要推测（返回 0）。

        :return: 下一条指令地址，或 0 表示不需要推测
        """
        # 推测性地跳过故障指令
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0  # 已到末尾，不需要推测
        return self._next_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        追踪污点在系统中的传播并产生正确的观测。

        算法步骤：
        1. 校正指令大小并计算下一条指令地址
        2. 重置当前观测集合和目标寄存器
        3. 仅在推测中且有活跃污点时进行追踪
        4. 解析指令操作数（源/目标寄存器和内存地址寄存器）
        5. 检查内存写入地址是否被污点标记（地址未知 -> 整个内存污点）
        6. 检查内存读取地址是否被污点标记（值未知 -> 目标寄存器污点）
        7. 聚合源操作数污点并更新目标寄存器污点

        :param address: 指令地址
        :param size: 指令大小
        """
        # 校正指令大小（无效指令可能有错误的大小）
        if self._model.state.current_instruction.size() not in [0, size]:
            size = self._model.state.current_instruction.size()
        self._next_instruction_addr = address + size

        # 重置当前观测集合和目标寄存器（必须在检查是否跳过之前，
        # 否则 trace_mem_access 可能使用旧值）
        self._curr_observation = set()
        self._curr_taint = set()
        self._curr_dest_regs = []
        self._curr_dest_regs_sizes = {}
        self._curr_src_tainted = False

        # 仅在有活跃污点时追踪（故障后且污点未传播完毕）
        if not self._in_speculation or (not self._reg_taints and not self._mem_taints):
            return

        src_regs = set()
        mem_src_regs = set()
        mem_dest_regs = set()

        # 解析指令操作数：区分正常寄存器和内存地址中的寄存器
        for op in self._model.state.current_instruction.get_all_operands():
            if isinstance(op, RegisterOp):
                if op.src:
                    op_normalized = self._target_desc.reg_normalized[op.value]
                    src_regs.add(op_normalized)
                if op.dest:
                    op_normalized = self._target_desc.reg_normalized[op.value]
                    self._curr_dest_regs.append(op_normalized)
                    self._curr_dest_regs_sizes[op_normalized] = op.width
            elif isinstance(op, MemoryOp):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        if op.src:
                            mem_src_regs.add(normalized)
                        if op.dest:
                            mem_dest_regs.add(normalized)
            elif isinstance(op, FlagsOp):
                src_regs.update(op.get_flags_by_type('read'))
                self._curr_dest_regs.extend(op.get_flags_by_type('write'))
            elif isinstance(op, AgenOp):
                assert self._model.state.current_instruction.name == "lea"
                assert op.src
                for sub_op in re.split(r'\[|\]|\+|-|\*| ', op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        src_regs.add(normalized)

        # 聚合内存写入地址寄存器的值（如果被污点标记则使用污点）
        mem_dest_reg_values, _ = self._assemble_reg_values(mem_dest_regs)

        # 检查存储地址是否使用了污点寄存器 -> 地址未知
        tainted_mem_dest_regs = mem_dest_regs & self._reg_taints.keys()
        if tainted_mem_dest_regs:
            assert self._model.state.current_instruction.has_write()
            # 记录存储的观测：泄漏污点如果使用了被污点标记的寄存器
            self._curr_observation = self._curr_observation | mem_dest_reg_values
            # 地址未知 -> 整个内存被污点标记（隐式使用输入哈希）
            self._whole_memory_tainted = True

        # 聚合内存读取地址寄存器的值
        mem_src_reg_values, _ = self._assemble_reg_values(mem_src_regs)

        # 检查加载地址是否使用了污点寄存器 -> 值未知
        tainted_mem_src_regs = mem_src_regs & self._reg_taints.keys()

        if tainted_mem_src_regs and not self._model.state.current_instruction.name == "lea":
            assert self._model.state.current_instruction.has_read()
            # 记录加载的观测：泄漏污点
            self._curr_observation = self._curr_observation | mem_src_reg_values
            # 从未知地址加载 -> 目标寄存器被污点标记为完整输入（代表完整架构状态）
            self._curr_taint = {self._full_input_taint}
            for reg in self._curr_dest_regs:
                self._reg_taints[reg] = self._curr_taint
            # 记住指令使用了被污点标记的操作数
            self._curr_src_tainted = True
            # 所有目标寄存器已被最大污点标记，可以返回
            return

        # 聚合所有源寄存器的值/污点
        self._curr_taint, self._curr_src_tainted = self._assemble_reg_values(src_regs)
        self._update_reg_taints()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        在内存访问时追踪污点传播和观测。

        算法：
        1. 记录最后一次加载/存储的地址和大小（异常时需要）
        2. 仅在推测状态下处理
        3. 对于读取：检查地址是否被污点标记，传播地址污点到当前污点
        4. 对于写入：如果源被污点标记则将污点写入地址，否则清除地址污点
        5. 检查是否有污点观测需要泄漏到合约轨迹

        :param access: 内存访问类型
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 内存访问的值
        """
        # 记录地址和大小以备异常处理
        if access != UC_MEM_WRITE:
            self._curr_mem_load = (address, size)
        else:
            self._curr_mem_store = (address, size)

        if not self._in_speculation:
            # FIXME: 此分支应通过 self._model.tracer.enable_tracing 启用/禁用追踪
            return

        mem_value = self._model.emulator.mem_read(address, size)

        if access != UC_MEM_WRITE:
            # 对于读取：检查地址是否被污点标记
            is_tainted: bool = False
            taints = set()
            for i in range(size):
                if address + i in self._mem_taints:
                    is_tainted = True
                    taints.update(self._mem_taints[address + i])

            # 将地址污点添加到当前污点集合
            if is_tainted:
                self._curr_taint.update(taints)
            elif self._whole_memory_tainted:
                # 整个内存被污点标记 -> 使用完整输入污点
                self._curr_taint.add(self._full_input_taint)

            if is_tainted or self._whole_memory_tainted:
                # 地址被污点标记 -> 目标寄存器也被污点标记
                self._curr_src_tainted = True
                self._update_reg_taints()
            else:
                # 地址未被污点标记 -> 将存储的值添加到当前污点
                mem_value_int = int.from_bytes(mem_value, 'little')
                pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                self._curr_taint.add(_TaintedValue(pc, address, mem_value_int))
                self._update_reg_taints()

        if access == UC_MEM_WRITE:
            # 对于写入：检查源是否被污点标记
            if not self._curr_src_tainted:
                # 源未被污点标记 -> 清除地址范围的旧污点
                for i in range(size):
                    self._mem_taints.pop(address + i, None)
            elif not self._whole_memory_tainted:
                # 源被污点标记 -> 将当前污点写入地址范围
                for i in range(size):
                    self._mem_taints[address + i] = self._curr_taint

        # 检查内存访问是否创建污点观测
        if self._curr_observation:
            # 如果观测包含完整架构状态信息，仅泄漏输入哈希
            if self._full_input_taint in self._curr_observation:
                self._curr_observation = {self._full_input_taint}
            observation_list = list(self._curr_observation)
            observation_list.sort()
            # FIXME: 此处应替换为对追踪器的公共调用
        else:
            pass
            # 正常内存访问

    def _checkpoint(self, next_instruction_addr: int, include_current_inst: bool = True) -> None:
        """ 保存检查点，包括寄存器污点、内存污点和整体内存污点状态。 """
        self._reg_taints_checkpoints.append(copy(self._reg_taints))
        self._mem_taints_checkpoints.append(copy(self._mem_taints))
        self._whole_memory_tainted_checkpoints.append(copy(self._whole_memory_tainted))
        return super()._checkpoint(next_instruction_addr, include_current_inst=include_current_inst)

    def rollback(self) -> int:
        """ 回滚时恢复寄存器污点、内存污点和整体内存污点状态。 """
        self._reg_taints = self._reg_taints_checkpoints.pop()
        self._mem_taints = self._mem_taints_checkpoints.pop()
        self._whole_memory_tainted = self._whole_memory_tainted_checkpoints.pop()
        return super().rollback()

    def _get_rollback_address(self) -> int:
        """ 返回回滚地址（故障终止程序执行，回滚到故障处理程序）。 """
        return self._model.state.fault_handler_addr


class VspecDIVSpeculator(_VspecBaseSpeculator):
    """
    除法错误上的操作数值推测。
    仅对除法异常(errno 21)触发推测。
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化除法错误值推测器。
        仅触发 DIV 异常(errno 21)。
        """
        super().__init__(target_desc, model, taint_tracker)
        # 仅 DIV 异常
        self._errno_that_trigger_speculation = {21}


class VspecMemoryFaultsSpeculator(_VspecBaseSpeculator):
    """
    页故障上的操作数值推测。
    对 GP(6,7) 和 PF(12,13) 触发推测。
    包含页权限恢复和重新执行的逻辑。
    """

    pending_restore_protection: bool = False
    """ 是否需要恢复故障页权限 """
    pending_re_execution: bool = False
    """ 是否需要重新执行故障指令 """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化页故障值推测器。
        对 GP 和 PF 故障触发推测。
        """
        super().__init__(target_desc, model, taint_tracker)
        # 页故障和其他内存错误
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

    def _get_curr_load_taint(self) -> _TaintedValue:
        """
        页故障值推测的加载污点：值未定义，因此不包含内存值。

        :return: 污点值（value=0 表示值未定义）
        """
        load_addr = self._curr_mem_load[0]
        pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
        return _TaintedValue(pc, load_addr, 0)

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        处理权限恢复和重新执行的状态机。

        两种状态：
        1. pending_restore_protection: 需要恢复页权限
        2. pending_re_execution: 需要重新执行指令（然后标记恢复权限）

        FIXME: 此处使用了过时的接口；
        参见 speculator_faults.py:X86UnicornNull 中的维护版本。
        """
        if self.pending_restore_protection:
            self.pending_restore_protection = False
            # FIXME: 过时实现
        elif self.pending_re_execution:
            self.pending_re_execution = False
            self.pending_restore_protection = True
        super()._speculate_instruction(address, size)

    def _get_next_instruction(self) -> int:
        """
        返回下一条指令地址。
        如果到退出地址，返回 0（不需要推测）。

        FIXME: 使用了过时的接口。
        """
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0

        return self._next_instruction_addr


class VspecMemoryAssistsSpeculator(VspecMemoryFaultsSpeculator):
    """
    微代码辅助上的操作数值推测（MDS 类型）。
    仅对 A/D 位缺失(errno 12, 13)触发推测。
    回滚后恢复故障页权限为 RW。
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化微代码辅助值推测器。
        仅对 A/D 位缺失触发推测。
        """
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def rollback(self) -> int:
        """
        回滚时恢复故障页权限。

        如果不再处于推测状态（即最外层回滚），恢复故障页为 RW，
        因为辅助已完成（A/D 位已被设置）。

        :return: 回滚后的指令地址
        """
        next_instruction = super().rollback()
        if not self._in_speculation:
            # 辅助完成后移除保护
            self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)

        return next_instruction

    def _get_rollback_address(self) -> int:
        """
        返回回滚地址。

        如果仍处于推测中（嵌套推测），回滚到故障处理程序。
        如果是最外层推测，回滚到当前指令地址（辅助后重新执行）。

        :return: 回滚地址
        """
        if self._in_speculation:
            return self._model.state.fault_handler_addr
        return self._curr_instruction_addr


class VspecGPSpeculator(_VspecBaseSpeculator, X86NonCanonicalAddress):
    """
    一般保护故障(GP)上的操作数值推测。
    处理非规范地址和非规范地址到规范地址的转换。
    对 GP(errno 6, 7)触发推测。
    """

    address_register: int
    """ 使用非规范地址的寄存器 ID """
    register_value: int
    """ 寄存器的原始值（用于恢复）"""

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化 GP 值推测器。
        对 GP 和其他故障类型触发推测。
        """
        super().__init__(target_desc, model, taint_tracker)
        # 添加 GP 故障到触发集合
        self._errno_that_trigger_speculation.update([6, 7])

    def _speculate_fault(self, errno: int) -> int:
        """
        GP 故障时的值推测。

        与基类不同之处：
        - 加载地址被转换为规范地址后再读取内存值
        - 存储地址也被转换为规范地址后标记污点
        - 推测性地从当前指令地址重新执行（而非跳过）

        :param errno: 故障错误号
        :return: 推测性执行的指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 仅在源操作数未被污点标记时收集新污点
        if not self._curr_src_tainted:

            src_regs = set()
            for op in self._model.state.current_instruction.get_all_operands():
                if isinstance(op, RegisterOp):
                    if op.src:
                        op_normalized = self._target_desc.reg_normalized[op.value]
                        src_regs.add(op_normalized)
                    if op.dest:
                        op_normalized = self._target_desc.reg_normalized[op.value]
                        self._curr_dest_regs.append(op_normalized)
                        self._curr_dest_regs_sizes[op_normalized] = op.width
                elif isinstance(op, FlagsOp):
                    src_regs.update(op.get_flags_by_type('read'))
                    self._curr_dest_regs.extend(op.get_flags_by_type('write'))

            # 聚合源操作数的值/污点
            self._curr_taint, _ = self._assemble_reg_values(src_regs)

            # 对于读取操作：将非规范地址转换为规范地址后读取内存值
            if self._model.state.current_instruction.has_read():
                address = self._curr_mem_load[0]
                address = self._noncanonical_to_canonical(address)
                size = self._curr_mem_load[1]
                mem_value = self._emulator.mem_read(address, size)
                mem_value_int = int.from_bytes(mem_value, 'little')
                pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                self._curr_taint.add(_TaintedValue(pc, address, mem_value_int))

            # 对于写入操作：将非规范地址转换为规范地址后标记污点
            if self._model.state.current_instruction.has_write():
                address = self._curr_mem_store[0]
                address = self._noncanonical_to_canonical(address)
                size = self._curr_mem_store[1]
                for i in range(size):
                    self._mem_taints[address + i] = self._curr_taint

            # 设置 _curr_src_tainted 使 _update_reg_taints 正确工作
            self._curr_src_tainted = True
            self._update_reg_taints()

        # 推测性地从当前指令地址重新执行（而非跳过）
        return self._curr_instruction_addr

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        GP 值推测的内存访问处理。

        对于故障指令的内存访问，在 _speculate_fault 之前收集地址信息，
        然后调用 _speculate_fault 处理非规范地址转换。
        最后调用基类的 _speculate_mem_access 处理正常的污点传播。

        :param access: 内存访问类型
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 内存访问值
        """
        if self._curr_instruction_addr == self.faulty_instruction_addr:
            # 在故障指令处：收集地址信息并触发推测
            if access != UC_MEM_WRITE:
                self._curr_mem_load = (address, size)
            else:
                self._curr_mem_store = (address, size)
            self._speculate_fault(6)
        super()._speculate_mem_access(access, address, size, value)

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        GP 值推测的指令处理。

        对于非故障指令，调用基类的污点追踪逻辑。
        对于故障指令，跳过基类处理（已在 _speculate_mem_access 中处理）。
        同时调用 X86NonCanonicalAddress 的非规范地址转换逻辑。
        """
        super(X86NonCanonicalAddress, self)._speculate_instruction(address, size)
        if address != self.faulty_instruction_addr:
            super(_VspecBaseSpeculator, self)._speculate_instruction(address, size)

    def _noncanonical_to_canonical(self, address: int) -> int:
        """
        将非规范地址转换为最接近的规范地址。

        x86-64 规范地址规则：
        - 如果第48位为1（高位地址），高16位设为全1
        - 如果第48位为0（低位地址），高16位设为全0

        :param address: 非规范地址
        :return: 最接近的规范地址
        """
        if address & (1 << 47):  # 第48位为1 -> 高位地址
            address = address | 0xFFFF800000000000
        else:  # 第48位为0 -> 低位地址
            address = address & 0x00007FFFFFFFFFF
        return address

    def _get_rollback_address(self) -> int:
        """ 回滚地址为故障处理程序。 """
        return self._model.state.fault_handler_addr

    def reset(self) -> None:
        """ 重置时清除故障指令地址和寄存器信息。 """
        self.faulty_instruction_addr = -1
        self.address_register = -1
        self.register_value = -1
        return super().reset()


class VspecAllSpeculator(_VspecBaseSpeculator):
    """
    最宽松的推测合约。

    使用 vspec-unknown 合约，但在异常情况下目标操作数依赖完整架构状态
    （即完整输入的哈希），而非源操作数的具体值。
    这模拟了最极端的推测行为：任何故障都可能泄露完整的架构状态。
    """

    def _speculate_fault(self, errno: int) -> int:
        """
        最宽松合约的故障推测。

        与 VspecBase 不同之处：
        - 目标操作数的污点直接设为 _full_input_taint（完整架构状态）
        - 不聚合源操作数的具体值，而是用输入哈希替代
        - 存储地址的污点也设为 _full_input_taint

        :param errno: 故障错误号
        :return: 推测性执行的下一条指令地址；0 表示不推测
        """
        if not self._fault_triggers_speculation(errno):
            return 0

        # 开始推测：保存检查点
        self._checkpoint(self._get_rollback_address())

        # 仅在源操作数未被污点标记时收集新污点
        if not self._curr_src_tainted:

            # 收集目标操作数
            for op in self._model.state.current_instruction.get_all_operands():
                if isinstance(op, RegisterOp):
                    if op.dest:
                        self._curr_dest_regs.append(self._target_desc.reg_normalized[op.value])
                elif isinstance(op, FlagsOp):
                    self._curr_dest_regs.extend(op.get_flags_by_type('write'))

            # 存储地址的污点设为完整输入哈希
            if self._model.state.current_instruction.has_write():
                address = self._curr_mem_store[0]
                size = self._curr_mem_store[1]
                for i in range(size):
                    self._mem_taints[address + i] = {self._full_input_taint}

            # 目标寄存器的污点设为完整输入哈希（代表完整架构状态）
            for reg in self._curr_dest_regs:
                self._reg_taints[reg] = {self._full_input_taint}

        return self._get_next_instruction()


class VspecAllDIVSpeculator(VspecAllSpeculator):
    """
    除法错误上的任意值推测。
    仅对 DIV 异常(errno 21)触发推测。
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """ 初始化除法错误任意值推测器。仅触发 DIV 异常。 """
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {21}


class VspecAllMemoryFaultsSpeculator(VspecAllSpeculator):
    """
    页故障上的任意值推测。
    对 GP(6,7) 和 PF(12,13) 触发推测。
    包含页权限恢复和重新执行的状态机逻辑。

    FIXME: 此类中的权限恢复逻辑使用了过时的接口。
    """

    pending_restore_protection: bool = False
    """ 是否需要恢复故障页权限 """
    pending_re_execution: bool = False
    """ 是否需要重新执行故障指令 """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """ 初始化页故障任意值推测器。对页故障和内存错误触发推测。 """
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        处理权限恢复和重新执行的状态机。
        FIXME: 使用了过时的接口。
        """
        if self.pending_restore_protection:
            self.pending_restore_protection = False
            # FIXME: 过时实现
        elif self.pending_re_execution:
            self.pending_re_execution = False
            self.pending_restore_protection = True
            return
        super()._speculate_instruction(address, size)

    def _get_next_instruction(self) -> int:
        """
        返回下一条指令地址。
        FIXME: 使用了过时的接口。
        """
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0

        return self._next_instruction_addr


class VspecAllMemoryAssistsSpeculator(VspecAllSpeculator):
    """
    微代码辅助上的任意值推测（MDS 类型）。
    仅对 A/D 位缺失(errno 12, 13)触发推测。
    回滚后恢复故障页权限为 RW（因为辅助已完成）。
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """ 初始化微代码辅助任意值推测器。仅对 A/D 位缺失触发推测。 """
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def rollback(self) -> int:
        """
        回滚时恢复故障页权限。

        如果不再处于推测状态（最外层回滚），恢复故障页为 RW，
        因为辅助已完成（A/D 位已被设置）。

        :return: 回滚后的指令地址
        """
        next_instruction = super().rollback()
        if not self._in_speculation:
            # 辅助完成后移除保护
            self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return next_instruction

    def _get_rollback_address(self) -> int:
        """
        返回回滚地址。
        嵌套推测时回滚到故障处理程序，
        最外层推测时回滚到当前指令地址（辅助后重新执行）。

        :return: 回滚地址
        """
        if self._in_speculation:
            return self._model.state.fault_handler_addr
        return self._curr_instruction_addr

"""
文件：Unicorn 后端合约模型追踪器集合。

追踪器(tracer)是在测试用例于合约模型上执行期间记录特定事件的组件。
不同的追踪器实现了不同合约的观测条款(observation clause)。
追踪器记录的信息构成合约轨迹(contract trace)，用于检测微架构侧信道泄漏。

本模块包含以下追踪器：
- UnicornTracer: 抽象基类，提供通用功能
- NoneTracer: 不记录任何信息的占位追踪器
- PCTracer: 记录所有执行指令的程序计数器(PC)
- MemoryTracer: 记录所有内存访问地址
- L1DTracer: 与 MemoryTracer 类似，但标记为 L1D 轨迹
- CTTracer: 同时记录 PC 和内存地址（常用于常量时间合约）
- TruncatedCTTracer: 以缓存行粒度记录 PC 和内存地址
- TruncatedCTWithOverflowsTracer: 缓存行粒度 + 跨行溢出
- CTNonSpecStoreTracer: 非推测性存储过滤
- ArchTracer: 记录寄存器值和加载值（用于安全推测机制建模）
- ActorNITracer: 基于 actor 的非干扰追踪器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC

from typing import List, TYPE_CHECKING, Optional
from unicorn import UC_MEM_READ
import xxhash

from ..traces import CTrace, CTraceEntry
from ..config import CONF

if TYPE_CHECKING:
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_code import TestCaseProgram


# ==================================================================================================
# 抽象追踪器接口
# ==================================================================================================
class UnicornTracer(ABC):
    """
    所有追踪器必须实现的接口定义，以及通用功能的实现。

    追踪器通过 observe_instruction 和 observe_mem_access 方法在模型执行期间
    收集观测信息，最终通过 get_trace 方法生成合约轨迹(CTrace)。

    enable_tracing 标志控制是否实际记录轨迹数据（通常由 measurement_start/end 宏控制）。
    """
    trace: List[CTraceEntry]
    """ 当前收集的轨迹条目列表 """
    enable_tracing: bool = False
    """ 是否启用轨迹记录（由 measurement 宏控制）"""
    _model: UnicornModel
    _taint_tracker: UnicornTaintTracker
    _uc_target_desc: UnicornTargetDesc
    _test_case: Optional[TestCaseProgram] = None
    _input: Optional[InputData] = None

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化追踪器。
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__()
        self.trace = []
        self._model = model
        self._taint_tracker = taint_tracker
        self._uc_target_desc = target_desc.uc_target_desc

    # ==============================================================================================
    # 公共接口
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ 加载测试用例到追踪器 """
        self._test_case = test_case

    def reset(self, input_: InputData) -> None:
        """
        初始化/重置追踪器状态，用于追踪加载的测试用例与给定输入。
        清空轨迹列表并禁用追踪（直到 measurement_start 宏启用）。
        :param input_: 当前执行的输入数据
        """
        self.trace = []
        self.enable_tracing = False
        self._input = input_

    def get_trace(self) -> CTrace:
        """ 返回收集的轨迹，形式为 CTrace 对象。
        通过归一化地址（将绝对地址转换为沙箱偏移量）使轨迹可重现，
        以确保不同运行间的轨迹具有可比性。
        :return: 归一化后的合约轨迹
        """

        # 通过归一化地址使轨迹可重现
        normalized_trace: List[CTraceEntry] = []
        layout = self._model.layout
        for org_entry in self.trace:
            if org_entry.type_ == "pc":
                # PC 地址转换为代码区偏移量
                entry = CTraceEntry("pc", layout.code_addr_to_offset(org_entry.value))
            elif org_entry.type_ == "mem":
                # 内存地址转换为数据区偏移量
                entry = CTraceEntry("mem", layout.data_addr_to_offset(org_entry.value))
            else:
                entry = CTraceEntry(org_entry.type_, org_entry.value)
            normalized_trace.append(entry)
        return CTrace(normalized_trace)

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        追踪内存访问事件。
        值是否记录到轨迹取决于具体追踪器的实现。
        :param access: 访问类型（UC_MEM_READ 或 UC_MEM_WRITE）
        :param address: 内存访问地址
        :param size: 内存访问大小
        :param value: 读取或写入的值
        """

    def observe_instruction(self, pc: int, size: int) -> None:
        """
        追踪指令执行事件。
        值是否记录到轨迹取决于具体追踪器的实现。
        :param pc: 指令的程序计数器
        :param size: 指令的大小
        """

    # ==============================================================================================
    # 私有方法

    def _add_mem_address_to_trace(self, address: int) -> None:
        """ 记录给定内存地址到轨迹（仅在追踪启用时），
        同时调用污点追踪器标记内存地址为污点。
        :param address: 要记录的内存地址
        """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("mem", address))
            self._taint_tracker.taint("mem")

    def _add_pc_to_trace(self, address: int) -> None:
        """ 记录给定程序计数器到轨迹（仅在追踪启用时），
        同时调用污点追踪器标记 PC 为污点。
        :param address: 要记录的 PC 地址
        """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("pc", address))
            self._taint_tracker.taint("pc")

    def _add_dependencies_to_trace(self, dependency_hash: int) -> None:
        """ 记录给定依赖哈希到轨迹（仅在追踪启用时），
        同时调用污点追踪器标记内存为污点。
        :param dependency_hash: 依赖关系的哈希值
        """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("val", dependency_hash))
            self._taint_tracker.taint("mem")

    def _add_value_to_trace(self, val: int) -> None:
        """ 记录给定无类型值到轨迹（仅在追踪启用时）。
        :param val: 要记录的值
        """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("val", val))


# ==================================================================================================
# 具体追踪器实现
# ==================================================================================================
class NoneTracer(UnicornTracer):
    """
    不记录任何信息的追踪器。
    作为占位符使用，当测试用例需要在模型上执行但不需追踪时使用。
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        pass

    def observe_instruction(self, pc: int, size: int) -> None:
        pass

    def get_trace(self) -> CTrace:
        """ 返回空轨迹 """
        return CTrace.empty_trace()


class PCTracer(UnicornTracer):
    """
    记录模型上所有执行指令的程序计数器(PC)的追踪器。

    示例：执行以下程序时：
        0x0: mov eax, 0x1
        0x4: mov ebx, 0x2
        0x8: mov ecx, 0x3

    输出轨迹为 [0x0, 0x4, 0x8]
    """

    def observe_instruction(self, pc: int, size: int) -> None:
        """ 记录每条指令的 PC 地址 """
        self._add_pc_to_trace(pc)
        super().observe_instruction(pc, size)


class MemoryTracer(UnicornTracer):
    """
    记录模型访问的所有内存地址的追踪器。

    示例：执行以下程序时：
        0x0: mov eax, [0x100]
        0x4: mov ebx, [0x200]
        0x8: mov ecx, [0x300]

    输出轨迹为 [0x100, 0x200, 0x300]
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 记录每次内存访问的地址 """
        self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class L1DTracer(MemoryTracer):
    """
    与 MemoryTracer 类似，但轨迹会被标记为 L1D 轨迹；
    即当此类轨迹被打印时，将以 L1D 缓存映射的形式呈现。
    """

    def get_trace(self) -> CTrace:
        """ 获取轨迹并标记为 L1D 格式 """
        trace = super().get_trace()
        trace.set_printed_as_l1d(True)
        return trace


class CTTracer(PCTracer):
    """
    同时观测内存访问地址和程序计数器的追踪器。
    实现常量时间(constant-time)合约的观测条款。
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 记录内存访问地址（同时继承 PCTracer 的 PC 记录） """
        self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class TruncatedCTTracer(UnicornTracer):
    """
    以缓存行粒度（64字节对齐）观测内存访问地址和程序计数器的追踪器。
    通过对地址右移6位再左移6位实现对齐，模拟 L1D 缓存行的观测粒度。
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 记录缓存行对齐后的内存地址 """
        self._add_mem_address_to_trace((address >> 6) << 6)
        super().observe_mem_access(access, address, size, value)

    def observe_instruction(self, pc: int, size: int) -> None:
        """ 记录缓存行对齐后的 PC 地址 """
        self._add_pc_to_trace((pc >> 6) << 6)
        super().observe_instruction(pc, size)


class TruncatedCTWithOverflowsTracer(UnicornTracer):
    """
    以缓存行粒度观测内存地址和 PC + 同时观测跨缓存行溢出的追踪器。

    当内存访问或指令跨越缓存行边界时，额外记录溢出目标缓存行的地址。
    这更精确地模拟了 L1D 缓存的行为，因为跨行访问会影响两个缓存行。
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 记录缓存行对齐的内存地址，并在跨行时记录溢出缓存行 """
        self._add_mem_address_to_trace((address >> 6) << 6)
        if (address + size) % 64 != (address % 64):  # 记录跨缓存行溢出
            self._add_mem_address_to_trace(((address + size) >> 6) << 6)
        return super().observe_mem_access(access, address, size, value)

    def observe_instruction(self, pc: int, size: int) -> None:
        """ 记录缓存行对齐的 PC 地址，并在跨行时记录溢出缓存行 """
        self._add_pc_to_trace((pc >> 6) << 6)
        if (pc + size) // 64 != (pc // 64):  # 记录跨缓存行溢出
            self._add_pc_to_trace(((pc + size) >> 6) << 6)
        return super().observe_instruction(pc, size)


class CTNonSpecStoreTracer(PCTracer):
    """
    仅在非推测状态下或为读取操作时观测内存地址的追踪器。
    推测性存储(store)不在轨迹中暴露，因为它们在回滚后不会持久化，
    但推测性读取(load)仍会暴露（模拟 L1D 缓存填充行为）。
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 仅追踪非推测内存访问和推测性读取（过滤推测性存储）"""
        # 追踪所有非推测内存访问和推测性读取
        if not self._model.speculator.in_speculation() or access == UC_MEM_READ:
            self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class ArchTracer(CTTracer):
    """
    类似于 CTTracer，额外暴露：
    - 首次内存访问时的寄存器状态
    - 从内存加载的值

    主要用途是建模安全推测机制（如 Speculative Taint Tracking, STT）
    所提供的保证。在这些机制下，攻击者可观测到完整的架构状态。
    """
    _started: bool = False

    def reset(self, input_: InputData) -> None:
        """ 重置追踪器，包括重置首指令标记 """
        super().reset(input_)
        self._started = False

    def observe_instruction(self, pc: int, size: int) -> None:
        """ 第一条指令暴露所有寄存器值，后续指令仅记录 PC """
        # 第一条指令必须暴露所有寄存器值
        if not self._started:
            self._started = True
            for reg in self._uc_target_desc.usable_registers[:-1]:  # 排除栈指针
                val = self._model.emulator.reg_read(reg)
                assert isinstance(val, int), f"Expected int, got {type(val)}"
                self.trace.append(CTraceEntry("val", val))

        return super().observe_instruction(pc, size)

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ 对于读取操作，额外记录加载的值并标记为 ld_val 污点 """
        if access == UC_MEM_READ:
            # 记录从内存读取的实际值
            val = int.from_bytes(self._model.emulator.mem_read(address, size), byteorder='little')
            self._add_value_to_trace(val)
            self._taint_tracker.taint("ld_val")
        super().observe_mem_access(access, address, size, value)


# ==================================================================================================
# 基于 Actor 的追踪器
# ==================================================================================================
class ActorNITracer(CTTracer):
    """
    暴露具有 observer 标志的 actor 的所有数据 + 非 observer actor 的顺序轨迹的追踪器。

    该追踪器实现了非干扰(non-interference)合约的观测条款：
    - observer actor 的输入数据哈希被添加到轨迹中
    - 所有 actor 的内存访问和 PC 被记录
    - 污点追踪器被用来标记 observer actor 的数据区域
    """
    _observer_actor_ids: List[int]

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        """
        初始化 actor 非干扰追踪器。
        要求至少有一个 observer actor 和一个非 observer actor。
        :param target_desc: 目标架构描述
        :param model: Unicorn 模型实例
        :param taint_tracker: 污点追踪器实例
        """
        super().__init__(target_desc, model, taint_tracker)
        n_observers = len([desc for desc in CONF.get_actors_conf().values() if desc['observer']])
        if n_observers == len(CONF.get_actors_conf()):
            raise ValueError("ActorNITracer requires at least 1 non-observer actor")
        if n_observers == 0:
            raise ValueError("ActorNITracer requires at least 1 observer actor")

    def reset(self, input_: InputData) -> None:
        """ 重置追踪器并确定 observer actor 的 ID 列表 """
        super().reset(input_)
        assert self._test_case is not None, "Test case not loaded"
        self._observer_actor_ids = [
            actor.get_id() for actor in self._test_case.get_actors() if actor.observer
        ]

    def get_trace(self) -> CTrace:
        """ 获取轨迹并添加 observer actor 的输入数据哈希。
        同时调用污点追踪器标记 observer actor 的数据区域为污点。
        """
        ctrace = super().get_trace()
        ctrace = self._add_observer_traces(ctrace)
        self._taint_tracker.taint_actors(self._observer_actor_ids)
        return ctrace

    def _add_observer_traces(self, ctrace: CTrace) -> CTrace:
        """
        将 observer actor 的输入数据哈希添加到轨迹末尾。
        使用 xxhash 对每个 observer actor 的输入片段计算哈希值。
        :param ctrace: 基础合约轨迹
        :return: 添加了 observer 数据哈希的新轨迹
        """
        assert self._input is not None, "Input not loaded"
        fragment_hashes: List[CTraceEntry] = []
        for actor_id in self._observer_actor_ids:
            input_fragment = self._input[actor_id]
            data = input_fragment.tobytes()
            hash_ = xxhash.xxh64(data, seed=0).intdigest()
            fragment_hashes.append(CTraceEntry("val", hash_))
        # 将类型化轨迹与 observer 数据哈希合并
        new_trace = ctrace.get_typed() + fragment_hashes
        return CTrace(new_trace)

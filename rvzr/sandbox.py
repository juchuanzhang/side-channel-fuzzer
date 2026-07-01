"""
文件：沙箱（Sandbox）内存布局常量与管理类
定义数据沙箱和代码沙箱的内存布局，确保执行器（executor）和模型（model）
之间的内存布局一致性。详见 docs/sandbox.md。

沙箱是模糊测试框架的核心概念之一：测试用例在隔离的沙箱环境中执行，
数据和代码分别映射到独立的内存区域，以防止测试用例影响系统其他部分。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from enum import Enum
from typing import Dict, List, Tuple, TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from .tc_components.test_case_code import TestCaseProgram

PAGE_SIZE = 4096  # 页大小常量：4KB，与硬件页大小一致

SandboxAddr = int          # 沙箱地址类型（整型）
DataAddr = SandboxAddr     # 数据沙箱地址类型
CodeAddr = SandboxAddr     # 代码沙箱地址类型
BaseAddrTuple = Tuple[DataAddr, CodeAddr]  # 基地址元组：数据基地址和代码基地址


# ==================================================================================================
# 区域枚举定义
# ==================================================================================================
class DataArea(Enum):
    """
    数据沙箱区域枚举类：定义数据沙箱中各功能区域的标识。
    每个区域在数据沙箱中有特定的用途和偏移量。
    """
    START = 0          # 数据沙箱起始位置
    MACRO_STACK = 1    # 宏堆栈区域（用于宏指令的堆栈操作）
    UNDERFLOW_PAD = 2  # 下溢填充区域（防止堆栈下溢越界）
    MAIN = 3           # 主数据区域（存放测试输入数据）
    FAULTY = 4         # 故障页区域（模拟页表故障）
    REG_INIT = 5       # 寄存器初始化区域
    GPR = 6            # 通用寄存器保存区域（8个64位GPR）
    SIMD = 7           # SIMD寄存器保存区域（8个256位YMM）
    OVERFLOW_PAD = 8   # 上溢填充区域（防止堆栈上溢越界）
    RSP_INIT = 9       # RSP初始化区域（堆栈指针初始值）


class CodeArea(Enum):
    """
    代码沙箱区域枚举类：定义代码沙箱中各功能区域的标识。
    """
    START = 0   # 代码沙箱起始位置
    MAIN = 1    # 主代码区域（存放测试用例的主要指令序列）
    MACRO = 2   # 宏代码区域（存放辅助宏指令）


# ==================================================================================================
# 沙箱布局类
# ==================================================================================================
class SandboxLayout:
    """
    数据和代码沙箱布局管理类。
    负责确保执行器、模型和代码生成器之间的内存布局一致性。
    
    沙箱布局的核心思想：每个参与者（actor）拥有独立的数据和代码区域，
    区域内部按固定格式划分，所有偏移量和大小在框架各模块间保持一致。
    
    该类同时提供类方法（用于查询布局常量）和实例方法（用于查询基于基地址的具体地址）。
    """
    _data_start: DataAddr
    _data_end: DataAddr
    _code_start: CodeAddr
    _code_end: CodeAddr

    _data_addresses: List[Dict[DataArea, DataAddr]]    # 每个actor的数据区域地址映射表
    _code_addresses: List[Dict[CodeArea, CodeAddr]]    # 每个actor的代码区域地址映射表

    # 注意：_DataAreaLayout 和 _CodeAreaLayout 中的常量必须与执行器内核模块中的
    # actor_data_t 和 actor_code_t 结构体定义保持一致
    # （见 rvzr/executor_km/include/sandbox_manager.h）
    _DataAreaLayout = np.dtype(
        [
            ('MACRO_STACK', np.uint8, 64),               # 宏堆栈：64字节
            ('UNDERFLOW_PAD', np.uint8, PAGE_SIZE - 64),  # 下溢填充：填充到页边界
            ('MAIN', np.uint8, PAGE_SIZE),                # 主数据区：1页（4096字节）
            ('FAULTY', np.uint8, PAGE_SIZE),              # 故障页：1页
            ('GPR', np.uint8, 64),                        # GPR区：64字节（8个64位寄存器）
            ('SIMD', np.uint8, 256),                      # SIMD区：256字节（8个256位寄存器）
            ('OVERFLOW_PAD', np.uint8, PAGE_SIZE - 64 - 256),  # 上溢填充
        ],
        align=False,
    )

    _CodeAreaLayout = np.dtype(
        [
            ('MAIN', np.uint8, 2 * PAGE_SIZE),    # 主代码区：2页
            ('MACRO', np.uint8, PAGE_SIZE),        # 宏代码区：1页
        ],
        align=False,
    )

    # ==============================================================================================
    # 布局常量访问器（类方法）
    # ==============================================================================================
    @classmethod
    def data_area_size(cls, area: DataArea) -> int:
        """
        获取数据沙箱中指定区域的大小。
        :param area: 要查询的数据区域
        :return: 该区域的字节大小
        """
        return cls._DataAreaLayout[area.name].itemsize

    @classmethod
    def data_area_offset(cls, area: DataArea) -> int:
        """
        获取数据沙箱中指定区域的偏移量（相对于单个actor的数据起始地址）。
        :param area: 要查询的数据区域
        :return: 该区域的字节偏移量
        """
        if area == DataArea.START:
            return 0
        if area == DataArea.REG_INIT:
            # REG_INIT 与 GPR 区域共享偏移量（寄存器初始化值存放在GPR区域）
            return cls._DataAreaLayout.fields['GPR'][1]  # type: ignore
        if area == DataArea.RSP_INIT:
            # RSP_INIT 位于 FAULTY 区域之前8字节处（堆栈指针初始值）
            return cls._DataAreaLayout.fields['FAULTY'][1] - 8  # type: ignore
        return cls._DataAreaLayout.fields[area.name][1]  # type: ignore

    @classmethod
    def data_size_per_actor(cls) -> int:
        """
        获取单个actor的数据沙箱大小。
        :return: 单个actor数据沙箱的字节大小
        """
        return cls._DataAreaLayout.itemsize

    @classmethod
    def code_area_size(cls, area: CodeArea) -> int:
        """
        获取代码沙箱中指定区域的大小。
        :param area: 要查询的代码区域
        :return: 该区域的字节大小
        """
        return cls._CodeAreaLayout[area.name].itemsize

    @classmethod
    def code_area_offset(cls, area: CodeArea) -> int:
        """
        获取代码沙箱中指定区域的偏移量（相对于单个actor的代码起始地址）。
        :param area: 要查询的代码区域
        :return: 该区域的字节偏移量
        """
        if area == CodeArea.START:
            return 0
        return cls._CodeAreaLayout.fields[area.name][1]  # type: ignore

    @classmethod
    def code_size_per_actor(cls) -> int:
        """
        获取单个actor的代码沙箱大小。
        :return: 单个actor代码沙箱的字节大小
        """
        return cls._CodeAreaLayout.itemsize

    # ==============================================================================================
    # 实例接口（基于基地址的具体地址计算）
    # ==============================================================================================
    def __init__(self, bases: BaseAddrTuple, n_actors: int):
        """
        初始化沙箱布局实例。
        :param bases: 基地址元组（数据基地址, 代码基地址），从执行器内核模块获取
        :param n_actors: 参与者数量，决定沙箱的总大小
        """
        # 数据沙箱边界计算
        self._data_start = bases[0]
        self.data_size = self._DataAreaLayout.itemsize * n_actors  # 总数据大小 = 单actor大小 × actor数
        self._data_end = bases[0] + self.data_size
        assert self.data_size % PAGE_SIZE == 0  # 数据沙箱大小必须页对齐

        # 代码沙箱边界计算
        self._code_start = bases[1]
        self.code_size = self._CodeAreaLayout.itemsize * n_actors  # 总代码大小 = 单actor大小 × actor数
        self._code_end = bases[1] + self.code_size
        assert self.code_size % PAGE_SIZE == 0  # 代码沙箱大小必须页对齐

        # 预计算每个actor的数据和代码区域地址
        # 注：预计算是合理的，因为沙箱布局对象初始化后会频繁使用
        self._data_addresses = []
        for actor_id in range(n_actors):
            actor_data_start = self._data_start + actor_id * self.data_size_per_actor()
            self._data_addresses.append(
                {area: actor_data_start + self.data_area_offset(area) for area in DataArea})
        self._code_addresses = []
        for actor_id in range(n_actors):
            actor_code_start = self._code_start + actor_id * self.code_size_per_actor()
            self._code_addresses.append(
                {area: actor_code_start + self.code_area_offset(area) for area in CodeArea})

    def code_start(self) -> CodeAddr:
        """获取代码沙箱起始地址（只读访问）"""
        return self._code_start

    def code_end(self) -> CodeAddr:
        """获取代码沙箱结束地址（只读访问）"""
        return self._code_end

    def data_start(self) -> DataAddr:
        """获取数据沙箱起始地址（只读访问）"""
        return self._data_start

    def data_end(self) -> DataAddr:
        """获取数据沙箱结束地址（只读访问）"""
        return self._data_end

    def get_data_addr(self, area: DataArea, actor_id: int) -> DataAddr:
        """
        获取指定actor在数据沙箱中指定区域的起始地址。
        :param area: 要查询的数据区域
        :param actor_id: 参与者ID
        :return: 该区域的起始地址
        """
        actor_data_start = self._data_start + actor_id * self.data_size_per_actor()
        return actor_data_start + self.data_area_offset(area)

    def get_code_addr(self, area: CodeArea, actor_id: int) -> CodeAddr:
        """
        获取指定actor在代码沙箱中指定区域的起始地址。
        :param area: 要查询的代码区域
        :param actor_id: 参与者ID
        :return: 该区域的起始地址
        """
        actor_code_start = self._code_start + actor_id * self.code_size_per_actor()
        return actor_code_start + self.code_area_offset(area)

    def get_exit_addr(self, test_case: TestCaseProgram) -> CodeAddr:
        """
        获取代码沙箱中给定测试用例的退出指令地址。
        退出地址位于main代码段的最后一个字节。
        :param test_case: 测试用例对象
        :return: 退出指令地址
        """
        main_section = test_case.find_section(name="main")
        main_size = main_section.get_elf_data()["size"]
        exit_offset = self._code_start + main_size - 1
        return exit_offset

    def is_data_addr(self, addr: DataAddr) -> bool:
        """
        检查给定地址是否在数据沙箱范围内。
        :param addr: 待检查的地址
        :return: 若在数据沙箱范围内返回True，否则返回False
        """
        return self._data_start <= addr < self._data_end

    def is_code_addr(self, addr: CodeAddr) -> bool:
        """
        检查给定地址是否在代码沙箱范围内。
        :param addr: 待检查的地址
        :return: 若在代码沙箱范围内返回True，否则返回False
        """
        return self._code_start <= addr < self._code_end

    def data_addr_to_offset(self, addr: DataAddr) -> DataAddr:
        """
        将数据沙箱中的绝对地址转换为相对于数据沙箱起始地址的偏移量。
        :param addr: 绝对地址
        :return: 偏移量
        """
        return addr - self._data_start

    def code_addr_to_offset(self, addr: CodeAddr) -> CodeAddr:
        """
        将代码沙箱中的绝对地址转换为相对于代码沙箱起始地址的偏移量。
        :param addr: 绝对地址
        :return: 偏移量
        """
        return addr - self._code_start

    def code_addr_to_actor_id(self, addr: CodeAddr) -> int:
        """
        根据代码沙箱地址确定所属的actor ID。
        :param addr: 代码沙箱地址
        :return: actor ID
        """
        return (addr - self._code_start) // self.code_size_per_actor()

    def data_addr_to_actor_id(self, addr: DataAddr) -> int:
        """
        根据数据沙箱地址确定所属的actor ID。
        :param addr: 数据沙箱地址
        :return: actor ID
        """
        return (addr - self._data_start) // self.data_size_per_actor()

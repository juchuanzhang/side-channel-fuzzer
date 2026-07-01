"""
文件：ARM64架构特定的常量和列表定义
本文件定义了ARM64（AArch64）架构的目标描述信息，包括寄存器映射、
页表项位定义、分支条件等，用于支持微架构侧信道模糊测试框架在ARM64平台上的运行。

File: arm64-specific constants and lists

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import re
import unicorn.arm64_const as ucc  # type: ignore

from rvzr.tc_components.instruction import Instruction
from rvzr.target_desc import TargetDesc, CPUDesc, UnicornTargetDesc


class ARM64TargetDesc(TargetDesc):
    """
    ARM64架构的目标描述类。
    定义了ARM64平台上的寄存器名称、大小、规范化映射、页表项位配置、
    分支条件码等架构相关信息，供模糊测试器、代码生成器和模拟器使用。

    Target description for arm64 architecture.
    """

    # 寄存器大小映射：记录每个ARM64寄存器名称对应的位宽（32位或64位）
    # w系列为32位通用寄存器，x系列为64位通用寄存器
    # wsp/wzr为32位特殊寄存器（栈指针/零寄存器），sp/xzr为64位特殊寄存器
    register_sizes = {
        "w0": 32, "w1": 32, "w2": 32, "w3": 32, "w4": 32, "w5": 32, "w6": 32, "w7": 32,
        "wsp": 32, "wzr": 32,
        "x0": 64, "x1": 64, "x2": 64, "x3": 64, "x4": 64, "x5": 64, "x6": 64, "x7": 64,
        "sp": 64, "xsp": 64, "xzr": 64,
    }  # yapf: disable

    # 按位宽分类的寄存器列表：用于根据所需位宽选择合适的寄存器
    registers_by_size = {
        32: ["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"],
        64: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    }  # yapf: disable

    # 寄存器规范化映射：将ARM64架构特定的寄存器名称映射为统一的内部表示
    # 例如w0和x0都映射为R0，表示同一个物理寄存器的不同位宽视图
    # CF/ZF/SF/OF映射到ARM64的条件标志位（NZCV寄存器中的N/Z/C/V位）
    # pc映射为RIP（程序计数器），sp映射为RSP（栈指针）
    reg_normalized = {
        "w0": "R0", "x0": "R0",
        "w1": "R1", "x1": "R1",
        "w2": "R2", "x2": "R2",
        "w3": "R3", "x3": "R3",
        "w4": "R4", "x4": "R4",
        "w5": "R5", "x5": "R5",
        "w6": "R6", "x6": "R6",
        "w7": "R7", "x7": "R7",
        "w8": "R8", "x8": "R8",
        "w9": "R9", "x9": "R9",
        "w10": "R10", "x10": "R10",
        "w20": "R20", "x20": "R20",
        "w30": "R30", "x30": "R30",
        "CF": "CF", "ZF": "ZF", "SF": "SF", "OF": "OF",
        "pc": "RIP",
        "sp": "RSP", "wsp": "RSP", "xsp": "RSP",
    }  # yapf: disable

    # 寄存器反规范化映射：将统一的内部寄存器表示映射回ARM64架构特定名称
    # 根据所需位宽选择对应的w（32位）或x（64位）寄存器名
    reg_denormalized = {
        "R0": {64: "x0", 32: "w0"},
        "R1": {64: "x1", 32: "w1"},
        "R2": {64: "x2", 32: "w2"},
        "R3": {64: "x3", 32: "w3"},
        "R4": {64: "x4", 32: "w4"},
        "R5": {64: "x5", 32: "w5"},
        "R6": {64: "x6", 32: "w6"},
        "R7": {64: "x7", 32: "w7"},
        "R20": {64: "x20", 32: "w20"},
        "R30": {64: "x30", 32: "w30"},
        "RIP": {64: "pc"},
        "RSP": {64: "sp", 32: "wsp"},
    }  # yapf: disable

    # 可用于内存索引寻址的寄存器列表：这些寄存器可用作内存访问的基地址寄存器
    mem_index_registers = ["x0", "x1", "x2", "x3", "x4", "x5"]

    # 页属性到ARM64页表项（PTE）位名称的映射
    # 每个属性对应一个PTE位名称和一个反转标志（True表示该属性为0时生效）
    # 例如"present"映射到"valid"位（位值为1表示有效，反转标志False）
    # "writable"映射到"non_writable"位（位值为1表示不可写，反转标志True）
    page_property_to_pte_bit_name = {
        "present": ("valid", False),
        "writable": ("non_writable", True),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "executable": ("non_executable", True),
    }

    # ARM64页表项（PTE）各位的定义：位位置和反转标志
    # valid: 位0，值为1表示页有效
    # user: 位6，值为1表示用户可访问
    # non_writable: 位7，值为1表示不可写
    # accessed: 位10，值为1表示已访问
    # non_executable: 位53，值为1表示不可执行
    pte_bits = {
        "valid": (0, True),
        "user": (6, False),
        "non_writable": (7, False),
        "accessed": (10, True),
        "non_executable": (53, True),
    }

    # FIXME: EPTE is not yet supported on ARM64; this is a placeholder
    # 注意：ARM64上尚未支持扩展页表项（EPTE），以下为占位配置
    # 虚拟机页属性到VM PTE位名称的映射（目前与普通PTE映射相同）
    page_property_to_vm_pte_bit_name = {
        "present": ("valid", False),
        "writable": ("non_writable", True),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "executable": ("non_executable", True),
    }

    # FIXME: EPTE is not yet supported on ARM64; this is a placeholder
    # 注意：ARM64上尚未支持扩展页表项（EPTE），以下为占位配置
    # 虚拟机PTE各位定义（目前所有位位置设为0，功能尚未实现）
    vm_pte_bits = {
        "valid": (0, True),
        "user": (0, False),
        "non_writable": (0, False),
        "accessed": (0, True),
        "non_executable": (0, True),
    }

    # ARM64分支条件码及其对应的标志位依赖关系
    # 每个条件码对应9个标志位的依赖列表：[CF, PF, AF, ZF, SF, TF, IF, DF, OF]
    # "r"表示该条件码依赖对应的标志位，""表示不依赖
    # 例如"eq"依赖ZF（第4位），"cs"依赖CF（第1位），"mi"依赖SF（第5位）
    branch_conditions = {
        "eq": ["", "", "", "r", "", "", "", "", ""],
        "ne": ["", "", "", "r", "", "", "", "", ""],
        "cs": ["r", "", "", "", "", "", "", "", ""],
        "cc": ["r", "", "", "", "", "", "", "", ""],
        "mi": ["", "", "", "", "r", "", "", "", ""],
        "pl": ["", "", "", "", "r", "", "", "", ""],
        "vs": ["", "", "", "", "", "", "", "", "r"],
        "vc": ["", "", "", "", "", "", "", "", "r"],
        "hi": ["r", "", "", "r", "", "", "", "", ""],
        "ls": ["r", "", "", "r", "", "", "", "", ""],
        "ge": ["", "", "", "", "r", "", "", "", "r"],
        "lt": ["", "", "", "", "r", "", "", "", "r"],
        "gt": ["", "", "", "r", "r", "", "", "", "r"],
        "le": ["", "", "", "r", "r", "", "", "", "r"],
        "al": ["", "", "", "", "", "", "", "", ""]
    }

    def __init__(self) -> None:
        """
        ARM64目标描述的初始化方法。
        根据被测CPU和配置信息，过滤屏蔽的寄存器、构建CPU描述，
        并连接Unicorn模拟器的目标描述。
        """
        super().__init__()

        # modify/set target parameters based on the CPU under test and the configuration
        # 根据被测CPU和配置修改/设置目标参数
        self.registers_by_size = self._filter_blocked_registers()
        self.cpu_desc = self._build_cpu_desc()

        # connect Unicorn TD
        # 连接Unicorn模拟器的ARM64目标描述
        self.uc_target_desc = ARM64UnicornTargetDesc()

    @staticmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        """
        判断给定指令是否为无条件分支指令。
        ARM64架构中，指令名"b"为无条件跳转。

        参数:
            inst: 待判断的指令对象
        返回值:
            True表示是无条件分支，False表示不是
        """
        return inst.name == "b"

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        """
        判断给定指令是否为函数调用指令。
        ARM64架构中，指令名"bl"为带链接的分支（即函数调用）。

        参数:
            inst: 待判断的指令对象
        返回值:
            True表示是调用指令，False表示不是
        """
        return inst.name == "bl"

    def _build_cpu_desc(self) -> CPUDesc:
        """
        从/proc/cpuinfo文件中读取CPU信息，构建CPU描述对象。
        解析CPU的供应商（vendor）、架构版本（family）、型号（model）和步进（stepping）信息。

        返回值:
            包含CPU供应商、型号、架构版本和步进信息的CPUDesc对象
        """
        vendor = self.get_vendor()

        # 从/proc/cpuinfo读取CPU详细信息
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()

            # 解析CPU架构版本（如ARMv8对应8）
            family_match = re.search(r"CPU architecture\s*:\s+(.*)", cpuinfo)
            assert family_match, "Failed to find family in /proc/cpuinfo"
            family = int(family_match.group(1), 16)

            # 解析CPU型号变体（variant字段）
            model_match = re.search(r"CPU variant\s+:\s+(.*)", cpuinfo)
            assert model_match, "Failed to find model name in /proc/cpuinfo"
            model = int(model_match.group(1), 16)

            # 解析CPU步进号（part字段，标识具体CPU型号编号）
            stepping_match = re.search(r"CPU part\s+:\s+(.*)", cpuinfo)
            assert stepping_match, "Failed to find stepping in /proc/cpuinfo"
            stepping = int(stepping_match.group(1), 16)

        return CPUDesc(vendor, model, family, stepping)


class ARM64UnicornTargetDesc(UnicornTargetDesc):  # pylint: disable=too-few-public-methods
    """
    ARM64架构在Unicorn模拟器上下文中的目标描述类。
    定义了Unicorn模拟器可用的ARM64寄存器常量映射，
    以及内存屏障指令、标志寄存器、程序计数器、栈指针等关键寄存器的映射。

    arm64 target description in the context of a Unicorn-based model.
    """

    # Unicorn模拟器中可用的ARM64寄存器常量列表
    # 包含x0-x5通用寄存器、NZCV条件标志寄存器和栈指针寄存器
    usable_registers: List[int] = [
        ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3,
        ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5, ucc.UC_ARM64_REG_NZCV, ucc.UC_ARM64_REG_SP
    ]

    # 可用的128位SIMD寄存器列表（目前为空，尚未支持）
    usable_simd128_registers: List[int] = []

    # ARM64寄存器名称到Unicorn常量的映射字典
    # 将汇编中使用的寄存器名（如"x0"）映射为Unicorn引擎的内部常量编号
    reg_str_to_constant = {
        "x0": ucc.UC_ARM64_REG_X0,
        "x1": ucc.UC_ARM64_REG_X1,
        "x2": ucc.UC_ARM64_REG_X2,
        "x3": ucc.UC_ARM64_REG_X3,
        "x4": ucc.UC_ARM64_REG_X4,
        "x5": ucc.UC_ARM64_REG_X5,
        "x6": ucc.UC_ARM64_REG_X6,
        "x7": ucc.UC_ARM64_REG_X7,
        "x8": ucc.UC_ARM64_REG_X8,
        "x9": ucc.UC_ARM64_REG_X9,
        "x10": ucc.UC_ARM64_REG_X10,
        "x11": ucc.UC_ARM64_REG_X11,
        "x12": ucc.UC_ARM64_REG_X12,
        "x13": ucc.UC_ARM64_REG_X13,
        "x14": ucc.UC_ARM64_REG_X14,
        "x15": ucc.UC_ARM64_REG_X15,
        "x16": ucc.UC_ARM64_REG_X16,
        "x17": ucc.UC_ARM64_REG_X17,
        "x18": ucc.UC_ARM64_REG_X18,
        "x19": ucc.UC_ARM64_REG_X19,
        "x20": ucc.UC_ARM64_REG_X20,
        "x21": ucc.UC_ARM64_REG_X21,
        "x22": ucc.UC_ARM64_REG_X22,
        "x23": ucc.UC_ARM64_REG_X23,
        "x24": ucc.UC_ARM64_REG_X24,
        "x25": ucc.UC_ARM64_REG_X25,
        "x26": ucc.UC_ARM64_REG_X26,
        "x27": ucc.UC_ARM64_REG_X27,
        "x28": ucc.UC_ARM64_REG_X28,
        "x29": ucc.UC_ARM64_REG_X29,
        "x30": ucc.UC_ARM64_REG_X30
    }

    # 规范化寄存器名到Unicorn常量的映射
    # 将内部统一的寄存器名（如"R0"）映射为Unicorn常量
    # FLAGS和各标志位（SF/ZF/CF/OF）都映射到NZCV寄存器（ARM64的条件标志寄存器）
    # RIP和RSP设为-1，表示在Unicorn中需要特殊处理（非标准寄存器映射）
    reg_norm_to_constant = {
        "R0": ucc.UC_ARM64_REG_X0,
        "R1": ucc.UC_ARM64_REG_X1,
        "R2": ucc.UC_ARM64_REG_X2,
        "R3": ucc.UC_ARM64_REG_X3,
        "R4": ucc.UC_ARM64_REG_X4,
        "R5": ucc.UC_ARM64_REG_X5,
        "R6": ucc.UC_ARM64_REG_X6,
        "R7": ucc.UC_ARM64_REG_X7,
        "R20": ucc.UC_ARM64_REG_X20,
        "R30": ucc.UC_ARM64_REG_X30,
        "FLAGS": ucc.UC_ARM64_REG_NZCV,
        "SF": ucc.UC_ARM64_REG_NZCV,  # N（负数标志）
        "ZF": ucc.UC_ARM64_REG_NZCV,  # Z（零标志）
        "CF": ucc.UC_ARM64_REG_NZCV,  # C（进位标志）
        "OF": ucc.UC_ARM64_REG_NZCV,  # V（溢出标志）
        "RIP": -1,
        "RSP": -1,
    }

    # ARM64内存屏障指令列表：数据内存屏障(dmb)、数据同步屏障(dsb)、指令同步屏障(isb)
    barriers: List[str] = ['dmb', 'dsb', 'isb']
    # ARM64条件标志寄存器（NZCV）的Unicorn常量编号
    flags_register: int = ucc.UC_ARM64_REG_NZCV
    # ARM64程序计数器寄存器的Unicorn常量编号
    pc_register: int = ucc.UC_ARM64_REG_PC
    # ARM64栈指针寄存器的Unicorn常量编号
    sp_register: int = ucc.UC_ARM64_REG_SP
    # 测试用例Actor基地址寄存器（x20），用于指向沙箱数据区域
    actor_base_register: int = ucc.UC_ARM64_REG_X20

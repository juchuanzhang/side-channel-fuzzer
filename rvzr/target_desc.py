"""
文件：目标平台的架构细节描述，
包括寄存器大小、寄存器名称、CPU描述以及页表项位映射等。
为微架构侧信道模糊测试框架提供目标架构的抽象接口和具体信息。

File: Architectural details of the target platform,
such as register sizes, register names, and CPU description.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, NamedTuple, Literal, TYPE_CHECKING
import subprocess

from rvzr.config import CONF, PagePropertyName

if TYPE_CHECKING:
    from .tc_components.instruction import Instruction, RegSize

# ==================================================================================================
# 自定义类型 / Custom Types
# ==================================================================================================
Vendor = Literal["Intel", "AMD", "ARM", "Unknown"]  # CPU厂商类型
RegName = str  # 寄存器名称类型
RegNormalizedName = str  # 归一化寄存器名称类型（如A代替rax）
RegUnicornID = int  # Unicorn模拟器寄存器ID类型
# 页表项位名称类型，定义了架构无关的页属性名称
PTEBitName = Literal["present", "writable", "non_writable", "user", "write-through",
                     "cache-disable", "accessed", "dirty", "reserved_bit", "executable",
                     "non_executable", "valid"]
PTEBitOffset = int  # 页表项位的偏移量类型
# 页属性名称到页表项位名称的映射类型，包含是否反转的标志
PTEBitNameMapper = Dict[PagePropertyName, Tuple[PTEBitName, bool]]


# ==================================================================================================
# 用例特定的描述符 / Use-case Specific Descriptors
# ==================================================================================================
class CPUDesc(NamedTuple):
    """
    CPU描述信息，包含厂商、型号、家族和步进版本。
    CPU description.
    """

    vendor: Vendor  # CPU厂商
    model: int  # CPU型号编号
    family: int  # CPU家族编号
    stepping: int  # CPU步进版本


class MacroSpec(NamedTuple):
    """
    宏规范描述，用于定义测试用例中的宏指令。
    包括宏类型ID、名称和参数列表。
    Macro specification.
    """

    type_: int  # 宏类型ID（负数用于生成，正数用于执行）
    name: str  # 宏名称
    args: Tuple[str, str, str, str]  # 宏参数列表（最多4个参数）


class UnicornTargetDesc:  # pylint: disable=too-few-public-methods
    """
    Unicorn模拟器上下文中的目标描述。
    包含Unicorn模拟器所需的寄存器ID映射、屏障指令、
    标志寄存器、程序计数器、栈指针和Actor基址寄存器等信息。

    Target description in the context of a Unicorn-based model
    """

    usable_registers: List[RegUnicornID]
    """ 测试用例在目标平台上使用的Unicorn寄存器ID列表 / List of Unicorn register IDs that are used by test cases on the target platform. """

    usable_simd128_registers: List[RegUnicornID]
    """ 测试用例在目标平台上使用的Unicorn SIMD 128位寄存器ID列表 / List of Unicorn SIMD register IDs that are used by test cases on the target platform. """

    reg_str_to_constant: Dict[RegName, RegUnicornID]
    """ 寄存器名称到Unicorn常量的映射 / Mapping from register names to their Unicorn constants. """

    reg_norm_to_constant: Dict[RegNormalizedName, RegUnicornID]
    """ 归一化寄存器名称到Unicorn常量的映射 / Mapping from normalized register names to their Unicorn constants. """

    barriers: List[str]
    """ 被视为投机屏障的指令名称列表 / List of instruction names that are considered as speculation barriers """

    flags_register: RegUnicornID
    """ 标志寄存器的Unicorn ID / Unicorn register ID of the flags register """

    pc_register: RegUnicornID
    """ 程序计数器寄存器的Unicorn ID / Unicorn register ID of the program counter register """

    sp_register: RegUnicornID
    """ 栈指针寄存器的Unicorn ID / Unicorn register ID of the stack pointer register """

    actor_base_register: RegUnicornID
    """ 保存活跃Actor基址的寄存器的Unicorn ID / Unicorn register ID of the register that holds the base address of the active actor """


# ==================================================================================================
# 主要目标描述类 / Main Target Description
# ==================================================================================================
class TargetDesc(ABC):
    """
    目标描述的抽象基类，定义了目标架构描述类的接口。
    子类需实现特定架构（如x86-64、arm64）的描述信息。

    Abstract class defining the interface to target description classes.
    """

    cpu_desc: CPUDesc
    """ 目标CPU描述 / Target CPU description. """

    # 宏规范字典。所有宏都是跨平台的，因此对所有目标都相同。
    # 负数ID的宏用于测试用例生成，正数ID的宏用于执行。
    # List of macro specifications. All macros are cross-platform, hence the same for all targets.
    macro_specs: Dict[str, MacroSpec] = {
        # macros with negative IDs are used for generation
        # and are not supposed to reach the final binary
        # 负数ID宏用于生成阶段，不会出现在最终二进制中
        "random_instructions":
            MacroSpec(-1, "random_instructions", ("int", "int", "", "")),

        # macros with positive IDs are used for execution and can be interpreted by executor/model
        # 正数ID宏用于执行阶段，可被执行器/模型解释
        "function":
            MacroSpec(0, "function", ("", "", "", "")),
        "measurement_start":  # 测量开始宏 / Measurement start macro
            MacroSpec(1, "measurement_start", ("", "", "", "")),
        "measurement_end":  # 测量结束宏 / Measurement end macro
            MacroSpec(2, "measurement_end", ("", "", "", "")),
        "fault_handler":  # 故障处理宏 / Fault handler macro
            MacroSpec(3, "fault_handler", ("", "", "", "")),
        "switch":  # Actor切换宏 / Actor switch macro
            MacroSpec(4, "switch", ("actor_id", "function_id", "", "")),
        "set_k2u_target":  # 设置内核到用户切换目标 / Set kernel-to-user switch target
            MacroSpec(5, "set_k2u_target", ("actor_id", "function_id", "", "")),
        "switch_k2u":  # 内核到用户切换 / Switch kernel-to-user
            MacroSpec(6, "switch_k2u", ("actor_id", "", "", "")),
        "set_u2k_target":  # 设置用户到内核切换目标 / Set user-to-kernel switch target
            MacroSpec(7, "set_u2k_target", ("actor_id", "function_id", "", "")),
        "switch_u2k":  # 用户到内核切换 / Switch user-to-kernel
            MacroSpec(8, "switch_u2k", ("actor_id", "", "", "")),
        "set_h2g_target":  # 设置宿主机到客户机切换目标 / Set host-to-guest switch target
            MacroSpec(9, "set_h2g_target", ("actor_id", "function_id", "", "")),
        "switch_h2g":  # 宿主机到客户机切换 / Switch host-to-guest
            MacroSpec(10, "switch_h2g", ("actor_id", "", "", "")),
        "set_g2h_target":  # 设置客户机到宿主机切换目标 / Set guest-to-host switch target
            MacroSpec(11, "set_g2h_target", ("actor_id", "function_id", "", "")),
        "switch_g2h":  # 客户机到宿主机切换 / Switch guest-to-host
            MacroSpec(12, "switch_g2h", ("actor_id", "", "", "")),
        "landing_k2u":  # 内核到用户着陆点 / Landing kernel-to-user
            MacroSpec(13, "landing_k2u", ("", "", "", "")),
        "landing_u2k":  # 用户到内核着陆点 / Landing user-to-kernel
            MacroSpec(14, "landing_u2k", ("", "", "", "")),
        "landing_h2g":  # 宿主机到客户机着陆点 / Landing host-to-guest
            MacroSpec(15, "landing_h2g", ("", "", "", "")),
        "landing_g2h":  # 客户机到宿主机着陆点 / Landing guest-to-host
            MacroSpec(16, "landing_g2h", ("", "", "", "")),
        "set_data_permissions":  # 设置数据权限宏 / Set data permissions macro
            MacroSpec(18, "set_data_permissions", ("actor_id", "int", "int", ""))
        # FIXME: macro IDs should not be hardcoded but rather received from the executor
        # 宏ID不应硬编码，应从执行器获取
        # or at least we need a test that will check that the IDs match
    }

    uc_target_desc: UnicornTargetDesc
    """ Unicorn模拟器上下文中的目标描述 / Target description in the context of a Unicorn-based model """

    register_sizes: Dict[RegName, RegSize]
    """ 寄存器名称到其位宽的映射字典 / Dictionary mapping register names to their sizes in bits. """

    registers_by_size: Dict[RegSize, List[RegName]]
    """ 给定位宽下所有寄存器名称的列表字典 / Dictionary with lists of all registers for a given size. """

    reg_normalized: Dict[RegName, RegNormalizedName]
    """ 完整寄存器名称到归一化大小无关名称的映射。例如：rax -> A
    Mapping from full register names to normalized size-independent names. E.g., rax -> A"""

    reg_denormalized: Dict[RegNormalizedName, Dict[RegSize, RegName]]
    """ 归一化名称到完整寄存器名称的反向映射。
    例如：A -> {64: rax, 32: eax, 16: ax, 8: al}
    Reverse mapping from normalized names to full register names.
    E.g., A -> {64: rax, 32: eax, 16: ax, 8: al} """

    page_property_to_pte_bit_name: PTEBitNameMapper
    """
    架构无关的页属性名称到架构特定的页表项位名称的映射，
    包含是否反转的标志。
    例如：
        'writable' -> ('writable', False)
        'executable' -> ('non_executable', True)

    Dictionary mapping architecture-independent page property names to architecture-specific
    page table entry bit names together with a bit indicating whether the property is inverted.
    E.g.,
        'writable' -> ('writable', False)
        'executable' -> ('non_executable', True)
    """

    pte_bits: Dict[PTEBitName, Tuple[PTEBitOffset, bool]]
    """
    页表项字段名称到其位偏移和默认值的映射字典。
    Dictionary mapping page table entry field names to their bit offsets and their default values.
    """

    page_property_to_vm_pte_bit_name: PTEBitNameMapper
    """
    架构无关的页属性名称到架构特定的虚拟机页表项位名称的映射。
    这是Intel EPT和AMD NPT的统一映射。

    Dictionary mapping architecture-independent page property names to architecture-specific
    VM page table entry bit names. This is the unified mapping for both Intel EPT and AMD NPT.
    """

    vm_pte_bits: Dict[PTEBitName, Tuple[PTEBitOffset, bool]]
    """
    虚拟机页表项字段名称到其位偏移和默认值的映射字典。
    这是Intel EPT和AMD NPT等各种宿主机到客户机页表的统一接口。

    Dictionary mapping VM page table entry field names to their bit offsets
    and their default values. This is the unified interface for various types of host-to-guest
    page tables, such as Intel EPT and AMD NPT.
    """

    branch_conditions: Dict[str, List[str]]
    """ 分支指令到其条件码的映射字典 / Dictionary mapping branch instructions to their condition codes. """

    mem_index_registers: List[RegName]
    """ 可用作内存索引寄存器的寄存器列表 / List of register that can be used as memory index registers. """

    @classmethod
    def get_vendor(cls) -> Vendor:
        """
        通过执行lscpu命令读取CPU厂商信息。
        返回: CPU厂商字符串（"Intel"、"AMD"、"ARM"或"Unknown"）

        Read the CPU vendor from lscpu
        """
        output = subprocess.check_output("lscpu", shell=True)
        if b"Intel" in output:
            return "Intel"
        if b"AMD" in output:
            return "AMD"
        if b"ARM" in output:
            return "ARM"
        return "Unknown"

    @staticmethod
    @abstractmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        """
        检查指令是否为无条件分支。
        参数:
            inst: 待检查的指令对象
        返回:
            True如果指令是无条件分支，否则False

        Check if the instruction is an unconditional branch.
        """

    @staticmethod
    @abstractmethod
    def is_call(inst: Instruction) -> bool:
        """
        检查指令是否为调用指令。
        参数:
            inst: 待检查的指令对象
        返回:
            True如果指令是调用指令，否则False

        Check if the instruction is a call.
        """

    def get_macro_spec_from_type(self, type_: int) -> MacroSpec:
        """
        根据宏类型ID获取宏规范。
        参数:
            type_: 宏类型ID
        返回:
            对应的MacroSpec对象
        异常:
            KeyError: 如果宏类型ID不存在

        Get the macro specification of a given macro type.
        :param type_: macro type
        :return: macro specification
        """
        for macro_spec in self.macro_specs.values():
            if macro_spec.type_ == type_:
                return macro_spec
        raise KeyError(f"Unknown macro type: {type_}")

    def _filter_blocked_registers(self) -> Dict[RegSize, List[str]]:
        """
        过滤被阻止的寄存器，用于子类初始化时移除黑名单中的寄存器。
        白名单中的寄存器即使出现在黑名单中也会被保留。

        返回:
            按寄存器大小分组的过滤后寄存器名称字典

        Filter function used to remove blocked registers. Invoked by subclasses.
        """

        filtered_decoding: Dict[RegSize, List[str]] = {}
        for size, registers in self.registers_by_size.items():
            filtered_decoding[size] = []
            for register in registers:
                # 保留不在黑名单中的寄存器，或在白名单中的寄存器
                if register not in CONF.register_blocklist or register in CONF.register_allowlist:
                    filtered_decoding[size].append(register)
        return filtered_decoding

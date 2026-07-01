"""
文件: x86架构特定的常量和列表定义
File: x86-specific constants and lists

本模块定义了x86架构的目标描述(Target Description)，包括：
- 寄存器名称、大小、归一化映射
- 页表项(PTE)位定义及EPT/NPT扩展
- 内存地址前缀（如byte ptr, word ptr等）
- Unicorn模拟器中的x86寄存器常量映射

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict, Final, Tuple
import re
import unicorn.x86_const as ucc  # type: ignore

from rvzr.tc_components.instruction import Instruction
from rvzr.target_desc import TargetDesc, CPUDesc, UnicornTargetDesc, PTEBitNameMapper, \
    PTEBitOffset, PTEBitName


class X86TargetDesc(TargetDesc):
    """
    x86架构的目标描述类。

    继承自通用TargetDesc，提供x86架构特有的寄存器定义、页表位映射
    以及内存操作相关的常量。用于支持测试用例生成器、汇编解析器和模拟器
    对x86架构的适配。

    主要功能：
    - 定义x86寄存器及其位宽映射
    - 寄存器归一化（将不同尺寸的同源寄存器映射到统一标识符）
    - 页表项(PTE)和扩展页表(EPT/NPT)的位偏移与默认值
    - 根据CPU厂商(Intel/AMD)选择相应的VM页表位定义
    """

    # 寄存器位宽映射：每个x86寄存器名到其位宽大小(位)
    register_sizes = {
        "mm0": 64, "mm1": 64, "mm2": 64, "mm3": 64, "mm4": 64, "mm5": 64, "mm6": 64, "mm7": 64,
        "xmm0": 128, "xmm1": 128, "xmm2": 128, "xmm3": 128, "xmm4": 128, "xmm5": 128, "xmm6": 128,
        "xmm7": 128,
        "ymm0": 256, "ymm1": 256, "ymm2": 256, "ymm3": 256, "ymm4": 256, "ymm5": 256, "ymm6": 256,
        "ymm7": 256,

        "rax": 64, "rbx": 64, "rcx": 64, "rdx": 64, "rsi": 64, "rdi": 64, "rsp": 64, "rbp": 64,
        "r8": 64, "r9": 64, "r10": 64, "r11": 64, "r12": 64, "r13": 64, "r14": 64, "r15": 64,

        "eax": 32, "ebx": 32, "ecx": 32, "edx": 32, "esi": 32, "edi": 32, "r8d": 32, "r9d": 32,
        "r10d": 32, "r11d": 32, "r12d": 32, "r13d": 32, "r14d": 32, "r15d": 32,

        "ax": 16, "bx": 16, "cx": 16, "dx": 16, "si": 16, "di": 16, "r8w": 16, "r9w": 16,
        "r10w": 16, "r11w": 16, "r12w": 16, "r13w": 16, "r14w": 16, "r15w": 16,

        "al": 8, "bl": 8, "cl": 8, "dl": 8, "sil": 8, "dil": 8, "r8b": 8, "r9b": 8,
        "r10b": 8, "r11b": 8, "r12b": 8, "r13b": 8, "r14b": 8, "r15b": 8,
        "ah": 8, "bh": 8, "ch": 8, "dh": 8,
    }  # yapf: disable

    # 按位宽分组的寄存器列表：用于根据所需操作数大小查找可用寄存器
    registers_by_size = {
        8: ["al", "bl", "cl", "dl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b",
            "r14b", "r15b"],
        16: ["ax", "bx", "cx", "dx", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
             "r14w", "r15w"],
        32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
             "r13d", "r14d", "r15d"],
        64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
             "r14", "r15", "rsp", "rbp", "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"],
        128: ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"],
        256: ["ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7"],
    }  # yapf: disable

    # 寄存器归一化映射：将不同尺寸的同源寄存器（如rax/eax/ax/al）映射到统一标识符（如"A"）
    # 用于判断两个不同名称的寄存器是否指向同一物理寄存器
    reg_normalized = {
        "rax": "A", "eax": "A", "ax": "A", "al": "A", "ah": "A",
        "rbx": "B", "ebx": "B", "bx": "B", "bl": "B", "bh": "B",
        "rcx": "C", "ecx": "C", "cx": "C", "cl": "C", "ch": "C",
        "rdx": "D", "edx": "D", "dx": "D", "dl": "D", "dh": "D",
        "rsi": "SI", "esi": "SI", "si": "SI", "sil": "SI",
        "rdi": "DI", "edi": "DI", "di": "DI", "dil": "DI",
        "r8": "8", "r8d": "8", "r8w": "8", "r8b": "8",
        "r9": "9", "r9d": "9", "r9w": "9", "r9b": "9",
        "r10": "10", "r10d": "10", "r10w": "10", "r10b": "10",
        "r11": "11", "r11d": "11", "r11w": "11", "r11b": "11",
        "r12": "12", "r12d": "12", "r12w": "12", "r12b": "12",
        "r13": "13", "r13d": "13", "r13w": "13", "r13b": "13",
        "r14": "14", "r14d": "14", "r14w": "14", "r14b": "14",
        "r15": "15", "r15d": "15", "r15w": "15", "r15b": "15",
        "FLAGS": "FLAGS",
        "rip": "RIP",
        "rsp": "RSP",
        "CF": "CF", "PF": "PF", "AF": "AF", "ZF": "ZF", "SF": "SF", "TF": "TF", "IF": "IF",
        "DF": "DF", "OF": "OF", "AC": "AC",
        "mm0": "MM0",
        "mm1": "MM1",
        "mm2": "MM2",
        "mm3": "MM3",
        "mm4": "MM4",
        "mm5": "MM5",
        "mm6": "MM6",
        "mm7": "MM7",
        "xmm0": "XMM0",
        "xmm1": "XMM1",
        "xmm2": "XMM2",
        "xmm3": "XMM3",
        "xmm4": "XMM4",
        "xmm5": "XMM5",
        "xmm6": "XMM6",
        "xmm7": "XMM7",
        "ymm0": "YMM0",
        "ymm1": "YMM1",
        "ymm2": "YMM2",
        "ymm3": "YMM3",
        "ymm4": "YMM4",
        "ymm5": "YMM5",
        "ymm6": "YMM6",
        "ymm7": "YMM7",
        "cr0": "CR0",
        "cr2": "CR2",
        "cr3": "CR3",
        "cr4": "CR4",
        "cr8": "CR8",
        "xcr0": "XCR0",
        "dr0": "DR0",
        "dr1": "DR1",
        "dr2": "DR2",
        "dr3": "DR3",
        "dr6": "DR6",
        "dr7": "DR7",
        "gdtr": "GDTR",
        "idtr": "IDTR",
        "ldtr": "LDTR",
        "tr": "TR",
        "gs": "GS",
        "fs": "FS",
        "es": "ES",
        "ds": "DS",
        "cs": "CS",
        "ss": "SS",
        "fsbase": "FSBASE",
        "gsbase": "GSBASE",
        "msrs": "MSRS",
        "x87control": "X87CONTROL",
        "tsc": "TSC",
        "tscaux": "TSCAUX",
    }  # yapf: disable

    # 寄存器反归一化映射：将归一化标识符映射回具体尺寸的寄存器名
    # 用于将归一化的寄存器标识转换为特定宽度的实际寄存器名
    reg_denormalized = {
        "A": {64: "rax", 32: "eax", 16: "ax", 8: "al"},
        "B": {64: "rbx", 32: "ebx", 16: "bx", 8: "bl"},
        "C": {64: "rcx", 32: "ecx", 16: "cx", 8: "cl"},
        "D": {64: "rdx", 32: "edx", 16: "dx", 8: "dl"},
        "SI": {64: "rsi", 32: "esi", 16: "si", 8: "sil"},
        "DI": {64: "rdi", 32: "edi", 16: "di", 8: "dil"},
        "8": {64: "r8", 32: "r8d", 16: "r8w", 8: "r8b"},
        "9": {64: "r9", 32: "r9d", 16: "r9w", 8: "r9b"},
        "10": {64: "r10", 32: "r10d", 16: "r10w", 8: "r10b"},
        "11": {64: "r11", 32: "r11d", 16: "r11w", 8: "r11b"},
        "12": {64: "r12", 32: "r12d", 16: "r12w", 8: "r12b"},
        "13": {64: "r13", 32: "r13d", 16: "r13w", 8: "r13b"},
        "14": {64: "r14", 32: "r14d", 16: "r14w", 8: "r14b"},
        "15": {64: "r15", 32: "r15d", 16: "r15w", 8: "r15b"},
        "RIP": {64: "rip", 32: "rip", 16: "rip", 8: "rip"},
        "RSP": {64: "rsp", 32: "rsp", 16: "rsp", 8: "rsp"},
        "MM0": {64: "mm0"},
        "MM1": {64: "mm1"},
        "MM2": {64: "mm2"},
        "MM3": {64: "mm3"},
        "MM4": {64: "mm4"},
        "MM5": {64: "mm5"},
        "MM6": {64: "mm6"},
        "MM7": {64: "mm7"},
        "XMM0": {128: "xmm0"},
        "XMM1": {128: "xmm1"},
        "XMM2": {128: "xmm2"},
        "XMM3": {128: "xmm3"},
        "XMM4": {128: "xmm4"},
        "XMM5": {128: "xmm5"},
        "XMM6": {128: "xmm6"},
        "XMM7": {128: "xmm7"},
        "YMM0": {256: "ymm0"},
        "YMM1": {256: "ymm1"},
        "YMM2": {256: "ymm2"},
        "YMM3": {256: "ymm3"},
        "YMM4": {256: "ymm4"},
        "YMM5": {256: "ymm5"},
        "YMM6": {256: "ymm6"},
        "YMM7": {256: "ymm7"}
    }  # yapf: disable

    # 可用作内存索引的寄存器列表（用于生成内存操作数地址计算）
    mem_index_registers = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]

    # 页属性到PTE位名称的映射：将语义化的属性名映射到PTE中的具体位名及反转标志
    # 例如 "executable" 映射到 "non_executable"，反转标志为True（表示逻辑相反）
    page_property_to_pte_bit_name = {
        "present": ("present", False),
        "writable": ("writable", False),
        "user": ("user", False),
        'write-through': ("write-through", False),
        "cache-disable": ("cache-disable", False),
        "accessed": ("accessed", False),
        "dirty": ("dirty", False),
        "executable": ("non_executable", True),
        "reserved_bit": ("reserved_bit", False),
    }

    # x86标准页表项(PTE)位定义：名称到(位偏移, 默认值)的映射
    pte_bits: Dict[PTEBitName, Tuple[PTEBitOffset, bool]] = {
        # 名称: (位位置, 默认值)
        "present": (0, True),
        "writable": (1, True),
        "user": (2, False),
        "write-through": (3, False),
        "cache-disable": (4, False),
        "accessed": (5, True),
        "dirty": (6, True),
        "reserved_bit": (51, False),
        "non_executable": (63, True),
    }

    # 页属性到Intel EPT位名称的映射
    _page_property_to_epte_bit_name: PTEBitNameMapper = {
        "present": ("present", False),
        "writable": ("writable", False),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "dirty": ("dirty", False),
        "executable": ("executable", False),
        "reserved_bit": ("reserved_bit", False),
    }

    # Intel扩展页表(EPT)位定义：名称到(位偏移, 默认值)的映射
    # EPT与标准PTE的位布局不同，例如可执行位在第2位而非第63位
    _epte_bits_intel: Dict[PTEBitName, Tuple[PTEBitOffset, bool]] = {
        # 名称: (位位置, 默认值)
        "present": (0, True),
        "writable": (1, True),
        "executable": (2, False),
        "accessed": (8, True),
        "dirty": (9, True),
        "user": (10, False),
        "reserved_bit": (51, False),
    }

    # 页属性到AMD NPT位名称的映射
    _page_property_to_npte_bit_name: PTEBitNameMapper = {
        "present": ("present", False),
        "writable": ("writable", False),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "dirty": ("dirty", False),
        "executable": ("non_executable", True),
        "reserved_bit": ("reserved_bit", False),
    }

    # AMD嵌套页表(NPT)位定义：名称到(位偏移, 默认值)的映射
    # NPT布局与Intel EPT不同，使用与标准PTE类似的位排列
    _npte_bits_amd: Dict[PTEBitName, Tuple[PTEBitOffset, bool]] = {
        # 名称: (位位置, 默认值)
        "present": (0, True),
        "writable": (1, True),
        "user": (2, True),
        "accessed": (5, True),
        "dirty": (6, True),
        "reserved_bit": (51, False),
        "non_executable": (63, True),
    }

    # 内存操作数地址前缀映射：不同位宽的内存访问对应的汇编前缀
    # 例如8位内存访问使用"byte ptr"，128位使用"xmmword ptr"
    memory_addr_prefixes: Final[Dict[int, str]] = {
        8: "byte ptr",
        16: "word ptr",
        32: "dword ptr",
        64: "qword ptr",
        80: "tbyte ptr",
        128: "xmmword ptr",
        256: "ymmword ptr",
        512: "zmmword ptr",
        4608: "ptr",
    }

    def __init__(self) -> None:
        """
        初始化x86目标描述。

        根据被测CPU和配置调整目标参数：
        - 过滤被阻止的寄存器
        - 构建CPU描述（厂商、型号、系列、步进）
        - 根据厂商选择VM页表位定义（Intel用EPT，AMD用NPT）
        - 连接Unicorn模拟器目标描述
        """
        super().__init__()

        # 根据被测CPU和配置修改/设置目标参数
        self.registers_by_size = self._filter_blocked_registers()
        self.cpu_desc = self._build_cpu_desc()

        # 根据CPU厂商选择VM页表位和属性映射
        if self.cpu_desc.vendor == 'Intel':
            self.vm_pte_bits = self._epte_bits_intel
            self.page_property_to_vm_pte_bit_name = self._page_property_to_epte_bit_name
        else:
            self.vm_pte_bits = self._npte_bits_amd
            self.page_property_to_vm_pte_bit_name = self._page_property_to_npte_bit_name

        # 连接Unicorn目标描述
        self.uc_target_desc = X86UnicornTargetDesc()

    @staticmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        """
        判断指令是否为无条件分支指令。

        :param inst: 待判断的指令对象
        :return: 若为无条件分支返回True，否则False
        """
        return inst.category == "BASE-UNCOND_BR"

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        """
        判断指令是否为函数调用指令。

        :param inst: 待判断的指令对象
        :return: 若为CALL指令返回True，否则False
        """
        return inst.category == "BASE-CALL"

    def _build_cpu_desc(self) -> CPUDesc:
        """
        从/proc/cpuinfo构建CPU描述对象。

        解析CPU信息文件获取厂商、系列(family)、型号(model)和步进(stepping)信息。
        若厂商不是Intel或AMD，返回默认的零值描述。

        :return: 包含厂商、型号、系列和步进信息的CPUDesc对象
        """
        vendor = self.get_vendor()
        if vendor not in ["Intel", "AMD"]:
            return CPUDesc(vendor, 0, 0, 0)

        with open("/proc/cpuinfo", "r") as f:
            cpuinfo = f.read()

            # 解析CPU family（系列号）
            family_match = re.search(r"cpu family\s+:\s+(.*)", cpuinfo)
            assert family_match, "Failed to find family in /proc/cpuinfo"
            family = int(family_match.group(1), 16)

            # 解析CPU model（型号号）
            model_match = re.search(r"model\s+:\s+(.*)", cpuinfo)
            assert model_match, "Failed to find model name in /proc/cpuinfo"
            model = int(model_match.group(1), 16)

            # 解析CPU stepping（步进号）
            stepping_match = re.search(r"stepping\s+:\s+(.*)", cpuinfo)
            assert stepping_match, "Failed to find stepping in /proc/cpuinfo"
            stepping = int(stepping_match.group(1), 16)

        return CPUDesc(vendor, model, family, stepping)


class X86UnicornTargetDesc(UnicornTargetDesc):  # pylint: disable=too-few-public-methods
    """
    x86架构在Unicorn模拟器上下文中的目标描述类。

    定义了Unicorn模拟器中可用的x86寄存器常量映射，以及
    寄存器名称字符串到Unicorn常量、归一化标识符到Unicorn常量的映射。
    用于在模拟器中读写寄存器值和构建模拟状态。
    """

    # Unicorn中可用的通用寄存器常量列表
    usable_registers: List[int] = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS, ucc.UC_X86_REG_RSP
    ]

    # Unicorn中可用的128位SIMD寄存器常量列表
    usable_simd128_registers: List[int] = [
        ucc.UC_X86_REG_XMM0, ucc.UC_X86_REG_XMM1, ucc.UC_X86_REG_XMM2, ucc.UC_X86_REG_XMM3,
        ucc.UC_X86_REG_XMM4, ucc.UC_X86_REG_XMM5, ucc.UC_X86_REG_XMM6, ucc.UC_X86_REG_XMM7
    ]

    # 寄存器名称字符串到Unicorn常量的映射
    # 用于将汇编中的寄存器名转换为Unicorn API所需的常量ID
    reg_str_to_constant = {
        "al": ucc.UC_X86_REG_AL,
        "bl": ucc.UC_X86_REG_BL,
        "cl": ucc.UC_X86_REG_CL,
        "dl": ucc.UC_X86_REG_DL,
        "dil": ucc.UC_X86_REG_DIL,
        "sil": ucc.UC_X86_REG_SIL,
        "spl": ucc.UC_X86_REG_SPL,
        "bpl": ucc.UC_X86_REG_BPL,
        "ah": ucc.UC_X86_REG_AH,
        "bh": ucc.UC_X86_REG_BH,
        "ch": ucc.UC_X86_REG_CH,
        "dh": ucc.UC_X86_REG_DH,
        "ax": ucc.UC_X86_REG_AX,
        "bx": ucc.UC_X86_REG_BX,
        "cx": ucc.UC_X86_REG_CX,
        "dx": ucc.UC_X86_REG_DX,
        "di": ucc.UC_X86_REG_DI,
        "si": ucc.UC_X86_REG_SI,
        "sp": ucc.UC_X86_REG_SP,
        "bp": ucc.UC_X86_REG_BP,
        "eax": ucc.UC_X86_REG_EAX,
        "ebx": ucc.UC_X86_REG_EBX,
        "ecx": ucc.UC_X86_REG_ECX,
        "edx": ucc.UC_X86_REG_EDX,
        "edi": ucc.UC_X86_REG_EDI,
        "esi": ucc.UC_X86_REG_ESI,
        "esp": ucc.UC_X86_REG_ESP,
        "ebp": ucc.UC_X86_REG_EBP,
        "rax": ucc.UC_X86_REG_RAX,
        "rbx": ucc.UC_X86_REG_RBX,
        "rcx": ucc.UC_X86_REG_RCX,
        "rdx": ucc.UC_X86_REG_RDX,
        "rdi": ucc.UC_X86_REG_RDI,
        "rsi": ucc.UC_X86_REG_RSI,
        "rsp": ucc.UC_X86_REG_RSP,
        "rbp": ucc.UC_X86_REG_RBP,
        "xmm0": ucc.UC_X86_REG_XMM0,
        "xmm1": ucc.UC_X86_REG_XMM1,
        "xmm2": ucc.UC_X86_REG_XMM2,
        "xmm3": ucc.UC_X86_REG_XMM3,
        "xmm4": ucc.UC_X86_REG_XMM4,
        "xmm5": ucc.UC_X86_REG_XMM5,
        "xmm6": ucc.UC_X86_REG_XMM6,
        "xmm7": ucc.UC_X86_REG_XMM7
    }

    # 归一化寄存器标识符到Unicorn常量的映射
    # 用于将归一化后的寄存器标识（如"A", "FLAGS"等）转换为Unicorn常量
    # 值为-1的条目表示Unicorn不支持直接读写该寄存器
    reg_norm_to_constant = {
        "A": ucc.UC_X86_REG_RAX,
        "B": ucc.UC_X86_REG_RBX,
        "C": ucc.UC_X86_REG_RCX,
        "D": ucc.UC_X86_REG_RDX,
        "DI": ucc.UC_X86_REG_RDI,
        "SI": ucc.UC_X86_REG_RSI,
        "SP": ucc.UC_X86_REG_RSP,
        "BP": ucc.UC_X86_REG_RBP,
        "8": ucc.UC_X86_REG_R8,
        "9": ucc.UC_X86_REG_R9,
        "10": ucc.UC_X86_REG_R10,
        "11": ucc.UC_X86_REG_R11,
        "12": ucc.UC_X86_REG_R12,
        "13": ucc.UC_X86_REG_R13,
        "14": ucc.UC_X86_REG_R14,
        "15": ucc.UC_X86_REG_R15,
        "FLAGS": ucc.UC_X86_REG_EFLAGS,
        "CF": ucc.UC_X86_REG_EFLAGS,
        "PF": ucc.UC_X86_REG_EFLAGS,
        "AF": ucc.UC_X86_REG_EFLAGS,
        "ZF": ucc.UC_X86_REG_EFLAGS,
        "SF": ucc.UC_X86_REG_EFLAGS,
        "TF": ucc.UC_X86_REG_EFLAGS,
        "IF": ucc.UC_X86_REG_EFLAGS,
        "DF": ucc.UC_X86_REG_EFLAGS,
        "OF": ucc.UC_X86_REG_EFLAGS,
        "AC": ucc.UC_X86_REG_EFLAGS,
        "XMM0": ucc.UC_X86_REG_XMM0,
        "XMM1": ucc.UC_X86_REG_XMM1,
        "XMM2": ucc.UC_X86_REG_XMM2,
        "XMM3": ucc.UC_X86_REG_XMM3,
        "XMM4": ucc.UC_X86_REG_XMM4,
        "XMM5": ucc.UC_X86_REG_XMM5,
        "XMM6": ucc.UC_X86_REG_XMM6,
        "XMM7": ucc.UC_X86_REG_XMM7,
        "XMM8": ucc.UC_X86_REG_XMM8,
        "XMM9": ucc.UC_X86_REG_XMM9,
        "XMM10": ucc.UC_X86_REG_XMM10,
        "XMM11": ucc.UC_X86_REG_XMM11,
        "XMM12": ucc.UC_X86_REG_XMM12,
        "XMM14": ucc.UC_X86_REG_XMM14,
        "XMM15": ucc.UC_X86_REG_XMM15,
        "RIP": -1,
        "RSP": -1,
        "CR0": -1,
        "CR2": -1,
        "CR3": -1,
        "CR4": -1,
        "CR8": -1,
        "XCR0": -1,
        "DR0": -1,
        "DR1": -1,
        "DR2": -1,
        "DR3": -1,
        "DR6": -1,
        "DR7": -1,
        "GDTR": -1,
        "IDTR": -1,
        "LDTR": -1,
        "TR": -1,
        "FSBASE": -1,
        "GSBASE": -1,
        "MSRS": -1,
        "X87CONTROL": -1,
        "TSC": -1,
        "TSCAUX": -1,
    }

    # 内存屏障指令列表（用于在测试用例中插入序列化操作）
    barriers: List[str] = ['mfence', 'lfence']
    # 特殊寄存器常量：标志寄存器、程序计数器、栈指针、Actor基址寄存器
    flags_register: int = ucc.UC_X86_REG_EFLAGS
    pc_register: int = ucc.UC_X86_REG_RIP
    sp_register: int = ucc.UC_X86_REG_RSP
    actor_base_register: int = ucc.UC_X86_REG_R14

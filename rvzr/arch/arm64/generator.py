"""
文件：ARM64架构测试用例生成器的实现
本文件实现了ARM64架构上的测试用例生成器，包括：
1. ARM64汇编代码打印器（_ARM64Printer）：将内部指令表示转换为ARM64汇编文本
2. ARM64沙箱插桩Pass（_ARM64SandboxPass）：对内存访问指令插入沙箱保护代码，
   防止越界内存访问导致异常
3. ARM64后索引加载修补Pass（_ARM64PatchUndefinedLoadsPass）：修复后索引寻址
   模式下的寄存器冲突问题
4. ARM64生成器主类（ARM64Generator）：组合以上Pass，生成完整的测试用例

File: arm64 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import math
import random
from typing import List, Dict, TYPE_CHECKING, Tuple, Callable, Literal

from rvzr.code_generator import CodeGenerator, Pass, Printer
from rvzr.sandbox import SandboxLayout, DataArea
from rvzr.instruction_spec import InstructionSpec
from rvzr.tc_components.instruction import Instruction, Operand, RegisterOp, FlagsOp, \
    MemoryOp, ImmediateOp, AgenOp, CondOp
from rvzr.tc_components.test_case_code import TestCaseProgram, BasicBlock, InstructionNode

from .target_desc import ARM64TargetDesc

if TYPE_CHECKING:
    from rvzr.elf_parser import ELFParser
    from rvzr.asm_parser import AsmParser
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc


# ==================================================================================================
# Private: Assembly Printing（私有模块：汇编代码打印）
# ==================================================================================================
class _ARM64Printer(Printer):
    """
    ARM64汇编代码打印器。
    将内部的Instruction对象转换为ARM64汇编代码文本字符串，
    处理ARM64特有的条件操作数（CondOp）、内存操作数和宏指令格式。
    """

    def __init__(self, target_desc: ARM64TargetDesc) -> None:
        """
        初始化ARM64打印器。

        参数:
            target_desc: ARM64目标描述对象，提供寄存器映射等信息
        """
        super().__init__(target_desc)
        # ARM64测试用例的序言模板（空，ARM64不需要特殊的序言代码）
        self.prologue_template = [""]
        # ARM64测试用例的结语模板，包含数据段声明和退出标记
        self.epilogue_template = [
            ".section .data.main\n",
            ".test_case_exit:nop\n",
        ]

    def _instruction_to_str(self, inst: Instruction) -> str:
        """
        将Instruction对象转换为ARM64汇编代码字符串。
        特殊处理ARM64的条件操作数（CondOp）：将其从操作数列表中提取出来，
        直接附加在指令名后面（如"add eq x0, x1"中的"eq"）。

        参数:
            inst: 待转换的指令对象
        返回值:
            ARM64汇编代码字符串
        """
        # 处理宏指令的特殊情况
        if inst.name == "macro":
            return self._macro_to_str(inst)

        # Handle conditional operands specially for ARM64
        # ARM64的条件码需要附加在指令名后面，而非作为独立操作数
        cond_op_str = ""
        operands = list(inst.operands)
        if operands and isinstance(operands[0], CondOp):
            cond_op_str = operands[0].value
            operands = operands[1:]

        # 将剩余操作数转换为字符串并用逗号连接
        operands_str = ", ".join([self._operand_to_str(op) for op in operands])
        # 标注插桩指令和不可移除指令的注释
        if inst.is_instrumentation:
            comment = "// instrumentation"
        elif inst.is_noremove:
            comment = "// noremove"
        else:
            comment = ""
        return f"{inst.name}{cond_op_str} {operands_str} {comment}"

    def _operand_to_str(self, op: Operand) -> str:
        """
        将Operand对象转换为ARM64汇编操作数字符串。
        内存操作数和地址生成操作数用方括号包裹，
        立即数操作数用#前缀标识（纯数字时），其他操作数直接返回其值。

        参数:
            op: 待转换的操作数对象
        返回值:
            ARM64汇编操作数字符串
        """
        # 内存操作数和地址生成操作数使用方括号语法（如[x0]）
        if isinstance(op, (MemoryOp, AgenOp)):
            return f"[{op.value}]"
        # 立即数操作数：纯数字加#前缀，非纯数字（如符号常量）不加#
        if isinstance(op, ImmediateOp):
            if self._is_digit_extended(op.value):
                return f"#{op.value}"
            return f"{op.value}"

        return op.value

    def _macro_to_str(self, inst: Instruction) -> str:
        """
        将宏指令转换为ARM64汇编文本。
        宏指令使用nop指令序列作为占位符。

        参数:
            inst: 宏指令对象
        返回值:
            ARM64宏定义文本字符串
        """
        macro_placeholder = "nop; nop; nop"
        # 如果宏没有参数，只显示宏名；否则显示宏名和参数
        if inst.operands[1].value.lower() == ".noarg":
            return f".macro{inst.operands[0].value}: {macro_placeholder}"
        return f".macro{inst.operands[0].value}{inst.operands[1].value}: {macro_placeholder}"

    @staticmethod
    def _is_digit_extended(s: str) -> bool:
        """
        扩展版的数字判断函数。
        与标准is_digit不同，本函数支持判断十六进制（0x前缀）和
        二进制（0b前缀）数字字符串。

        参数:
            s: 待判断的字符串
        返回值:
            True表示是有效的数字字符串，False表示不是

        An extended version of the is_digit function. The difference is that is_digit
        handles only decimal numbers, while this function can handle hex and binary
        numbers as well.
        """
        try:
            base = 10
            if s.startswith("0x"):
                base = 16  # 十六进制
            if s.startswith("0b"):
                base = 2   # 二进制
            int(s, base)
            return True
        except ValueError:
            return False


# ==================================================================================================
# Private: Collection of Instrumentation Passes（私有模块：插桩Pass集合）
# ==================================================================================================

_DispatcherKey = Literal["memory"]
_SandboxDispatcher = Dict[_DispatcherKey, Tuple[List[InstructionNode],
                                                Callable[[InstructionNode, BasicBlock], None]]]


class _ARM64SandboxPass(Pass):
    """
    ARM64沙箱插桩Pass。
    在测试用例中插入保护代码，防止以下类型的异常：
    - 越界内存访问（通过AND掩码和ADD基地址将内存访问限制在沙箱区域内）
    - 更多类型待添加

    注意：与x86不同，ARM64上除零不会触发异常，因此不需要对除法指令插入沙箱保护。

    A pass that instruments the test case to prevent certain types of faults,
    including:
    - out-of-sandbox memory accesses
    - ... (more to be added in the future)

    NOTE: in contrast to x86, arm64 does not fault on div by zero, so no need to
    sandbox division instructions
    """

    # pylint: disable=R0801
    # NOTE: there's an overlap between this class and it's equivalent in x86/generator.py
    # This is acceptable for now as functions are different enough so that deduplication
    # would hurt readability

    def __init__(self, target_desc: TargetDesc) -> None:
        """
        初始化沙箱Pass。

        参数:
            target_desc: 目标架构描述对象
        """
        super().__init__()
        self.target_desc = target_desc

        # 计算可直接访问的沙箱内存区域大小（主数据区+故障数据区）
        size_of_directly_accessible_memory = SandboxLayout.data_area_size(DataArea.MAIN) \
            + SandboxLayout.data_area_size(DataArea.FAULTY)
        # 根据内存大小计算掩码宽度，生成二进制掩码用于限制内存访问范围
        mask_width = int(math.log(size_of_directly_accessible_memory, 2))
        self.sandbox_address_mask = "#0b" + "1" * mask_width

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行沙箱插桩。
        遍历所有基本块，收集需要沙箱保护的内存访问指令，
        然后对每条指令插入AND掩码和ADD基地址的插桩代码。

        参数:
            test_case: 待处理的测试用例程序对象
        """
        dispatcher: _SandboxDispatcher = {
            "memory": ([], self._sandbox_memory_access),
        }

        for bb in test_case.iter_basic_blocks():
            dispatcher["memory"][0].clear()

            # collect all instructions that require sandboxing
            # 收集所有需要沙箱保护的指令
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue  # 跳过已有的插桩指令和模板指令

                # 检测包含显式内存操作数的指令，加入沙箱保护列表
                if inst.has_mem_operand(True):
                    dispatcher["memory"][0].append(node)

            # sandbox them
            # 对收集到的指令执行沙箱插桩
            for _, (nodes, sandbox_func) in dispatcher.items():
                for node in nodes:
                    sandbox_func(node, bb)

    def _sandbox_memory_access(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        对单个内存访问指令插入沙箱保护代码。
        保护策略：先用AND指令将地址寄存器与掩码做位运算（限制地址范围），
        再用ADD指令加上x20基地址（将地址重定向到沙箱数据区域）。

        参数:
            node: 需要保护的指令节点
            parent: 包含该指令的基本块

        Force the memory accesses into the page starting from x20
        """

        instr = node.instruction

        # if implicit_mem_operands:
        #     raise GeneratorException("Implicit memory accesses are not supported")

        # raise GeneratorException("Attempt to sandbox an instruction without memory operands")

        # 获取显式和隐式内存操作数
        mem_operands = instr.get_mem_operands(True)
        implicit_mem_operands = \
            instr.get_mem_operands(include_explicit=False, include_implicit=True)
        mask = self.sandbox_address_mask

        if mem_operands and not implicit_mem_operands:
            # 确保只有1个内存操作数（多内存操作数指令暂不支持）
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand = mem_operands[0]
            address_reg = mem_operand.value
            # 立即数掩码的宽度不超过32位
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32

            # 插入AND指令：将地址寄存器与沙箱掩码做位运算，限制地址在沙箱范围内
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, False, True)) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, False)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "", "", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)

            # 插入ADD指令：将掩码后的地址加上x20基地址，重定向到沙箱数据区域
            add_base = Instruction("add", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, False, True)) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, False)) \
                .add_op(RegisterOp("x20", 64, True, False)) \
                .add_op(FlagsOp(("w", "", "", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, add_base)
            return

        # 隐式内存访问目前不支持沙箱保护
        raise NotImplementedError("Implicit memory accesses are not yet supported")

    @staticmethod
    def requires_sandbox(inst: InstructionSpec) -> bool:
        """
        判断指令规范是否需要沙箱插桩保护。
        只要指令包含内存操作数就需要保护。

        参数:
            inst: 指令规范对象
        返回值:
            True表示需要沙箱保护，False表示不需要

        Check if the instruction requires instrumentation to prevent faults
        """
        if inst.has_mem_operand:
            return True
        return False


class _ARM64PatchUndefinedLoadsPass(Pass):
    """
    ARM64后索引加载修补Pass。
    修复ARM64后索引寻址模式（post-index）下的寄存器冲突问题：
    当ldr/str指令的目标寄存器与基址寄存器重叠时，后索引写入可能
    导致未定义行为，此Pass将目标寄存器替换为其他可用寄存器。
    """

    def __init__(self, target_desc: TargetDesc) -> None:
        """
        初始化后索引加载修补Pass。

        参数:
            target_desc: 目标架构描述对象，用于查找可用寄存器
        """
        super().__init__()
        self.target_desc = target_desc

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行后索引加载修补。
        遍历所有基本块，检测使用后索引寻址的ldr/str指令，
        并将冲突的目标寄存器替换为同位宽的其他可用寄存器。

        参数:
            test_case: 待处理的测试用例程序对象
        """
        for bb in test_case.iter_basic_blocks():
            to_patch: List[Instruction] = []

            for node in bb.iter_nodes():
                inst = node.instruction

                if inst.is_instrumentation or inst.is_from_template:
                    continue  # 跳过插桩指令和模板指令

                # check if it's a load with post-index
                # 检测后索引寻址模式的加载/存储指令
                if self._is_post_index(inst):
                    to_patch.append(inst)

            # fix operands
            # 修复操作数：将冲突的目标寄存器替换为同位宽的其他寄存器
            for inst in to_patch:
                org_dest = inst.operands[0]
                assert isinstance(org_dest, RegisterOp)
                # 查找与原目标寄存器同位宽的可用寄存器列表
                assert org_dest.width in self.target_desc.registers_by_size
                options = self.target_desc.registers_by_size[org_dest.width]
                # 排除原目标寄存器本身
                options = [i for i in options if i != org_dest.value]
                # 随机选择一个替代寄存器
                new_value = random.choice(options)
                inst.operands[0].value = new_value

    def _is_post_index(self, inst: Instruction) -> bool:
        """
        判断指令是否使用后索引寻址模式。
        后索引寻址模式特征：ldr/str指令包含立即数操作数，
        且目标寄存器的64位规范化名称出现在内存操作数的地址表达式中，
        这意味着基址寄存器在访问后被更新，与目标寄存器冲突。

        参数:
            inst: 待判断的指令对象
        返回值:
            True表示是后索引寻址模式，False表示不是
        """
        # 仅ldr/str指令可能使用后索引寻址
        if "ldr" not in inst.name and "str" not in inst.name:
            return False
        # 后索引寻址模式必须包含立即数操作数
        if inst.get_imm_operands() == []:
            return False

        # 检查目标寄存器是否与内存基址寄存器重叠
        ops = inst.operands
        assert isinstance(ops[0], RegisterOp)
        assert isinstance(ops[1], MemoryOp)
        normalized_dest = self.target_desc.reg_normalized[ops[0].value]
        normalized_dest = self.target_desc.reg_denormalized[normalized_dest][64]
        if normalized_dest in ops[1].value:
            return True  # 目标寄存器出现在基址中，存在后索引冲突
        return False


# ==================================================================================================
# Public Interface（公共接口：ARM64测试用例生成器主类）
# ==================================================================================================
class ARM64Generator(CodeGenerator):
    """
    ARM64架构测试用例生成器的主类。
    继承通用CodeGenerator，配置ARM64特有的插桩Pass（沙箱保护和后索引修补）
    和ARM64汇编打印器，用于生成完整的ARM64测试用例程序。

    arm64-specific implementation of the test case program generator
    """

    def __init__(self, seed: int, instruction_set: InstructionSet, target_desc: TargetDesc,
                 asm_parser: AsmParser, elf_parser: ELFParser) -> None:
        """
        初始化ARM64生成器。

        参数:
            seed: 随机数种子，用于控制测试用例生成的随机性
            instruction_set: 指令集规范，定义可用的指令及其操作数格式
            target_desc: ARM64目标描述对象
            asm_parser: 汇编解析器，用于解析生成的汇编代码
            elf_parser: ELF解析器，用于解析编译后的二进制文件
        """
        super().__init__(seed, instruction_set, target_desc, asm_parser, elf_parser)
        assert isinstance(self._target_desc, ARM64TargetDesc)

        # configure instrumentation passes
        # 配置插桩Pass：沙箱保护和后索引加载修补
        self._passes = [
            _ARM64SandboxPass(self._target_desc),
            _ARM64PatchUndefinedLoadsPass(self._target_desc),
        ]
        # 设置ARM64汇编打印器
        self._printer = _ARM64Printer(self._target_desc)

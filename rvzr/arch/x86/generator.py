"""
文件: x86架构测试用例生成器的实现
File: x86 implementation of the test case generator

本模块实现了x86架构特有的测试用例程序生成器，包括：
- 沙箱(Sandbox)插桩：防止除零、除法溢出、越界内存访问等故障
- 非规范地址访问插桩：构造访问非规范地址的内存操作
- 用户态到内核态(U2K)内存访问插桩：模拟Meltdown类跨特权级泄漏
- 未定义标志位修复插桩：在未定义标志和依赖指令之间插入修补指令
- 未定义结果修复插桩：修复BSF/BSR等指令的零源操作数问题
- 操作码替换插桩：将某些指令替换为原始操作码字节
- 汇编打印器：将内部指令表示转换为x86 Intel语法汇编文本

核心算法：
- 除法沙箱：通过OR/AND/SHR操作修改除数和被除数以防止异常
- 内存沙箱：通过AND掩码将内存访问限制在沙箱区域内
- 标志修补：反向遍历指令序列，追踪未定义标志并插入修补指令

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import math
import re
import random
from copy import deepcopy
from dataclasses import dataclass
from typing import List, Dict, Set, TYPE_CHECKING, Union, Final, Tuple, Callable, Literal
from typing_extensions import assert_never

from rvzr.code_generator import CodeGenerator, Pass, Printer
from rvzr.config import CONF
from rvzr.sandbox import SandboxLayout, DataArea, PAGE_SIZE
from rvzr.instruction_spec import OT, InstructionSpec
from rvzr.tc_components.actor import ActorPL, ActorID
from rvzr.tc_components.instruction import Instruction, Operand, RegisterOp, FlagsOp, \
    MemoryOp, ImmediateOp, AgenOp, copy_op_with_flow_modification, \
    copy_inst_with_modification
from rvzr.tc_components.test_case_code import TestCaseProgram, BasicBlock, InstructionNode

from .target_desc import X86TargetDesc

if TYPE_CHECKING:
    from rvzr.elf_parser import ELFParser
    from rvzr.asm_parser import AsmParser
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc


# ==================================================================================================
# 私有模块: 异常类型识别
# ==================================================================================================
@dataclass
class _FaultFilter:
    """
    本地服务类，识别测试用例中允许的异常类型。

    根据配置的faults_allowlist判断是否允许以下异常：
    - div-by-zero: 除零异常
    - div-overflow: 除法溢出异常
    - non-canonical-access: 非规范地址访问异常
    - user-to-kernel-access: 用户态到内核态的跨特权级访问
    """

    def __init__(self) -> None:
        self.div_by_zero: bool = 'div-by-zero' in CONF.faults_allowlist
        self.div_overflow: bool = 'div-overflow' in CONF.faults_allowlist
        self.non_canonical_access: bool = 'non-canonical-access' in CONF.faults_allowlist
        self.u2k_access: bool = 'user-to-kernel-access' in CONF.faults_allowlist


# ==================================================================================================
# 私有模块: 汇编打印
# ==================================================================================================
class _X86Printer(Printer):
    """
    x86 Intel语法汇编打印器。

    将内部的Instruction对象转换为x86 Intel语法汇编文本。
    处理指令名称、操作数格式化和宏指令的特殊打印。
    """

    target_desc: X86TargetDesc

    def __init__(self, target_desc: X86TargetDesc) -> None:
        """
        初始化x86打印器。

        :param target_desc: x86目标描述对象，用于获取内存地址前缀等信息
        """
        super().__init__(target_desc)
        self.prologue_template = [".intel_syntax noprefix\n"]
        self.epilogue_template = [
            ".section .data.main\n",
            ".test_case_exit:nop\n",
        ]

    def _instruction_to_str(self, inst: Instruction) -> str:
        """
        将指令对象转换为汇编文本字符串。

        :param inst: 指令对象
        :return: x86 Intel语法汇编文本
        """
        if inst.name == "macro":
            return self._macro_to_str(inst)

        operands = ", ".join([self._operand_to_str(op) for op in inst.operands])
        if inst.is_instrumentation:
            comment = "# instrumentation"
        elif inst.is_noremove:
            comment = "# noremove"
        else:
            comment = ""
        return f"{inst.name} {operands} {comment}"

    def _operand_to_str(self, op: Operand) -> str:
        """
        将操作数对象转换为汇编文本字符串。

        内存和AGEN操作数使用大小前缀（如dword ptr [rax]）。

        :param op: 操作数对象
        :return: 汇编操作数文本
        """
        if isinstance(op, (MemoryOp, AgenOp)):
            prefix = self.target_desc.memory_addr_prefixes[op.width]
            return f"{prefix} [{op.value}]"

        return op.value

    def _macro_to_str(self, inst: Instruction) -> str:
        """
        将宏指令转换为汇编文本字符串。

        宏指令使用nop占位指令替代宏体。

        :param inst: 宏指令对象
        :return: 宏定义的汇编文本
        """
        macro_placeholder = "nop qword ptr [rax + 0xff]"
        if inst.operands[1].value.lower() == ".noarg":
            return f".macro{inst.operands[0].value}: {macro_placeholder}"
        return f".macro{inst.operands[0].value}{inst.operands[1].value}: {macro_placeholder}"


# ==================================================================================================
# 私有模块: 插桩Pass集合
# ==================================================================================================
class _X86NonCanonicalAddressPass(Pass):
    """
    非规范地址访问插桩Pass。

    选择一个随机内存访问指令，将其替换为对非规范地址的访问。
    在x86-64中，非规范地址（如0x8000_0000_0000_0000以上的地址）
    会触发#GP异常，用于测试与非规范地址相关的CPU漏洞。

    插桩方法：
    1. 使用LEA计算原始地址
    2. 使用MOV加载随机掩码（使地址变为非规范）
    3. 使用XOR将掩码应用到地址上
    4. 替换原始内存操作数为修改后的地址
    """
    _target_desc: X86TargetDesc

    def __init__(self, target_desc: X86TargetDesc) -> None:
        """
        初始化非规范地址访问Pass。

        :param target_desc: x86目标描述对象
        """
        super().__init__()
        self._target_desc = target_desc

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行非规范地址访问插桩。

        遍历所有基本块，收集可插桩的内存访问指令，
        随机选择部分指令进行插桩。每个基本块最多插桩一次，
        以避免Unicorn在回滚时反复触发异常。

        :param test_case: 待插桩的测试用例
        """
        for bb in test_case.iter_basic_blocks():
            memory_instructions = []
            for node in bb.iter_nodes():
                instr = node.instruction
                if instr.is_instrumentation or instr.is_from_template:
                    continue
                if instr.name in ["div", "idiv"]:
                    # 除法指令的插桩难以与其他插桩组合，跳过
                    continue
                if instr.has_mem_operand(True):
                    memory_instructions.append(node)

            # 随机选择内存访问指令进行插桩
            for node in memory_instructions:
                n = len(memory_instructions)
                rand_bool = random.randint(0, n) == 0
                if not rand_bool:
                    continue
                self._instrument(node, bb)

                # 确保#GP只发生一次，否则Unicorn会反复抛出异常
                return

    def _instrument(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        对选定的内存访问指令进行插桩，使其访问非规范地址。

        插桩序列：
        - lea offset_reg, [原始地址]    ; 计算地址
        - mov mask_reg, 随机掩码          ; 加载高位掩码
        - xor offset_reg, mask_reg       ; 将地址变为非规范地址

        :param node: 待插桩的指令节点
        :param parent: 包含该节点的基本块
        """
        # pylint: disable = too-many-locals
        # 注意：这是一个相当复杂的插桩，局部变量数量较多是合理的
        instr = node.instruction

        # 收集源操作数中的寄存器操作数
        src_operands = []
        for o in instr.get_src_operands():
            if isinstance(o, RegisterOp):
                src_operands.append(o)

        # 检查插桩是否可行
        mem_operands = instr.get_mem_operands(include_explicit=True)
        implicit_mem_operands = \
            instr.get_mem_operands(include_explicit=False, include_implicit=True)
        if not mem_operands or implicit_mem_operands:
            return  # 该指令难以插桩；跳过

        # 查找适合插桩的寄存器
        assert len(mem_operands) == 1, f"Unexpected instruction format {instr.name}"
        mem_operand: Operand = mem_operands[0]
        mask_reg = self._find_mask_register(src_operands)
        offset_reg = self._find_offset_register(instr)

        # 生成随机掩码使地址变为非规范地址（高位设置为随机值）
        mask = hex((random.getrandbits(16) << 48))

        # 添加插桩指令序列
        # lea offset_reg, [原始内存操作数]  ; 计算原始地址
        lea = Instruction("lea", is_instrumentation=True) \
            .add_op(RegisterOp(offset_reg, 64, False, True)) \
            .add_op(MemoryOp(mem_operand.value, 64, True, False))
        parent.insert_before(node, lea)
        # mov mask_reg, 随机掩码  ; 加载非规范地址掩码
        mov = Instruction("mov", is_instrumentation=True) \
            .add_op(RegisterOp(mask_reg, 64, True, True)) \
            .add_op(ImmediateOp(mask, 64))
        parent.insert_before(node, mov)
        # xor offset_reg, mask_reg  ; 将地址高位设为随机值使其非规范
        mask_inst = Instruction("xor", is_instrumentation=True) \
            .add_op(RegisterOp(offset_reg, 64, True, True)) \
            .add_op(RegisterOp(mask_reg, 64, True, False))
        parent.insert_before(node, mask_inst)

        # 更新原始指令的内存操作数
        for idx, op in enumerate(instr.operands):
            if op == mem_operand:
                old_op = instr.operands[idx]
                assert isinstance(old_op, MemoryOp)
                addr_op = MemoryOp(offset_reg, old_op.width, old_op.src, old_op.dest)
                instr.operands[idx] = addr_op

    def _find_mask_register(self, src_operands: List[RegisterOp]) -> str:
        """
        查找适合用作掩码寄存器的寄存器名。

        优先选择rax，若源操作数使用了rax则改为rbx，
        以避免掩码寄存器与偏移寄存器冲突。

        :param src_operands: 源操作数中的寄存器列表
        :return: 选定的掩码寄存器名
        """
        # 不用偏移寄存器作为掩码寄存器
        candidate_list = ["rax", "rbx"]
        mask_reg = candidate_list[0]
        for operands in src_operands:
            op_regs = re.split(r'\+|-|\*| ', operands.value)
            for reg in op_regs:
                if self._target_desc.reg_normalized[mask_reg] == \
                   self._target_desc.reg_normalized[reg]:
                    mask_reg = candidate_list[1]
        return mask_reg

    def _find_offset_register(self, inst: Instruction) -> str:
        """
        查找适合用作地址偏移寄存器的寄存器名。

        优先选择rcx，若指令使用了rcx则改为rdx，
        以避免偏移寄存器与指令的其他操作数冲突。

        :param inst: 待插桩的指令
        :return: 选定的偏移寄存器名
        """
        # 不重复使用目标寄存器
        candidate_list = ["rcx", "rdx"]
        offset_reg = candidate_list[0]
        for op in inst.get_all_operands():
            if not isinstance(op, RegisterOp):
                continue
            if self._target_desc.reg_normalized[offset_reg] == \
               self._target_desc.reg_normalized[op.value]:
                offset_reg = candidate_list[1]
        return offset_reg


class _X86U2KAccessPass(Pass):
    """
    用户态到内核态(User-to-Kernel)内存访问插桩Pass。

    对用户特权级(User)角色的内存访问指令进行插桩，使其访问内核角色(actor 0)
    的FAULTY数据区域，构造跨特权级的内存访问模式，用于检测类似Meltdown的CPU漏洞。

    Pass随机选择用户角色中的内存访问指令，修改其内存操作数使其指向内核内存，
    计算基于沙箱内存布局的固定偏移量。

    重要：此Pass必须在_X86SandboxPass之后运行，因为它需要修改沙箱插桩添加的掩码，
    以确保跨特权级访问只命中单一页面。
    """

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        识别并插桩用户角色中的内存访问指令。

        :param test_case: 待处理的测试用例
        """
        # 使用枚举顺序作为actor ID
        # FIXME: 这可能有脆弱性，因为它假设二进制中的section顺序与
        # 测试用例中定义的actor顺序相同。但我们无法在此获取实际的section ID，
        # 因为汇编尚未生成，这是一个鸡生蛋蛋生鸡的问题。
        for sec_id, sec in enumerate(test_case):
            owner = sec.owner
            # 只插桩用户特权级角色（内核访问不会触发Meltdown）
            if owner.privilege_level != ActorPL.USER:
                continue

            for func in sec:
                to_instrument: List[InstructionNode] = []
                for bb in func:
                    for node in bb.iter_nodes():
                        instr = node.instruction
                        # 跳过插桩代码和模板代码
                        if instr.is_instrumentation or instr.is_from_template:
                            continue
                        # 跳过div/idiv，因为插桩会影响其操作数约束
                        if instr.name in ["div", "idiv"]:
                            continue
                        if instr.has_mem_operand(False):
                            to_instrument.append(node)

                    for node in to_instrument:
                        # 基于avg_mem_accesses配置的概率随机选择指令
                        probability = 1 / CONF.avg_mem_accesses
                        if random.random() > probability:
                            continue

                        self._instrument(node, bb, sec_id)

    def _instrument(self, node: InstructionNode, _: BasicBlock, owner_id: ActorID) -> None:
        """
        修改内存访问指令使其指向内核内存。

        计算从用户的MAIN区域到内核FAULTY区域的偏移量，
        并将该偏移量添加到内存操作数中。同时修改沙箱掩码
        以确保访问只命中一个页面。

        :param node: 待插桩的指令节点
        :param _: 父基本块（未使用）
        :param owner_id: 指令拥有者的actor ID（用于偏移量计算）
        """
        instr = node.instruction

        # 计算从用户MAIN区域到内核FAULTY区域的内存偏移量
        # 使用基础地址为(0,0)的虚拟SandboxLayout计算两个区域的相对偏移
        layout = SandboxLayout((0, 0), owner_id)
        user_main_start = layout.get_data_addr(DataArea.MAIN, owner_id)
        kernel_faulty_start = layout.get_data_addr(DataArea.FAULTY, 0)
        offset = user_main_start - kernel_faulty_start

        # 选择要修改的内存操作数（随机选择若指令有多个）
        mem_operands: List[MemoryOp] = instr.get_mem_operands(True)
        if len(mem_operands) == 1:
            mem_operand = mem_operands[0]
        else:
            mem_operand = random.choice(mem_operands)

        # 通过减去偏移量将内存访问重定向到内核内存
        mem_operand.value += " - " + str(offset)

        # 调整_X86SandboxPass添加的掩码，使其只命中单一页面
        # SandboxPass添加了AND指令来掩码内存地址以保持在actor的数据沙箱内。
        # 我们需要将这些掩码缩减到PAGE_SIZE，以确保跨特权级访问只命中内核的FAULTY页面。
        previous_node = node.previous
        while previous_node and previous_node.instruction.is_instrumentation:
            for op in previous_node.instruction.operands:
                if not isinstance(op, ImmediateOp):
                    continue
                mask_value = int(op.value, base=0)
                if mask_value > PAGE_SIZE:
                    mask_value %= PAGE_SIZE
                op.value = bin(mask_value)
            previous_node = previous_node.previous


_DispatcherKey = Literal["memory", "division", "bit_test", "repeated", "corrupted_cf", "enclu"]
_SandboxDispatcher = Dict[_DispatcherKey, Tuple[List[InstructionNode],
                                                Callable[[InstructionNode, BasicBlock], None]]]


class _X86SandboxPass(Pass):
    """
    沙箱插桩Pass，防止测试用例触发某些类型的故障。

    插桩内容包括：
    - 内存访问沙箱：将内存访问限制在R14开始的沙箱页面内
    - 除法保护：防止除零和除法溢出
    - 位测试(BT*)保护：限制位偏移量在字节范围内
    - 重复指令(rep*)保护：限制RCX计数器值
    - CF(进位标志)损坏保护：在移位/旋转指令后恢复CF
    - ENCLU指令保护：限制EAX参数为有效值

    核心算法：
    - 内存沙箱：使用AND掩码截断地址低位，然后加上R14基址
    - 除法保护：使用OR/AND/SHR操作修改除数和被除数
    """

    mask_3bits = "0b111"
    bit_test_names = ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]

    def __init__(self, target_desc: TargetDesc, faults: _FaultFilter) -> None:
        """
        初始化沙箱Pass。

        计算沙箱地址掩码，基于可直接访问的内存区域大小（MAIN + FAULTY）。

        :param target_desc: 目标架构描述对象
        :param faults: 异常过滤器，判断哪些异常是允许的
        """
        super().__init__()
        self.target_desc = target_desc
        self.faults = faults

        # 计算沙箱地址掩码：掩码位数 = log2(MAIN区域大小 + FAULTY区域大小)
        size_of_directly_accessible_memory = SandboxLayout.data_area_size(DataArea.MAIN) \
            + SandboxLayout.data_area_size(DataArea.FAULTY)
        mask_width = int(math.log(size_of_directly_accessible_memory, 2))
        self.sandbox_address_mask = "0b" + "1" * mask_width

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行沙箱插桩。

        使用调度器(dispatcher)按类型收集需要沙箱的指令，
        然后对每种类型的指令调用相应的沙箱函数。

        :param test_case: 待插桩的测试用例
        """
        dispatcher: _SandboxDispatcher = {
            "memory": ([], self._sandbox_memory_access),
            "division": ([], self._sandbox_division),
            "bit_test": ([], self._sandbox_bit_test),
            "repeated": ([], self._sandbox_repeated_instruction),
            "corrupted_cf": ([], self._sandbox_corrupted_cf),
            "enclu": ([], self._sandbox_enclu),
        }

        for bb in test_case.iter_basic_blocks():
            dispatcher["memory"][0].clear()
            dispatcher["division"][0].clear()
            dispatcher["bit_test"][0].clear()
            dispatcher["repeated"][0].clear()
            dispatcher["corrupted_cf"][0].clear()
            dispatcher["enclu"][0].clear()

            # 收集所有需要沙箱的指令
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue

                if inst.has_mem_operand(True):
                    dispatcher["memory"][0].append(node)
                if inst.name in ["div", "rex div", "idiv", "rex idiv"]:
                    dispatcher["division"][0].append(node)
                elif inst.name in self.bit_test_names:
                    dispatcher["bit_test"][0].append(node)
                elif "rep" in inst.name:
                    dispatcher["repeated"][0].append(node)
                elif inst.category in ["BASE-ROTATE", "BASE-SHIFT"]:
                    dispatcher["corrupted_cf"][0].append(node)
                elif inst.name == "enclu":
                    dispatcher["enclu"][0].append(node)

            # 对收集到的指令执行沙箱插桩
            for _, (nodes, sandbox_func) in dispatcher.items():
                for node in nodes:
                    sandbox_func(node, bb)

    def _sandbox_memory_access(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        将内存访问强制限制在R14开始的沙箱页面内。

        对于显式内存操作数：
        - 在指令前插入AND掩码指令截断地址低位
        - 将内存操作数改为 "r14 + 截断后的地址"

        对于隐式内存操作数（如STRINGOP等）：
        - 在指令前后插入AND掩码和ADD/SUB R14指令
        - 确保隐式地址寄存器在沙箱范围内，并在指令后恢复原值

        对于SIMD和lock指令，掩码需要额外调整以满足对齐要求。

        :param node: 待沙箱的指令节点
        :param parent: 包含该节点的基本块
        """
        instr = node.instruction

        mem_operands = instr.get_mem_operands(True)
        implicit_mem_operands = instr.get_mem_operands(
            include_explicit=False, include_implicit=True)

        mask = self.sandbox_address_mask
        # SIMD操作数需要更大的对齐掩码
        if any(op.width >= 256 for op in mem_operands):
            mask = mask[:-5] + "0" * 5  # YMM操作数需要32字节对齐
        elif any(op.width >= 128 for op in mem_operands):
            mask = mask[:-4] + "0" * 4  # XMM操作数需要16字节对齐

        # lock/xchg指令需要8字节对齐
        if CONF.x86_generator_align_locks:  # type: ignore  # pylint: disable = no-member
            if "lock" in instr.name or instr.name == "xchg":
                mask = mask[:-3] + "0" * 3

        # 处理显式内存操作数
        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            # AND掩码：截断地址低位使其在沙箱范围内
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, 64, True, True)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)
            # 将地址修改为R14基址+截断后的偏移
            instr.get_mem_operands(True)[0].value = "r14 + " + address_reg
            return

        # 处理隐式内存操作数
        mem_operands = implicit_mem_operands
        assert mem_operands, "Attempt to sandbox an instruction without memory operands"

        # 去重操作数
        uniq_operands: Dict[str, MemoryOp] = {}
        for o in mem_operands:
            if o.value not in uniq_operands:
                uniq_operands[o.value] = o

        # 对每个隐式内存操作数执行沙箱插桩
        for address_reg, mem_operand in uniq_operands.items():
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            assert address_reg in self.target_desc.registers_by_size[64], \
                f"Unexpected address register {address_reg} used in {instr}"
            # AND掩码：截断地址低位
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)

            # ADD R14：将沙箱基址加到地址上
            add_base = Instruction("add", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOp("r14", 64, True, False)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, add_base)

            # SUB R14：在指令后恢复地址寄存器的原始值
            remove_base = Instruction("sub", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOp("r14", 64, True, False)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_after(node, remove_base)

    def _sandbox_division(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        除法保护插桩：防止除零和除法溢出。

        防止两类除法故障：
        - 除零(Divide-by-zero)：除数为0时触发
        - 除法溢出(Division overflow)：商大于目标寄存器时触发

        防除零策略：
            divisor = divisor | 1  (无符号/允许溢出的有符号除法)
            divisor = divisor | 0b1000 且 divisor低位 = 0b11111000  (禁止溢出的有符号除法)

        防溢出策略：
            无符号除法：D = (D & divisor) >> 1  确保D始终小于除数
            有符号除法：D = D & 3  限制被除数高位为0-3，消除溢出可能性

        特殊情况：
            1) 除数是D(RDX)寄存器 → 无法同时修改除数和被除数，删除指令
            2) 8位除法(AX单独) → 插桩过于复杂，直接设AX=1

        副作用：降低除法操作数的熵值（减少可测试的值范围）

        :param node: 待沙箱的除法指令节点
        :param parent: 包含该节点的基本块
        """
        # pylint: disable = too-many-locals
        # FIXME: 此函数需要重构为更简单的部分

        inst = node.instruction

        # 确定允许的异常类型
        owner_name = parent.get_owner().name
        actor_blocklist = CONF.get_actors_conf()[owner_name]["fault_blocklist"]
        enable_div_by_zero = self.faults.div_by_zero & ("div-by-zero" not in actor_blocklist)
        enable_div_overflow = self.faults.div_overflow & ("div-overflow" not in actor_blocklist)

        # 复制除法源操作数并标记为目标（可能需要修改）
        operand = inst.operands[0]
        assert isinstance(operand, (RegisterOp, MemoryOp)), \
               f"Unexpected operand type {operand}"
        divisor = copy_op_with_flow_modification(operand, dest=True)
        size = divisor.width

        # 禁止64位除法以防止Zero Division Injection
        if size == 64 and CONF.x86_disable_div64:  # type: ignore  # pylint: disable = no-member
            parent.delete(node)
            return

        # 防止除零
        if not enable_div_by_zero:
            if "idiv" not in inst.name or enable_div_overflow:
                # 无符号除法和允许溢出的有符号除法：
                # OR除数与1即可防止除零
                instrumentation = Instruction("or", is_instrumentation=True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOp("1", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)
            else:
                # 禁止溢出的有符号除法：
                # 需要使除数既非零又足够大以避免溢出
                # 正数除数：OR 0b10000确保最小值为15
                instrumentation = Instruction("or", is_instrumentation=True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOp("0b1000", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)

                # 负数除数：清除低4位使值至少为-15
                divider_8_bit: Union[RegisterOp, MemoryOp]
                if isinstance(divisor, MemoryOp):
                    divider_8_bit = MemoryOp(divisor.value, 8, divisor.src, divisor.dest)
                elif isinstance(divisor, RegisterOp):
                    reg_normalized = self.target_desc.reg_normalized[divisor.value]
                    reg_8_bit = self.target_desc.reg_denormalized[reg_normalized][8]
                    divider_8_bit = RegisterOp(reg_8_bit, 8, divisor.src, divisor.dest)
                else:
                    assert_never(divisor)

                instrumentation = Instruction("and", is_instrumentation=True) \
                    .add_op(divider_8_bit) \
                    .add_op(ImmediateOp("0b11111000", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)

        if enable_div_overflow:
            return
        # 防止除法溢出

        # 检查无法插桩的情况：
        # - 除数是D(RDX)寄存器 → 无法同时修改除数和被除数
        # - 除数是带RDX偏移的内存值
        # - 除法中AX既是被除数又是内存偏移
        if divisor.value in ["rdx", "edx", "dx", "dh", "dl"] \
           or "rdx" in divisor.value \
           or ("rax" in divisor.value and size == 8):
            parent.delete(node)
            return

        # 特殊情况：8位除法中被除数是AX
        # 插桩：直接设置AX=1
        if size == 8:
            instrumentation = Instruction("mov", is_instrumentation=True).\
                add_op(RegisterOp("ax", 16, False, True)).\
                add_op(ImmediateOp("1", 16))
            parent.insert_before(node, instrumentation)
            return

        # 正常情况：获取被除数高位寄存器(D)
        d_register = {64: "rdx", 32: "edx", 16: "dx"}[size]

        # 有符号除法(idiv)防溢出
        if "idiv" in inst.name:
            # 通过将D高位清零限制被除数范围，使被除数最大为4 << div_size - 1
            # D = D & 3
            instrumentation = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(ImmediateOp("0b11", 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, instrumentation)

        # 无符号除法(div)防溢出
        else:
            # 确保D始终小于除数：
            # D = (D & divisor) >> 1
            instrumentation = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(divisor) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, instrumentation)

            instrumentation = Instruction("shr", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(ImmediateOp("1", 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "undef")), True)
            parent.insert_before(node, instrumentation)

    def _sandbox_bit_test(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        位测试(BT*)指令的沙箱插桩。

        BT*指令的访问地址基于两个操作数，_sandbox_memory_access处理第一个操作数，
        此函数确保偏移量始终在一个字节范围内，防止越界访问。

        :param node: 待沙箱的BT*指令节点
        :param parent: 包含该节点的基本块
        """
        inst = node.instruction

        address = inst.operands[0]
        if isinstance(address, RegisterOp):
            # 不访问内存的版本，不需要沙箱
            return

        offset = inst.operands[1]
        if isinstance(offset, ImmediateOp):
            # 立即数偏移：直接替换为较小的随机值
            offset.value = str(random.randint(0, 7))
            return

        # 寄存器偏移：用AND掩码截断高位，使值最大为7
        assert isinstance(offset, RegisterOp)

        if address.value != offset.value:
            new_offset = copy_op_with_flow_modification(offset, dest=True)
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(new_offset) \
                .add_op(ImmediateOp(self.mask_3bits, 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)
            return

        # 特殊情况：偏移和地址使用同一寄存器 → 无法沙箱，删除指令
        parent.delete(node)

    def _sandbox_repeated_instruction(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        重复指令(rep*)的沙箱插桩。

        限制RCX计数器值：AND掩码截断为最大0xFF，然后ADD 1确保至少执行一次。

        :param node: 待沙箱的rep*指令节点
        :param parent: 包含该节点的基本块
        """
        # AND掩码：截断RCX为0xFF
        apply_mask = Instruction("and", is_instrumentation=True) \
            .add_op(RegisterOp("rcx", 64, True, True)) \
            .add_op(ImmediateOp("0xff", 8)) \
            .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
        # ADD 1：确保RCX至少为1（0xFF & val + 1）
        add_base = Instruction("add", is_instrumentation=True) \
            .add_op(RegisterOp("rcx", 64, True, True)) \
            .add_op(ImmediateOp("1", 1)) \
            .add_op(FlagsOp(("w", "w", "w", "w", "w", "", "", "", "w")), True)
        parent.insert_before(node, apply_mask)
        parent.insert_before(node, add_base)

    def _sandbox_corrupted_cf(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        CF(进位标志)损坏保护的沙箱插桩。

        在移位/旋转指令后插入STC指令恢复CF标志，
        防止模型和执行器之间因CF实现差异导致的误报。

        :param node: 待沙箱的移位/旋转指令节点
        :param parent: 包含该节点的基本块
        """
        # FIXME: 这应该是一个单独的Pass
        set_cf = Instruction("stc", is_instrumentation=True) \
            .add_op(FlagsOp(("w", "", "", "", "", "", "", "", "")), True)
        parent.insert_after(node, set_cf)

    def _sandbox_enclu(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        ENCLU指令的沙箱插桩。

        将EAX设置为有效的ENCLU操作码之一(0-ereport, 1-egetkey, 4-eexit, 5-eaccept, 6-emodpe, 7-eacceptcopy)。

        :param node: 待沙箱的ENCLU指令节点
        :param parent: 包含该节点的基本块
        """
        # FIXME: 这应该是一个单独的Pass
        options = [
            "0",  # ereport
            "1",  # egetkey
            "4",  # eexit
            "5",  # eaccept
            "6",  # emodpe
            "7",  # eacceptcopy
        ]
        set_rax = Instruction("mov", is_instrumentation=True) \
            .add_op(RegisterOp("eax", 32, True, True)) \
            .add_op(ImmediateOp(random.choice(options), 1))
        parent.insert_before(node, set_rax)

    @staticmethod
    def requires_sandbox(inst: InstructionSpec) -> bool:
        """
        检查指令是否需要沙箱插桩以防止故障。

        :param inst: 指令规格对象
        :return: True表示需要沙箱插桩
        """
        if inst.has_mem_operand:
            return True
        if inst.name in ["div", "rex div"]:
            return True
        if inst.name in ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]:
            return True
        if inst.category in ["BASE-SHIFT", "BASE-ROTATE"]:
            return True
        return False


class _X86PatchUndefinedFlagsPass(Pass):
    """
    未定义标志位修补Pass。

    某些指令对FLAGS有未定义的影响（如SHL可能或不覆盖OF），
    这会导致模型和执行器之间的不匹配，产生误报。

    修补方法：分析测试用例，当一条有未定义标志的指令后紧跟
    一条使用该标志的指令时，在两者之间插入一条随机指令，
    该指令覆盖未定义的标志。

    例如，将：
        SHL eax, eax  // 未定义OF
        JNO .label    // 使用OF
    替换为：
        SHL eax, eax
        ADD ebx, ecx  // 随机指令覆盖OF
        JNO .label

    核心算法：反向遍历指令序列，追踪需要设置的标志集合，
    当遇到未定义标志时查找修补指令序列。
    """
    patch_candidates: List[InstructionSpec]

    def __init__(self, instruction_set: InstructionSet, generator: CodeGenerator) -> None:
        """
        初始化未定义标志修补Pass。

        从指令集中筛选可用于修补的候选指令：
        - 不改变控制流
        - 不需要沙箱插桩
        - 只写入标志而不读取标志（确保不引入新的标志依赖）

        :param instruction_set: 指令集对象
        :param generator: 代码生成器对象
        """
        super().__init__()
        self.instruction_set = instruction_set
        self.generator = generator

        self.patch_candidates = []
        for instruction_spec in instruction_set.instructions:
            # 不改变控制流
            if instruction_spec.is_control_flow:
                continue

            # 不需要沙箱插桩的指令才是安全的修补候选
            if _X86SandboxPass.requires_sandbox(instruction_spec):
                continue

            # 检查指令是否只写入标志而不读取标志（不引入新依赖）
            has_read = False
            has_write = False
            for op in instruction_spec.operands + instruction_spec.implicit_operands:
                if op.type == OT.FLAGS:
                    for f in op.values:
                        if f in ['r', 'r/w', 'r/cw']:
                            has_read = True
                        elif f in ['w']:
                            has_write = True
            if not has_read and has_write:
                self.patch_candidates.append(instruction_spec)

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行未定义标志修补。

        :param test_case: 待修补的测试用例
        """
        for bb in test_case.iter_basic_blocks():
            self._patch_flags_in_bb(bb)

    def _patch_flags_in_bb(self, bb: BasicBlock) -> None:
        """
        在基本块内修补未定义标志。

        核心算法：
        1. 收集终止指令(条件跳转)读取的标志集合
        2. 反向遍历指令列表，追踪需要设置的标志
        3. 遇到未定义标志时，查找修补指令并插入
        4. 处理基本块入口处残留的未定义标志

        :param bb: 待修补的基本块
        """
        # pylint: disable = too-many-branches
        # FIXME: 此函数需要重构

        # 获取基本块中所有指令节点
        all_instructions: List[InstructionNode] = []
        for node in bb.iter_nodes():
            all_instructions.append(node)

        # 初始化需要设置的标志集合
        flags_to_set: Set[str] = set()

        # 收集终止指令(条件跳转)读取的标志
        # 假设终止指令不修改标志，因此在此处不需要修补
        for term in bb.terminators:
            flags = term.get_flags_operand()
            if flags:
                for f in flags.get_flags_by_type('read'):
                    flags_to_set.add(f)

        # 反向遍历指令列表
        # 在遍历过程中追踪未定义标志值，并在需要时插入额外指令覆盖它们
        while all_instructions:
            node = all_instructions.pop()
            inst = node.instruction
            flags = inst.get_flags_operand()

            # 跳过模板指令和不读/写标志的指令
            if inst.is_from_template or not flags:
                continue

            # 修补未定义标志：在指令后插入覆盖指令
            undef_flags = [i for i in flags.get_flags_by_type('undef') if i in flags_to_set]
            if undef_flags:
                patches = self._find_flags_patch(undef_flags, flags_to_set)
                for patch in patches:
                    bb.insert_after(node, patch)
                    # 移除被修补指令覆盖的标志
                    for f in patch.get_flags_operand().get_flags_by_type('write'):  # type: ignore
                        flags_to_set.discard(f)

            # 移除当前指令写入的标志
            for f in flags.get_flags_by_type('write'):
                flags_to_set.discard(f)

            # 添加当前指令读取的标志作为新的依赖
            for f in flags.get_flags_by_type('read'):
                flags_to_set.add(f)

        # 确保进入基本块时不存在未定义标志
        if flags_to_set:
            # 在基本块入口处插入修补指令
            entry_node = bb.get_first(exclude_macros=True)
            if not entry_node:
                raise ValueError("X86PatchUndefinedFlagsPass: No place to insert a patch")

            patches = self._find_flags_patch(list(flags_to_set), flags_to_set)
            for patch in patches:
                bb.insert_before(entry_node, patch)

    def _find_flags_patch(self, undef_flags: List[str],
                          flags_to_set: Set[str]) -> List[Instruction]:
        """
        查找能覆盖指定未定义标志的指令序列。

        从候选修补指令中搜索能覆盖undef_flags但不引入新的未定义标志依赖的指令。
        可能需要多条修补指令来覆盖所有未定义标志。

        :param undef_flags: 需要被修补指令覆盖的未定义标志列表
        :param flags_to_set: 后续指令将读取的标志集合（修补不应引入新的未定义依赖）
        :return: 覆盖所有未定义标志的修补指令列表
        :raises ValueError: 若无法找到合适的修补指令
        """
        org_undef = deepcopy(undef_flags)
        patches: List[Instruction] = []
        for instruction_spec in self.patch_candidates:
            patch = self.generator.generate_instruction(instruction_spec, True)
            patch_flags = patch.get_flags_operand()
            assert patch_flags
            # 检查修补指令是否会引入新的未定义标志依赖
            new_undef_flags = [
                i for i in patch_flags.get_flags_by_type('undef')
                if i not in undef_flags and i in flags_to_set
            ]
            # 检查修补指令是否覆盖了部分未定义标志
            not_patched_flags = [
                i for i in undef_flags if i not in patch_flags.get_flags_by_type('write')
            ]

            # 选择不引入新依赖且覆盖了部分标志的修补指令
            if not new_undef_flags and not_patched_flags != undef_flags:
                patches.append(patch)
                undef_flags = not_patched_flags
                if not undef_flags:
                    break

        if undef_flags:
            raise ValueError("Could not find an instruction to patch flags.\n"
                             f"  Initial flags to be patched: {org_undef}\n"
                             f"  Flags for which a patch was not found: {undef_flags}")

        return patches


class _X86PatchUndefinedResultPass(Pass):
    """
    未定义结果修补Pass。

    某些指令在源操作数为零时产生未定义结果（如BSF/BSR），
    此Pass修补这些指令以避免未定义行为。
    """

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例中的位扫描(BSF/BSR)指令执行修补。

        :param test_case: 待修补的测试用例
        """
        for bb in test_case.iter_basic_blocks():
            bit_scan = []
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue
                if inst.name in ["bsf", "bsr"]:
                    bit_scan.append(node)
            for node in bit_scan:
                self._patch_bit_scan(node, bb)

    @staticmethod
    def _patch_bit_scan(node: InstructionNode, parent: BasicBlock) -> None:
        """
        修补位扫描指令(BSF/BSR)的零源操作数问题。

        位扫描指令在源操作数为零时产生未定义结果。
        修补方法：OR源操作数与最高位掩码，确保源操作数不为零。

        :param node: 待修补的BSF/BSR指令节点
        :param parent: 包含该节点的基本块
        """
        inst = node.instruction

        # 获取源操作数
        src_operand = inst.operands[1]
        assert isinstance(src_operand, (RegisterOp, MemoryOp)), \
               f"Unexpected operand type {src_operand}"

        # 复制源操作数（因为可能需要修改）
        source = copy_op_with_flow_modification(src_operand, dest=True)

        # 构造最高位掩码
        mask = bin(1 << (source.width - 1))
        mask_size = source.width
        if source.width in [64, 32]:
            mask = "0b1000000000000000000000000000000"
            mask_size = 32
        # OR操作确保源操作数的最高位为1，使其不为零
        apply_mask = Instruction("or", is_instrumentation=True) \
            .add_op(source) \
            .add_op(ImmediateOp(mask, mask_size)) \
            .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
        parent.insert_before(node, apply_mask)


class _X86PatchOpcodesPass(Pass):
    """
    操作码替换Pass。

    将汇编指令替换为其原始操作码字节。
    这是为了测试具有多个操作码的指令以及标准汇编器不支持/不允许的指令。

    例如，UD2指令有多种替代操作码（32位模式的无效编码），
    INT1指令使用0xF1操作码（ICEBP）。
    """
    _OPCODES: Final[Dict[str, List[str]]] = {
        "ud2": [
            "0x0f, 0x0b",  # UD2指令的标准操作码
            # 以下操作码在64位模式下无效；
            # 所有操作码用NOP填充以防止objdump误解析
            "0x06, 0x90",  # 32位PUSH编码
            "0x07, 0x90",  # 32位POP编码
            "0x0e, 0x90",  # 32位PUSH的替代编码
            "0x16, 0x90",  # 32位PUSH的另一种编码
            "0x17, 0x90",  # 32位POP的另一种编码
            "0x1e, 0x90",  # 32位PUSH编码
            "0x1f, 0x90",  # 32位POP编码
            "0x27, 0x90",  # DAA
            "0x2f, 0x90",  # DAS
            "0x37, 0x90",  # AAA
            "0x3f, 0x90",  # AAS
            "0x60, 0x90",  # PUSHA
            "0x61, 0x90",  # POPA
            "0x62, 0x90",  # BOUND
            "0x82, 0x90",  # 32位逻辑指令别名
            "0x9a, 0x90",  # 32位CALLF编码
            "0xc4, 0x90",  # LES
            "0xd4, 0x90",  # AAM
            "0xd5, 0x90",  # AAD
            "0xd6, 0x90",  # 保留操作码
            "0xea, 0x90",  # 32位JMPF编码
        ],
        "int1": ["0xf1"]  # ICEBP操作码
    }

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        对测试用例执行操作码替换。

        遍历所有基本块，收集需要替换的指令（UD2, INT1等），
        随机选择一个操作码版本进行替换。

        :param test_case: 待处理的测试用例
        """
        for bb in test_case.iter_basic_blocks():
            # 收集所有需要操作码替换的指令
            to_patch = []
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue
                if inst.name in self._OPCODES:
                    to_patch.append(node)

            # 执行替换
            for node in to_patch:
                self._instrument(node, bb)

    def _instrument(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        将指令替换为随机选择的原始操作码字节。

        :param node: 待替换的指令节点
        :param parent: 包含该节点的基本块
        """
        inst = node.instruction
        opcode_options = self._OPCODES[inst.name]
        opcode = random.choice(opcode_options)
        new_inst = copy_inst_with_modification(inst, name=".byte " + opcode)
        parent.insert_before(node, new_inst)
        parent.delete(node)


# ==================================================================================================
# 公共接口
# ==================================================================================================
class X86Generator(CodeGenerator):
    """
    x86架构特有的测试用例程序生成器。

    继承自通用CodeGenerator，配置x86特有的插桩Pass序列：
    1. _X86PatchUndefinedFlagsPass - 修补未定义标志位
    2. _X86SandboxPass - 沙箱插桩（防止各类故障）
    3. _X86PatchUndefinedResultPass - 修补未定义结果
    4. _X86NonCanonicalAddressPass - 非规范地址访问插桩（可选）
    5. _X86U2KAccessPass - 用户到内核访问插桩（可选，必须在SandboxPass之后）
    6. _X86PatchOpcodesPass - 操作码替换

    Pass执行顺序很重要：
    - U2KPass必须在SandboxPass之后（修改沙箱掩码）
    - PatchUndefinedFlagsPass必须在SandboxPass之前（否则掩码指令会干扰标志追踪）
    """

    _faults: _FaultFilter

    def __init__(self, seed: int, instruction_set: InstructionSet, target_desc: TargetDesc,
                 asm_parser: AsmParser, elf_parser: ELFParser) -> None:
        """
        初始化x86测试用例生成器。

        :param seed: 随机种子
        :param instruction_set: 指令集规格对象
        :param target_desc: 目标架构描述对象
        :param asm_parser: 汇编解析器
        :param elf_parser: ELF解析器
        """
        super().__init__(seed, instruction_set, target_desc, asm_parser, elf_parser)
        assert isinstance(self._target_desc, X86TargetDesc)

        self._faults = _FaultFilter()

        # 配置插桩Pass序列（执行顺序很重要）
        self._passes = [
            _X86PatchUndefinedFlagsPass(self._instruction_set, self),
            _X86SandboxPass(self._target_desc, self._faults),
            _X86PatchUndefinedResultPass(),
        ]
        # 可选Pass：根据异常过滤器决定是否启用
        if self._faults.non_canonical_access:
            self._passes.append(_X86NonCanonicalAddressPass(self._target_desc))
        if self._faults.u2k_access:
            self._passes.append(_X86U2KAccessPass())  # 必须在SandboxPass之后
        self._passes.append(_X86PatchOpcodesPass())
        self._printer = _X86Printer(self._target_desc)

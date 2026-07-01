"""
文件：指令最小化pass集合——对测试用例的指令进行操作（即简化测试用例代码）。

该模块包含多种指令级最小化pass，每种pass采用不同的策略来简化测试用例：
1. InstructionRemovalPass：逐条移除指令
2. InstructionSimplificationPass：将复杂指令替换为简单指令
3. ConstantSimplificationPass：将常数替换为零
4. MaskSimplificationPass：将掩码逐步缩小
5. NopReplacementPass：将指令替换为NOP
6. LabelRemovalPass：移除未使用的标签
7. FenceInsertionPass：在指令前插入内存屏障

所有pass的共同目标是在不丢失违规的前提下，尽可能简化测试用例代码。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
import os
import re
from subprocess import run
from typing import TYPE_CHECKING, List, Dict, Callable
from typing_extensions import assert_never

from .pass_abc import BaseMinimizationPass
from ..logs import warning
from ..config import CONF

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData
    from ..fuzzer import Fuzzer
    from ..isa_spec import InstructionSet
    from ..postprocessing.progress_printer import ProgressPrinter


class BaseInstructionMinimizationPass(BaseMinimizationPass):
    """
    指令最小化pass的基类，提供标准的最小化循环和抽象接口。
    子类需实现modify_instruction和verify_modification方法来定义
    具体的指令修改算法和验证逻辑。
    """
    name: str = ""

    # ------------------------------------------------
    # 抽象接口
    @abc.abstractmethod
    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """ 执行最小化pass的主函数 """

    @abc.abstractmethod
    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        根据子类定义的算法修改指定位置的指令。
        :param instructions: 指令列表
        :param cursor: 待修改指令的位置索引
        :return: 修改后的指令列表，如果修改失败返回空列表
        """

    @abc.abstractmethod
    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        根据子类定义的算法验证修改是否有效。
        :param test_case: 修改后的测试用例
        :param inputs: 用于验证的输入列表
        :return: True表示修改有效，False表示无效
        """

    def minimization_loop(self,
                          test_case: TestCaseProgram,
                          inputs: List[InputData],
                          skip_instrumentation_lines: bool = True) -> List[int]:
        """
        标准最小化循环——从后向前逐条应用modify_instruction算法，
        并检查修改后的测试用例是否仍通过verify_modification验证。

        :param test_case: 待最小化的测试用例对象
        :param inputs: 用于验证的输入列表
        :param skip_instrumentation_lines: 如果为True，跳过带有instrumentation注释的行
        :return: 通过验证的指令ID列表
        """

        def line_is_skipped(line: str) -> bool:
            """ 判断某行是否应被跳过（不进行最小化处理） """
            if not line:
                return True
            # 跳过满足以下条件的行：
            is_skipped = line == ""  # 空行
            is_skipped |= (line[0] == self._comment_symbol)  # 注释行
            is_skipped |= ("lfence" in line)  # 内存屏障指令
            is_skipped |= ('.' == line[0])  # 标签行
            is_skipped |= ('noremove' in line)  # 明确标记为不可移除的行
            is_skipped |= (skip_instrumentation_lines and 'instrumentation' in line)  # instrumentation标记行
            is_skipped |= (self._base_register in line and '[' not in line)  # 沙箱基地址更新
            return is_skipped

        # 获取测试用例的所有指令行
        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()

        # 从后向前遍历所有指令，收集可以通过修改且仍通过验证的指令ID列表
        cursor = len(instructions)
        modifiable_ids = []
        while True:
            cursor -= 1
            line = instructions[cursor].strip().lower()
            # 检查是否完成遍历
            if cursor == 0:
                break

            # 某些行不做处理
            if line_is_skipped(line):
                continue

            # 创建修改后的测试用例
            modified_instructions = self.modify_instruction(instructions, cursor)
            if not modified_instructions:  # 如果修改失败，跳过此行
                self._progress.next(False)
                continue

            # 从修改后的指令创建测试用例对象
            tmp_test_case = self._get_test_case_from_instructions(modified_instructions)

            # 验证修改并更新可修改指令列表
            check_passed = self.verify_modification(tmp_test_case, inputs)
            if check_passed:
                self._progress.next(True)
                instructions = modified_instructions
                modifiable_ids.append(cursor)
            else:
                self._progress.next(False)

        return modifiable_ids

    def set_violation(self, violation: Violation) -> None:
        """ 设置正在最小化的违规对象 """


class InstructionRemovalPass(BaseInstructionMinimizationPass):
    """
    指令移除pass——从后向前逐条移除指令，
    检查移除后违规是否仍被触发。如果仍触发则保留移除，否则恢复。
    """
    name = "Instruction Removal Pass"

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行指令移除pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 移除非必要指令后的测试用例
        """
        modifiable_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        instructions: List[str] = []
        with open(test_case.asm_path(), "r") as f:
            for i, line in enumerate(f):
                if i in modifiable_ids:
                    # 该指令可以被移除
                    # 同时清除前一行中的instrumentation标记
                    if "instrumentation" in instructions[-1].lower():
                        instructions[-1] = instructions[-1].replace("instrumentation", "")
                else:
                    # 该指令对违规至关重要；保留
                    instructions.append(line)

        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """ 移除指定位置的指令（删除该行） """
        return instructions[:cursor] + instructions[cursor + 1:]

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查移除指令后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)


class InstructionSimplificationPass(BaseInstructionMinimizationPass):
    """
    指令简化pass——将复杂指令逐步替换为更简单的指令。
    例如：cmov -> mov, xchg -> mov, add -> mov, sub -> add, mul -> inc 等。
    每次替换后检查违规是否仍被触发。
    """
    name = "Instruction Simplification Pass"

    # 指令替换映射表：键为原始指令助记符，值为替换函数
    _instruction_replacements: Dict[str, Callable[[str], str]] = {
        "cmova": lambda _: "mov",      # 条件移动 -> 无条件移动
        "cmovae": lambda _: "mov",
        "cmovb": lambda _: "mov",
        "cmovbe": lambda _: "mov",
        "cmovc": lambda _: "mov",
        "cmove": lambda _: "mov",
        "cmovg": lambda _: "mov",
        "cmovge": lambda _: "mov",
        "cmovl": lambda _: "mov",
        "cmovle": lambda _: "mov",
        "cmovna": lambda _: "mov",
        "cmovnae": lambda _: "mov",
        "cmovnb": lambda _: "mov",
        "cmovnbe": lambda _: "mov",
        "cmovnc": lambda _: "mov",
        "cmovne": lambda _: "mov",
        "cmovng": lambda _: "mov",
        "cmovnge": lambda _: "mov",
        "cmovnl": lambda _: "mov",
        "cmovnle": lambda _: "mov",
        "cmovno": lambda _: "mov",
        "cmovnp": lambda _: "mov",
        "cmovns": lambda _: "mov",
        "cmovnz": lambda _: "mov",
        "cmovo": lambda _: "mov",
        "cmovp": lambda _: "mov",
        "cmovs": lambda _: "mov",
        "cmovz": lambda _: "mov",
        "xchg": lambda _: "mov",       # 交换 -> 移动
        "cmpxchg": lambda _: "xchg",   # 比较交换 -> 交换
        "rep": lambda _: "",           # 重复前缀 -> 移除
        "lock": lambda _: "",          # 锁前缀 -> 移除
        "add": lambda _: "mov",        # 加法 -> 移动
        "sub": lambda _: "add",        # 减法 -> 加法
        "or": lambda _: "add",         # 或运算 -> 加法
        "xor": lambda _: "add",        # 异或 -> 加法
        "and": lambda _: "add",        # 与运算 -> 加法
        "cmp": lambda _: "add",        # 比较 -> 加法
        "bsr": lambda _: "add",        # 位扫描反向 -> 加法
        "bsf": lambda _: "add",        # 位扫描正向 -> 加法
        "bt": lambda _: "add",         # 位测试 -> 加法
        "bts": lambda _: "add",        # 位测试并设置 -> 加法
        "btr": lambda _: "add",        # 位测试并重置 -> 加法
        "btc": lambda _: "add",        # 位测试并取反 -> 加法
        "bzhi": lambda _: "add",       # 高位零提取 -> 加法
        "bextr": lambda _: "add",      # 位提取 -> 加法
        "blsi": lambda _: "add",       # 最低设置位隔离 -> 加法
        "blsmsk": lambda _: "add",     # 最低设置位掩码 -> 加法
        "xadd": lambda _: "add",       # 交换并加 -> 加法
        "test": lambda _: "add",       # 测试 -> 加法
        "adc": lambda _: "add",        # 带进位加 -> 加法
        "sbb": lambda _: "sub",        # 带借位减 -> 减法
        "mul": lambda _: "inc",        # 乘法 -> 自增
        "div": lambda _: "inc",        # 除法 -> 自增
        "setb": lambda _: "inc",       # 条件设置 -> 自增
        "not": lambda _: "inc",        # 取反 -> 自增
        "idiv": lambda _: "div",       # 有符号除 -> 无符号除
        "imul": lambda line: "add" if len(line.split(",")) == 2 else "imul",  # 有符号乘：双操作数->加法
    }

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行指令简化pass。ARM64架构不支持此pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 简化指令后的测试用例
        """
        if CONF.instruction_set == "arm64":
            warning("postprocessor", "--enable-simplification-pass has no effect on ARM64")
            return test_case

        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        将指定位置的指令替换为更简单的指令。
        根据指令助记符查找替换映射表，如果找到则替换。
        """
        tmp = list(instructions)  # 创建副本
        clean_line = tmp[cursor].strip().lower()
        words = clean_line.split(" ")
        key = words[0]  # 指令助记符
        replacement_func = self._instruction_replacements.get(key, None)
        if not replacement_func:
            return []  # 没有可用的替换
        tmp[cursor] = " ".join([replacement_func(clean_line)] + words[1:]) + "\n"

        return tmp

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查指令替换后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)


class ConstantSimplificationPass(BaseInstructionMinimizationPass):
    """
    常数简化pass——将测试用例中的常数逐步替换为零（x86）或1（arm64），
    检查替换后违规是否仍被触发。
    """
    name = "Constant Simplification Pass"

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet,
                 progress: ProgressPrinter):
        super().__init__(fuzzer, instruction_set_spec, progress)
        if CONF.instruction_set == "x86-64":
            self._match_dec = re.compile(r"^-?[0-9]+$")   # 十进制常数匹配
            self._match_hex = re.compile(r"^-?0x[0-9a-f]+$")  # 十六进制常数匹配
            self._match_bin = re.compile(r"^-?0b[01]+$")   # 二进制常数匹配
            self._replacement = "0"  # 替换值为0
        elif CONF.instruction_set == "arm64":
            self._match_dec = re.compile(r"^#-?[0-9]+$")   # ARM64十进制常数（带#前缀）
            self._match_hex = re.compile(r"^#-?0x[0-9a-f]+$")  # ARM64十六进制常数
            self._match_bin = re.compile(r"^#-?0b[01]+$")   # ARM64二进制常数
            self._replacement = "#1"  # ARM64替换值为#1（同时安全的立即数和位掩码值）
        else:
            assert_never(CONF.instruction_set)

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行常数简化pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 简化常数后的测试用例
        """
        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        将指定位置指令中的第一个常数替换为零/一。
        逐个检查指令中的操作数，找到第一个匹配十进制/十六进制/二进制格式的常数并替换。
        """
        tmp = list(instructions)  # 创建副本
        clean_line = tmp[cursor].strip().lower()
        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            if word == self._replacement:  # 已经是替换值，跳过
                break
            if self._match_dec.match(word) or self._match_hex.match(word) \
               or self._match_bin.match(word):
                # 找到常数，替换为零/一
                tmp[cursor] = ", ".join(words[:word_id] + [self._replacement]
                                        + words[word_id + 1:]) + "\n"
                return tmp
        return []  # 未找到可替换的常数

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查常数替换后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)


class MaskSimplificationPass(BaseInstructionMinimizationPass):
    """
    掩码简化pass——将instrumentation指令中的掩码逐步缩小，
    检查缩小后违规是否仍被触发。
    例如：and rax, 0b1111111111111 -> and rax, 0b1111111111110
    """
    name = "Mask Simplification Pass"

    # 掩码替换映射表：每个掩码映射到去掉最低有效位的更小掩码
    _mask_replacements = {
        "0b1111111111111": "0b1111111111110",
        "0b1111111111110": "0b1111111111100",
        "0b1111111111100": "0b1111111111000",
        "0b1111111111000": "0b1111111110000",
        "0b1111111110000": "0b1111111100000",
        "0b1111111100000": "0b1111111000000",
        "0b1111111000000": "0b1111110000000",
        "0b1111110000000": "0b1111100000000",
        "0b1111100000000": "0b1111000000000",
        "0b1111000000000": "0b1110000000000",
        "0b1110000000000": "0b1100000000000",
        "0b1100000000000": "0b1000000000000",
        "0b1000000000000": "0b0000000000000",
    }

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行掩码简化pass。不跳过instrumentation行。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 简化掩码后的测试用例
        """
        inst_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=False)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        将指定位置指令中的掩码替换为更小的掩码。
        分离注释部分，在操作数中查找掩码并替换。
        """
        tmp = list(instructions)  # 创建副本

        comment_split = tmp[cursor].split(self._comment_symbol)
        clean_line = comment_split[0].strip().lower()  # 指令部分
        comment = self._comment_symbol.join(comment_split[1:]) if len(comment_split) > 1 else ""  # 注释部分

        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            replacement = self._mask_replacements.get(word, None)
            if replacement:
                # 找到掩码，替换为更小的掩码
                tmp[cursor] = ", ".join(words[:word_id] + [replacement] + words[word_id + 1:]) \
                    + " " + self._comment_symbol + comment
                return tmp

        return []  # 未找到可替换的掩码

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查掩码缩小后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)


class NopReplacementPass(BaseInstructionMinimizationPass):
    """
    NOP替换pass——将指令替换为相同大小的NOP指令，
    检查替换后违规是否仍被触发。

    通过汇编器确定指令大小，然后选择对应大小的NOP指令进行替换。
    跳过跳转指令和循环指令（替换它们会破坏控制流）。
    """
    name = "NOP Replacement Pass"

    # x86-64不同大小的NOP指令映射表
    _replacements_x86 = {
        1: "nop  # 1 B",
        2: ".byte 0x66, 0x90  # 2 B",
        3: "nop dword ptr [rax]  # 3 B",
        4: "nop qword ptr [rax]  # 4 B",
        5: "nop qword ptr [rax + 1]  # 5 B",
        6: "nop qword ptr [rax + rax + 1]  # 6 B",
        7: "nop dword ptr [rax + 0xff]  # 7 B",
        8: "nop qword ptr [rax + 0xff]  # 8 B",
        9: "nop qword ptr [rax + rax + 0xff]  # 9 B",
    }
    # ARM64的NOP映射表（所有指令都是4字节）
    _replacements_arm64 = {
        4: "nop",  # all instructions are 4 bytes
    }

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet,
                 progress: ProgressPrinter):
        super().__init__(fuzzer, instruction_set_spec, progress)
        if CONF.instruction_set == "x86-64":
            self._replacements = self._replacements_x86
        elif CONF.instruction_set == "arm64":
            self._replacements = self._replacements_arm64
        else:
            assert_never(CONF.instruction_set)

        # 匹配跳转指令的正则表达式
        self._match_jump = re.compile(r"^j[a-z]* .*") if CONF.instruction_set == "x86-64" else \
            re.compile(r"^b\.[a-z]* .*|^bl[a-z]* .*")
        # 匹配循环指令的正则表达式
        self._match_loop = re.compile(r"^loop[a-z]* .*") if CONF.instruction_set == "x86-64" else \
            re.compile(r"^cbz .*|^cbnz .*|^tbnz .*|^tbz .*")

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行NOP替换pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 替换为NOP后的测试用例
        """
        modified_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=True)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            lines = f.readlines()

        instructions = []
        for i, line in enumerate(lines):
            # 不可修改的行直接保留
            if i not in modified_ids:
                instructions.append(line)
                continue

            # 获取NOP替换指令
            replacement = self.modify_instruction([line], 0)
            if not replacement:
                warning("postprocessor", f"Inconsistent NOP output: {line}")
                instructions.append(line)
                continue

            # 该指令可以被替换为NOP
            instructions.append(replacement[0])

            # 清除前一行中的instrumentation标记
            if "instrumentation" in instructions[-2].lower():
                instructions[-2] = instructions[-2].replace("instrumentation", "")

        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        将指定位置的指令替换为相同大小的NOP。
        通过临时汇编文件确定指令大小，然后查找对应的NOP指令。
        """
        tmp = list(instructions)  # 创建副本

        line = tmp[cursor].strip().lower()
        if "nop" in line:
            return []  # 已经是NOP，无需替换

        # 跳过跳转指令，替换它们会破坏汇编解析器的控制流分析
        if self._match_jump.match(line) or self._match_loop.match(line):
            return []

        # 确定指令大小：通过汇编器编译临时文件来测量
        with open("tmp.asm", "w") as f:
            if CONF.instruction_set == "x86-64":
                f.write(".intel_syntax noprefix\n")
            f.write(line)
            f.write("\n")
        run("as tmp.asm -o tmp.o", shell=True, check=True)
        run("objcopy -O binary --only-section=.text tmp.o tmp.o", shell=True, check=True)
        size = os.path.getsize("tmp.o")  # 获取指令的字节大小
        os.remove("tmp.asm")
        os.remove("tmp.o")

        if size not in self._replacements:
            return []  # 没有对应大小的NOP

        tmp[cursor] = self._replacements[size] + "\n"
        return tmp

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查NOP替换后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)


class LabelRemovalPass(BaseInstructionMinimizationPass):
    """
    标签移除pass——迭代移除测试用例中未使用的标签。
    注意：此pass不进行验证，因为标签不被执行。
    仅检查标签是否被其他指令引用，未被引用的标签将被移除。
    """
    name = "Label Removal Pass"
    _reserved = [
        ".intel_syntax noprefix", ".test_case_exit:", ".section", ".function", ".macro", "syntax"
    ]  # 保留标签列表（不可移除）

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行标签移除pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 移除未使用标签后的测试用例
        """
        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
            n_instructions = len(instructions)

        for i in range(n_instructions):
            line = instructions[i].strip().lower()

            # 跳过非标签行
            if not line.startswith("."):
                self._progress.next(False)
                continue

            # 跳过保留标签
            if any(reserved in line for reserved in self._reserved):
                continue

            # 检查标签是否被其他指令引用
            label = instructions[i].strip().replace(":", "")
            used = False
            for inst in instructions:
                if label in inst and inst != instructions[i]:
                    used = True
                    break

            # 移除未使用的标签
            if not used:
                self._progress.next(True)
                instructions[i] = ""
            else:
                self._progress.next(False)

        self._progress.pass_finish()
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        return []  # 未使用

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return True  # 未使用


class FenceInsertionPass(BaseInstructionMinimizationPass):
    """
    内存屏障插入pass——在每条指令前迭代插入LFENCE（x86）或DSB+ISB（arm64）指令，
    检查插入后违规是否仍被触发。如果仍触发，说明该指令前不需要推测执行屏障。
    
    此pass的目的：通过在关键位置插入内存屏障来精确定位需要推测执行的位置，
    从而帮助理解违规的推测执行机制。
    """
    name = "Fence Insertion Pass"

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet,
                 progress: ProgressPrinter):
        super().__init__(fuzzer, instruction_set_spec, progress)
        # 匹配跳转指令的正则表达式
        self._match_jump = re.compile(r"^j[a-z]* .*") if CONF.instruction_set == "x86-64" else \
            re.compile(r"^b\.[a-z]* .*|^bl[a-z]* .*")
        # 匹配循环指令的正则表达式
        self._match_loop = re.compile(r"^loop[a-z]* .*") if CONF.instruction_set == "x86-64" else \
            re.compile(r"^cbz .*|^cbnz .*|^tbnz .*|^tbz .*")
        # 内存屏障指令：x86用lfence，arm64用dsb sy + isb
        self._fence = "lfence" if CONF.instruction_set == "x86-64" else "dsb sy\n isb"

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """
        执行内存屏障插入pass。
        :param test_case: 测试用例对象
        :param inputs: 输入列表
        :return: 插入内存屏障后的测试用例
        """
        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = instructions[:i] + [self._fence + "\n"] + instructions[i:]
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        在指定位置前插入内存屏障指令。
        跳过控制流指令（跳转和循环），因为它们的目标已经有屏障保护。
        """
        curr_instr = instructions[cursor].lower()
        if self._match_jump.match(curr_instr) or self._match_loop.match(curr_instr):
            return []  # 跳过控制流指令——其目标已有屏障保护
        return instructions[:cursor] + [self._fence + "\n"] + instructions[cursor:]

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ 检查插入屏障后违规是否仍被触发 """
        return self._check_for_violation(test_case, inputs, self._ignore_list)
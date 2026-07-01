"""
File: Test Case Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT

文件用途：测试用例代码生成器。
负责随机生成侧信道模糊测试所需的测试用例程序代码，包括：
- 创建参与者（actor）及其对应的代码段（section）
- 生成随机函数和控制流图（基本块+边）
- 随机填充指令和操作数
- 从模板文件展开生成测试用例
- 将生成的汇编代码编译为目标文件并解析ELF数据

核心类层次：CodeGenerator(ABC) -> ISA-specific子类
内部辅助类：_FunctionGenerator, _InstructionGenerator, _OperandGenerator
"""
from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING, List, Tuple, Optional, Final, Callable, Dict, TextIO, Iterable
from subprocess import CalledProcessError, run
from copy import deepcopy
from abc import ABC, abstractmethod

from .tc_components.actor import Actor
from .tc_components.instruction import Instruction, RegisterOp, FlagsOp, MemoryOp, \
    ImmediateOp, AgenOp, LabelOp, CondOp, AnyOperand
from .tc_components.test_case_code import TestCaseProgram, Function, BasicBlock, CodeSection, \
    TC_EXIT_LABEL
from .instruction_spec import OT
from .logs import GeneratorLogger, error, inform
from .config import CONF, ActorsConf

if TYPE_CHECKING:
    from .tc_components.test_case_code import InstructionNode
    from .target_desc import TargetDesc
    from .asm_parser import AsmParser
    from .instruction_spec import InstructionSpec, OperandSpec
    from .isa_spec import InstructionSet
    from .elf_parser import ELFParser


# ==================================================================================================
# Interfaces and common functionality of ISA-specific service classes
# ISA特定服务类的接口和通用功能
# ==================================================================================================
class Pass(ABC):
    """
    Interface to an instrumentation pass that modifies a generated test case

    测试用例插桩 Pass 的抽象接口。
    每个 Pass 对生成后的测试用例进行修改（如添加测量代码、替换指令等），
    子类需实现 run_on_test_case 方法。
    """

    @abstractmethod
    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Run the pass on all instructions in a given test case

        在给定测试用例的所有指令上运行此 Pass。

        :param test_case: 待处理的测试用例
        """


class Printer(ABC):
    """
    Interface to an ISA-specific assembly printer; that is, a class that prints
    a valid assembly representation of a test case

    ISA特定汇编打印器的抽象接口。
    将测试用例对象输出为合法的汇编代码文件。
    子类需实现指令、操作数和宏的字符串转换方法。
    """

    prologue_template: List[str]
    """ List of lines that must be printed at the beginning of the assembly file — 汇编文件头部行列表 """

    epilogue_template: List[str]
    """ List of lines that must be printed at the end of the assembly file — 汇编文件尾部行列表 """

    def __init__(self, target_desc: TargetDesc) -> None:
        self.target_desc = target_desc

    def print(self, test_case: TestCaseProgram) -> None:
        """
        Print the assembly representation of a test case to a file associated with the test case
        (i.e., test_case.asm_file)

        将测试用例的汇编表示写入关联的.asm文件。

        :param test_case: The test case to print — 待打印的测试用例
        """
        with open(test_case.asm_path(), "w") as f:
            for line in self.prologue_template:
                f.write(line)

            for section in test_case:
                self._print_section(section, f)

            for line in self.epilogue_template:
                f.write(line)

    def _print_section(self, sec: CodeSection, file_: TextIO) -> None:
        """ 打印一个代码段（包含段声明和所有函数） """
        file_.write(f".section .data.{sec.name}\n")
        for func in sec:
            self._print_function(func, file_)

    def _print_function(self, func: Function, file_: TextIO) -> None:
        """ 打印一个函数（包含函数标签、所有基本块和退出基本块） """
        file_.write(f"{func.name}:\n")
        for bb in func:
            self._print_basic_block(bb, file_)

        self._print_basic_block(func.get_exit_bb(), file_)

    def _print_basic_block(self, bb: BasicBlock, file_: TextIO) -> None:
        """ 打印一个基本块（包含基本块标签、所有指令和终止指令） """
        file_.write(f"{bb.name.lower()}:\n")
        for inst in bb:
            file_.write(self._instruction_to_str(inst) + "\n")
        for inst in bb.terminators:
            file_.write(self._instruction_to_str(inst) + "\n")

    @abstractmethod
    def _instruction_to_str(self, inst: Instruction) -> str:
        """ Convert an instruction object to its assembly representation — 将指令对象转换为汇编字符串 """

    @abstractmethod
    def _operand_to_str(self, op: AnyOperand) -> str:
        """ Convert an operand object to its assembly representation — 将操作数对象转换为汇编字符串 """

    @abstractmethod
    def _macro_to_str(self, inst: Instruction) -> str:
        """ Convert a macro instruction object to its assembly representation — 将宏指令对象转换为汇编字符串 """


# ==================================================================================================
# ISA-independent Code Generator
# ISA无关的代码生成器
# ==================================================================================================
class CodeGenerator(ABC):
    """
    ISA-independent implementation of the class responsible for generating test case code.

    Some of the methods are abstract and must be implemented by the ISA-specific subclasses.

    ISA无关的测试用例代码生成器基类。
    负责随机生成测试用例程序，包括创建参与者、生成函数和控制流、
    填充随机指令、处理模板、编译和ELF解析。
    ISA特定的功能由子类实现（如Pass、Printer、特定指令生成等）。
    """

    _instruction_set: InstructionSet  # Specification of the tested instruction set — 测试指令集规范
    _target_desc: TargetDesc  # Description of the tested architecture — 目标架构描述
    _asm_parser: AsmParser  # Parser for assembly files — 汇编文件解析器
    _elf_parser: ELFParser  # Parser for ELF files — ELF文件解析器
    _passes: List[Pass]  # List of passes to run on the generated test case; set by subclasses — 插桩Pass列表
    _printer: Printer  # Printer for the generated test case; set by subclasses — 汇编打印器

    _state: int = 0  # Current seed value — 当前种子值
    _cached_template: Optional[TestCaseProgram] = None  # Parsed template assembly file — 缓存的模板测试用例

    _function_generator: Final[_FunctionGenerator]
    _instruction_generator: Final[_InstructionGenerator]

    __log: Final[GeneratorLogger]

    def __init__(self, seed: int, instruction_set: InstructionSet, target_desc: TargetDesc,
                 asm_parser: AsmParser, elf_parser: ELFParser) -> None:
        """
        初始化代码生成器。

        :param seed: 随机种子值，0表示使用随机种子
        :param instruction_set: 指令集规范
        :param target_desc: 目标架构描述
        :param asm_parser: 汇编解析器实例
        :param elf_parser: ELF解析器实例
        """
        self._instruction_set = instruction_set
        self._target_desc = target_desc
        self._asm_parser = asm_parser
        self._elf_parser = elf_parser
        self._set_seed(seed)

        self.__log = GeneratorLogger()
        self.__log.dbg_dump_instruction_pool(instruction_set.instructions)
        self._passes = []

        self._function_generator = _FunctionGenerator(self._target_desc, instruction_set)
        self._instruction_generator = _InstructionGenerator(self._target_desc)

    # ----------------------------------------------------------------------------------------------
    # Public Interface
    # 公共接口
    def create_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCaseProgram:
        """
        Generate a random test case, write its assembly code to a file,
        and assemble it into an object (unless disabled).
        :param asm_file: the path to the output file
        :param disable_assembler: if True, the function will not assemble the test case
        :return: the generated test case object

        生成随机测试用例，写入汇编文件，并编译为目标文件。

        流程：
        1. 创建参与者及其代码段
        2. 生成空函数并填充随机指令
        3. 运行插桩Pass
        4. 添加测量符号
        5. 打印汇编文件
        6. 编译并解析ELF数据

        :param asm_file: 输出汇编文件路径
        :param disable_assembler: 是否禁用编译步骤
        :return: 生成的测试用例对象
        """
        if not asm_file:
            asm_file = 'generated.asm'
        test_case = TestCaseProgram(asm_file, seed=self._state)

        # create actors and their corresponding sections
        # 创建参与者及其对应的代码段
        actors_config: ActorsConf = CONF.get_actors_conf()
        if len(actors_config) != 1:
            error("Generation of test cases with multiple actors is not yet supported")
        self.generate_actors_with_sections(test_case, actors_config)

        # create empty main function and fill it with random instructions
        # 创建空的主函数并用随机指令填充
        main_section = test_case[0]
        default_actor = main_section.owner
        assert default_actor.is_main
        main_func = self._function_generator.generate_empty(".function_0", main_section)
        self._function_generator.fill_function(main_func)

        # add it to the test case, in the first section
        # 将主函数添加到第一个段中
        test_case[0].append(main_func)

        # process the test case
        # 运行所有插桩Pass
        for p in self._passes:
            p.run_on_test_case(test_case)

        # add symbols to test case
        # 添加测量开始/结束符号
        self._add_required_symbols(test_case)

        self._printer.print(test_case)

        if disable_assembler:
            return test_case

        # 编译汇编文件为目标文件
        test_case.assign_obj(asm_file[:-4] + ".o")
        assemble(test_case)
        # 解析ELF数据填充到测试用例
        self._elf_parser.populate_elf_data(test_case.get_obj(), test_case)

        self._update_state()
        return test_case

    def create_test_case_from_template(self, template_file: str) -> TestCaseProgram:
        """
        Generate a test case based on a template by expanding RANDOM_* macros.
        Run instrumentation _passes and print the result into a file

        :param template_file: The path to the template file
        :return: The generated test case object
        :raises FileNotFoundError: if the template file does not exist
        :raises CalledProcessError: if the assembler fails to assemble the test case

        从模板文件生成测试用例，通过展开RANDOM_*宏指令填充随机指令。

        流程：
        1. 解析模板文件（支持缓存以避免重复解析）
        2. 标记模板中的指令
        3. 展开随机指令宏
        4. 运行插桩Pass
        5. 编译并解析ELF数据

        :param template_file: 模板文件路径
        :return: 生成的测试用例对象
        """
        # create a TestCaseProgram object from the template file
        # 从模板文件创建TestCaseProgram对象（使用缓存避免重复解析）
        if self._cached_template:
            test_case = deepcopy(self._cached_template)
            test_case.generator_seed = self._state
        else:
            test_case = self._asm_parser.parse_file(
                template_file, self, self._elf_parser, is_template=True)
            test_case.generator_seed = self._state
            self._cached_template = deepcopy(test_case)

        # Label all instructions from the template as such
        # 标记所有模板中的指令
        for func in test_case.iter_functions():
            for bb in func:
                for instr in bb:
                    instr.is_from_template = True

        # Expand the template
        # 展开模板中的随机指令宏
        self._set_seed(self._state)  # reset the seed in case it was updated by other modules
        self._expand_template(test_case, CONF.get_actors_conf())
        for p in self._passes:
            p.run_on_test_case(test_case)

        # Print into assembly and assemble into an object file
        # 打印汇编文件并编译为目标文件
        asm_file = 'generated.asm'
        test_case.reassign_asm_file(asm_file)
        self._printer.print(test_case)

        test_case.assign_obj(asm_file[:-4] + ".o")
        assemble(test_case)
        self._elf_parser.populate_elf_data(test_case.get_obj(), test_case)

        self._update_state()
        return test_case

    def generate_actors_with_sections(self, test_case: TestCaseProgram,
                                      actors_dict: ActorsConf) -> None:
        """
        Stand-alone interface to create actors for the given test case and
        populate them with the corresponding sections.

        NOTE: This method leaves the sections *empty*; i.e., it does not populate the test case
        with functions, basic blocks, and instructions.

        :param test_case: The test case to which the actors will be added
        :param actors_dict: The configuration of the actors
        :return: None

        为测试用例创建参与者及其代码段。段初始为空（不含函数和指令）。

        :param test_case: 待添加参与者的测试用例
        :param actors_dict: 参与者配置字典
        """
        for name, actor_dict in actors_dict.items():
            actor = Actor.from_dict(actor_dict, self._target_desc)

            # add the actor to the test case
            # 将参与者添加到测试用例中
            if name == "main":  # the main actor is created by default; overwrite it — 主参与者默认已创建，覆盖它
                test_case.add_actor_with_section(actor, allow_overwrite=True)
            else:  # all other actors should not exist yet — 其他参与者不应已存在
                test_case.add_actor_with_section(actor)

    def generate_instruction(self,
                             spec: InstructionSpec,
                             is_instrumentation: Optional[bool] = None) -> Instruction:
        """
        Stand-alone interface to generate a random instruction based on the specification.

        :param spec: The specification of the instruction
        :return: The generated instruction

        根据指令规范生成随机指令的独立接口。

        :param spec: 指令规范
        :param is_instrumentation: 是否标记为插桩指令（None时使用默认值）
        :return: 生成的指令对象
        """
        # To correctly inherit the default value of is_instrumentation from the instruction
        # generator, we have two separate calls
        # 为正确继承指令生成器的默认is_instrumentation值，分两种调用方式
        if is_instrumentation is None:
            return self._instruction_generator.generate(spec)
        return self._instruction_generator.generate(spec, is_instrumentation)

    # ----------------------------------------------------------------------------------------------
    # Private: Seed Management
    # 私有：种子管理
    def _set_seed(self, seed: int) -> None:
        """
        Set the seed value used to generate test programs
        :param seed: The seed value

        设置生成器种子值。seed=0时自动使用随机种子。

        :param seed: 种子值
        """
        if seed == 0:
            seed = random.randint(1, 1000000)
            inform("prog_gen", f"Setting program_generator_seed to random value: {seed}")
        self._state = seed
        random.seed(self._state)

    def _update_state(self) -> None:
        """
        更新生成器状态：递增种子并重新设置随机数生成器。
        每次生成一个测试用例后调用，确保下一个测试用例使用不同种子。
        """
        self._state += 1
        random.seed(self._state)

    # ----------------------------------------------------------------------------------------------
    # Private: Misc.
    # 私有：其他辅助方法
    def _add_required_symbols(self, test_case: TestCaseProgram) -> None:
        """
        在测试用例中添加测量开始和结束符号标记。
        measurement_start放在第一个基本块开头，
        measurement_end放在退出基本块末尾。
        """
        # add measurement_start and measurement_end symbols
        sec_main = test_case[0]
        assert sec_main.owner.is_main
        func_main = sec_main[0]

        # 在第一个基本块开头插入measurement_start宏
        bb_first = func_main[0]
        instr = Instruction("macro", category="MACRO") \
            .add_op(LabelOp(".measurement_start")) \
            .add_op(LabelOp(".noarg"))
        bb_first.insert_before(bb_first.get_first(), instr)

        # 在退出基本块末尾插入measurement_end宏
        bb_last = func_main.get_exit_bb()
        instr = Instruction("macro", category="MACRO") \
            .add_op(LabelOp(".measurement_end")) \
            .add_op(LabelOp(".noarg"))
        bb_last.insert_after(bb_last.get_last(), instr)

    def _expand_template(self, test_case: TestCaseProgram, actors_config: ActorsConf) -> None:
        """
        展开模板中的.random_instructions宏指令。
        查找所有宏实例，根据宏参数（指令数、内存访问比例）
        替换为随机生成的指令序列。
        """
        nodes_to_expand: List[Tuple[InstructionNode, str]] = []

        # find all instances of .macro.random_instructions
        # 查找所有.random_instructions宏实例
        for bb in test_case.iter_basic_blocks():
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.name == "macro" and inst.operands[0].value == ".random_instructions":
                    nodes_to_expand.append((node, bb.get_owner().name))

        # replace all instances of .macro.random_instructions with random instructions
        # 将所有宏实例替换为随机指令序列
        for node, actor_name in nodes_to_expand:
            inst = node.instruction
            bb = node.parent
            # 解析宏参数：.random_instructions.<指令数>.<内存访问数>[.<其他参数>]
            operands = inst.operands[1].value.split(".")
            assert len(operands) >= 3 and len(operands) <= 5
            n_instr = int(operands[1])  # 要生成的指令数量
            n_mem = int(operands[2])  # 内存访问指令数量

            # determine the instruction set for this actor
            # 确定此参与者可用的指令集（排除黑名单中的指令）
            block = actors_config[actor_name]["instruction_blocklist"]
            non_memory_access_instructions = \
                [i for i in self._instruction_set.non_memory_access_specs if i.name not in block]
            store_instructions = \
                [i for i in self._instruction_set.store_instructions if i.name not in block]
            load_instruction = \
                [i for i in self._instruction_set.load_instruction if i.name not in block]

            # replace the macro with random instructions
            # 删除宏节点，逐条插入随机指令
            bb.delete(node)
            for _ in range(n_instr):
                inst = self._instruction_generator.generate_from_random_spec(
                    non_memory_access_instructions=non_memory_access_instructions,
                    store_instructions=store_instructions,
                    load_instructions=load_instruction,
                    memory_access_probability=n_mem / n_instr)  # 内存访问概率 = 内存访问数/总指令数
                if node.previous:
                    bb.insert_after(node.previous, inst)
                else:
                    bb.insert_before(bb.get_first(), inst)


def assemble(test_case: TestCaseProgram) -> None:
    """
    Assemble an assembly file into an object file and creates a stripped binary
    :param test_case: The test case to be assembled

    将汇编文件编译为目标文件。使用系统汇编器（as命令），
    编译失败时提供格式化的错误信息。

    :param test_case: 待编译的测试用例
    """

    def pretty_error_msg(error_msg: str) -> None:
        """ 将汇编器错误信息格式化为人类可读的形式，包含源代码行内容 """
        with open(asm_file, "r") as f:
            lines = f.read().split("\n")

        msg = "Error appeared while assembling the test case:\n"
        for line in error_msg.split("\n"):
            line = line.removeprefix(asm_file + ":")
            line_num_str = re.search(r"(\d+):", line)
            if not line_num_str:
                msg += line
            else:
                # 显示错误行号及对应源代码内容
                parsed = lines[int(line_num_str.group(1)) - 1]
                msg += f"\n  Line {line}\n    (the line was parsed as {parsed})"
        return msg

    asm_file = test_case.asm_path()
    obj_container = test_case.get_obj()
    obj_file = obj_container.obj_path

    try:
        # 使用系统汇编器编译汇编文件
        out = run(f"as {asm_file} -o {obj_file}", shell=True, check=True, capture_output=True)
    except CalledProcessError as e:
        error_msg = e.stderr.decode()
        if "Assembler messages:" in error_msg:
            print(pretty_error_msg(error_msg))
        else:
            print(error_msg)
        exit(1)
    finally:
        pass
        # run(f"rm {patched_asm_file}", shell=True, check=True)

    output = out.stderr.decode()
    if "Assembler messages:" in output:
        print("WARNING: [generator]" + pretty_error_msg(output))

    obj_container.mark_as_assembled()


# ==================================================================================================
# Private Service Classes
# 私有辅助类
# ==================================================================================================
class _FunctionGenerator:
    """
    Class responsible for generating random functions

    随机函数生成器。
    负责生成函数的控制流图（DAG结构的基本块+边），
    并在基本块中填充随机指令。
    """

    _instruction_generator: _InstructionGenerator
    _isa_spec: InstructionSet

    def __init__(self, target_desc: TargetDesc, isa_spec: InstructionSet) -> None:
        """
        初始化函数生成器。

        :param target_desc: 目标架构描述
        :param isa_spec: 指令集规范
        """
        self._instruction_generator = _InstructionGenerator(target_desc)
        self._isa_spec = isa_spec

    def generate_empty(self, label: str, parent: CodeSection) -> Function:
        """
        Generates an empty function with a random DAG of basic blocks

        生成一个空函数，包含随机DAG结构的基本块控制流图。

        控制流图构建规则：
        - 每个基本块有1-2个后继（取决于是否有条件分支指令）
        - 第一个后继总是下一个基本块（避免死代码）
        - 最后一个基本块直接连接到退出节点
        - 支持条件分支时最多2个后继

        :param label: 函数标签名
        :param parent: 所属代码段
        :return: 生成的空函数对象
        """
        func = Function(label, parent)

        # Define the maximum allowed number of successors for any BB
        # 确定基本块的最大后继数（有条件分支时为2，否则为1）
        if self._isa_spec.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb if CONF.min_successors_per_bb < 2 else 2
            assert min_successors <= max_successors, "min_successors_per_bb > max_successors_per_bb"
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        # 创建指定数量的基本块
        if CONF.min_bb_per_function == CONF.max_bb_per_function:
            node_count = CONF.min_bb_per_function
        else:
            node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}", func) for i in range(node_count)]

        # Connect BBs into a graph
        # 将基本块连接成DAG图
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            # 最后一个基本块只有一个后继——退出节点
            if i == node_count - 1:
                current_bb.successors = [func.get_exit_bb()]
                break

            # the rest of the node have a random number of successors
            # 其他基本块有随机数量的后继
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i > node_count:
                # the number is adjusted to the position when close to the end
                # 接近末尾时调整后继数量，避免超出范围
                successor_count = node_count - i

            # one of the targets (the first successor) is always the next node - to avoid dead code
            # 第一个后继总是下一个基本块，确保无死代码
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            # 其他后继从后续基本块中随机选择
            options = nodes[i + 2:]
            options.append(func.get_exit_bb())
            for _ in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        # Function returns are not yet supported
        # hence all functions end with an unconditional jump to the exit
        # 函数返回暂不支持，所有函数以无条件跳转到退出节点结束
        inst = self._instruction_generator.generate(self._isa_spec.get_unconditional_jump_spec())
        assert isinstance(inst.operands[0], LabelOp)
        inst.operands[0].value = TC_EXIT_LABEL
        func.get_exit_bb().terminators = [inst]

        # Finalize the function
        # 完成函数构建
        func.extend(nodes)
        return func

    def fill_function(self, func: Function) -> None:
        """
        Fill an (assumed empty) function with random instructions
        :param func: the function to fill
        :return: None
        :raises AssertionError: if the function is not empty
        :raises NotImplementedError: if one of the basic blocks has more than two successors

        用随机指令填充空函数。先添加终止指令（分支/跳转），再填充普通指令。

        :param func: 待填充的函数
        """
        self._add_terminators_in_function(func)
        self._add_instructions_in_function(func)

    def _add_terminators_in_function(self, func: Function) -> None:
        """
        为函数中的每个基本块添加终止指令（跳转/分支）。

        - 0个后继：函数返回（暂不支持，跳过）
        - 1个后继：无条件跳转（退出基本块除外，它隐式落下去）
        - 2个后继：条件分支 + 无条件落下去
        """

        def add_fallthrough(bb: BasicBlock, destination: BasicBlock) -> None:
            # create an unconditional branch and add it
            # 创建无条件跳转指令并添加为终止指令
            terminator_spec = self._isa_spec.get_unconditional_jump_spec()
            terminator = self._instruction_generator.generate(terminator_spec)
            label = terminator.get_label_operand()
            assert label is not None
            label.value = destination.name
            bb.terminators.append(terminator)

        for bb in func:
            assert not bb.terminators, "Basic block already has terminators"
            if len(bb.successors) == 0:
                # Return instruction — 返回指令（暂不处理）
                continue

            if len(bb.successors) == 1:
                # Unconditional branch — 无条件分支
                dest = bb.successors[0]
                if dest.is_exit:
                    # DON'T insert a branch to the exit
                    # the last basic block always falls through implicitly
                    # 退出基本块不插入跳转，隐式落下去
                    continue
                add_fallthrough(bb, dest)
                continue

            if len(bb.successors) == 2:
                # Conditional branch — 条件分支
                # 随机选择条件分支类型
                spec = random.choice(self._isa_spec.cond_branches)
                terminator = self._instruction_generator.generate(spec)
                label = terminator.get_label_operand()
                assert label
                label.value = bb.successors[0].name  # 条件成立时跳转到第一个后继
                bb.terminators.append(terminator)

                # 条件不成立时落下去到第二个后继
                add_fallthrough(bb, bb.successors[1])
                continue

            # > 2 successors — 超过2个后继（间接跳转，暂不支持）
            raise NotImplementedError("Indirect jumps/calls are not yet supported")

    def _add_instructions_in_function(self, func: Function) -> None:
        """
        Fill the function with random instructions.
        Ensures that all basic blocks are filled with roughly the same number of instructions
        :param func: the function to fill
        :return: None

        用随机指令填充函数。指令均匀分布在各基本块中。
        每次随机选择一个基本块，向其中插入一条随机指令，
        直到达到配置的程序大小。

        :param func: 待填充的函数
        """
        bb_list: List[BasicBlock] = list(func)
        assert all(len(bb) == 0 for bb in bb_list), "Basic blocks are not empty"
        for _ in range(0, CONF.program_size):
            bb = random.choice(bb_list)  # 随机选择一个基本块
            inst = self._instruction_generator.generate_from_random_spec(
                self._isa_spec.non_memory_access_specs, self._isa_spec.store_instructions,
                self._isa_spec.load_instruction, CONF.avg_mem_accesses / CONF.program_size)
            bb.insert_after(bb.get_last(), inst)


class _InstructionGenerator:
    """
    Class responsible for generating random instructions

    随机指令生成器。
    根据指令规范生成随机指令对象，包括显式操作数和隐式操作数。
    支持从随机选择的规范生成指令（带内存访问概率控制）。
    """

    _operand_generator: _OperandGenerator

    def __init__(self, target_desc: TargetDesc) -> None:
        """
        初始化指令生成器。

        :param target_desc: 目标架构描述
        """
        self._operand_generator = _OperandGenerator(target_desc)

    def generate(self, spec: InstructionSpec, is_instrumentation: bool = False) -> Instruction:
        """
        Generate a random instruction object based on the specification
        :param spec: The specification of the instruction
        :param is_instrumentation: Whether to label the instruction as instrumentation
        :return: The generated instruction

        根据规范生成随机指令对象。
        为指令的每个显式和隐式操作数规范生成对应的操作数。

        :param spec: 指令规范
        :param is_instrumentation: 是否标记为插桩指令
        :return: 生成的指令对象
        """

        # fill up with random operands, following the spec
        # 按规范创建指令骨架
        inst = Instruction.from_spec(spec, is_instrumentation=is_instrumentation)

        # generate explicit operands
        # 生成显式操作数
        for operand_spec in spec.operands:
            operand = self._operand_generator.generate(operand_spec, inst)
            inst.operands.append(operand)

        # generate implicit operands
        # 生成隐式操作数（如标志寄存器等）
        for operand_spec in spec.implicit_operands:
            operand = self._operand_generator.generate(operand_spec, inst)
            inst.implicit_operands.append(operand)

        return inst

    def generate_from_random_spec(self,
                                  non_memory_access_instructions: List[InstructionSpec],
                                  store_instructions: List[InstructionSpec],
                                  load_instructions: List[InstructionSpec],
                                  memory_access_probability: float = 0.0) -> Instruction:
        """
        Generate an instruction from a randomly-selected specification
        :param non_memory_access_instructions: The list of available non-memory access instructions
        :param store_instructions: The list of available store instructions
        :param load_instructions: The list of available load instructions
        :return: The generated instruction

        从随机选择的规范生成指令。
        根据内存访问概率决定生成内存访问指令还是非内存访问指令。
        内存访问指令中，store和load各占50%概率。

        :param non_memory_access_instructions: 可用的非内存访问指令列表
        :param store_instructions: 可用的store指令列表
        :param load_instructions: 可用的load指令列表
        :param memory_access_probability: 内存访问指令的概率
        :return: 生成的指令对象
        """

        def pick_spec() -> InstructionSpec:
            # ensure the requested avg. number of mem. accesses
            # 根据概率决定是否选择内存访问指令
            search_for_memory_access = random.random() < memory_access_probability
            if not search_for_memory_access:
                return random.choice(non_memory_access_instructions)

            # 内存访问指令中，store和load各50%概率
            if store_instructions:
                search_for_store = random.random() < 0.5  # 50% probability of stores
            else:
                search_for_store = False

            if search_for_store:
                return random.choice(store_instructions)

            return random.choice(load_instructions)

        spec = pick_spec()
        return self.generate(spec)


class _OperandGenerator:
    """
    Class responsible for generating random operands for instructions

    随机操作数生成器。
    根据操作数规范生成不同类型的操作数：
    - REG：寄存器操作数
    - MEM：内存操作数
    - IMM：立即数操作数（支持位掩码、范围、预定义列表）
    - LABEL：标签操作数
    - AGEN：地址生成操作数
    - FLAGS：标志操作数
    - COND：条件操作数
    """

    def __init__(self, target_desc: TargetDesc) -> None:
        """
        初始化操作数生成器。

        :param target_desc: 目标架构描述，提供寄存器列表等信息
        """
        self.target_desc = target_desc

    def generate(self, spec: OperandSpec, parent: Instruction) -> AnyOperand:
        """
        Generate a random operand object based on the specification

        根据操作数类型规范生成对应的操作数对象。
        通过操作数类型到生成函数的映射表分发到具体生成方法。

        :param spec: 操作数规范
        :param parent: 所属指令
        :return: 生成的操作数对象
        """
        generators: Dict[OT, Callable[[OperandSpec, Instruction], AnyOperand]] = {
            OT.REG: self._generate_reg_operand,
            OT.MEM: self._generate_mem_operand,
            OT.IMM: self._generate_imm_operand,
            OT.LABEL: self._generate_label_operand,
            OT.AGEN: self._generate_agen_operand,
            OT.FLAGS: self._generate_flags_operand,
            OT.COND: self._generate_cond_operand,
        }
        return generators[spec.type](spec, parent)

    def _generate_reg_operand(self, spec: OperandSpec, _: Instruction) -> RegisterOp:
        """
        生成随机寄存器操作数。从规范允许的寄存器列表中随机选择。

        :param spec: 操作数规范（包含允许的寄存器列表、位宽、源/目标属性）
        :return: 寄存器操作数对象
        """
        choices = spec.values
        reg = random.choice(choices)
        return RegisterOp(reg, spec.width, spec.src, spec.dest)

    def _generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> MemoryOp:
        """
        生成随机内存操作数。地址寄存器从规范允许值或目标架构的内存索引寄存器中选择。

        :param spec: 操作数规范
        :return: 内存操作数对象
        """
        if spec.values:
            address_reg = random.choice(spec.values)
        else:
            # 无预定义地址寄存器时，从架构默认内存索引寄存器中选择
            address_reg = random.choice(self.target_desc.mem_index_registers)
        return MemoryOp(address_reg, spec.width, spec.src, spec.dest)

    def _generate_imm_operand(self, spec: OperandSpec, inst: Instruction) -> ImmediateOp:
        """
        生成随机立即数操作数。支持多种生成方式：
        1. 位掩码（ARM64特有）
        2. 预定义值列表
        3. 预定义范围 [min-max]
        4. 根据位宽随机生成

        :param spec: 操作数规范
        :param inst: 所属指令（用于错误提示）
        :return: 立即数操作数对象
        """
        # generate bitmask
        # ARM64位掩码立即数生成
        if spec.values and spec.values[0] == "bitmask":
            return self._generate_bitmask_operand(spec, inst)

        # generate from a predefined list
        # 从预定义值列表中选择
        if spec.values and "[" not in spec.values[0]:
            options: Iterable[str] | Iterable[int]
            try:
                options = [int(v) for v in spec.values]  # 尝试解析为整数列表
            except ValueError:
                # handle non-digit immediates (e.g., dsb SY in ARM64)
                # 处理非数字立即数（如ARM64的dsb SY）
                options = list(spec.values)
            value = str(random.choice(options))
            return ImmediateOp(value, spec.width)

        # generate from a predefined range
        # 从预定义范围 [min-max] 中随机选择
        if spec.values:
            assert "[" in spec.values[0], f"Invalid IMM spec for instruction: {inst}"
            range_ = spec.values[0][1:-1].split("-")
            if range_[0] == "":
                # 处理负数范围，如 [-10-100]
                range_ = range_[1:]
                range_[0] = "-" + range_[0]
            assert len(range_) == 2
            value = str(random.randint(int(range_[0]), int(range_[1])))
            return ImmediateOp(value, spec.width)

        # generate from width
        # 根据位宽随机生成（有符号或无符号）
        if spec.is_signed:
            range_min = pow(2, spec.width - 1) * -1  # 有符号最小值
            range_max = pow(2, spec.width - 1) - 1  # 有符号最大值
        else:
            range_min = 0  # 无符号最小值
            range_max = pow(2, spec.width) - 1  # 无符号最大值
        value = str(random.randint(range_min, range_max))
        return ImmediateOp(value, spec.width)

    def _generate_bitmask_operand(self, spec: OperandSpec, _: Instruction) -> ImmediateOp:
        """
        生成ARM64位掩码立即数。
        ARM64的位掩码立即数有特殊编码规则：由旋转和模式参数定义。
        算法：随机选择模式大小和ones位数，生成重复二进制模式，然后旋转。

        :param spec: 操作数规范
        :return: 立即数操作数对象
        """
        assert CONF.instruction_set == "arm64"

        # 随机选择模式参数
        if spec.width == 64:
            imms_zero_pos = random.randint(1, 6)
        else:
            imms_zero_pos = random.randint(1, 5)
        imms_ones = random.randint(1, 2**imms_zero_pos - 1)

        # 随机旋转值
        immr = random.randint(0, spec.width - 1)

        # 构建二进制模式：zeros + ones，然后重复以填满位宽
        pattern = "0" * (2**imms_zero_pos - imms_ones) + "1" * imms_ones
        multiplier = spec.width // (2**imms_zero_pos)
        value_str = pattern * multiplier
        value = int(value_str, 2)
        # 右旋转：将值右移immr位，被移出的位补到高位
        value = (value >> immr) | (value << (spec.width - immr)) & (2**spec.width - 1)

        if spec.width == 64:
            value_str = f"0x{value:016x}"
        else:
            value_str = f"0x{value:08x}"
        return ImmediateOp(value_str, spec.width)

    def _generate_label_operand(self, _: OperandSpec, __: Instruction) -> LabelOp:
        """
        生成标签操作数。实际标签值在终止指令添加时设置。

        :return: 空标签操作数
        """
        return LabelOp("")  # the actual label will be set in add_terminators_in_function

    def _generate_agen_operand(self, spec: OperandSpec, __: Instruction) -> AgenOp:
        """
        生成地址生成（AGEN）操作数。
        随机生成1-3个元素的地址表达式：[reg1], [reg1+reg2], [reg1+reg2+imm]

        :param spec: 操作数规范
        :return: 地址生成操作数对象
        """
        n_operands = random.randint(1, 3)
        reg1 = random.choice(self.target_desc.mem_index_registers)
        if n_operands == 1:
            return AgenOp(reg1, spec.width)

        reg2 = random.choice(self.target_desc.mem_index_registers)
        if n_operands == 2:
            return AgenOp(reg1 + " + " + reg2, spec.width)

        # 三个元素：两个寄存器 + 一个16位随机立即数偏移
        imm = str(random.randint(0, pow(2, 16) - 1))
        return AgenOp(reg1 + " + " + reg2 + " + " + imm, spec.width)

    def _generate_flags_operand(self, spec: OperandSpec, parent: Instruction) -> FlagsOp:
        """
        生成标志操作数。
        如果指令有条件操作数，需合并条件标志和规范标志；
        目前条件操作数支持尚未完全实现。

        :param spec: 操作数规范
        :param parent: 所属指令
        :return: 标志操作数对象
        """
        # pylint: disable=too-many-branches
        # NOTE: there are many options for COND flags, so many branches are needed

        cond_op = parent.get_cond_operand()
        if not cond_op:
            # 无条件操作数时，直接使用规范中的标志值
            return FlagsOp(spec.values)
        raise NotImplementedError("COND operand is not yet supported")
        # pylint: disable=unreachable
        # NOTE: the code below is temporary disabled

        # 条件标志合并逻辑（暂未启用）
        flag_values = self.target_desc.branch_conditions[cond_op.value]
        if not spec.values:
            return FlagsOp(flag_values)

        # combine implicit flags with the condition
        # 合并隐式标志与条件标志
        merged_flags = []
        for flag_pair in zip(flag_values, spec.values):
            if "undef" in flag_pair:
                merged_flags.append("undef")
            elif "r/w" in flag_pair:
                merged_flags.append("r/w")
            elif "w" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/w")
                else:
                    merged_flags.append("w")
            elif "cw" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/cw")
                else:
                    merged_flags.append("cw")
            elif "r" in flag_pair:
                merged_flags.append("r")
            else:
                merged_flags.append("")
        return FlagsOp(merged_flags)

    def _generate_cond_operand(self, _: OperandSpec, __: Instruction) -> CondOp:
        """
        生成随机条件操作数。从目标架构的条件分支列表中随机选择。

        :return: 条件操作数对象
        """
        cond = random.choice(list(self.target_desc.branch_conditions))
        return CondOp(cond)

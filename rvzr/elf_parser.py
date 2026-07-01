"""
File: Parsing of ELF files to populate sections of a TestCaseCode object.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT

文件用途：ELF二进制文件解析器。
从ELF目标文件中提取段数据、函数数据、指令地址和宏信息，
并将其填充到TestCaseCode对象中，用于构建侧信道模糊测试所需的
符号表和指令映射。解析过程包括符号表解析和objdump输出解析两个阶段。
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, List, Tuple, TypedDict, NamedTuple, Final
from subprocess import run
from elftools.elf.elffile import ELFFile, SymbolTableSection  # type: ignore

from rvzr.tc_components.test_case_binary import SymbolTable, SymbolTableEntry, TestCaseBinary
from rvzr.tc_components.actor import ActorPL, ActorMode
from rvzr.tc_components.instruction import Instruction
from rvzr.config import CONF

if TYPE_CHECKING:
    from rvzr.tc_components.test_case_code import TestCaseProgram, CodeSection
    from rvzr.tc_components.test_case_binary import InstructionMap
    from rvzr.target_desc import TargetDesc


class _ParsingError(Exception):
    """
    ELF解析过程中的错误异常类。
    """

    def __init__(self, message: str):
        full_msg = f"[ELFParser] Error while parsing assembly\n       Issue: {message}"
        super().__init__(full_msg)


# ==================================================================================================
# Private: ELF Symbol Table Parser
# 私有：ELF符号表解析器
# ==================================================================================================
class _ELFData(TypedDict):
    """ ELF文件解析后的数据结构，包含段数据和退出地址 """
    section_data: Dict[int, _SectionData]
    exit_addr: int


class _SectionData(TypedDict):
    """ 单个段的数据结构，包含段ID、名称、偏移、大小和函数字典 """
    id_: int
    name: str
    offset: int
    size: int
    functions: Dict[str, _FunctionData]


class _FunctionData(TypedDict):
    """ 单个函数的数据结构，包含函数ID、名称和偏移地址 """
    id_: int
    name: str
    offset: int


class _SymtabParser:
    """
    ELF符号表解析器。
    从ELF文件的.symtab段中提取段信息、函数地址和退出地址，
    并按ELF文件中的出现顺序对段和函数进行排序和编号。
    """

    def parse(self, obj_file: str) -> _ELFData:
        """
        Parse the ELF symbol table to get the addresses of all functions and sections.
        The section and function IDs are assigned in the order they appear in the ELF file.
        :param obj_file: path to the ELF file
        :return: a dictionary containing the section data and the exit address

        解析ELF符号表，获取所有函数和段的地址。
        段和函数ID按其在ELF文件中的出现顺序分配。

        :param obj_file: ELF文件路径
        :return: 包含段数据和退出地址的字典
        """
        elf_data = self._get_unsorted_data(obj_file)
        self._sort_elf_data(elf_data)
        return elf_data

    def _get_unsorted_data(self, obj_file: str) -> _ELFData:
        """
        Transform the ELF symbol table into a dictionary of sections and functions

        将ELF符号表转换为段和函数的字典结构。
        从ELF文件中提取.data段信息、函数符号和退出地址。
        """
        elf_data: _ELFData = {"section_data": {}, "exit_addr": -1}

        with open(obj_file, "rb") as f:
            data = ELFFile(f)

            # sanity check: we build test cases in such a way that there should be no segments
            # 安全检查：测试用例构建方式确保不应有段（segments）
            assert data.num_segments() == 0, f"{data.num_segments()}"

            # collect section info
            # 收集段信息：只处理.data开头的段
            for s_id, s in enumerate(data.iter_sections()):
                if s.name[:6] != ".data.":
                    continue
                s_entry: _SectionData = {
                    "id_": s_id,
                    "name": s.name.split(".")[2],  # 段名取.data后面的部分
                    "offset": s['sh_offset'],  # 段在文件中的偏移
                    "size": s['sh_size'],  # 段大小
                    "functions": {}
                }
                elf_data["section_data"][s_id] = s_entry

            # get addresses of functions and macros
            # 获取函数和宏的地址信息
            symtab: SymbolTableSection = data.get_section_by_name(".symtab")  # type: ignore
            for s in symtab.iter_symbols():
                if s.name.startswith(".function"):
                    # 函数符号：记录名称和偏移，关联到所属段
                    f_entry: _FunctionData = {
                        "id_": -1,  # will be assigned later — 后续排序时分配
                        "name": s.name,
                        "offset": s.entry.st_value
                    }
                    s_id = s['st_shndx']
                    elf_data["section_data"][s_id]["functions"][s.name] = f_entry

                # 获取退出地址（.test_case_exit符号的地址）
                if ".test_case_exit" in s.name:
                    elf_data["exit_addr"] = s.entry.st_value
        assert elf_data["exit_addr"] != -1, "Failed to find exit address"
        return elf_data

    def _sort_elf_data(self, elf_data: _ELFData) -> None:
        """
        Sort sections and functions by their appearance in the ELF file

        按ELF文件中的出现顺序对段和函数进行排序和重新编号。
        函数ID在整个文件中唯一，段ID按顺序递增。
        """

        # assign consecutive ids to sections, in the order they appear in ELF
        # 按ELF中出现顺序为段分配连续ID
        sorted_section_ids = sorted(elf_data["section_data"].keys())
        new_section_data = {}
        for new_s_id, org_s_id in enumerate(sorted_section_ids):
            new_section_data[new_s_id] = elf_data["section_data"][org_s_id]
            new_section_data[new_s_id]["id_"] = new_s_id
        elf_data["section_data"] = new_section_data

        # assign consecutive ids to functions, in the order they appear in ELF
        # 按ELF中出现顺序为函数分配连续ID（跨段唯一）
        sorted_new_section_ids = sorted(elf_data["section_data"].keys())
        new_f_id = 0  # function ids are unique across all sections — 函数ID跨段唯一
        for s_id in sorted_new_section_ids:
            function_data = elf_data["section_data"][s_id]["functions"]
            # 函数按偏移地址排序
            sorted_function_data = sorted(function_data.values(), key=lambda x: x["offset"])
            for f_data in sorted_function_data:
                f_data["id_"] = new_f_id
                new_f_id += 1


# ==================================================================================================
# Private: Objdump Output Parser
# 私有：Objdump输出解析器
# ==================================================================================================
_SectionName = str
_InstructionAddr = int
_InstrAddrMap = Dict[_SectionName, List[_InstructionAddr]]


class _ObjdumpSectionDesc(NamedTuple):
    """ objdump输出中段的描述信息，包含段名和是否跳过标志 """
    name: str
    skip: bool


class _ObjdumpOutputParser:
    """
    Objdump输出解析器。
    解析objdump的反汇编输出，提取每个段中所有指令的地址，
    用于构建指令映射表（InstructionMap）。
    """

    def __init__(self) -> None:
        # 根据ISA选择objdump参数
        self._objdump_flags = "--no-show-raw-insn -D -M intel -m i386:x86-64"
        if CONF.instruction_set == "arm64":
            self._objdump_flags = "--no-show-raw-insn -D -m aarch64"

    def parse(self, obj_file: str) -> _InstrAddrMap:
        """
        Parse the output of objdump to get the addresses of all instructions
        :param obj_file: path to the ELF file
        :return: a dictionary mapping section names to lists of its instruction addresses

        解析objdump输出，获取所有指令的地址。
        返回一个字典，将段名映射到该段中指令地址列表。

        :param obj_file: ELF文件路径
        :return: 段名到指令地址列表的映射字典
        """
        # Get raw objdump output
        # 获取objdump的原始输出
        dump = run(
            f"objdump {self._objdump_flags} {obj_file} "
            "| awk '/ [0-9a-f]+:/{print $1} /section/{print $0}'",
            shell=True,
            check=True,
            capture_output=True)

        # Prepare for parsing
        instruction_addresses: Dict[_SectionName, List[_InstructionAddr]] = {}
        section_desc = _ObjdumpSectionDesc("", False)

        # Loop over output lines, keeping track of the latest section header,
        # and recording addresses of instructions for each section
        # 循环处理输出行，跟踪当前段头部，记录每个段的指令地址
        for line in dump.stdout.decode().split("\n"):
            if not line:
                continue

            # Enter a new section
            # 进入新段
            if "section" in line:
                section_desc = self._parse_section_header(line)
                assert section_desc.name not in instruction_addresses
                instruction_addresses[section_desc.name] = []
                continue

            # Skip instruction in ignored sections
            # 跳过不需要处理的段中的指令
            if section_desc.skip:
                continue

            # Parse instruction addresses
            # 解析指令地址（16进制字符串转整数）
            assert section_desc.name != "", "Failed to parse objdump output (section_name)"
            instruction_addresses[section_desc.name].append(int(line[:-1], 16))

        return instruction_addresses

    def _parse_section_header(self, line: str) -> _ObjdumpSectionDesc:
        """
        解析objdump输出中的段头部行。
        判断段是否需要跳过（如.note.gnu段），并提取段名。
        """
        if ".note.gnu" in line:
            return _ObjdumpSectionDesc("", True)  # 跳过GNU备注段
        if ".data." not in line:
            return _ObjdumpSectionDesc("", False)  # 非数据段，跳过

        # Use regex to find .data.<section_name> pattern anywhere in the line
        # 使用正则表达式匹配.data.<段名>模式
        match = re.search(r'\.data\.(\w+)', line)
        if match:
            section_name = match.group(1)
            return _ObjdumpSectionDesc(section_name, False)\

        # no match found
        raise _ParsingError("Failed to parse objdump output (section_name)\n"
                            f"       Could not find .data.<section_name> pattern in: '{line}'")


# ==================================================================================================
# Public Interface: Parser Class
# 公共接口：ELF解析器类
# ==================================================================================================
class ELFParser:
    """
    ELF parser that extracts the following data from the ELF file:
    - Section data
    - Function data
    - Instruction addresses
    - Macros

    ELF文件解析器，从编译后的目标文件中提取以下数据：
    - 段数据（偏移、大小、ID）
    - 函数数据（名称、偏移、ID）
    - 指令地址（通过objdump获取）
    - 宏信息（解析宏指令并转换为符号表条目）

    解析结果填充到TestCaseBinary对象的符号表和指令映射中，
    用于侧信道模糊测试的违规检测和追踪分析。
    """
    _target_desc: Final[TargetDesc]

    def __init__(self, target_desc: TargetDesc) -> None:
        """
        初始化ELF解析器。

        :param target_desc: 目标架构描述对象，包含宏规范等信息
        """
        self._target_desc = target_desc
        # ARM64架构中宏展开为3条指令，x86中为1条
        self._instruction_per_macro = 3 if CONF.instruction_set == 'arm64' else 1

    # ----------------------------------------------------------------------------------------------
    # Public Methods
    def populate_elf_data(self, test_case_bin: TestCaseBinary,
                          test_case_code: TestCaseProgram) -> None:
        """
        Populate .symbol_table and .instruction_map attributes of a TestCaseBinary object
        by parsing the ELF file associated with this object (TestCaseBinary.obj_path).

        解析ELF文件，将符号表和指令映射数据填充到TestCaseBinary对象中。

        :param test_case_bin: 待填充的二进制数据容器
        :param test_case_code: 测试用例代码对象，用于查找段和函数
        """
        # get metadata from the ELF file and objdump output
        # 从ELF文件和objdump输出获取元数据
        symbol_table: SymbolTable
        instruction_map: InstructionMap
        symbol_table, instruction_map = self._assign_bin_metadata(test_case_bin.obj_path,
                                                                  test_case_code)

        # check that the data was populated correctly and the macros are well-formed
        # 验证段和宏数据的正确性
        self._validate_sections(test_case_code.get_sections(), instruction_map)
        self._validate_macros(test_case_code, symbol_table)

        # assign the parsed data to the test case
        # 将解析数据赋值给测试用例
        test_case_bin.assign_elf_data(symbol_table, instruction_map)

    # ----------------------------------------------------------------------------------------------
    # Private: Assignment of metadata to Section -> Function -> Instruction
    # 私有：将元数据分配到段 -> 函数 -> 指令层级结构

    def _assign_bin_metadata(self, obj_file: str,
                             test_case_code: TestCaseProgram) -> Tuple[SymbolTable, InstructionMap]:
        """
        从ELF文件提取元数据，构建符号表和指令映射。

        :param obj_file: ELF目标文件路径
        :param test_case_code: 测试用例代码对象
        :return: (符号表, 指令映射) 元组
        """
        # pylint: disable=too-many-locals
        # NOTE: the check is disabled because I haven't found a way to reduce the number of locals

        # Initialize data structures
        # 初始化数据结构
        symbol_table: SymbolTable = []
        instruction_map: InstructionMap = {}

        # Extract data from the ELF file and objdump output
        # 从ELF文件和objdump输出提取数据
        elf_data = _SymtabParser().parse(obj_file)
        instr_addr_map = _ObjdumpOutputParser().parse(obj_file)

        # Use the data to construct the symbol table and instruction map
        # 使用提取的数据构建符号表和指令映射
        sorted_sections = sorted(elf_data["section_data"].values(), key=lambda x: x["id_"])
        all_functions = [f for s in sorted_sections for f in s["functions"].values()]
        for section_data in sorted_sections:
            # Assign section metadata
            # 分配段元数据（偏移、大小、ID）
            section_obj = test_case_code.find_section(name=section_data["name"])
            self._assign_section_metadata(section_data, section_obj)

            # Assign function metadata
            # 分配函数元数据（创建符号表条目）
            sorted_functions = sorted(section_data["functions"].values(), key=lambda x: x["id_"])
            for func_data in sorted_functions:
                self._assign_function_metadata(func_data, section_data, symbol_table)

            # Create a local instruction map for the section
            # 为当前段创建指令映射子表
            instruction_map[section_data["id_"]] = {}

            # Assign instruction metadata
            # 分配指令元数据：遍历函数中的基本块和指令
            cursor = 0  # 指令地址游标，跟踪当前在objdump地址列表中的位置
            for func_data in sorted_functions:
                function_object = test_case_code.find_function(func_data["name"])
                assert function_object.get_owner() == section_obj.owner
                # 验证函数偏移与objdump地址一致
                assert func_data["offset"] == instr_addr_map[section_data["name"]][cursor], \
                    f"offsets: {func_data['offset']} {instr_addr_map[section_data['name']][cursor]}"

                for bb in list(function_object) + [function_object.get_exit_bb()]:
                    for inst in list(bb) + bb.terminators:
                        # 为每条指令分配地址和大小信息
                        self._assign_instruction_metadata(inst, instr_addr_map, cursor,
                                                          section_data, instruction_map)
                        if inst.name != "macro":
                            cursor += 1
                            continue

                        # Assign metadata for macros
                        # 为宏指令分配元数据（宏在ELF中展开为多条指令）
                        self._assign_macro_metadata(inst, sorted_sections, all_functions,
                                                    symbol_table)
                        # 宏指令占用多条指令位置，游标按展开后的指令数递增
                        cursor += self._instruction_per_macro

        # Fixup: the last instruction in .data.main is the test case exit, and it must map to a NOP
        # 修正：main段最后一条指令是测试用例退出点，映射为一个NOP指令
        exit_nop = Instruction("nop", "BASE-NOP", is_instrumentation=True)
        instr_addr_map["main"].append(elf_data["exit_addr"])
        self._assign_instruction_metadata(exit_nop, instr_addr_map, len(instruction_map[0]),
                                          sorted_sections[0], instruction_map)

        # Sort symbols in the symbol table by section id and offset within the section
        # 按段ID和段内偏移对符号表排序
        symbol_table.sort(key=lambda x: (x.sid, x.offset))

        return symbol_table, instruction_map

    @staticmethod
    def _assign_section_metadata(section_data: _SectionData, section_obj: CodeSection) -> None:
        """
        将ELF段元数据（偏移、大小、ID）分配到代码段对象中。

        :param section_data: ELF段数据字典
        :param section_obj: 测试用例中的代码段对象
        """
        section_obj.assign_elf_data(
            offset=section_data["offset"], size=section_data["size"], id_=section_data["id_"])

    @staticmethod
    def _assign_function_metadata(func_data: _FunctionData, section_data: _SectionData,
                                  symbol_table: SymbolTable) -> None:
        """
        为函数创建符号表条目，记录段ID、偏移和函数ID。

        :param func_data: 函数数据字典
        :param section_data: 所属段数据字典
        :param symbol_table: 符号表列表
        """
        func_symbol = SymbolTableEntry(
            sid=section_data["id_"],
            type_=0,  # type_=0 表示函数符号
            offset=func_data["offset"],
            arg=func_data["id_"],
        )
        symbol_table.append(func_symbol)

    def _assign_instruction_metadata(self, inst: Instruction, instr_addr_map: _InstrAddrMap,
                                     cursor: int, section_data: _SectionData,
                                     instr_map: InstructionMap) -> None:
        """
        为单条指令分配二进制属性（段ID、偏移、大小），并加入指令映射。

        :param inst: 指令对象
        :param instr_addr_map: 段名到指令地址列表的映射
        :param cursor: 当前指令在地址列表中的位置索引
        :param section_data: 所属段数据
        :param instr_map: 指令映射表
        """
        section_name = section_data["name"]
        instr_addr_map_in_sec = instr_addr_map[section_name]

        # get instruction info
        # 获取指令地址
        address = instr_addr_map_in_sec[cursor]
        # 指令大小 = 下一条指令地址 - 当前指令地址（最后一条指令大小为0）
        if cursor + 1 < len(instr_addr_map_in_sec):
            size = instr_addr_map_in_sec[cursor + 1] - address
        else:
            size = 0

        # assign instruction metadata
        # 分配指令的二进制属性
        inst.assign_binary_properties(section_id=section_data["id_"], offset=address, size=size)

        # add instruction to the instruction map
        # 将指令加入映射表（按地址索引）
        instr_map[section_data["id_"]][address] = inst

        # if the instruction is a macro, it may span several instructions;
        # make it look like it does by adding NOPs to the instruction map
        # 宏指令在ELF中展开为多条指令，用NOP占位符填充映射表中的额外位置
        if inst.name == "macro":
            for i in range(1, self._instruction_per_macro):
                address = instr_addr_map_in_sec[cursor + i]
                nop_placeholder = Instruction("nop", "BASE-NOP")
                nop_placeholder.is_macro_placeholder = True  # 标记为宏占位NOP
                instr_map[section_data["id_"]][address] = nop_placeholder

    def _assign_macro_metadata(self, inst: Instruction, sections_data: List[_SectionData],
                               functions_data: List[_FunctionData],
                               symbol_table: SymbolTable) -> None:
        """
        Convert a macro instruction to a symbol table entry by parsing its symbolic arguments
        according to the macro specification (see x86_target_desc.py). Add the resulting
        symbol to the symbol table.

        Example:
        - Input (macro instruction): MACRO 1, .main.function_1
        - Processing:
            type: 1 (actor switch)
            arg 1: main -> 0 (offset of section main)
            arg 2: function_1 -> 12 (offset of function function_1 within section main)
            arg 3: none
            arg 4: none
            compressed macro argument: 0 + (12 << 16) + (0 << 32) + (0 << 48) = 786432
        - Output (symbol table entry): SymbolTableEntry(0, 1, 0, 786432)

        将宏指令转换为符号表条目。根据宏规范解析符号参数，
        将actor_id、function_id和整数参数压缩为16位块组合的单一整数。

        示例：
        - 输入宏指令：MACRO 1, .main.function_1
        - 处理过程：
            type: 1 (参与者切换)
            arg 1: main -> 0 (main段的偏移)
            arg 2: function_1 -> 12 (function_1函数在main段内的偏移)
            压缩参数：0 + (12 << 16) = 786432
        - 输出符号表条目：SymbolTableEntry(0, 1, 0, 786432)

        :param inst: 宏指令对象
        :param sections_data: 所有段数据列表
        :param functions_data: 所有函数数据列表
        :param symbol_table: 符号表列表
        """

        # pylint: disable=too-many-locals
        # NOTE: the check is disabled because I haven't found a way to reduce the number of locals

        def section_name_to_id(name: str) -> int:
            """ 将段名转换为段ID """
            for entry in sections_data:
                if entry["name"] == name:
                    return entry["id_"]
            raise _ParsingError(f"Macro references an unknown actor {name}")

        def function_name_to_id(name: str) -> int:
            """ 将函数名转换为函数ID """
            for entry in functions_data:
                if entry["name"] == name:
                    return entry["id_"]
            raise _ParsingError(f"Macro references an unknown function {name}")

        assert inst.name == "macro"

        # find the spec for this macro arguments
        # 查找宏规范
        macro_name = inst.operands[0].value[1:].lower()
        try:
            macro_spec = self._target_desc.macro_specs[macro_name]
        except IndexError as e:
            raise _ParsingError(f"Unknown macro {macro_name} in {inst}") from e

        # convert macro operands to compressed symbol arguments
        # 将宏操作数转换为压缩的符号参数（每个参数占16位，组合为一个整数）
        str_args = inst.operands[1].value.split('.')[1:]
        symbol_args: int = 0
        for i, str_arg in enumerate(str_args):
            str_arg = str_arg.lower()
            if macro_spec.args[i] == "":
                # 空参数，跳过
                continue
            if macro_spec.args[i] == "actor_id":
                # 段ID参数，左移i*16位存入压缩参数
                actor_id = section_name_to_id(str_arg)
                symbol_args += (actor_id << i * 16)
                continue
            if macro_spec.args[i] == "function_id":
                # 函数ID参数，左移i*16位存入压缩参数
                symbol_args += (function_name_to_id("." + str_arg) << i * 16)
                continue
            if macro_spec.args[i] == "int":
                # 整数参数，支持16进制和10进制，截断为16位后左移
                if str_arg.startswith("0x"):
                    val = int(str_arg, 16) & 0xFFFF
                else:
                    val = int(str_arg) & 0xFFFF
                symbol_args += (val << i * 16)
                continue
            raise ValueError(f"Invalid macro argument {macro_spec.args[i]}")

        # add the macro to the symbol table
        # 将宏符号加入符号表
        symbol_table.append(
            SymbolTableEntry(
                sid=inst.section_id(),
                type_=macro_spec.type_,
                offset=inst.section_offset(),
                arg=symbol_args,
            ))

    # ----------------------------------------------------------------------------------------------
    # Private: Validation of the parsed data
    # 私有：解析数据的验证
    def _validate_sections(self, sections: List[CodeSection],
                           instruction_map: InstructionMap) -> None:
        """
        Validate that all sections in the test case have been populated with ELF data
        :param sections: list of sections in the test case
        :param instruction_map: constructed InstructionMap
        :return: None
        :raises _ParsingError: if at least one section was not populated
        :raises _ParsingError: if the instruction map does not match the sections

        验证所有段都已正确填充ELF数据，且指令映射与段数量一致。

        :param sections: 测试用例中的段列表
        :param instruction_map: 构建的指令映射
        :raises _ParsingError: 段未填充或映射不匹配时抛出异常
        """
        # 检查指令映射段数与测试用例段数一致
        if len(instruction_map) != len(sections):
            raise _ParsingError(
                "InstructionMap does not have the same number of sections as the test case")

        for section_obj in sections:
            try:
                _ = section_obj.get_elf_data()  # will throw an exception if the section is not set
                # 如果段未设置ELF数据，会抛出异常
            except AssertionError as e:
                raise _ParsingError(f"Failed to find section for actor `{section_obj.name}`") from e

    def _validate_macros(self, test_case: TestCaseProgram, symbol_table: SymbolTable) -> None:
        """
        Validate that all macros in the test case are well-formed

        验证测试用例中所有宏指令的合法性：
        - 宏引用的actor_id必须存在
        - 参与者切换宏的目标类型必须匹配（如set_k2u_target必须指向用户态actor）
        """
        for symbol in symbol_table:
            if symbol.type_ == 0:  # function — 函数符号，跳过
                continue
            macro_spec = self._target_desc.get_macro_spec_from_type(symbol.type_)

            # validate that the actor id is valid
            # 验证宏引用的actor_id是否合法
            for i in range(4):
                if macro_spec.args[i] != "actor_id":
                    continue
                # 从压缩参数中提取16位actor_id
                target_actor_id = (symbol.arg >> (i * 16)) & 0xFFFF

                # check that the actor exists
                # 检查actor是否存在
                try:
                    actor = test_case.find_actor(actor_id=target_actor_id)
                except KeyError as e:
                    raise _ParsingError(
                        f"Macro references an unknown actor id {target_actor_id}") from e

                # validate that the actor type matches the macro
                # 验证actor类型与宏匹配
                if macro_spec.name == "set_k2u_target" and \
                   actor.privilege_level != ActorPL.USER and actor.mode != ActorMode.HOST:
                    raise _ParsingError("Macro set_k2u_target expects a user actor")
                if macro_spec.name == "set_u2k_target" and \
                   actor.privilege_level != ActorPL.KERNEL and actor.mode != ActorMode.HOST:
                    raise _ParsingError("Macro set_u2k_target expects a kernel actor")
                if macro_spec.name == "set_h2g_target" and \
                   actor.mode != ActorMode.HOST and actor.privilege_level != ActorPL.KERNEL:
                    raise _ParsingError("Macro set_h2g_target expects a host actor")
                if macro_spec.name == "set_g2h_target" and \
                   actor.mode != ActorMode.GUEST and actor.privilege_level != ActorPL.KERNEL:
                    raise _ParsingError("Macro set_g2h_target expects a guest actor")

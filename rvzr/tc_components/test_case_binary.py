"""
文件：表示汇编后测试用例代码的二进制形式（ELF目标文件）的类。

本模块定义了TestCaseBinary类，用于管理测试用例的目标文件，包括符号表、
指令映射、二进制数据读取以及RCBF格式保存等功能。

File: Classes representing assembled test case code in a binary form (ELF object file).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, NamedTuple, Final, Optional

from .instruction import Instruction
from ..logs import error

if TYPE_CHECKING:
    from .test_case_code import TestCaseProgram

SectionID = int          # 段ID类型
SymbolType = int         # 符号类型
SymbolOffset = int       # 符号偏移量类型
MacroArgument = int      # 宏参数类型
# 指令映射：段ID -> (段内偏移 -> 指令对象)
InstructionMap = Dict[SectionID, Dict[int, Instruction]]


class SymbolTableEntry(NamedTuple):
    """ 测试用例符号表中的符号条目。

    Symbol in a test case symbol table """

    sid: SectionID
    """ 包含该符号的段ID """

    offset: SymbolOffset
    """ 符号在参与者段中的偏移量 """

    type_: SymbolType
    """ 符号类型（0表示函数符号，其他表示宏符号） """

    arg: MacroArgument
    """ 符号的参数（对函数符号为函数编号，对宏符号为宏类型） """


SymbolTable = List[SymbolTableEntry]


class TestCaseBinary:
    """
    表示测试用例程序的ELF目标文件（即编译后的汇编代码）的类。

    该类管理目标文件的路径、符号表、指令映射，并提供二进制数据读取
    和RCBF格式保存功能。

    A class representing the object ELF file (i.e., compiled assembly) of a test case program
    """

    obj_path: Final[str]
    """ 从asm_path生成的目标文件路径 """

    _symbol_table: Optional[List[SymbolTableEntry]] = None
    """ 测试用例程序中的符号列表 """

    _instruction_map: Optional[InstructionMap] = None
    """ 段ID+偏移量到对应指令对象的映射字典 """

    _parent: TestCaseProgram  # 父测试用例程序
    _obj_is_assembled: bool = False  # 标记目标文件是否已汇编

    def __init__(self, obj_path: str, parent: TestCaseProgram):
        """
        初始化二进制测试用例对象。

        :param obj_path: 目标文件路径
        :param parent: 父测试用例程序
        """
        self.obj_path = obj_path
        self._parent = parent

    def mark_as_assembled(self) -> None:
        """ 标记目标文件为已汇编状态。

        Mark the object file as assembled """
        self._obj_is_assembled = True

    def to_bytes(self, padded_section_size: int = 0, padding_byte: bytes = b'') -> bytes:
        """
        返回汇编后目标文件的完整二进制数据，段按参与者ID排序。
        可选择将每个段填充到指定大小。

        :param padded_section_size: 每个段要填充到的目标大小，0表示不填充
        :param padding_byte: 用于填充的字节（必须为单字节）
        :return: 包含所有段编译后二进制数据的字节串

        Return the full binary of the assembled object file, with sections ordered by actor ID.
        Optionally, pad each section to a specified size with a specified padding byte.

        :param pad_to_size: The size to pad each section to
        :param padding_byte: The byte to use for padding
        :return: A list of byte strings, each containing the full compiled binary of a section
        """
        assert self._obj_is_assembled, \
            "Attempting to read sections from an non-assembled object file"
        assert padded_section_size == 0 or len(padding_byte) == 1, \
            "padding_byte must be specified as a single byte if pad_to_size is set"

        code = b''
        with open(self.obj_path, 'rb') as bin_file:
            # 按参与者ID排序遍历，确保段顺序一致
            for actor in self._parent.get_actors(sorted_=True):

                # 从目标文件中读取段数据
                # Read the section from the object file
                section_data = actor.code_section().get_elf_data()
                offset = section_data["offset"]
                size = section_data["size"]

                bin_file.seek(offset)
                code += bin_file.read(size)

                # 应用填充：确保段达到指定大小
                # Apply padding
                assert padded_section_size >= size, \
                    "Padded section size is less than to the original section size"
                if padded_section_size > size:
                    padding = padded_section_size - size
                    code += padding_byte * padding

        return code

    def get_macro_offset(self, macro_type: int) -> int:
        """
        返回指定类型宏在其段中的偏移量。
        如果有多个相同类型的宏，返回第一个。

        :param macro_type: 宏的类型ID
        :return: 宏在目标文件中的偏移量；如果未找到则返回-1

        Return the offset of the macro of the given type in its section.
        If there are multiple macros of the same type, the first one is returned.
        :param macro_id: The ID of the macro
        :return: The offset of the macro in the object file; -1 if not found
        """
        assert self._symbol_table is not None, \
            "assign_elf_data() has not been called on this object"
        for symbol in self._symbol_table:
            if symbol.type_ == macro_type:
                return symbol.offset
        return -1

    def assign_elf_data(self, symbol_table: List[SymbolTableEntry],
                        instruction_map: InstructionMap) -> None:
        """
        分配从ELF文件解析的符号表和指令映射（通常由ELFParser实例调用）。

        :param symbol_table: 从ELF文件解析的符号表
        :param instruction_map: 从ELF文件解析的指令映射

        Assign the symbol table and instruction map based on the data parsed from the ELF file
        (normally assigned by an ELFParser instance).
        """
        assert self._symbol_table is None, "Attempting to reassign symbol table"
        assert self._instruction_map is None, "Attempting to reassign instruction map"
        self._symbol_table = symbol_table
        self._instruction_map = instruction_map

    def symbol_table(self) -> List[SymbolTableEntry]:
        """ 返回测试用例程序的符号表。

        Return the symbol table of the test case program """
        assert self._symbol_table is not None, "Symbol table has not been populated"
        return self._symbol_table

    def instruction_map(self) -> InstructionMap:
        """ 返回测试用例程序的指令映射。

        Return the instruction map of the test case program """
        assert self._instruction_map is not None, "Instruction map has not been populated"
        return self._instruction_map

    def save_rcbf(self, path: str) -> None:
        """
        将测试用例二进制保存为RCBF格式文件。
        RCBF格式参见docs/devel/binary-formats.md。

        文件结构：
        1. 头部：参与者数量、符号数量
        2. 参与者元数据：ID、模式、特权级别、PTE属性、EPT属性
        3. 符号表：函数符号（按参数排序）和宏符号（按段+偏移排序）
        4. 段元数据：段ID、段大小
        5. 代码数据：各段的二进制代码

        :param path: RCBF文件的保存路径

        Save the test case binary in the RCBF format
        (see docs/devel/binary-formats.md for details).
        :param path: The path to save the RCBF file to
        """
        assert self._obj_is_assembled, "Attempting to save an un-assembled object file"
        actors = self._parent.get_actors(sorted_=True)
        symbol_table = self.symbol_table()

        # 安全检查：确保符号类型有效（模板不能作为测试用例）
        # sanity check
        if any(symbol.type_ < 0 for symbol in symbol_table):
            error("attempt to use template as a test case")

        # 写入RCBF文件
        # write the RCBF file
        with open(path, 'wb') as f:
            # 头部信息：参与者数量和符号数量
            # header
            f.write((len(actors)).to_bytes(8, byteorder='little'))  # n_actors
            f.write((len(symbol_table)).to_bytes(8, byteorder='little'))  # n_symbols

            # 参与者元数据：每个参与者的ID、模式、特权级别和页表属性
            # actor metadata
            for actor in actors:
                f.write((actor.get_id()).to_bytes(8, byteorder='little'))
                f.write((actor.mode.value).to_bytes(8, byteorder='little'))
                f.write((actor.privilege_level.value).to_bytes(8, byteorder='little'))
                f.write((actor.data_properties).to_bytes(8, byteorder='little'))
                f.write((actor.data_ept_properties).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))  # unused（保留字段）

            # 符号表：函数符号按参数排序，宏符号按段ID+偏移排序
            # symbol table (first functions sorted by argument, then macros sorted by actor+offset)
            function_symbols = [s for s in symbol_table if s[2] == 0]   # type_==0 为函数符号
            macro_symbols = [s for s in symbol_table if s[2] != 0]      # type_!=0 为宏符号
            for aid, s_offset, s_id, arg in sorted(function_symbols, key=lambda s: s.arg):
                # print("function", s_id, aid, s_offset, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))
            for aid, s_offset, s_id, arg in sorted(macro_symbols, key=lambda s: (s.sid, s.offset)):
                # print("macro", aid, s_offset, s_id, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))

            # 段元数据：每个段的ID、大小和保留字段
            # section metadata
            for actor in actors:
                section_data = actor.code_section().get_elf_data()
                # print("section\n")
                f.write((section_data["id"]).to_bytes(8, byteorder='little'))
                f.write((section_data["size"]).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))

            # 代码数据：按参与者顺序写入各段的二进制代码
            # code
            with open(self.obj_path, 'rb') as bin_file:
                for actor in actors:
                    section_data = actor.code_section().get_elf_data()
                    bin_file.seek(section_data["offset"])  # type: ignore
                    # print(code, section.size)
                    f.write(bin_file.read(section_data["size"]))

            # print(self.obj_path, f.tell())

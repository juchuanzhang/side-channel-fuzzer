"""
文件：表示测试用例代码及其组件的类。

本模块定义了测试用例程序的代码结构层次：
指令节点(InstructionNode) -> 基本块(BasicBlock) -> 函数(Function) -> 代码段(CodeSection) -> 测试用例程序(TestCaseProgram)
这些类构成了测试用例代码的双链表和层级结构，支持指令的插入、删除和遍历操作。

File: Class representing test case code and its components.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import List, Dict, Optional, Final, TypedDict, Generator as GeneratorType
from dataclasses import dataclass
import shutil

from .actor import Actor, ActorID, ActorName, ActorPL, ActorMode
from .instruction import Instruction
from .test_case_binary import TestCaseBinary


# ==================================================================================================
# 程序结构层次：代码段(CodeSection) -> 函数(Function) -> 基本块(BasicBlock) -> 指令节点(InstructionNode) -> 指令(Instruction)
# Program Structure: CodeSection -> Function -> BasicBlock -> InstructionNode -> Instruction
# ==================================================================================================
@dataclass
class InstructionNode:
    """
    指令节点类，将指令表示为双链表中的节点，构成基本块的指令序列。
    支持前驱和后继指针，便于指令的插入和删除操作。

    Wrapper class to represent an instruction as a node
    in a double-linked list that constitutes a basic block
    """
    instruction: Final[Instruction]
    """ 包装的指令对象 """

    parent: Final[BasicBlock]
    """ 该指令所属的基本块 """

    next: Optional[InstructionNode] = None
    """ 基本块中的下一个指令节点 """

    previous: Optional[InstructionNode] = None
    """ 基本块中的上一个指令节点 """

    def __init__(self, instruction: Instruction, parent: BasicBlock):
        """
        初始化指令节点。

        :param instruction: 包装的指令对象
        :param parent: 所属的基本块
        """
        self.instruction = instruction
        self.parent = parent
        self.next = None
        self.previous = None

    def __str__(self) -> str:
        return str(self.instruction)


class BasicBlock:
    """ 测试用例代码中的基本块。基本块是连续执行的指令序列，
    只有一个入口点（第一条指令）和一个或多个出口点（最后一条指令/终止指令）。

    Basic block in the test case code """

    name: Final[str]
    """ 基本块的名称（即标签） """

    parent: Final[Optional[Function]]
    """ 拥有该基本块的函数 """

    successors: List[BasicBlock]
    """ 该基本块的后继基本块列表 """

    terminators: List[Instruction]
    """ 该基本块中的终止指令列表（如分支、返回指令） """

    is_exit: Final[bool]
    """ 标识该基本块是否为函数退出块 """

    _start: Optional[InstructionNode] = None  # 基本块的第一条指令节点
    _end: Optional[InstructionNode] = None    # 基本块的最后一条指令节点

    def __init__(self, name: str, parent: Optional[Function] = None, is_exit: bool = False):
        """
        初始化基本块。

        :param name: 基本块名称/标签
        :param parent: 所属函数，默认为None
        :param is_exit: 是否为函数退出块，默认为False
        """
        self.name = name
        self.parent = parent
        self.is_exit = is_exit
        self.successors = []
        self.terminators = []

    def __str__(self) -> str:
        return self.name

    def __len__(self) -> int:
        """ 基本块的长度即其中指令的数量。

        Length of the basic block is the number of instructions in it """
        count = 0
        if self._start:
            node = self._start
            count = 1
            while node.next:
                node = node.next
                count += 1
        return count

    def __iter__(self) -> GeneratorType[Instruction, None, None]:
        """ 默认迭代器，遍历基本块中的指令对象。

        Default iterator over the instructions in the basic block """
        current_node = self._start
        while current_node:
            yield current_node.instruction
            current_node = current_node.next

    def iter_nodes(self) -> GeneratorType[InstructionNode, None, None]:
        """ 非默认迭代器：遍历基本块中的指令节点对象（而非指令本身）。

        Non-default iterator: Iterate over the nodes in the basic block """
        current_node = self._start
        while current_node:
            yield current_node
            current_node = current_node.next

    def get_owner(self) -> Actor:
        """ 获取拥有该基本块的参与者（通过所属函数的所属代码段）。

        Get the actor that owns the basic block """
        assert self.parent is not None, "Basic block does not have a parent function"
        return self.parent.parent.owner

    # ----------------------------------------------------------------------------------------------
    # 指令插入和删除
    # Instruction insertion and deletion
    def insert_after(self, position: Optional[InstructionNode], inst: Instruction) -> None:
        """
        在基本块中指定位置节点之后插入一条指令。

        :param position: 插入位置节点；如果为None且基本块非空，则在末尾插入；
                         如果为None且基本块为空，则作为第一条指令
        :param inst: 要插入的指令
        :raises ValueError: 如果position不属于该基本块

        Insert an instruction after a given position node in a basic block
        :param position: If not None, the node after which to insert the new instruction;
                         If None, insert at the _end of the basic block
        :param inst: The instruction to insert
        :return: None
        :raises ValueError: If `position` is not found in the basic block
        """
        inst_node = InstructionNode(inst, self)

        # 位置为None且基本块为空：设置起始和结束为新指令
        # Position is None and the BB is empty: set the start and end to the new instruction
        if position is None and self._end is None:
            self._start = inst_node
            self._end = inst_node
            return

        # 位置为None且基本块非空：在末尾插入
        # Position is None and the BB is not empty: set the position to the end of the BB
        if position is None:
            position = self._end
        assert position is not None

        # 位置不为None：确保该位置节点属于此基本块
        # Position is not None: ensure that `position` belongs to this BB
        if position.parent != self:
            raise ValueError("`position` not found in the basic block")

        # 在指定位置后插入新指令，更新双链表指针
        # Insert the new instruction
        next_ = position.next
        position.next = inst_node
        inst_node.previous = position
        if next_:
            inst_node.next = next_
            next_.previous = inst_node
        else:
            # 新指令成为基本块的最后一个节点
            self._end = inst_node

    def insert_before(self, position: Optional[InstructionNode], inst: Instruction) -> None:
        """
        在基本块中指定位置节点之前插入一条指令。

        :param position: 插入位置节点；如果为None且基本块非空，则在开头插入；
                         如果为None且基本块为空，则作为第一条指令
        :param inst: 要插入的指令
        :raises ValueError: 如果position不属于该基本块

        Insert an instruction before a given position node in a basic block
        :param position: If not None, the node before which to insert the new instruction;
                         If None, insert at the beginning of the basic block
        :param inst: The instruction to insert
        :return: None
        :raises ValueError: If `position` is not found in the basic block
        """
        inst_node = InstructionNode(inst, self)

        # 位置为None且基本块为空：设置起始和结束为新指令
        # Position is None and the BB is empty: set the start and end to the new instruction
        if position is None and self._start is None:
            self._start = inst_node
            self._end = inst_node
            return

        # 位置为None且基本块非空：在开头插入
        # Position is None and the BB is not empty: set the position to the start of the BB
        if position is None:
            position = self._start
        assert position is not None

        # 位置不为None：确保该位置节点属于此基本块
        # Position is not None: ensure that `position` belongs to this BB
        if position.parent != self:
            raise ValueError(f"instruction {position} belongs to {position.parent}, not {self}")

        # 在指定位置前插入新指令，更新双链表指针
        # Insert the new instruction
        previous = position.previous
        position.previous = inst_node
        inst_node.next = position
        if previous:
            inst_node.previous = previous
            previous.next = inst_node
        else:
            # 新指令成为基本块的第一个节点
            self._start = inst_node

    def delete(self, target: InstructionNode) -> None:
        """
        从基本块中删除一个指令节点，更新双链表连接。

        :param target: 要删除的节点
        :raises ValueError: 如果节点不属于该基本块

        Delete a node from a basic block
        :param target: The node to delete
        :return: None
        :raises ValueError: If the node does not belong to the basic block
        """
        # 验证该节点确实属于此基本块
        # Verify that this node indeed belongs to this BB
        if target.parent != self:
            raise ValueError("Error deleting an instruction from a BB; instruction not found")

        # 修补双链表连接
        # Patch the linked list
        previous = target.previous
        next_ = target.next
        if previous is None and next_ is None:  # 基本块中唯一的指令：清空基本块
            self._end = None
            self._start = None
        elif previous is None:  # 基本块的第一条指令：更新起始节点
            next_.previous = None  # type: ignore
            self._start = next_
        elif next_ is None:  # 基本块的最后一条指令：更新结束节点
            previous.next = None
            self._end = previous
        else:  # 中间位置的指令：连接前后节点
            previous.next = next_
            next_.previous = previous

    # ----------------------------------------------------------------------------------------------
    # 指令访问
    # Instruction access
    def get_first(self, exclude_macros: bool = False) -> Optional[InstructionNode]:
        """
        获取基本块中的第一个指令节点。

        :param exclude_macros: 如果为True，返回第一个非宏指令节点
        :return: 第一个节点，如果基本块为空则返回None

        Get the first InstructionNode in the basic block
        :param exclude_macros: If True, return the first non-macro instruction
        :return: The first node or None if the basic block is empty
        """
        if not exclude_macros:
            return self._start if self._start is not None else None

        # 跳过宏指令，找到第一个非宏指令
        # Skip macro instructions
        entry_node = self.get_first()
        while entry_node:
            if entry_node.instruction.name != "macro":
                break
            entry_node = entry_node.next
        return entry_node

    def get_last(self) -> Optional[InstructionNode]:
        """
        获取基本块中的最后一个指令节点。

        :return: 最后一个节点，如果基本块为空则返回None

        Get the last InstructionNode in the basic block
        :return: The last node or None if the basic block is empty
        """
        return self._end if self._end is not None else None

    def find_instruction_node(self, inst: Instruction) -> Optional[InstructionNode]:
        """
        在基本块中查找对应给定指令的指令节点。

        :param inst: 要查找的指令
        :return: 对应的节点，如果未找到则返回None

        Find a InstructionNode in the basic block that corresponds to a given instruction
        :param inst: The instruction to find
        :return: The node corresponding to the instruction or None if not found
        """
        for node in self.iter_nodes():
            if node.instruction == inst:
                return node
        return None


class Function:
    """
    测试用例代码中的函数。

    本类本质上是基本块列表的包装器，具有以下特殊特性：
    * 基本块按其在汇编代码中出现的顺序排列。
    * 最后一个基本块有特殊处理：假定它是函数的退出块，应包含很少或没有指令。
      重要提示：在迭代函数中的基本块或计算其长度时，退出块不包含在内。

    Function in the test case code.
    This class is essentially a wrapper around a list of basic blocks, with special features:
    * The basic blocks are ordered by their appearance in the assembly code.
    * The last basic block has special handling: it is assumed to be the exit block of the function,
      and it should contain little-to-no instructions. IMPORTANT: This basic block
      is NOT included when iterating over the basic blocks in the function
      or when calculating its length.
    """

    name: Final[str]
    """ 函数名称，与汇编代码中的函数标签匹配 """

    parent: Final[CodeSection]
    """ 拥有该函数的代码段 """

    _all_bb: List[BasicBlock]
    """ 函数中所有基本块的列表，按汇编中出现顺序排列，最后一个始终为退出块 """

    def __init__(self, name: str, parent: CodeSection):
        """
        初始化函数，自动创建一个退出基本块。

        :param name: 函数名称
        :param parent: 所属代码段
        """
        self.name = name
        self.parent = parent
        # 创建退出基本块，名称为.exit_前缀加函数名去掉.function_前缀
        exit_bb = BasicBlock(f".exit_{name.removeprefix('.function_')}", parent=self, is_exit=True)
        self._all_bb = [exit_bb]

    def __len__(self) -> int:
        """ 函数的长度是其基本块数量，不包括退出块。

        Length of the function is the number of basic blocks in it, excluding the exit block """
        return len(self._all_bb[:-1])

    def __iter__(self) -> GeneratorType[BasicBlock, None, None]:
        """ 遍历函数中的基本块，不包括退出块。

        Iterate over the basic blocks in the function, excluding the exit block """
        for bb in self._all_bb[:-1]:
            yield bb

    def __getitem__(self, id_: int) -> BasicBlock:
        """ 通过索引获取基本块（不包括退出块）。

        Get a basic block by its index, excluding the exit block """
        assert len(self._all_bb) > 1, "Function has no non-exit basic blocks"
        non_exit_bbs = self._all_bb[:-1]
        return non_exit_bbs[id_]

    def append(self, bb: BasicBlock) -> None:
        """ 将基本块添加到倒数第二个位置（最后一个始终是退出块）。

        Append a basic block to the second-to-last position in the function
          (the last is always exit) """
        # 先弹出退出块，添加新基本块，再重新添加退出块
        exit_bb = self._all_bb.pop()
        self._all_bb.append(bb)
        self._all_bb.append(exit_bb)

    def extend(self, bb_list: List[BasicBlock]) -> None:
        """ 将一组基本块添加到函数末尾（退出块之前）。

        Extend the function with a list of basic blocks (added to the end) """
        exit_bb = self._all_bb.pop()
        self._all_bb.extend(bb_list)
        self._all_bb.append(exit_bb)

    def get_first_bb(self) -> BasicBlock:
        """ 获取函数的第一个基本块。如果没有基本块，返回默认退出块。

        Get the first basic block in the function.
        If there are no basic blocks, return the default exit block.
        """
        return self._all_bb[0]

    def get_exit_bb(self) -> BasicBlock:
        """ 获取函数的退出基本块（最后一个基本块）。

        Get the last basic block in the function.
        If there are no basic blocks, return the default exit block.
        """
        exit_ = self._all_bb[-1]
        assert exit_.is_exit, "The last basic block is not marked as an exit block"
        return self._all_bb[-1]

    def get_owner(self) -> Actor:
        """ 获取拥有该函数的参与者。

        Get the actor that owns the function """
        return self.parent.owner


class _ELFSectionData(TypedDict):
    """ ELF文件中段的数据类型定义。

    Data of a section in the ELF file """
    offset: int    # 段在目标文件中的偏移量
    size: int      # 段的字节大小
    id: int        # 段ID


class CodeSection:
    """
    测试用例代码中的代码段。

    本类本质上是函数有序列表的包装器，函数按其在汇编代码中的出现顺序排列。
    每个代码段对应一个参与者（Actor），包含该参与者的所有函数。

    Section in the test case code.
    This class is essentially a wrapper around an ordered list of functions, with special features:
    * The functions are ordered by their appearance in the assembly code.
    """

    name: Final[str]
    """ 代码段名称 """

    owner: Actor
    """ 拥有该代码段的参与者 """

    id_: Optional[int] = None
    """ 代码段ID，必须与ELF文件中的段ID匹配 """

    _functions: Final[List[Function]]  # 代码段中的函数列表
    _bin_offset: Optional[int] = None  # 代码段在目标文件中的偏移量
    _bin_size: Optional[int] = None    # 代码段在目标文件中的字节大小

    def __init__(self, owner: Actor):
        """
        初始化代码段，自动将其分配给对应的参与者。

        :param owner: 拥有该代码段的参与者
        """
        self.owner = owner
        self.name = owner.name
        # 将此代码段分配给参与者
        owner.assign_code_section(self)
        self._functions = []

    def __iter__(self) -> GeneratorType[Function, None, None]:
        """ 遍历代码段中的函数。

        Iterate over the functions in the section """
        for func in self._functions:
            yield func

    def __len__(self) -> int:
        """ 代码段的长度即其中函数的数量。

        Length of the section is the number of functions in it """
        return len(self._functions)

    def __getitem__(self, id_: int) -> Function:
        """ 通过索引获取函数。

        Get a function by its index """
        return self._functions[id_]

    def append(self, func: Function) -> None:
        """ 将函数添加到代码段，不允许重复名称。

        Append a function to the section """
        assert func.name not in [f.name for f in self._functions], \
            f"Function {func.name} already exists in the section"
        self._functions.append(func)

    def assign_elf_data(self, offset: int, size: int, id_: int) -> None:
        """
        分配ELF段数据（偏移量、大小和段ID）。只能分配一次。

        :param offset: 段在目标文件中的偏移量
        :param size: 段的字节大小
        :param id_: 段ID

        Assign ELF data to the section """
        assert self._bin_offset is None and self._bin_size is None and self.id_ is None, \
            "ELF data is already assigned"
        self._bin_offset = offset
        self._bin_size = size
        self.id_ = id_

    def get_elf_data(self) -> _ELFSectionData:
        """ 获取ELF段数据。

        Get the ELF data of the section """
        assert self._bin_offset is not None and self._bin_size is not None \
            and self.id_ is not None, "ELF data is not assigned"
        return {"offset": self._bin_offset, "size": self._bin_size, "id": self.id_}


# ==================================================================================================
# 所有程序信息的组合
# All Program Information Combined
# ==================================================================================================
TC_EXIT_LABEL = ".test_case_exit"  # 测试用例退出标签


class TestCaseProgram:
    """ 测试用例程序类。表示一个完整的测试用例程序，包含所有参与者、
    代码段、函数、基本块和指令的层级结构，以及与汇编文件和目标文件的管理。

    A class representing a test case program """

    generator_seed: int
    """ 生成该测试用例程序所使用的种子值 """

    _asm_path: str  # 包含测试用例程序的汇编文件路径
    _obj: Optional[TestCaseBinary] = None  # 汇编后的测试用例程序的目标文件表示
    _obj_is_assembled: bool = False  # 标记目标文件是否已汇编

    _sections: Final[List[CodeSection]]  # 测试用例程序中的代码段列表
    _actors: Dict[ActorName, Actor]  # 测试用例程序中的参与者字典
    _tc_exit_bb: Final[BasicBlock]  # 终止测试用例的特殊基本块

    def __init__(self, asm_path: str, seed: int = 0):
        """
        初始化测试用例程序，创建默认的主参与者及其代码段。

        :param asm_path: 汇编文件路径
        :param seed: 生成种子，默认为0
        """
        self.generator_seed = seed
        self._asm_path = asm_path
        # 创建测试用例退出基本块
        self._tc_exit_bb = BasicBlock(TC_EXIT_LABEL)

        # 初始化主参与者和其代码段
        self._actors = {"main": Actor.create_main()}
        self._sections = [CodeSection(self._actors["main"])]

    def __len__(self) -> int:
        """ 测试用例的长度即其代码段数量。

        Length of the test case is the number of sections """
        return len(self._sections)

    def __getitem__(self, id_: int) -> CodeSection:
        """ 通过索引获取代码段。

        Get a section by its index """
        return self._sections[id_]

    def get_tc_exit_bb(self) -> BasicBlock:
        """ 获取用于终止测试用例的特殊基本块。

        Get the special basic block used to terminate the test case """
        return self._tc_exit_bb

    # ----------------------------------------------------------------------------------------------
    # 迭代器
    # Iterators
    def __iter__(self) -> GeneratorType[CodeSection, None, None]:
        """ 默认迭代器，遍历测试用例中的代码段。

        Default iterator over the sections in the test case """
        for sec in self._sections:
            yield sec

    def iter_functions(self) -> GeneratorType[Function, None, None]:
        """ 非默认迭代器：遍历测试用例中的所有函数。

        Non-default iterator: Iterate over all functions in the test case """
        for sec in self._sections:
            for func in sec:
                yield func

    def iter_basic_blocks(self) -> GeneratorType[BasicBlock, None, None]:
        """
        非默认迭代器：按汇编文件中的出现顺序遍历测试用例中的所有基本块。

        Non-default iterator:
        Iterate over all basic blocks in the test case in their order of appearance in the asm file
        """
        for sec in self._sections:
            for func in sec:
                for bb in func:
                    yield bb

    # ----------------------------------------------------------------------------------------------
    # ELF文件管理
    # ELF file management
    def assign_obj(self, obj_path: str) -> None:
        """
        分配从汇编文件生成的目标文件。

        :param obj_path: 目标文件路径
        :raises AssertionError: 如果目标文件已分配

        Assign an object file generated from the assembly file
        :param obj_path: The path to the object file
        :return: None
        :raises AssertionError: If the object file is already assigned
        """
        assert self._obj is None, "Object file is already assigned"
        self._obj = TestCaseBinary(obj_path, self)

    def mark_as_assembled(self) -> None:
        """ 标记目标文件为已汇编状态。

        Mark the object file as assembled """
        assert self._obj is not None, "Object file is not assigned"
        self._obj_is_assembled = True
        self._obj.mark_as_assembled()

    def get_obj(self) -> TestCaseBinary:
        """
        获取已分配的TestCaseBinary对象（目标文件容器）。

        Get assigned TestCaseBinary, the container of the object file
        generated from the test case program
        """
        assert self._obj is not None, "Object file is not assigned"
        return self._obj

    # ----------------------------------------------------------------------------------------------
    # ASM文件管理
    # ASM file management
    def reassign_asm_file(self, asm_path: str) -> None:
        """ 重新分配汇编文件路径（仅在未汇编时允许）。

        Assign a new assembly file to the test case """
        assert not self._obj_is_assembled, \
            "Attempting to reassign the asm file after it has been assembled"
        self._asm_path = asm_path

    def asm_path(self) -> str:
        """ 获取分配的汇编文件路径。

        Get the path to the assigned assembly file """
        return self._asm_path

    def save(self, path: str) -> None:
        """
        将测试用例汇编代码保存到文件。

        :param path: 保存路径

        Save the test case assembly into a file.
        :param path: The path to the file
        :return: None
        """
        shutil.copy2(self._asm_path, path)

    # ----------------------------------------------------------------------------------------------
    # 参与者列表管理
    # Actor list management
    def add_actor_with_section(self, actor: Actor, allow_overwrite: bool = False) -> None:
        """
        向测试用例添加参与者并分配空代码段。

        如果同名参与者已存在且allow_overwrite为True，新参与者将覆盖旧的。
        否则，将抛出错误。

        :param actor: 要添加的参与者
        :param allow_overwrite: 是否允许覆盖现有参与者
        :raises ValueError: 如果参与者已存在且不允许覆盖

        Add an actor to the test case and assign it an empty CodeSection.

        If an actor with the same name already exists and `allow_overwrite` is True,
        the new actor will overwrite the existing one.
        Otherwise, an error will be raised.
        :param actor: The actor to add
        :param allow_overwrite: Whether to allow overwriting an existing actor
        :return: None
        :raises ValueError: If the actor already exists in the test case
        """
        if not allow_overwrite and actor.name in self._actors:
            raise ValueError(f"Actor {actor.name} already exists in the test case")

        # 主参与者的更新：必须为HOST/KERNEL模式
        # Update of the main actor
        if actor.is_main:
            assert actor.mode == ActorMode.HOST
            assert actor.privilege_level == ActorPL.KERNEL
            self._actors[actor.name] = actor
            section = self._sections[0]
            section.owner = actor
            actor.assign_code_section(section)
            return

        # 已有参与者的更新：保留原代码段
        # Update of an actor
        if allow_overwrite and actor.name in self._actors:
            self._actors[actor.name] = actor
            section = self.find_section(actor.name)
            section.owner = actor
            actor.assign_code_section(section)
            return

        # 新参与者：创建新的代码段
        # New actor
        self._actors[actor.name] = actor
        section = CodeSection(actor)
        self._sections.append(section)

    def get_actors(self, sorted_: bool = False) -> List[Actor]:
        """
        获取参与者列表。

        :param sorted_: 是否按ID排序参与者
        :return: 参与者列表

        Get a list of actors.
        :param sorted: Whether to sort the actors by ID
        :return: A list of actors
        """
        if sorted_:
            return sorted(self._actors.values(), key=lambda x: x.get_id())
        return list(self._actors.values())

    def find_actor(self,
                   name: Optional[ActorName] = None,
                   actor_id: Optional[ActorID] = None) -> Actor:
        """
        通过名称或ID查找参与者。必须提供名称或ID之一，但不能同时提供两者。

        :param name: 参与者名称
        :param actor_id: 参与者ID
        :return: 参与者对象
        :raises KeyError: 如果给定名称/ID的参与者不存在
        :raises ValueError: 如果既未提供名称也未提供ID，或两者都提供了

        Select an actor by name or ID.
        :param name: The name of the actor
        :param actor_id: The ID of the actor
        :return: The actor
        :raises KeyError: If an actor with the given name/ID does not exist in the test case
        :raises ValueError: If neither name nor ID is provided or if both are provided
        """
        # 检查接口约束：必须提供名称或ID之一，且不能同时提供
        # check interface
        assert name is not None or actor_id is not None, "Either name or ID must be provided"
        assert name is None or actor_id is None, "Only one of name or ID should be provided"

        # 通过名称查找
        # select by name
        if name is not None:
            if name not in self._actors:
                raise KeyError(f"Actor {name} does not exist in the test case")
            return self._actors[name]

        # 通过ID查找：遍历所有参与者
        # select by ID
        for actor in self._actors.values():
            if actor.get_id() == actor_id:
                return actor
        raise KeyError(f"Actor with ID {actor_id} does not exist in the test case")

    def n_actors(self) -> int:
        """
        获取测试用例中的参与者数量。

        :return: 参与者数量

        Get the number of actors in the test case.
        :return: The number of actors
        """
        return len(self._actors)

    # ==============================================================================================
    # 函数和段管理
    # Function and section management
    def get_sections(self) -> List[CodeSection]:
        """ 获取测试用例中的代码段列表。

        Get a list of sections in the test case """
        return self._sections

    def find_section(self, name: str) -> CodeSection:
        """
        通过名称查找代码段。

        :param name: 代码段名称
        :return: 代码段对象
        :raises KeyError: 如果代码段不存在

        Get a section by name
        :param name: The name of the section
        :return: The section
        :raises KeyError: If the section does not exist in the test case
        """
        for sec in self._sections:
            if sec.name == name:
                return sec
        raise KeyError(f"Section {name} does not exist in the test case")

    def find_function(self, name: str) -> Function:
        """
        通过名称查找函数。

        :param name: 函数名称
        :return: 函数对象
        :raises KeyError: 如果函数不存在

        Get a function by name
        :param name: The name of the function
        :return: The function
        :raises KeyError: If the function does not exist in the test case
        """
        for sec in self._sections:
            for func in sec:
                if func.name == name:
                    return func
        raise KeyError(f"Function {name} does not exist in the test case")

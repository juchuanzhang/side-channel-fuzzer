"""
文件: 从Side Channel Fuzzer仓库下载x86指令集规范，并将其解析为JSON格式供生成器使用
File: A script that downloads the x86 instruction set from the Side Channel Fuzzer repository
      and parses it into a JSON file that can be used by the generator.

本模块实现了x86指令集规范的获取和解析流程：
- 定义x86寄存器位宽、非控制流指令、安全扩展指令等常量
- 解析XML格式的x86指令集规范文件，提取指令和操作数信息
- 将解析结果转换为JSON格式保存
- 支持指令扩展过滤和缺失指令补充
- 下载远程XML规范文件并自动清理

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import sys
import json
import subprocess
from typing import List, Optional, Literal
from xml.etree import ElementTree as ET

# ==================================================================================================
# x86特定常量定义
# ==================================================================================================

# x86寄存器位宽映射：寄存器名到其位宽大小(位)
REG_SIZE = {
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "r11": 64,
    "rip": 64,
    "rsp": 64,
    "rbp": 64,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "ax": 16,
    "dx": 16,
    "bp": 16,
    "sp": 16,
    "al": 8,
    "ah": 8,
    "cl": 8,
    "spl": 8,
    "tmm0": 0,
    "mxcsr": 32,
    'es': 16,
    'ss': 16,
    'ds': 16,
    'fs': 16,
    'gs': 16,
    'cr0': 64,
    'cr3': 64,
    'cr4': 64,
    'cr8': 64,
    'xcr0': 64,
    'dr0': 64,
    'dr1': 64,
    'dr2': 64,
    'dr3': 64,
    'dr6': 64,
    'dr7': 64,
    'gdtr': 80,
    'ldtr': 96,
    'idtr': 80,
    'tr': 16,
    'msrs': 64,
    'x87control': 16,
    'x87pop': 16,
    'x87status': 16,
    'tsc': 64,
    "tscaux": 64,
    "fsbase": 64,
    "gsbase": 64,
}
# 批量添加MMX/XMM/YMM寄存器的位宽
REG_SIZE.update({f"mm{i}": 64 for i in range(8)})
REG_SIZE.update({f"xmm{i}": 128 for i in range(16)})
REG_SIZE.update({f"ymm{i}": 256 for i in range(16)})
# ZMM寄存器暂不启用（AVX-512需要更大支持）
# REG_SIZE.update({f"zmm{i}": 512 for i in range(32)})

# 虽然以RIP为操作数，但不应被视为控制流指令的指令列表
# （如int, int1等中断指令，它们虽然使用RIP但不是分支）
NON_CONTROL_FLOW_INST = ["int", "int1", "int3", "into"]

# ==================================================================================================
# x86扩展指令列表
# ==================================================================================================

# 安全扩展指令：可以在Unicorn默认后端中安全测试的指令扩展
SAFE_EXTENSIONS = [
    "BASE",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE4a",
    "CLFLUSHOPT",
    "CLFSH",
    "SSE",
    "RDTSCP",
    "LONGMODE",
]

# 安全扩展指令（DynamoRIO后端）：可以在DynamoRIO实验性后端中安全测试的指令扩展
SAFE_EXTENSIONS_DR = [
    "3DNOW_PREFETCH",
    "3DNOW",
    "ADOX_ADCX",
    "AES",
    "AVX_VNNI",
    "AVX",
    "AVX2",
    "AVX2GATHER",
    "AVX512EVEX",
    "AVX512VEX",
    "AVXAES",
    "BASE",
    "BMI1",
    "BMI2",
    "CLFLUSHOPT",
    "CLFSH",
    "FMA",
    "FMA4",
    "GFNI",
    "LONGMODE",
    "LZCNT",
    "MCOMMIT",
    "MMX",
    "MOVBE",
    "MOVDIR",
    "PCLMULQDQ",
    "PCONFIG",
    "PKU",
    "PREFETCHWT1",
    "PTWRITE",
    "RDPID",
    "RDPRU",
    "RDRAND",
    "RDSEED",
    "RDWRFSGS",
    "SERIALIZE",
    "SHA",
    "SMAP",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE4a",
    "SSSE3",
    "TBM",
    "UINTR",
    "VAES",
    "VPCLMULQDQ",
    "XOP",
]

# 所有扩展指令：包含可能使系统崩溃的危险扩展（仅在配置正确时可安全测试）
ALL_EXTENSIONS = SAFE_EXTENSIONS + [
    "VTX",
    "SVM",
    "SMX",
    "WBNOINVD",
    "XSAVE",
    "XSAVEOPT",
    "XSAVES",
    "SGX",
    "ENQCMD",
    "INVPCID",
    "KEYLOCKER",
    "MONITOR",
    "PAUSE",
    "RDRAND",
    "RDSEED",
    "RDWRFSGS",
    "HRESET",
    "SMAP",
    "AMD_INVLPGB",
    "SNP",
]

# ==================================================================================================
# 表示解析后XML数据的内部类
# ==================================================================================================

# 操作数类型枚举
OP_TYPE = Literal["REG", "MEM", "AGEN", "IMM", "LABEL", "FLAGS"]


class _XMLOperandSpec:
    """
    从XML文件解析的操作数规格类。

    表示一条指令的单个操作数，包含：
    - values: 操作数的可能值列表（如寄存器名列表）
    - type_: 操作数类型（REG/MEM/AGEN/IMM/LABEL/FLAGS）
    - xtype: 扩展类型属性
    - width: 操作数位宽
    - is_signed: 是否为有符号操作数
    - src: 是否为源操作数（被读取）
    - dest: 是否为目标操作数（被写入）
    - magic: 是否为隐式/特殊操作数
    - comment: 注释信息
    """
    values: List[str]
    type_: OP_TYPE
    xtype: str
    width: int
    is_signed: bool = True
    comment: str
    src: bool = False
    dest: bool = False
    magic: bool = False

    def to_json(self) -> str:
        """
        将操作数规格转换为JSON字符串。

        先将所有值转换为小写，然后序列化为JSON。

        :return: JSON格式的操作数规格字符串
        """
        values_lower = []
        for v in self.values:
            values_lower.append(v.lower())
        self.values = values_lower
        return json.dumps(self, default=vars)


class _XMLInstructionSpec:
    """
    从XML文件解析的指令规格类。

    表示一条完整的x86指令，包含：
    - name: 指令名称
    - category: 指令类别（扩展名-类别名格式）
    - is_control_flow: 是否为控制流指令
    - operands: 显式操作数列表
    - implicit_operands: 隐式操作数列表
    """
    name: str
    category: str = ""
    is_control_flow: bool = False
    operands: List[_XMLOperandSpec]
    implicit_operands: List[_XMLOperandSpec]

    def __init__(self) -> None:
        self.operands = []
        self.implicit_operands = []

    def __str__(self) -> str:
        """ 返回指令规格的简要字符串描述 """
        return f"{self.name} {self.is_control_flow} {self.category} " \
            f"{len(self.operands)} {len(self.implicit_operands)}"

    def to_json(self) -> str:
        """
        将指令规格转换为JSON字符串。

        手动构建JSON格式字符串，包含指令名、类别、控制流标志、
        显式操作数和隐式操作数。

        :return: JSON格式的指令规格字符串
        """
        s = "{"
        s += f'"name": "{self.name.lower()}", "category": "{self.category}", '
        s += f'"is_control_flow": {str(self.is_control_flow).lower()},\n'
        s += '  "operands": [\n    '
        s += ',\n    '.join([o.to_json() for o in self.operands])
        s += '\n  ],\n'
        if self.implicit_operands:
            s += '  "implicit_operands": [\n    '
            s += ',\n    '.join([o.to_json() for o in self.implicit_operands])
            s += '\n  ]'
        else:
            s += '  "implicit_operands": []'
        s += "\n}"
        return s


# ==================================================================================================
# 解析XML文件并转换为JSON的类
# ==================================================================================================
class _ParseFailed(Exception):
    """ 解析失败时抛出的异常 """


class XMLSpecParser:
    """
    XML规范解析器类。

    解析x86指令集的XML规范文件，将指令信息转换为内部的_XMLInstructionSpec对象列表，
    并支持保存为JSON格式。主要功能：
    - 解析XML文件中的指令节点
    - 根据指定的扩展列表过滤指令
    - 处理各类操作数（寄存器、内存、地址生成、立即数、标签、标志位）
    - 补充XML中缺失的指令规格
    - 验证请求的扩展是否可用
    """
    n_instructions_in_xml: int = 0
    _tree: ET.Element
    _instructions: List[_XMLInstructionSpec]
    _current_spec: _XMLInstructionSpec

    def __init__(self, extensions: List[str]) -> None:
        """
        初始化解析器。

        :param extensions: 要解析的指令扩展列表，用于过滤指令
        """
        self.extensions = extensions
        self._instructions = []

    def __len__(self) -> int:
        """ 返回已解析的指令数量 """
        return len(self._instructions)

    def parse_file(self, filename: str) -> None:
        """
        解析XML文件并保存_XMLInstructionSpec对象列表。

        流程：
        1. 从XML文件构建元素树
        2. 检查请求的扩展是否可用
        3. 逐个解析树中的指令节点

        :param filename: XML规范文件的路径
        """
        # 从XML文件构建元素树
        parser = ET.ElementTree()
        tree = parser.parse(filename)
        if not tree:
            print("No input. Exiting")
            sys.exit(1)
        self._tree = tree
        self.n_instructions_in_xml = len(list(self._tree.iter('instruction')))

        # 检查请求的扩展是否可用
        self._check_extension_list()

        # 解析树中的所有节点
        for instruction_node in self._tree.iter('instruction'):
            instruction_spec = self._parse_node(instruction_node)  # pylint: disable=e1128
            if instruction_spec is not None:
                self._instructions.append(instruction_spec)

    def save_as_json(self, filename: str) -> None:
        """
        将解析后的指令列表保存为JSON文件。

        :param filename: JSON输出文件的路径
        """
        json_str = "[\n" + ",\n".join([i.to_json() for i in self._instructions]) + "\n]"
        with open(filename, "w+") as f:
            f.write(json_str)

    def _parse_node(self, node: ET.Element) -> Optional[_XMLInstructionSpec]:
        """
        解析单个XML指令节点。

        流程：
        1. 检查节点是否应被跳过（SAE/舍入/零化等不支持特性）
        2. 检查指令扩展是否在请求列表中
        3. 创建指令规格对象
        4. 逐个解析操作数节点（REG/MEM/AGEN/IMM/relbr/FLAGS）
        5. 设置操作数属性（隐式/源/目标等）
        6. 判断指令是否为控制流指令

        :param node: XML指令节点元素
        :return: 解析后的_XMLInstructionSpec对象，若跳过则返回None
        """
        # pylint: disable=too-many-branches  # 解析器中多分支是合理的

        # 检查节点是否应被跳过
        if self._node_is_not_supported(node):
            return None
        if node.attrib['extension'] not in self.extensions:
            return None

        # 创建新的指令规格对象
        instruction = _XMLInstructionSpec()

        # 解析指令属性
        instruction.category = f"{node.attrib['extension']}-{node.attrib['category']}"
        instruction.name = node.attrib['asm'].removeprefix("{load} ")\
            .removeprefix("{store} ").removeprefix("{disp32} ").lower()

        try:
            for op_node in node.iter('operand'):
                # 根据操作数类型创建对应的操作数规格
                op_type = op_node.attrib['type']
                if op_type == 'reg':
                    parsed_op = self._parse_reg_operand(op_node)
                elif op_type == 'mem':
                    parsed_op = self._parse_mem_operand(op_node)
                elif op_type == 'agen':
                    op_node.text = node.attrib['agen']
                    parsed_op = self._parse_agen_operand(op_node)
                elif op_type == 'imm':
                    parsed_op = self._parse_imm_operand(op_node)
                elif op_type == 'relbr':
                    parsed_op = self._parse_label_operand(op_node)
                elif op_type == 'flags':
                    parsed_op = self._parse_flags_operand(op_node)
                else:
                    raise _ParseFailed("Unknown operand type " + op_type)

                # 将操作数添加到指令规格中
                # suppressed=1的操作数为隐式操作数
                if op_node.attrib.get('suppressed', '0') == '1':
                    instruction.implicit_operands.append(parsed_op)
                else:
                    instruction.operands.append(parsed_op)

                # 设置操作数的额外属性
                if op_node.attrib.get('implicit', '0') == '1':
                    parsed_op.magic = True

                # 根据操作数类型设置指令的控制流属性
                if parsed_op.type_ == "REG":
                    text = getattr(op_node, 'text', '').lower()
                    # RIP操作数通常表示控制流，但排除中断指令
                    if text == "rip" and instruction.name not in NON_CONTROL_FLOW_INST:
                        instruction.is_control_flow = True
                elif parsed_op.type_ == "LABEL":
                    instruction.is_control_flow = True

        except _ParseFailed as e:
            # 解析失败时跳过该指令
            print(f"WARN: Skipping instruction {instruction.name} due to `{e}`")
            return None

        return instruction

    def _node_is_not_supported(self, node: ET.Element) -> bool:
        """
        检查XML节点是否包含不支持的特性。

        SAE(Suppress All Exceptions)、舍入控制(roundc)和零化(zeroing)
        是AVX-512的特性，目前不支持。

        :param node: XML指令节点
        :return: True表示节点不被支持应跳过
        """
        return node.attrib.get('sae', '') == '1' or \
            node.attrib.get('roundc', '') == '1' or \
            node.attrib.get('zeroing', '') == '1'

    def _parse_reg_operand(self, op: ET.Element) -> _XMLOperandSpec:
        """
        解析寄存器操作数。

        从XML节点提取寄存器名列表、读写属性和位宽信息。
        若位宽未指定，则从REG_SIZE映射中查找。

        :param op: XML操作数节点
        :return: 寄存器操作数规格对象
        :raises _ParseFailed: 若寄存器不在REG_SIZE映射中
        """
        assert op.text is not None

        spec = _XMLOperandSpec()
        spec.type_ = "REG"
        if op.attrib.get('xtype', '') != '':
            spec.xtype = op.attrib.get('xtype', '')

        # 解析寄存器值列表（逗号分隔的多个可选寄存器）
        spec.values = op.text.lower().split(',')
        if spec.values[0] not in REG_SIZE:
            raise _ParseFailed(f"Unsupported register operand {spec.values[0]}")

        # 读取/写入属性
        spec.src = op.attrib.get('r', "0") == "1"
        spec.dest = op.attrib.get('w', "0") == "1"

        # 位宽：优先使用XML中的width属性，否则从REG_SIZE查找
        spec.width = int(op.attrib.get('width', 0))
        if spec.width == 0:
            spec.width = REG_SIZE[spec.values[0]]

        return spec

    @staticmethod
    def _parse_mem_operand(op: ET.Element) -> _XMLOperandSpec:
        """
        解析内存操作数。

        从XML节点提取内存操作的基址寄存器、读写属性和位宽。
        不支持VSIB（Vector SIB）内存寻址和内存后缀。

        :param op: XML操作数节点
        :return: 内存操作数规格对象
        :raises _ParseFailed: 若包含VSIB寻址或不支持的内存后缀
        """
        assert op.attrib is not None

        # 不支持的功能检查
        if op.attrib.get('VSIB', '0') != '0':
            raise _ParseFailed("Vector SIB memory addressing is not supported")
        if op.attrib.get('memory-suffix', '') != '':
            raise _ParseFailed(f"Unsupported memory suffix {op.attrib.get('memory-suffix', '')}")

        # 提取基址寄存器选项
        choices = []
        if op.attrib.get('base', ''):
            choices = [op.attrib.get('base', '')]

        spec = _XMLOperandSpec()
        spec.type_ = "MEM"
        spec.values = choices
        spec.src = op.attrib.get('r', "0") == "1"
        spec.dest = op.attrib.get('w', "0") == "1"
        spec.width = int(op.attrib.get('width', '0'))
        return spec

    @staticmethod
    def _parse_agen_operand(_: ET.Element) -> _XMLOperandSpec:
        """
        解析地址生成(AGEN)操作数。

        AGEN操作数表示LEA等指令中的地址计算，固定为64位宽。

        :param _: XML操作数节点（未使用）
        :return: AGEN操作数规格对象
        """
        spec = _XMLOperandSpec()
        spec.type_ = "AGEN"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 64
        return spec

    @staticmethod
    def _parse_imm_operand(op: ET.Element) -> _XMLOperandSpec:
        """
        解析立即数操作数。

        从XML节点提取立即数的值（仅隐式立即数有值）、位宽和符号属性。

        :param op: XML操作数节点
        :return: 立即数操作数规格对象
        """
        assert op.attrib is not None

        spec = _XMLOperandSpec()
        spec.type_ = "IMM"
        if op.attrib.get('implicit', '0') == '1':
            assert op.text is not None
            spec.values = [op.text]  # 隐式立即数有固定值
        else:
            spec.values = []  # 显式立即数无固定值，由生成器随机填充
        spec.src = True
        spec.dest = False
        spec.width = int(op.attrib.get('width', '0'))
        # 符号属性：s=0表示无符号，默认为有符号
        if op.attrib.get('s', '1') == '0':
            spec.is_signed = False
        return spec

    @staticmethod
    def _parse_label_operand(_: ET.Element) -> _XMLOperandSpec:
        """
        解析标签/分支目标操作数。

        用于分支指令的目标地址（相对分支），位宽为0（由生成器处理）。

        :param _: XML操作数节点（未使用）
        :return: 标签操作数规格对象
        """
        spec = _XMLOperandSpec()
        spec.type_ = "LABEL"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 0
        return spec

    @staticmethod
    def _parse_flags_operand(op: ET.Element) -> _XMLOperandSpec:
        """
        解析标志寄存器操作数。

        从XML节点提取各标志位(CF/PF/AF/ZF/SF/TF/IF/DF/OF)的读写属性。
        属性值可能为：r(读)、w(写)、r/w(读写)、r/cw(条件写)、undef(未定义)。

        :param op: XML操作数节点
        :return: 标志操作数规格对象
        """
        spec = _XMLOperandSpec()
        spec.type_ = "FLAGS"
        spec.values = [
            op.attrib.get("flag_CF", ""),
            op.attrib.get("flag_PF", ""),
            op.attrib.get("flag_AF", ""),
            op.attrib.get("flag_ZF", ""),
            op.attrib.get("flag_SF", ""),
            op.attrib.get("flag_TF", ""),
            op.attrib.get("flag_IF", ""),
            op.attrib.get("flag_DF", ""),
            op.attrib.get("flag_OF", ""),
        ]
        spec.src = False
        spec.dest = False
        spec.width = 0
        return spec

    def add_missing(self) -> None:  # pylint: disable=too-many-statements
        """
        补充XML规范文件中缺失的指令规格。

        XML文件中可能缺少某些指令的定义（如CLFLUSH、CLFLUSHOPT、INT1），
        此方法手动创建这些指令的规格并添加到列表中。

        为CLFLUSH和CLFLUSHOPT创建不同位宽的内存操作数版本，
        为INT1创建隐式RIP和标志操作数的版本。
        """
        extensions = self.extensions
        # 补充CLFLUSH指令规格（不同位宽的内存操作数版本）
        if not extensions or "CLFSH" in extensions:
            for width in [8, 16, 32, 64]:
                inst = _XMLInstructionSpec()
                inst.name = "clflush"
                inst.category = "CLFSH-MISC"
                inst.is_control_flow = False
                op = _XMLOperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self._instructions.append(inst)

        # 补充CLFLUSHOPT指令规格
        if not extensions or "CLFLUSHOPT" in extensions:
            for width in [8, 16, 32, 64]:
                inst = _XMLInstructionSpec()
                inst.name = "clflushopt"
                inst.category = "CLFLUSHOPT-CLFLUSHOPT"
                inst.is_control_flow = False
                op = _XMLOperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self._instructions.append(inst)

        # 补充INT1指令规格（ICEBP/类别中断）
        if not extensions or "BASE" in extensions:
            inst = _XMLInstructionSpec()
            inst.name = "int1"
            inst.category = "BASE-INTERRUPT"
            inst.is_control_flow = False
            op1 = _XMLOperandSpec()
            op1.type_, op1.src, op1.dest, op1.width = "REG", False, True, 64
            op1.values = ["rip"]
            op2 = _XMLOperandSpec()
            op2.type_, op2.src, op2.dest, op2.width = "FLAGS", False, False, 0
            op2.values = ["", "", "", "", "", "w", "w", "", ""]
            inst.implicit_operands = [op1, op2]
            self._instructions.append(inst)

    def _check_extension_list(self) -> None:
        """
        验证请求的指令扩展是否在XML文件中可用。

        遍历XML树获取所有可用的扩展列表，
        对于每个不在可用列表中的请求扩展打印错误信息。
        """
        # 获取所有可用扩展列表
        available_extensions = set()
        for instruction_node in self._tree.iter('instruction'):
            available_extensions.add(instruction_node.attrib['extension'])

        # 检查请求的扩展是否可用
        for ext in self.extensions:
            if ext not in available_extensions:
                print(f"ERROR: Unknown extension {ext}")
                print("\nAvailable extensions:")
                print(list(available_extensions))


class Downloader:
    """
    x86指令集规范下载器类。

    从远程仓库下载x86指令集的XML规范文件，
    解析并转换为JSON格式保存到本地。

    支持三种扩展选择模式：
    - ALL_SUPPORTED: 使用Unicorn安全扩展列表
    - ALL_SUPPORTED_DR: 使用DynamoRIO安全扩展列表
    - ALL_AND_UNSAFE: 使用所有扩展（包括危险扩展）
    """

    def __init__(self, extensions: List[str], out_file: str) -> None:
        """
        初始化下载器。

        根据扩展选择模式解析扩展列表，创建XML规范解析器。

        :param extensions: 指令扩展列表或特殊模式标识
        :param out_file: JSON输出文件路径
        """
        if "ALL_SUPPORTED" in extensions:
            extensions.extend(SAFE_EXTENSIONS)
            extensions = list(set(extensions))
            extensions.remove("ALL_SUPPORTED")
        elif "ALL_SUPPORTED_DR" in extensions:
            extensions.extend(SAFE_EXTENSIONS_DR)
            extensions = list(set(extensions))
            extensions.remove("ALL_SUPPORTED_DR")
        elif "ALL_AND_UNSAFE" in extensions:
            extensions.extend(ALL_EXTENSIONS)
            extensions = list(set(extensions))
            extensions.remove("ALL_AND_UNSAFE")
        self.extensions = extensions
        self.out_file = out_file
        self._transformer = XMLSpecParser(self.extensions)

    def run(self) -> None:
        """
        执行下载和转换流程。

        流程：
        1. 使用curl下载XML规范文件
        2. 解析XML文件并过滤指令
        3. 补充缺失的指令规格
        4. 保存为JSON格式
        5. 清理临时XML文件
        """
        print("> Downloading complete instruction spec...")
        subprocess.run(
            "curl -L -o x86_instructions.xml "
            "https://github.com/microsoft/side-channel-fuzzer/releases/download/"
            "v1.3.0/x86_instructions.xml",
            shell=True,
            check=True)

        print("\n> Filtering and transforming the instruction spec...")
        try:
            self._transformer.parse_file("x86_instructions.xml")
            self._transformer.add_missing()
            self._transformer.save_as_json(self.out_file)
        finally:
            # 清理临时XML文件
            subprocess.run("rm x86_instructions.xml", shell=True, check=True)

        n_parsed = len(self._transformer)
        n_all = self._transformer.n_instructions_in_xml
        print(f"Produced base.json with {n_parsed} instructions (out of {n_all} possible)")


# 注意：以下是XML文件中所有可用的指令类别完整列表（供参考）：
# "3DNOW-3DNOW", "ADOX_ADCX-ADOX_ADCX", "AES-AES", "AVXAES-AES", "AMX_BF16-AMX_TILE",
# "AMX_INT8-AMX_TILE", "AMX_TILE-AMX_TILE", "AVX2-AVX2", "AVX2GATHER-AVX2GATHER",
# "AVX512EVEX-AVX512_4FMAPS", "AVX512EVEX-AVX512_4VNNIW", "AVX512EVEX-AVX512_BITALG",
# "AVX512EVEX-AVX512", "AVX512EVEX-AVX512_VBMI", "AVX512EVEX-AVX512_VP2INTERSECT", "AVX-AVX",
# "BASE-BINARY", "BASE-BITBYTE", "SSE4a-BITBYTE", "AVX512EVEX-BLEND", "BMI1-BMI1", "BMI2-BMI2",
# "AVX-BROADCAST", "AVX2-BROADCAST", "AVX512EVEX-BROADCAST", "BASE-CALL", "CET-CET",
# "CLDEMOTE-CLDEMOTE", "CLFLUSHOPT-CLFLUSHOPT", "CLWB-CLWB", "CLZERO-CLZERO", "BASE-CMOV",
# "AVX512EVEX-COMPRESS", "BASE-COND_BR", "RTM-COND_BR", "AVX512EVEX-CONFLICT", "AVX-CONVERT",
# "AVX512EVEX-CONVERT", "BASE-CONVERT", "F16C-CONVERT", "LONGMODE-CONVERT", "SSE-CONVERT",
# "SSE2-CONVERT", "AVX-DATAXFER", "AVX2-DATAXFER", "AVX512EVEX-DATAXFER", "BASE-DATAXFER",
# "LONGMODE-DATAXFER", "MMX-DATAXFER", "MOVBE-DATAXFER", "SSE-DATAXFER", "SSE2-DATAXFER",
# "SSE3-DATAXFER", "SSE4a-DATAXFER", "ENQCMD-ENQCMD", "AVX512EVEX-EXPAND", "X87-FCMOV",
# "BASE-FLAGOP", "FMA4-FMA4", "AVX512EVEX-FP16", "AVX512EVEX-GATHER", "AVX512EVEX-GFNI",
# "GFNI-GFNI", "HRESET-HRESET", "AVX512EVEX-IFMA", "BASE-INTERRUPT", "BASE-IO",
# "BASE-IOSTRINGOP", "KEYLOCKER-KEYLOCKER", "KEYLOCKER_WIDE-KEYLOCKER_WIDE",
# "AVX512VEX-KMASK", "TDX-LEGACY", "AVX-LOGICAL", "AVX2-LOGICAL", "AVX512EVEX-LOGICAL",
# "BASE-LOGICAL", "MMX-LOGICAL", "RTM-LOGICAL", "SSE2-LOGICAL", "SSE4-LOGICAL",
# "AVX-LOGICAL_FP", "AVX512EVEX-LOGICAL_FP", "SSE-LOGICAL_FP", "SSE2-LOGICAL_FP",
# "LZCNT-LZCNT", "BASE-MISC", "CLFSH-MISC", "INVPCID-MISC", "MCOMMIT-MISC", "MONITOR-MISC",
# "MONITORX-MISC", "PAUSE-MISC", "SSE-MISC", "SSE2-MISC", "3DNOW-MMX", "MMX-MMX",
# "SSE2-MMX", "SSSE3-MMX", "MOVDIR-MOVDIR", "MPX-MPX", "BASE-NOP", "PCLMULQDQ-PCLMULQDQ",
# "PCONFIG-PCONFIG", "PKU-PKU", "BASE-POP", "LONGMODE-POP", "3DNOW_PREFETCH-PREFETCH",
# "SSE-PREFETCH", "PREFETCHWT1-PREFETCHWT1", "PTWRITE-PTWRITE", "BASE-PUSH", "LONGMODE-PUSH",
# "RDPID-RDPID", "RDPRU-RDPRU", "RDRAND-RDRAND", "RDSEED-RDSEED", "RDWRFSGS-RDWRFSGS",
# "BASE-RET", "LONGMODE-RET", "BASE-ROTATE", "AVX512EVEX-SCATTER", "BASE-SEGOP", "BASE-SEMAPHORE",
# "LONGMODE-SEMAPHORE", "SERIALIZE-SERIALIZE", "BASE-SETCC", "SGX-SGX", "SHA-SHA",
# "BASE-SHIFT", "SMAP-SMAP", "SSE-SSE", "SSE2-SSE", "SSE3-SSE", "SSE4-SSE", "SSSE3-SSE",
# "BASE-STRINGOP", "LONGMODE-STRINGOP", "AVX-STTNI", "BASE-SYSCALL", "LONGMODE-SYSCALL",
# "BASE-SYSRET", "LONGMODE-SYSRET", "AMD_INVLPGB-SYSTEM", "BASE-SYSTEM", "LONGMODE-SYSTEM",
# "RDTSCP-SYSTEM", "SMX-SYSTEM", "SNP-SYSTEM", "SVM-SYSTEM", "WBNOINVD-SYSTEM", "TBM-TBM",
# "TSX_LDTRK-TSX_LDTRK", "UINTR-UINTR", "BASE-UNCOND_BR", "RTM-UNCOND_BR", "AVX512EVEX-VAES",
# "VAES-VAES", "AVX512EVEX-VBMI2", "AVX_VNNI-VEX", "AVX512EVEX-VFMA", "FMA-VFMA",
# "VIA_PADLOCK_AES-VIA_PADLOCK", "VIA_PADLOCK_RNG-VIA_PADLOCK", "VIA_PADLOCK_SHA-VIA_PADLOCK",
# "AVX512EVEX-VPCLMULQDQ", "VPCLMULQDQ-VPCLMULQDQ", "VMFUNC-VTX", "VTX-VTX", "WAITPKG-WAITPKG",
# "BASE-WIDENOP", "SSE3-X87_ALU", "X87-X87_ALU", "XOP-XOP", "XSAVE-XSAVE", "XSAVEC-XSAVE",
# "XSAVES-XSAVE", "XSAVEOPT-XSAVEOPT"

"""
文件：配置工厂 - 根据配置选项构建各组件对象实例

本模块实现了工厂模式，根据全局配置 CONF 中的选项值创建对应的
模糊测试器、执行器、合约模型、程序生成器、汇编解析器、ELF 解析器、
输入数据生成器、分析器、最小化器和 ISA 规范下载器等组件实例。

工厂函数通过配置选项字符串查找对应的类类型，并实例化返回，
若配置值不在可选范围内则抛出 FactoryException 或 ConfigException。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Dict, Type, List, TYPE_CHECKING, Any, Optional, Union

from . import data_generator, analyser, executor, fuzzer, model, elf_parser
from .model_unicorn import tracer, speculator_abc, speculators_basic, \
    speculators_fault, speculators_vs, interpreter, model as uc_model
from .model_dynamorio import model as dr_model
from .postprocessing.minimizer import Minimizer

from .arch.x86 import asm_parser as x86_asm_parser, \
    executor as x86_executor, fuzzer as x86_fuzzer, generator as x86_generator, \
    target_desc as x86_target_desc, get_spec as x86_get_spec
from .arch.arm64 import asm_parser as arm64_asm_parser, \
    executor as arm64_executor, fuzzer as arm64_fuzzer, generator as arm64_generator, \
    target_desc as arm64_target_desc, get_spec as arm64_get_spec
from .config import CONF, ConfigException

if TYPE_CHECKING:
    from .isa_spec import InstructionSet
    from .target_desc import TargetDesc
    from .code_generator import CodeGenerator
    from .asm_parser import AsmParser
    from .sandbox import BaseAddrTuple


class FactoryException(SystemExit):
    """工厂异常类 - 当配置选项值不在可选范围内时抛出，显示可用选项列表"""

    def __init__(self, options: Dict[str, Type[Any]], key: str, conf_option_name: str) -> None:
        """初始化工厂异常，显示无效配置值及所有可用选项。

        参数:
            options: 可选的配置值到类类型的映射字典
            key: 无效的配置选项值
            conf_option_name: 配置选项名称
        """
        super().__init__(
            f"ERROR: unknown value `{key}` of `{conf_option_name}` configuration option.\n"
            "  Available options are:\n  - " + "\n  - ".join(options.keys()))


# ==================================================================================================
# 公共枚举映射 - 架构到目标描述类的映射
# ==================================================================================================
_TARGET_DESC: Dict[str, Type[TargetDesc]] = {
    "x86-64": x86_target_desc.X86TargetDesc,
    "arm64": arm64_target_desc.ARM64TargetDesc,
}
"""架构到目标描述类的映射 - 提供架构相关的寄存器、指令编码等信息"""


# ==================================================================================================
# 模糊测试器构建 - 根据配置创建对应架构和模式的模糊测试器
# ==================================================================================================
def get_fuzzer(instruction_set_path: str, working_directory: str, existing_test_case: str,
               input_paths: Optional[List[str]]) -> fuzzer.Fuzzer:
    """ 根据 CONF 配置选项构建模糊测试器实例。

    根据 CONF.fuzzer（basic/architectural/archdiff）和 CONF.instruction_set
    （x86-64/arm64）的组合选择对应的模糊测试器类进行实例化。

    参数:
        instruction_set_path: ISA 规范文件路径
        working_directory: 工作目录路径
        existing_test_case: 已有测试用例路径（可为空）
        input_paths: 输入文件路径列表（可为 None）

    返回:
        对应类型的模糊测试器实例

    异常:
        ConfigException: 配置选项值未知时抛出
    """

    if CONF.fuzzer == "architectural":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchitecturalFuzzer(instruction_set_path, working_directory,
                                                     existing_test_case, input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64ArchitecturalFuzzer(instruction_set_path, working_directory,
                                                         existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "archdiff":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchDiffFuzzer(instruction_set_path, working_directory,
                                                existing_test_case, input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64ArchDiffFuzzer(instruction_set_path, working_directory,
                                                    existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "basic":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86Fuzzer(instruction_set_path, working_directory, existing_test_case,
                                        input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64Fuzzer(instruction_set_path, working_directory,
                                            existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    raise ConfigException("ERROR: unknown value of `fuzzer` configuration option")


# ==================================================================================================
# 执行器构建 - 根据配置创建对应 CPU 平台的硬件追踪执行器
# ==================================================================================================
_EXECUTORS = {
    'x86-64-intel': x86_executor.X86IntelExecutor,
    'x86-64-amd': x86_executor.X86AMDExecutor,
    'arm64': arm64_executor.ARM64Executor,
}
"""执行器类型映射 - CPU 供应商到对应执行器类"""


def get_executor(enable_mismatch_check_mode: bool = False) -> executor.Executor:
    """ 根据 CONF.executor 配置选项构建执行器实例。

    参数:
        enable_mismatch_check_mode: 是否启用不匹配检查模式

    返回:
        对应类型的执行器实例

    异常:
        FactoryException: 配置值不在可选范围内时抛出
    """
    key: str = CONF.executor
    if key not in _EXECUTORS:
        raise FactoryException(_EXECUTORS, key, "executor")
    return _EXECUTORS[key](enable_mismatch_check_mode)


# ==================================================================================================
# 合约模型构建 - 包括追踪器、推测器和模型后端的选择
# ==================================================================================================
_TRACERS: Dict[str, Type[tracer.UnicornTracer]] = {
    "none": tracer.NoneTracer,
    "l1d": tracer.L1DTracer,
    "pc": tracer.PCTracer,
    "memory": tracer.MemoryTracer,
    "ct": tracer.CTTracer,
    "loads+stores+pc": tracer.CTTracer,
    "ct-nonspecstore": tracer.CTNonSpecStoreTracer,
    "arch": tracer.ArchTracer,
    "tct": tracer.TruncatedCTTracer,
    "tcto": tracer.TruncatedCTWithOverflowsTracer,
    "ct-ni": tracer.ActorNITracer,
}
"""合约追踪器类型映射 - 观测条款到对应追踪器类"""

_SPECULATORS_GENERIC: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    "seq": speculators_basic.SeqSpeculator,
    "no_speculation": speculators_basic.SeqSpeculator,
    "bpas": speculators_basic.StoreBpasSpeculator,
    "cond-bpas": speculators_basic.X86CondBpasSpeculator,
    "seq-assist": speculators_fault.SequentialAssistSpeculator,
}
"""通用推测器映射 - 所有架构共享的推测执行行为模拟器"""

_SPECULATORS_X86: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    **_SPECULATORS_GENERIC,
    "cond": speculators_basic.X86CondSpeculator,
    "conditional_br_misprediction": speculators_basic.X86CondSpeculator,
    "delayed-exception-handling": speculators_fault.X86UnicornDEH,
    "nullinj-fault": speculators_fault.X86UnicornNull,
    "nullinj-assist": speculators_fault.X86UnicornNullAssist,
    "meltdown": speculators_fault.X86Meltdown,
    "noncanonical": speculators_fault.X86NonCanonicalAddress,
    "vspec-ops-div": speculators_vs.VspecDIVSpeculator,
    "vspec-ops-memory-faults": speculators_vs.VspecMemoryFaultsSpeculator,
    "vspec-ops-memory-assists": speculators_vs.VspecMemoryAssistsSpeculator,
    "vspec-ops-gp": speculators_vs.VspecGPSpeculator,
    "vspec-all-div": speculators_vs.VspecAllDIVSpeculator,
    "vspec-all-memory-faults": speculators_vs.VspecAllMemoryFaultsSpeculator,
    "vspec-all-memory-assists": speculators_vs.VspecAllMemoryAssistsSpeculator,
}
"""x86-64 专用推测器映射 - 包含条件分支误预测、延迟异常处理、
空注入、Meltdown、非规范地址、值推测等各类 x86 推测行为模拟器"""

_SPECULATORS_ARM64: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    **_SPECULATORS_GENERIC,
    "cond": speculators_basic.ARM64CondSpeculator,
    "conditional_br_misprediction": speculators_basic.ARM64CondSpeculator,
    "delayed-exception-handling": speculators_fault.ARMUnicornDEH,
}
"""ARM64 专用推测器映射 - 包含条件分支误预测和延迟异常处理"""


def _get_exec_clause_name() -> str:
    """ 根据配置选项确定执行条款名称。

    处理组合执行条款的特殊情况：
    - cond + bpas 组合为 "cond-bpas"
    - conditional_br_misprediction + nullinj-fault 组合为 "cond-nullinj-fault"
    - 单一执行条款直接使用其名称

    返回:
        执行条款名称字符串

    异常:
        ConfigException: 未知的执行条款组合时抛出
    """
    if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
        clause_name = "cond-bpas"
    elif "conditional_br_misprediction" in CONF.contract_execution_clause and \
            "nullinj-fault" in CONF.contract_execution_clause:
        clause_name = "cond-nullinj-fault"
    elif len(CONF.contract_execution_clause) == 1:
        clause_name = CONF.contract_execution_clause[0]
    else:
        raise ConfigException(
            "ERROR: unknown value of `contract_execution_clause` configuration option")
    return clause_name


def _get_x86_unicorn_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                           enable_mismatch_check_mode: bool) -> model.Model:
    """构建 x86-64 Unicorn 后端的合约模型实例。

    根据观测条款和执行条款选择对应的追踪器、推测器和解释器类，
    组合创建 X86UnicornModel 实例。

    参数:
        bases: 沙箱基地址元组
        obs_clause_name: 观测条款名称
        exec_clause_name: 执行条款名称
        enable_mismatch_check_mode: 是否启用不匹配检查模式

    返回:
        X86UnicornModel 实例
    """
    target_desc = _TARGET_DESC[CONF.instruction_set]()
    tracer_cls = _TRACERS[obs_clause_name]
    speculator_cls = _SPECULATORS_X86[exec_clause_name]
    interpreter_cls = interpreter.X86ExtraInterpreter
    model_ = uc_model.X86UnicornModel(bases, target_desc, speculator_cls, tracer_cls,
                                      interpreter_cls, enable_mismatch_check_mode)
    return model_


def _get_arm64_unicorn_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                             enable_mismatch_check_mode: bool) -> model.Model:
    """构建 ARM64 Unicorn 后端的合约模型实例。

    参数和返回值与 _get_x86_unicorn_model 类似，但使用 ARM64 专用组件。

    参数:
        bases: 沙箱基地址元组
        obs_clause_name: 观测条款名称
        exec_clause_name: 执行条款名称
        enable_mismatch_check_mode: 是否启用不匹配检查模式

    返回:
        ARM64UnicornModel 实例
    """
    target_desc = _TARGET_DESC[CONF.instruction_set]()
    tracer_cls = _TRACERS[obs_clause_name]
    speculator_cls = _SPECULATORS_ARM64[exec_clause_name]
    interpreter_cls = interpreter.ARMExtraInterpreter
    model_ = uc_model.ARM64UnicornModel(bases, target_desc, speculator_cls, tracer_cls,
                                        interpreter_cls, enable_mismatch_check_mode)
    return model_


def _get_dr_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                  enable_mismatch_check_mode: bool) -> model.Model:
    """构建 DynamoRIO 后端的合约模型实例。

    DynamoRIO 后端使用 C++ 实现，需通过其 API 检查合约是否被支持。

    参数:
        bases: 沙箱基地址元组
        obs_clause_name: 观测条款名称
        exec_clause_name: 执行条款名称
        enable_mismatch_check_mode: 是否启用不匹配检查模式

    返回:
        DynamoRIOModel 实例

    异常:
        ConfigException: 观测条款或执行条款不被 DynamoRIO 后端支持时抛出
    """
    # DynamoRIO 后端用 C++ 实现，需通过 API 检查合约是否支持
    obs_clauses = dr_model.DynamoRIOModel.get_supported_obs_clauses()
    exec_clauses = dr_model.DynamoRIOModel.get_supported_exec_clauses()

    if obs_clause_name not in obs_clauses:
        raise ConfigException(f"ERROR: unsupported observation clause `{obs_clause_name}`.\n"
                              f"  Available options are:\n  - " + "\n  - ".join(obs_clauses))
    if exec_clause_name not in exec_clauses:
        raise ConfigException(f"ERROR: unsupported execution clause `{exec_clause_name}`.\n"
                              f"  Available options are:\n  - " + "\n  - ".join(exec_clauses))
    model_ = dr_model.DynamoRIOModel(bases, enable_mismatch_check_mode=enable_mismatch_check_mode)
    model_.configure_clauses(obs_clause_name, exec_clause_name)
    return model_


def get_model(bases: BaseAddrTuple, enable_mismatch_check_mode: bool = False) -> model.Model:
    """ 根据 CONF 配置选项构建合约模型实例。

    根据架构（x86-64/arm64）和模型后端（unicorn/dynamorio/dummy）的组合，
    选择对应的模型构建函数创建实例。

    参数:
        bases: 沙箱基地址元组
        enable_mismatch_check_mode: 是否启用不匹配检查模式

    返回:
        对应类型的合约模型实例

    异常:
        ConfigException: 配置选项值未知时抛出
    """
    obs_clause_name = CONF.contract_observation_clause  # 观测条款名称
    exec_clause_name = _get_exec_clause_name()          # 执行条款名称（可能为组合条款）

    if CONF.instruction_set == "x86-64":
        if CONF.model_backend == "unicorn":
            return _get_x86_unicorn_model(bases, obs_clause_name, exec_clause_name,
                                          enable_mismatch_check_mode)
        if CONF.model_backend == "dynamorio":
            return _get_dr_model(bases, obs_clause_name, exec_clause_name,
                                 enable_mismatch_check_mode)
        if CONF.model_backend == "dummy":
            return model.DummyModel(bases, enable_mismatch_check_mode)

        raise ConfigException("ERROR: unknown value of `model_backend` configuration option")

    if CONF.instruction_set == "arm64":
        if CONF.model_backend == "unicorn":
            return _get_arm64_unicorn_model(bases, obs_clause_name, exec_clause_name,
                                            enable_mismatch_check_mode)
        if CONF.model_backend == "dynamorio":
            raise ConfigException("ERROR: DynamoRIO backend is not supported for ARM64")
        if CONF.model_backend == "dummy":
            return model.DummyModel(bases, enable_mismatch_check_mode)

        raise ConfigException("ERROR: unknown value of `model_backend` configuration option")

    raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")


# ==================================================================================================
# 程序生成器及相关类构建
# ==================================================================================================
_GENERATORS: Dict[str, Type[CodeGenerator]] = {
    "x86-64": x86_generator.X86Generator,
    "arm64": arm64_generator.ARM64Generator,
}
"""架构到程序生成器类的映射"""

_ASM_PARSERS: Dict[str, Type[AsmParser]] = {
    'x86-64': x86_asm_parser.X86AsmParser,
    'arm64': arm64_asm_parser.ARM64AsmParser,
}
"""架构到汇编解析器类的映射"""

_ELF_PARSERS: Dict[str, Type[elf_parser.ELFParser]] = {
    'x86-64': elf_parser.ELFParser,
    'arm64': elf_parser.ELFParser,
}
"""架构到 ELF 解析器类的映射"""


def get_program_generator(seed: int, instruction_set: InstructionSet) -> CodeGenerator:
    """
    根据 CONF 配置选项构建程序生成器实例。

    创建目标描述、ELF 解析器和汇编解析器，组合生成对应架构的程序生成器。

    参数:
        seed: 程序生成器的随机种子
        instruction_set: 指令集规范对象

    返回:
        对应架构的程序生成器实例
    """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser_ = _ELF_PARSERS[key](target_desc)
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    generator = _GENERATORS[key](seed, instruction_set, target_desc, asm_parser, elf_parser_)
    return generator


def get_asm_parser(instruction_set: InstructionSet) -> AsmParser:
    """ 根据 CONF 配置选项构建汇编解析器实例。

    参数:
        instruction_set: 指令集规范对象

    返回:
        对应架构的汇编解析器实例
    """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    return asm_parser


def get_elf_parser() -> elf_parser.ELFParser:
    """ 根据 CONF 配置选项构建 ELF 解析器实例。

    返回:
        对应架构的 ELF 解析器实例
    """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser_ = _ELF_PARSERS[key](target_desc)
    return elf_parser_


# ==================================================================================================
# 输入数据生成器构建
# ==================================================================================================
_DATA_GENERATORS: Dict[str, Type[data_generator.DataGenerator]] = {
    'random': data_generator.DataGenerator,
}
"""输入数据生成器类型映射 - 生成器类型到对应类"""


def get_data_generator(seed: int) -> data_generator.DataGenerator:
    """ 根据 CONF.data_generator 配置选项构建输入数据生成器实例。

    参数:
        seed: 数据生成器的随机种子

    返回:
        对应类型的输入数据生成器实例

    异常:
        FactoryException: 配置值不在可选范围内时抛出
    """
    key: str = CONF.data_generator
    if key not in _DATA_GENERATORS:
        raise FactoryException(_DATA_GENERATORS, key, "data_generator")
    return _DATA_GENERATORS[key](seed)


# ==================================================================================================
# 分析器构建
# ==================================================================================================
_ANALYZERS: Dict[str, Type[analyser.Analyser]] = {
    'bitmaps': analyser.MergedBitmapAnalyser,
    'sets': analyser.SetAnalyser,
    'mwu': analyser.MWUAnalyser,
    'chi2': analyser.ChiSquaredAnalyser,
}
"""分析器类型映射 - 分析算法到对应类"""


def get_analyser() -> analyser.Analyser:
    """ 根据 CONF.analyser 配置选项构建追踪分析器实例。

    返回:
        对应类型的分析器实例

    异常:
        FactoryException: 配置值不在可选范围内时抛出
    """
    key: str = CONF.analyser
    if key not in _ANALYZERS:
        raise FactoryException(_ANALYZERS, key, "analyser")
    return _ANALYZERS[key]()


# ==================================================================================================
# 最小化器构建
# ==================================================================================================
_MINIMIZERS: Dict[str, Type[Minimizer]] = {
    'violation': Minimizer,
}
"""最小化器类型映射 - 当前仅支持 violation 类型"""


def get_minimizer(fuzzer_: fuzzer.Fuzzer, instruction_set: InstructionSet) -> Minimizer:
    """ 根据配置构建测试用例最小化器实例。

    当前硬编码为 violation 类型，预留未来扩展点。

    参数:
        fuzzer_: 模糊测试器实例（用于最小化时重现违规）
        instruction_set: 指令集规范对象

    返回:
        Minimizer 实例

    异常:
        FactoryException: 配置值不在可选范围内时抛出
    """
    key: str = "violation"  # 扩展点：未来可支持更多最小化器类型；当前硬编码
    if key not in _MINIMIZERS:
        raise FactoryException(_MINIMIZERS, key, "minimizer")
    return _MINIMIZERS[key](fuzzer_, instruction_set)


# ==================================================================================================
# ISA 规范下载器构建
# ==================================================================================================
Downloader = Union[x86_get_spec.Downloader, arm64_get_spec.Downloader]
"""下载器类型联合 - x86 或 ARM64 的 ISA 规范下载器"""

_SPEC_DOWNLOADERS: Dict[str, Type[Downloader]] = {
    'x86-64': x86_get_spec.Downloader,
    'arm64': arm64_get_spec.Downloader,
}
"""ISA 规范下载器映射 - 架构到对应下载器类"""


def get_downloader(arch: str, extensions: List[str], out_file: str) -> Downloader:
    """ 构建 ISA 规范下载器实例，用于下载指定架构的指令集规范文件。

    参数:
        arch: 目标架构名称（x86-64/arm64）
        extensions: 要包含的 ISA 扩展列表
        out_file: 输出文件路径

    返回:
        对应架构的 ISA 规范下载器实例

    异常:
        FactoryException: 架构不在可选范围内时抛出
    """
    key: str = arch
    if key not in _SPEC_DOWNLOADERS:
        raise FactoryException(_SPEC_DOWNLOADERS, key, "downloader")
    return _SPEC_DOWNLOADERS[key](extensions, out_file)

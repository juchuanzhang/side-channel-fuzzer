"""
文件：模糊测试配置选项管理

本模块实现了侧信道模糊测试框架的全局配置管理，使用 Borg 模式确保所有
配置实例共享同一状态。配置选项从 YAML 文件加载，支持 !include 语句
引用外部配置文件，并可根据目标架构自动设置架构特定的默认值。

配置项覆盖模糊测试器、程序生成器、输入数据生成器、合约模型、执行器、
分析器、覆盖率、最小化器、输出等所有组件的参数。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
from copy import deepcopy
from collections import OrderedDict
from typing import List, Dict, TextIO, Any, TypedDict, Set, Literal
from types import ModuleType

import yaml

from .arch.x86 import config as x86_config
from .arch.arm64 import config as arm64_config

# ==================================================================================================
# 自定义类型定义 - 用于配置项的类型约束
# ==================================================================================================
PagePropertyName = Literal['present', 'writable', 'user', 'write-through', 'cache-disable',
                           'accessed', 'dirty', 'executable', 'reserved_bit', 'randomized']
"""页面属性名称类型 - 定义内存页面的可配置属性名集合"""
PageConf = Dict[PagePropertyName, bool]
"""页面属性配置 - 将页面属性名映射到布尔值，表示该属性是否启用"""


class ActorConf(TypedDict):
    """ 执行者（Actor）配置的类型定义

    描述模糊测试中参与执行的角色的配置，包括：
    - name: 角色名称
    - mode: 运行模式（host/guest）
    - privilege_level: 权限级别
    - observer: 是否为观察者角色
    - data_properties: 数据内存页面属性配置
    - data_ept_properties: EPT（扩展页表）数据页面属性配置
    - instruction_blocklist: 禁止使用的指令集合
    - fault_blocklist: 禁止触发的异常集合
    """
    name: str
    mode: str
    privilege_level: str
    observer: bool
    data_properties: PageConf
    data_ept_properties: PageConf
    instruction_blocklist: Set[str]
    fault_blocklist: Set[str]


ActorConfKey = Literal["name", "mode", "privilege_level", "observer", "data_properties",
                       "data_ept_properties", "instruction_blocklist", "fault_blocklist"]
"""ActorConf 的合法键名集合"""

ActorsConf = Dict[str, ActorConf]
"""所有执行者的配置字典，键为执行者名称，值为对应配置"""

Architecture = Literal["x86-64", "arm64"]
"""支持的架构类型定义"""


# ==================================================================================================
# 辅助类
# ==================================================================================================
class IncludeLoader(yaml.SafeLoader):
    """
    YAML 加载器辅助类 - 支持 !include 语句在配置文件中引用外部 YAML 文件

    该类继承 yaml.SafeLoader，添加了以下功能：
    1. !include 标签处理器：允许在 YAML 文件中引用其他 YAML 文件
    2. 自定义映射构造器：为重复 include 的 file 键添加唯一 ID，
       防止多个 include 语句互相覆盖
    3. 循环引用检测：防止配置文件通过 !include 形成循环依赖
    """
    visited: List[str] = []        # 已访问文件路径列表，用于检测循环引用
    file_id_counter: int = 0       # 文件 ID 计数器，用于为 file 键生成唯一标识

    def __init__(self, stream: TextIO, include_dir: str = "") -> None:
        """
        初始化加载器，设置搜索路径并记录当前文件路径。

        参数:
            stream: YAML 文件流对象
            include_dir: include 文件的额外搜索目录
        """
        self._search_paths = [os.path.split(stream.name)[0]]  # 当前文件所在目录为首选搜索路径
        if include_dir:
            self._search_paths.append(include_dir)  # 添加额外的 include 搜索目录
        self.visited.append(os.path.abspath(stream.name))  # 记录当前文件路径用于循环检测
        super(IncludeLoader, self).__init__(stream)

    def __del__(self) -> None:
        """析构时移除当前文件路径记录，维护 visited 列栈的正确性"""
        if self.visited:
            self.visited.pop()

    def include(self, node: yaml.Node) -> Any:
        """
        处理 !include 标签，加载引用的 YAML 文件。

        该方法在搜索路径中查找引用的文件，检测循环引用，
        然后加载并返回引用文件的内容。

        参数:
            node: YAML 节点，包含引用文件的相对路径

        返回:
            引用文件解析后的 YAML 内容

        异常:
            ConfigException: 引用文件不存在或存在循环引用时抛出
        """
        # 在搜索路径中查找引用的文件
        relative_filename: str = self.construct_scalar(node)  # type: ignore
        for root in self._search_paths:
            filename = os.path.join(root, relative_filename)
            if os.path.exists(filename):
                break
        else:
            raise ConfigException(f"Included file {relative_filename} does not exist")

        # 检测循环引用 - 防止配置文件通过 !include 形成循环依赖
        if os.path.abspath(filename) in self.visited:
            raise ConfigException(f"Circular include detected in {filename}")

        with open(filename, 'r') as f:
            return yaml.load(f, IncludeLoader)

    def construct_yaml_map(self, node: yaml.MappingNode) -> Dict[Any, Any]:
        """
        自定义映射构造器 - 将所有 `file` 键重命名为 `file_<unique_id>`，
        防止多个 include 语句互相覆盖。

        当多个 !include 引用不同文件时，它们的 `file` 键会被重命名为
        `file_0`, `file_1` 等唯一标识，确保每个引用的内容独立保存。

        参数:
            node: YAML 映射节点

        返回:
            构造后的映射字典
        """
        for k, _ in node.value:
            if k.value == 'file':
                k.value = f'file_{self.file_id_counter}'  # 为 file 键添加唯一 ID
                self.file_id_counter += 1
        data = self.construct_mapping(node)
        return data


# 注册 !include 标签处理器和自定义映射构造器
IncludeLoader.add_constructor('!include', IncludeLoader.include)
IncludeLoader.add_constructor(u'tag:yaml.org,2002:map', IncludeLoader.construct_yaml_map)


class ConfigException(SystemExit):
    """配置异常类 - 当配置文件解析或验证出错时抛出，终止程序并显示错误信息"""

    def __init__(self, message: str) -> None:
        super().__init__("\nCONFIG ERROR: " + message + "\n")


def _get_architecture() -> Architecture:
    """通过读取 /proc/cpuinfo 自动检测当前系统的 CPU 架构。

    返回:
        'x86-64'（AMD 或 Intel CPU）或 'arm64'（ARM CPU），默认为 'x86-64'
    """
    with open('/proc/cpuinfo', 'r') as f:
        for line in f:
            if 'AuthenticAMD' in line or 'GenuineIntel' in line:
                return 'x86-64'
            if 'CPU implementer' in line:
                return 'arm64'
        return 'x86-64'  # 默认返回 x86-64


def _get_cpu_vendor() -> str:
    """通过读取 /proc/cpuinfo 自动检测当前系统的 CPU 供应商。

    返回:
        'x86-64-amd'（AMD）、'x86-64-intel'（Intel）或 'arm64'，
        默认为 'x86-64-intel'
    """
    with open('/proc/cpuinfo', 'r') as f:
        for line in f:
            if 'AuthenticAMD' in line:
                return 'x86-64-amd'
            if 'GenuineIntel' in line:
                return 'x86-64-intel'
            if 'CPU implementer' in line:
                return 'arm64'
        return 'x86-64-intel'


# ==================================================================================================
# 主配置类 - 使用 Borg 模式确保所有实例共享同一状态
# ==================================================================================================
class Conf:
    """
    全局配置数据类 - 存储并管理模糊测试框架的所有配置选项。

    使用 Borg 模式（共享状态模式）确保所有 Conf 实例共享相同的配置状态，
    而非 Singleton 的单实例限制。配置选项从 YAML 文件加载，
    可通过类属性直接访问。

    配置项按组件分组：
    - Fuzzer: 模糊测试算法与策略
    - Program Generator: 测试用例程序生成器
    - Input Data Generator: 输入数据生成器
    - Contract Model: 合约模型（模拟器）
    - Executor: 真实硬件执行器
    - Analyser: 追踪分析器
    - Coverage: 覆盖率收集
    - Minimizer: 测试用例最小化
    - Output: 输出与日志
    """

    # ==============================================================================================
    # 模糊测试器配置
    fuzzer: str = "basic"
    """ fuzzer: 模糊测试算法类型（basic/architectural/archdiff） """
    enable_priming: bool = True
    """ enable_priming: 是否通过 priming（替换输入）来验证违规 """
    enable_speculation_filter: bool = False
    """ enable_speculation_filter: 是否丢弃未触发推测执行的测试用例 """
    enable_observation_filter: bool = False
    """ enable_observation_filter: 是否丢弃未留下推测痕迹的测试用例 """
    enable_fast_path_model: bool = True
    """ enable_fast_path_boosting: 是否启用快速路径优化，
    对同一污点输入类中的所有输入使用相同的合约追踪 """

    # ==============================================================================================
    # 程序生成器配置
    generator: str = "random"
    """ generator: 程序生成器类型 """
    instruction_set: Architecture = _get_architecture()
    """ instruction_set: 待测试的指令集架构 """
    instruction_categories: List[str] = []
    """ instruction_categories: 用于生成程序的指令类别列表 """
    instruction_allowlist: List[str] = []
    """ instruction_allowlist: 允许用于生成程序的指令列表；
    与 instruction_categories 结合使用，优先级高于 instruction_blocklist。
    最终指令集合为：
     (instruction_categories 中的指令 - instruction_blocklist) + instruction_allowlist """
    instruction_blocklist: List[str] = []
    """ instruction_blocklist: 不允许用于生成程序的指令列表；
    从 instruction_categories 中过滤指令，但不影响 instruction_allowlist。
    最终指令集合为：
     (instruction_categories 中的指令 - instruction_blocklist) + instruction_allowlist """
    instruction_blocklist_append: List[str] = []
    """ instruction_blocklist_append: 与 instruction_blocklist 相同，
    但该列表会追加到现有 blocklist 而非替换 """
    program_generator_seed: int = 0
    """ program_generator_seed: 程序生成器种子；设为 0 时使用随机种子 """
    program_size: int = 24
    """ program_size: 生成的程序大小（指令数量） """
    avg_mem_accesses: int = 12
    """ avg_mem_accesses: 生成的程序中平均内存访问次数 """
    min_bb_per_function: int = 1
    """ min_bb_per_function: 每个函数中最小基本块数量 """
    max_bb_per_function: int = 2
    """ max_bb_per_function: 每个函数中最大基本块数量 """
    min_successors_per_bb: int = 2
    """ min_successors_per_bb: 每个基本块的最小后继数量
    注意1: 这是一个*提示*；如果指令集没有必要指令满足此要求，
    或需要特定后继数量以确保正确性，则可能被忽略"""
    max_successors_per_bb: int = 2
    """ max_successors_per_bb: 每个基本块的最大后继数量
    注意: 这是一个*提示*；可能因指令集限制或正确性要求被忽略 """
    register_allowlist: List[str] = []
    """ register_allowlist: 允许用于生成程序的寄存器列表；
     优先级高于 register_blocklist。
     最终寄存器集合为: (所有寄存器 - register_blocklist) + register_allowlist """
    register_blocklist: List[str] = []
    """ register_blocklist: 不允许用于生成程序的寄存器列表；
     优先级低于 register_allowlist。
     最终寄存器集合为: (所有寄存器 - register_blocklist) + register_allowlist """
    faults_allowlist: List[str] = []
    """ faults_allowlist: 默认情况下生成器不会生成触发异常的程序。
    此选项修改此行为，允许生成器生成可能触发异常的"不安全"指令序列。
    模型和执行器也将配置为优雅地处理这些异常 """

    # ==============================================================================================
    # 输入数据生成器配置
    data_generator: str = 'random'
    """ data_generator: 输入数据生成器类型 """
    data_generator_seed: int = 10
    """ data_generator_seed: 输入生成种子；设为 0 时使用随机种子 """
    data_generator_entropy_bits: int = 31
    """ data_generator_entropy_bits: 输入生成器创建的随机值的熵位数 """
    inputs_per_class: int = 2
    """ inputs_per_class: 每个输入类中的输入数量 """
    input_gen_probability_of_special_value: float = 0.05
    """ input_gen_probability_of_special_value: 在输入生成器中生成特殊值
    （零或最大值）的概率，用于测试微架构中的快速路径 """

    # ==============================================================================================
    # 合约模型配置
    model_backend: str = 'unicorn'
    """ model_backend: 用于在测试用例上收集合约追踪的后端引擎 """
    contract_execution_clause: List[str] = ["seq"]
    """ contract_execution_clause: 合约执行条款 - 定义推测执行行为的规范 """
    contract_observation_clause: str = 'ct'
    """ contract_observation_clause: 合约观测条款 - 定义可观测行为的规范 """
    model_min_nesting: int = 1
    """ model_min_nesting: 模型推测嵌套的最小层级 """
    model_max_nesting: int = 30
    """ model_max_nesting: 模型推测嵌套的最大层级 """
    model_max_spec_window: int = 250
    """ model_max_spec_window: 模型最大推测窗口大小 """

    # ==============================================================================================
    # 执行器配置
    executor: str = _get_cpu_vendor()
    """ executor: 硬件执行器类型（自动检测 CPU 供应商） """
    executor_mode: str = 'P+P'
    """ executor_mode: 硬件追踪收集模式（如 P+P、F+R 等） """
    executor_warmups: int = 5
    """ executor_warmups: 收集硬件追踪前的预热轮次数量 """
    executor_sample_sizes: List[int] = [10, 50, 100, 500]
    """ executor_sample_sizes: 测量时使用的样本大小列表；
    执行器先用第一个样本大小收集硬件追踪，
    若检测到违规则依次用后续样本大小尝试重现 """
    executor_filtering_repetitions: int = 10
    """ executor_filtering_repetitions: 过滤测试用例时的重复次数 """
    executor_taskset: int = 0
    """ executor_taskset: 执行器运行测试用例的 CPU 核编号 """
    enable_pre_run_flush: bool = True
    """ enable_pre_run_flush: 是否在运行测试用例前尽力刷新微架构状态 """

    # ==============================================================================================
    # 分析器配置
    analyser: str = 'chi2'
    """ analyser: 分析器类型（bitmaps/sets/mwu/chi2） """
    analyser_subsets_is_violation: bool = False
    """ analyser_subsets_is_violation: [仅适用于 analyser='sets' 或 'bitmaps']
    若为 False，当硬件追踪形成子集关系时，分析器不会标记为不匹配 """
    analyser_outliers_threshold: float = 0.1
    """ analyser_outliers_threshold: [仅适用于 analyser='sets' 或 'bitmaps']
    分析器忽略出现频率低于此百分比的硬件追踪。
    即：追踪通过过滤的条件是出现次数 >= (analyser_outliers_threshold * 追踪长度) """
    analyser_stat_threshold: float = 0.5
    """ analyser_stat_threshold: [仅适用于 analyser='chi2' 和 'mwu']
    统计检验阈值。若一对硬件追踪的（归一化）统计量低于此阈值，
    则认为追踪等价。

    注意：默认值 0.5 较保守，以避免误报（代价是漏报）。
    更精确的结果可将阈值设为更低值。

    chi2 检验: 阈值为 统计量 / (htrace1长度 + htrace2长度)
    mwu 检验: 阈值为 p-value """

    # ==============================================================================================
    # 覆盖率配置
    coverage_type: str = 'none'
    """ coverage_type: 覆盖率类型 """

    # ==============================================================================================
    # 最小化器配置
    minimizer_retries: int = 1
    """ minimizer_retries: 最小化时重现违规的尝试次数 """

    # ==============================================================================================
    # 输出配置
    multiline_output: bool = False
    """ multiline_output: 是否使用多行输出模式（而非单行重绘） """
    logging_modes: List[str] = ["info", "stat"]
    """ logging_modes: 启用的日志模式列表 """
    color: bool = False
    """ color: 是否使用彩色终端输出 """

    # ==============================================================================================
    # 配置选项的可选值（也由 ISA 特定 config.py 扩展）
    _option_values: Dict[str, List[str]] = {
        "fuzzer": ["basic", "architectural", "archdiff"],
        "generator": ["random"],
        "instruction_set": ["x86-64", "arm64"],
        "data_generator": ["random"],
        "model_backend": ["dummy", "unicorn", "dynamorio"],
        "contract_execution_clause": [
            "seq", "no_speculation", "seq-assist", "cond", "conditional_br_misprediction", "bpas",
            "nullinj-fault", "nullinj-assist", "delayed-exception-handling", "div-zero",
            "div-overflow", "meltdown", "fault-skip", "noncanonical", "vspec-ops-div",
            "vspec-ops-memory-faults", "vspec-ops-memory-assists", "vspec-ops-gp", "vspec-all-div",
            "vspec-all-memory-faults", "vspec-all-memory-assists"
        ],
        "contract_observation_clause": [
            "none", "l1d", "pc", "memory", "ct", "loads+stores+pc", "ct-nonspecstore", "ctr",
            "arch", "tct", "tcto", "ct-ni"
        ],
        "executor": ["x86-64-intel", "x86-64-amd", "arm64"],
        'executor_mode': [
            'P+P',
            'F+R',
            'E+R',
            'PP+P',
            'TSC',
            # 'GPR' 被故意排除
        ],
        'faults_allowlist': [
            'div-by-zero',
            'div-overflow',
            'opcode-undefined',
            'breakpoint',
            'debug-register',
            'non-canonical-access',
            'user-to-kernel-access',
        ],
        "analyser": ["bitmaps", "sets", "mwu", "chi2"],
        "coverage_type": ["none", "model_instructions"],
        "logging_modes": [
            "info",
            "stat",
            "dbg_generator",
            "dbg_timestamp",
            "dbg_violation",
            "dbg_dump_htraces",
            "dbg_dump_ctraces",
            "dbg_dump_traces_unlimited",
            "dbg_model",
            "dbg_coverage",
            "dbg_priming",
            "dbg_executor_raw",
            "dbg_isa_filter",
        ],
    }

    # ==============================================================================================
    # 内部状态（不在 YAML 中直接配置）
    _borg_shared_state: Dict[Any, Any] = {}  # Borg 模式的共享状态字典
    _no_generation: bool = False             # 是否禁用随机生成模式
    _handled_faults: List[str]               # 已处理的异常列表（由 ISA 特定 config.py 设置）
    _generator_fault_to_fault_name: Dict[str, str]  # 生成器异常名到实际异常名的映射
    _actors: ActorsConf                     # 所有执行者的配置字典
    _actor_default: ActorConf               # 默认执行者配置（作为新增执行者的模板）
    _config_path: str = ""                  # 当前配置文件路径

    def __init__(self) -> None:
        """初始化配置实例 - 实现 Borg 模式使所有实例共享同一状态"""
        # Borg 模式实现：所有实例共享 __dict__
        setattr(self, '__dict__', self._borg_shared_state)
        if not getattr(self, '_actors', None):
            self._actors = OrderedDict()

    def load(self, config_path: str, include_dir: str = "") -> None:
        """
        从 YAML 文件加载配置选项。

        参数:
            config_path: YAML 配置文件的路径
            include_dir: !include 引用文件的搜索目录

        该方法使用 IncludeLoader 解析 YAML 文件（支持 !include 语句），
        然后通过 _load_from_dict 设置配置值，最后执行值合理性检查。
        """
        self._config_path = config_path
        config_update: Dict[str, Any] = {}
        with open(config_path, "r") as f:
            loader = IncludeLoader(f, include_dir)
            try:
                config_update = loader.get_single_data()
            except yaml.scanner.ScannerError as e:  # type: ignore
                raise ConfigException(
                    f"Error parsing the configuration file {config_path}:\nError: {e}") from e
            finally:
                loader.dispose()  # type: ignore
        self._load_from_dict(config_update)
        self._value_sanity_check()

    def _load_from_dict(self, config_update: Dict[str, Any]) -> None:
        """
        从字典中加载配置值到 Conf 实例。

        处理逻辑：
        1. 若配置中指定了 instruction_set，先设置架构相关默认值
        2. 递归处理 include 引用的 file_* 键
        3. 设置其余配置选项，对特殊键（faults_allowlist、instruction_blocklist_append、
           actors、instruction_categories）进行特殊处理

        参数:
            config_update: 从 YAML 文件解析得到的配置字典
        """
        # 首先设置架构相关的默认值（确保架构依赖的选项优先初始化）
        if 'instruction_set' in config_update:
            self.instruction_set = config_update['instruction_set']
            self.set_to_arch_defaults()
            config_update.pop('instruction_set')

        # 递归加载被 include 引用的文件内容
        file_keys = []
        for k, v in config_update.items():
            if "file_" in k:
                self._load_from_dict(v)
                file_keys.append(k)
        for k in file_keys:  # 移除已处理的 `file_*` 键
            config_update.pop(k)

        # 设置其余配置选项
        for var, value in config_update.items():
            # 对特殊配置键进行特殊处理
            if var == "faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                self.safe_set(var, value)
                continue
            if var == "instruction_blocklist_append":
                self.instruction_blocklist.extend(value)  # 追加而非替换
                continue
            if var == "actors":
                self.set_actor_properties(value)
                continue
            if var == "instruction_categories":
                # 根据模型后端选择对应的指令类别选项列表进行验证
                backend = config_update.get("model_backend", self.model_backend)
                if backend == "unicorn":
                    options_name = "unicorn_instruction_categories"
                elif backend == "dynamorio":
                    options_name = "dr_instruction_categories"
                else:
                    options_name = "dr_instruction_categories"
                self.safe_set(var, value, options_name)

            self.safe_set(var, value)

    def safe_set(self, name: str, value: Any, options_name: str = "") -> None:
        """
        安全地设置配置选项，包含类型检查和值合法性验证。

        参数:
            name: 配置选项名称
            value: 要设置的值
            options_name: 用于值验证的可选值列表名称（默认与 name 相同）

        异常:
            ConfigException: 设置内部变量、未知变量或类型不匹配时抛出
        """
        assert name not in ["instruction_set"]  # instruction_set 需通过 set_to_arch_defaults 设置

        # 合理性检查
        if name[0] == "_":
            raise ConfigException(f"Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            raise ConfigException(f"Unknown configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            raise ConfigException(f"Wrong type of the configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")

        # 验证值是否在可选值范围内
        if options_name:
            self._check_options(options_name, value)
        else:
            self._check_options(name, value)
        setattr(self, name, value)

    def _check_options(self, name: str, value: Any) -> None:
        """
        检查配置值是否在合法的可选值范围内。

        参数:
            name: 可选值列表的名称
            value: 待检查的值（可以是字符串、列表或字典列表）

        异常:
            ConfigException: 值不在可选范围内时抛出
        """
        if name not in self._option_values:
            return  # 无可选值约束的配置项，跳过检查
        options = self._option_values[name]

        invalid_value = None
        if isinstance(value, str):
            # 字符串类型：直接检查是否在可选值列表中
            invalid_value = value if value not in options else None
        elif isinstance(value, List):
            # 列表类型：逐个检查每个元素是否在可选值列表中
            for v in value:
                if v in options:
                    continue
                if isinstance(v, Dict):
                    # 字典列表：检查字典的键是否在可选值列表中
                    for k in v:
                        if k not in options:
                            break
                    else:
                        continue
                invalid_value = v
                break
        else:
            raise ConfigException(f"Unexpected type of config variable {name}")

        if invalid_value:
            raise ConfigException(f"Unknown value '{invalid_value}' of config variable '{name}'\n"
                                  f"Possible options: {options}")
        return

    def _value_sanity_check(self) -> None:
        """
        检查配置值是否合理（值的范围与关系约束）。

        异常:
            ConfigException: 配置值不合理时抛出
        """
        if self.data_generator_entropy_bits > 32:
            raise ConfigException("data_generator_entropy_bits must be less or equal to 32 bits")
        if self.min_successors_per_bb > self.max_successors_per_bb:
            raise ConfigException("min_successors_per_bb is larger than max_successors_per_bb")

    def set_to_arch_defaults(self) -> None:
        """ 根据目标架构设置架构特定的配置默认值。

        从对应架构的 config.py 模块中加载默认值，包括：
        - 架构特定的选项值列表
        - 默认执行者配置
        - 已处理异常列表等
        """

        config: ModuleType
        if self.instruction_set == "x86-64":
            config = x86_config
        elif self.instruction_set == "arm64":
            config = arm64_config
        else:
            raise ConfigException(f"Unknown architecture {self.instruction_set}")

        # 从架构配置模块中提取所有基本类型的属性作为默认值
        config_defaults = {}
        for c in dir(config):
            if c.startswith("__"):
                continue
            values = getattr(config, c)
            if type(values) not in [bool, int, float, str, dict, list]:
                continue
            config_defaults[c] = values

        if "_option_values" not in config_defaults:
            raise ConfigException("ISA-specific config.py must define _option_values")

        # 设置架构特定的默认值
        for name, value in config_defaults.items():
            if name == "faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                continue
            if name == "_actor_default":
                self._actor_default = deepcopy(value)
                self._actors = OrderedDict()
                self._actors['main'] = deepcopy(value)  # 初始化 main 执行者
                continue
            if name == "_option_values":
                # 合并架构特定的可选值列表到全局可选值字典
                for k, v in value.items():
                    self._option_values[k] = v
                continue

            setattr(self, name, value)

    def update_handled_faults_with_generator_faults(self, new: List[str]) -> None:
        """
        根据生成器异常名列表更新已处理异常列表。

        将生成器使用的异常名称映射为实际异常名称，
        并将其添加到已处理异常列表中。

        参数:
            new: 生成器异常名称列表
        """
        for gen_fault in new:
            if not gen_fault:
                continue
            if gen_fault not in self._generator_fault_to_fault_name:
                raise ConfigException(f"Unknown generator fault {gen_fault}")
            fault = self._generator_fault_to_fault_name[gen_fault]
            if fault not in self._handled_faults:
                self._handled_faults.append(fault)

    def set_actor_properties(self, new: List[Dict[str, List[Dict[ActorConfKey, Any]]]]) -> None:
        """
        设置执行者（Actor）的配置属性。

        处理逻辑：
        1. 对每个执行者名称和属性字典进行验证
        2. main 执行者必须为 host 模式和 kernel 权限级别
        3. 对属性值进行合法性检查（模式、权限级别、数据属性等）
        4. 更新或创建执行者配置条目

        参数:
            new: 执行者配置列表，每个元素为 {名称: [属性键值对列表]} 的字典
        """
        for actor_dict in new:
            name = next(iter(actor_dict))  # 提取执行者名称
            self._check_options("actor", actor_dict[name])  # 验证执行者属性
            update = {k: v for tmp_dict in actor_dict[name] for k, v in tmp_dict.items()}  # 属性扁平化

            # main 执行者的模式与权限级别强制约束
            if name == "main":
                if update.get('mode', 'host') != 'host':
                    raise ConfigException("The main actor must be in 'host' mode")
                if update.get('privilege_level', 'kernel') != 'kernel':
                    raise ConfigException("The main actor must have 'kernel' privilege_level")

            # 获取或创建执行者配置条目
            if name in self._actors:
                entry = self._actors[name]
            else:
                entry = deepcopy(self._actor_default)  # 新执行者使用默认配置模板
                entry["name"] = name

            # 逐个设置执行者属性，对特殊属性进行验证
            for k, v in update.items():
                if k == "mode" and v not in self._option_values["actor_mode"]:
                    raise ConfigException(f"Unsupported actor mode {v}")
                if k == "privilege_level" and v not in self._option_values["actor_privilege_level"]:
                    raise ConfigException(f"Unsupported actor privilege_level {v}")

                if k == "data_properties":
                    # 验证数据页面属性名是否合法
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_properties"]:
                                raise ConfigException(
                                    f"Unsupported actor data_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "data_ept_properties":
                    # EPT 属性仅适用于 guest 模式的执行者
                    if update.get('mode', 'host') != 'guest':
                        raise ConfigException("data_ept_properties can only be used in guest mode")
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_ept_properties"]:
                                raise ConfigException(
                                    f"Unsupported actor data_ept_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "instruction_blocklist" or k == "fault_blocklist":
                    if v:
                        entry[k].update(v)
                    continue

                entry[k] = v
            self._actors[name] = entry

    def disable_generation(self) -> None:
        """禁用随机生成模式 - 当使用已有测试用例时调用"""
        self._no_generation = True

    def is_generation_enabled(self) -> bool:
        """检查随机生成模式是否启用"""
        return not self._no_generation

    def get_actors_conf(self) -> ActorsConf:
        """获取描述所有执行者的配置字典"""
        return self._actors


CONF = Conf()
CONF.set_to_arch_defaults()  # 初始化全局配置对象并设置架构默认值

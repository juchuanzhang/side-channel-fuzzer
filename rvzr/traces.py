"""
File: Classes representing contract and hardware traces as well as derived containers thereof.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT

文件用途：侧信道追踪（trace）的数据类和容器类。
定义了合约追踪（CTrace）和硬件追踪（HTrace）的核心数据结构，
以及基于等价类的追踪容器（ContractEqClass、HardwareEqClass、Violation），
用于侧信道模糊测试的违规检测和分析。

核心类：
- CTrace：合约追踪，从模型收集的抽象追踪（内存访问、PC、值、寄存器等）
- HTrace：硬件追踪，从执行器收集的微架构观测（缓存状态、TSC、寄存器等）
- TraceBundle：单次测量的完整数据（输入+合约追踪+硬件追踪）
- ContractEqClass/HardwareEqClass：等价类容器
- Violation：违规对象，表示检测到的合约违规
"""
from __future__ import annotations
from collections import Counter

from typing import List, Optional, Final, NamedTuple, Tuple, Dict, Generator, Callable, Literal
from typing_extensions import assert_never

import xxhash
import numpy as np
import numpy.typing as npt

from .tc_components.test_case_data import InputData, InputID
from .tc_components.test_case_code import TestCaseProgram
from .config import CONF

# x86和ARM64寄存器名映射（用于追踪打印）
_REG_ID_TO_NAME_X86 = {0: "rax", 1: "rbx", 2: "rcx", 3: "rdx", 4: "rsi", 5: "rdi"}
_REG_ID_TO_NAME_ARM = {0: "x0", 1: "x1", 2: "x2", 3: "x3", 4: "x4", 5: "x5"}

# ==================================================================================================
# Contract Trace
# 合约追踪
# ==================================================================================================
CTraceEntryType = Literal["mem", "pc", "val", "reg", "ind"]
# 追踪条目类型：mem=内存地址, pc=程序计数器, val=值, reg=寄存器, ind=间接调用


class CTraceEntry(NamedTuple):
    """
    Named tuple that represents a single entry in a contract trace.

    合约追踪条目：由类型和值组成的命名元组。
    类型说明：
    - "mem": 内存访问地址
    - "pc": 程序计数器值
    - "val": 数据值
    - "reg": 寄存器值
    - "ind": 间接调用地址
    """
    type_: CTraceEntryType
    value: int


UntypedCTrace = List[int]
# 无类型追踪：仅包含整数值的追踪列表


class CTrace:
    """
    Class representing a contract trace. It encapsulates a list of integers that represent a raw
    trace collected from the model, and it provides basic comparison and hashing interfaces that
    allow to compare traces for equality and to store them in sets or dictionaries.

    合约追踪类。
    封装从模型收集的原始追踪数据（CTraceEntry列表），提供比较和哈希接口。
    使用xxhash快速哈希进行等价判断，支持将追踪打印为L1D缓存映射形式。

    核心属性：
    - _trace: 类型化追踪条目列表
    - _untyped: 仅值列表（用于哈希计算）
    - _hash: xxhash计算的哈希值（用于快速比较）
    """
    _trace: Final[List[CTraceEntry]]
    _untyped: Final[UntypedCTrace]
    _hash: Final[int]

    _printed_as_l1d_map: bool = False
    """ Flag indicating that the trace should be printed  — 是否以L1D缓存映射形式打印的标志 """

    # ==============================================================================================
    # Constructors
    # 构造方法

    @classmethod
    def empty_trace(cls) -> CTrace:
        """
        Produce a dummy CTrace object with empty raw trace

        创建空合约追踪对象（用于伪违规等场景）。
        """
        return cls([])

    def __init__(self, trace: List[CTraceEntry]) -> None:
        """
        初始化合约追踪。

        :param trace: CTraceEntry列表，每条包含类型和值
        """
        self._trace = trace
        # 提取值列表（不含类型信息）
        self._untyped = [entry.value for entry in trace]
        # 使用xxhash计算哈希值，用于快速等价比较
        self._hash = xxhash.xxh64(str(self._untyped), seed=0).intdigest()

    # ==============================================================================================
    # Printers
    # 打印方法

    def __str__(self) -> str:
        """
        返回追踪的字符串表示。
        默认打印哈希值；如设置了L1D映射标志，则打印64位缓存状态位图。
        """
        # For most cases, just print the hash value
        if not self._printed_as_l1d_map:
            return str(self._hash)

        # When printing as L1D map was requested, print the trace as a 64-bit bit mask
        # representing the cache state
        # 以L1D缓存映射形式打印：将地址映射到64位缓存组位图
        map_value = 0
        for address in self._untyped:
            # 取地址的6-11位作为页偏移（对应L1D缓存组索引）
            page_offset = (address & 0b111111000000) >> 6
            # 将对应缓存组位设为1
            cache_set_index = 0x8000000000000000 >> page_offset
            map_value |= cache_set_index
        map_str = f"{map_value:064b}"
        # 用.和^替换0和1，可视化缓存状态
        map_str = map_str.replace("0", ".").replace("1", "^")
        return map_str

    def full_str(self,
                 m_col: str = "",
                 pc_col: str = "",
                 val_col: str = "",
                 reset_col: str = "") -> str:
        """
        Return a string representation of the complete typed trace.
        Optionally, the colors can be specified for memory addresses, program counters, and values.

        Example output: [mem: 0x100, pc: 0x200, val: 0x300]

        :param m_col: color for memory addresses entries
        :param pc_col: color for program counters entries
        :param val_col: color for values entries
        :param reset_col: color reset string
        :return: colorized string representation of the trace

        返回完整的类型化追踪字符串表示，支持彩色输出。
        每个条目按类型标记（mem, pc, val, reg, indcall），可指定颜色。

        :param m_col: 内存地址条目的颜色代码
        :param pc_col: PC条目的颜色代码
        :param val_col: 值条目的颜色代码
        :param reset_col: 颜色重置代码
        :return: 带颜色的追踪字符串
        """
        assert reset_col or not (m_col or pc_col or val_col), \
            "If any color is set, reset_col must be set as well"

        s = "["
        len_ = len(self._trace)
        # 根据ISA选择寄存器名映射
        reg_names = _REG_ID_TO_NAME_X86 if CONF.instruction_set == "x86-64" else _REG_ID_TO_NAME_ARM
        for i, item in enumerate(self._trace):
            if item.type_ == "mem":
                s += "mem: " + m_col + hex(item.value) + reset_col
            elif item.type_ == "pc":
                s += "pc: " + pc_col + hex(item.value) + reset_col
            elif item.type_ == "ind":
                s += "indcall: " + pc_col + hex(item.value) + reset_col
            elif item.type_ == "val":
                s += "val: " + val_col + hex(item.value) + reset_col
            elif item.type_ == "reg":
                # 寄存器条目使用索引映射到寄存器名
                name = reg_names[i]
                s += name + ": " + hex(item.value) + reset_col
            else:
                assert_never(item.type_)
            if i != len_ - 1:
                s += ", "
        return s + "]"

    # ==============================================================================================
    # Public Methods
    # 公共方法

    def __eq__(self, other: object) -> bool:
        """
        通过哈希值比较两个合约追踪是否相等。
        仅支持CTrace与CTrace的比较。
        """
        if not isinstance(other, CTrace):
            raise NotImplementedError("Cannot compare CTrace with non-CTrace object")
        return self._hash == other._hash

    def __lt__(self, other: CTrace) -> bool:
        """ 哈希值小于比较（用于排序） """
        return self._hash < other._hash

    def __gt__(self, other: CTrace) -> bool:
        """ 哈希值大于比较（用于排序） """
        return self._hash > other._hash

    def __len__(self) -> int:
        """ 返回追踪条目数量 """
        return len(self._untyped)

    def __hash__(self) -> int:
        """ 返回哈希值（用于集合和字典操作） """
        return self._hash

    def is_empty(self) -> bool:
        """
        Check if the trace was created from an empty list or via `empty_trace()`

        检查追踪是否为空。
        """
        return len(self) == 0

    def get_untyped(self) -> UntypedCTrace:
        """
        Get a raw trace containing only integers values of the CTrace without type information

        获取无类型的原始追踪（仅包含整数值，不含类型信息）。
        """
        return self._untyped

    def get_typed(self) -> List[CTraceEntry]:
        """
        Get the full trace used to construct the CTrace object

        获取完整的类型化追踪（包含类型和值的CTraceEntry列表）。
        """
        return self._trace

    def set_printed_as_l1d(self, val: bool = True) -> None:
        """
        Set the flag indicating that the trace should be printed as L1D map.
        This is normally used only for debugging purposes.
        :param val: flag value
        :return: None

        设置L1D缓存映射打印标志。开启后，__str__方法将追踪打印为64位缓存状态位图。

        :param val: 标志值
        """
        self._printed_as_l1d_map = val


# ==================================================================================================
# Hardware Trace
# 硬件追踪
# ==================================================================================================
HTraceType = Literal["cache", "tsc", "reg"]
# 硬件追踪类型：cache=缓存观测, tsc=时间戳计数器, reg=寄存器观测

# 硬件追踪样本的数据类型：包含追踪值和5个性能计数器读数
RawHTraceSample = np.dtype([
    ("trace", np.uint64),  # 追踪观测值（缓存位图/TSC值/寄存器值）
    ("pfc0", np.uint64),   # 性能计数器0
    ("pfc1", np.uint64),   # 性能计数器1
    ("pfc2", np.uint64),   # 性能计数器2
    ("pfc3", np.uint64),   # 性能计数器3
    ("pfc4", np.uint64),   # 性能计数器4
])
ArrayOfSamples = npt.NDArray[np.void]  # 样本数组类型
PFCTuple = Tuple[int, int, int, int, int]  # 性能计数器值元组


class HTrace:
    """
    Class representing a sequence of hardware trace samples. The samples are normally received from
    the executor: It executes a test case program with a given input multiple times, and each
    execution produces a single hardware trace and a set of readings from performance counters.
    The results of such repeated executions are collected into a single HTrace object.

    硬件追踪类。
    表示从执行器收集的一系列硬件追踪样本。执行器用给定输入多次执行测试用例，
    每次执行产生一个硬件追踪（缓存状态/TSC/寄存器）和一组性能计数器读数。
    多次执行的样本汇总到一个HTrace对象中。

    核心属性：
    - _raw: 原始样本数组（numpy结构化数组）
    - _hash: xxhash计算的哈希值
    - _is_corrupted_or_ignored: 是否为损坏或被忽略的样本（全零追踪）
    - type_: 追踪类型（cache/tsc/reg）
    """
    _raw: Final[ArrayOfSamples]
    _hash: Final[int]
    _is_corrupted_or_ignored: Final[bool]
    _max_pfc: Optional[PFCTuple] = None
    type_: Final[HTraceType]

    # ==============================================================================================
    # Constructors
    # 构造方法

    @classmethod
    def empty_trace(cls, type_: HTraceType = "cache") -> HTrace:
        """
        Get a dummy HTrace object with empty hardware trace and zeros for perf counters

        创建空硬件追踪对象（0个样本）。
        """
        return cls(np.ndarray(0, dtype=RawHTraceSample), type_)

    @classmethod
    def invalid_trace(cls, type_: HTraceType = "cache") -> HTrace:
        """
        Get a dummy HTrace object with corrupted hardware trace and zeros for perf counters

        创建无效硬件追踪对象（1个全零样本，标记为损坏）。
        """
        invalid_sample: npt.NDArray[np.void] = np.zeros(1, dtype=RawHTraceSample)
        return cls(invalid_sample, type_)

    def __init__(self, htrace_samples: ArrayOfSamples, type_: HTraceType = "cache") -> None:
        """
        初始化硬件追踪。

        :param htrace_samples: numpy结构化数组，每个元素包含trace和pfc0-pfc4
        :param type_: 追踪类型（cache/tsc/reg）
        """
        # check that the input has the expected shape
        # 验证输入数据的形状和类型
        assert htrace_samples.ndim == 1, "htrace_samples must be a 1D array"
        assert htrace_samples.dtype == RawHTraceSample, "htrace_samples must be of type RawHTrace"

        # store and process the samples
        # 存储并处理样本数据
        self._raw = htrace_samples
        # 对所有样本的trace字段计算哈希
        self._hash = xxhash.xxh64(str(htrace_samples['trace']), seed=0).intdigest()
        # 如果所有trace值为0，标记为损坏/忽略
        self._is_corrupted_or_ignored = all(x == 0 for x in htrace_samples['trace'])
        self.type_ = type_

    # ==============================================================================================
    # Printers
    # 打印方法

    def __str__(self) -> str:
        """ 返回哈希值的字符串表示 """
        return str(self._hash)

    def full_str(self,
                 line_prefix: str = "",
                 region1_col: str = "",
                 region2_col: str = "",
                 reset_col: str = "") -> str:
        """
        Return a string (table) representation of the set of samples used to create this trace

        :param line_prefix: string to prepend to each line
        :return: string representation of the trace

        返回硬件追踪的完整字符串表示（样本分布表）。
        根据追踪类型选择不同的打印格式：
        - cache: 64位缓存位图 + 出现次数
        - tsc: 时间戳值 + 出现次数
        - reg: 寄存器值列表

        :param line_prefix: 每行前缀字符串
        :param region1_col/region2_col: 缓存位图区域颜色
        :param reset_col: 颜色重置代码
        :return: 追踪的字符串表示
        """
        # Nothing to print if the trace is empty
        if self.is_empty():
            return line_prefix
        if self.type_ == "cache":
            return self._full_cache_str(line_prefix, region1_col, region2_col, reset_col)
        if self.type_ == "tsc":
            return self._full_tsc_str(line_prefix)
        if self.type_ == "reg":
            return self._full_arch_str(line_prefix)

        assert_never(self.type_)
        return ""  # pylint: disable=unreachable

    def _full_arch_str(self, line_prefix: str) -> str:
        """
        Return a string representation of an architectural trace.
        Example output:
        [rax:0x00000000000001, rbx:0x00000000000002, rcx:0x00000000000003, rdx:0x00000000000004,
        rsi:0x00000000000005, rdi:0x00000000000006]

        返回架构追踪的字符串表示：寄存器名+值的列表格式。
        """
        assert len(self._raw) == 1, "Invalid trace shape"
        s = line_prefix
        reg_names = _REG_ID_TO_NAME_X86 if CONF.instruction_set == "x86-64" else _REG_ID_TO_NAME_ARM
        s += "["
        # trace字段为主寄存器值，pfc0-pfc4为其他寄存器值
        s += f"{reg_names[0]}: 0x{self._raw[0]['trace']:x}, "
        s += f"{reg_names[1]}: 0x{self._raw[0]['pfc0']:x}, "
        s += f"{reg_names[2]}: 0x{self._raw[0]['pfc1']:x}, "
        s += f"{reg_names[3]}: 0x{self._raw[0]['pfc2']:x}, "
        s += f"{reg_names[4]}: 0x{self._raw[0]['pfc3']:x}, "
        s += f"{reg_names[5]}: 0x{self._raw[0]['pfc4']:x}"
        s += "]"
        return s

    def _full_tsc_str(self, line_prefix: str) -> str:
        """
        Return a string representation of a TSC trace.
        Example output:
        00000001 [16]
        00000002 [16]

        返回TSC追踪的字符串表示：时间戳值 + 出现次数。
        按出现次数降序排列。
        """
        s = ""
        mask = np.uint64(0xFFFFFFFFFFFFFF)  # 56位掩码，截断TSC值
        counter = Counter(self._raw['trace'])  # 统计每个值的出现次数
        trace_distribution = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        for t, c in trace_distribution:
            t = t & mask  # 截断为56位
            s += f"{line_prefix}{t:08} [{c}]\n"
        return s

    def _full_cache_str(self, line_prefix: str, r1_col: str, r2_col: str, reset_col: str) -> str:
        """
        Return a string representation of a cache trace
        Example output:
            .....^..................^....................................... [16]
            ........................^....................................... [16]

        返回缓存追踪的字符串表示：64位缓存位图 + 出现次数。
        位图用.（未访问）和^（已访问）表示，每8位交替着色。
        按出现次数降序排列。
        """
        s = ""
        counter = Counter(self._raw['trace'])
        trace_distribution = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        for t, c in trace_distribution:
            line = f"{t:064b}"
            line = line.replace("0", ".").replace("1", "^")
            # 每8位交替着色，便于区分缓存组区域
            line = r1_col + line[0:8] + r2_col + line[8:16] \
                + r1_col + line[16:24] + r2_col + line[24:32] \
                + r1_col + line[32:40] + r2_col + line[40:48] \
                + r1_col + line[48:56] + r2_col + line[56:64] \
                + reset_col + line[64:]
            s += f"{line_prefix}{line} [{c}]\n"
        return s

    def full_pair_str(self,
                      other: HTrace,
                      r1_col: str = "",
                      r2_col: str = "",
                      res_col: str = "") -> str:
        """
        Return a string representation of two sample distributions side-by-side

        返回两个硬件追踪的并排字符串表示（用于违规对比显示）。
        """
        if self.type_ == "cache":
            assert other.type_ == "cache"
            return self._full_cache_pair_str(other, r1_col, r2_col, res_col)
        if self.type_ == "tsc":
            assert other.type_ == "tsc"
            return self._full_tsc_pair_str(other)
        if self.type_ == "reg":
            raise NotImplementedError("Cannot compare architectural traces")

        assert_never(self.type_)
        return ""  # pylint: disable=unreachable

    def _full_tsc_pair_str(self, other: HTrace) -> str:
        """
        Return a string representation of two TSC sample distributions side-by-side
        Example output:
        00000001        |16     | 8      |
        00000002        |16     | 24     |

        返回两个TSC追踪的并排对比字符串。
        每行显示：TSC值 | 左追踪次数 | 右追踪次数
        """
        mask = np.uint64(0xFFFFFFFFFFFFFF)
        c1 = Counter(self.get_raw_traces())
        c2 = Counter(other.get_raw_traces())
        keys = set(c1.keys()) | set(c2.keys())
        # 排序：优先按c1次数，其次按c2次数
        traces = sorted(keys, key=lambda x: (c1[x] << 10000) + c2[x], reverse=True)

        final_str = ""
        for t in traces:
            t = t & mask
            final_str += f"{t:08} | {c1[t]:<6} | {c2[t]:<6} |\n"
        return final_str

    def _full_cache_pair_str(self, other: HTrace, r1_col: str, r2_col: str, res_col: str) -> str:
        """
        Return a string representation of two cache sample distributions side-by-side
        Example output:
        .....^..................^....................................... |16     | 8      |
        .....^.......................................................... |16     | 24     |

        返回两个缓存追踪的并排对比字符串。
        每行显示：缓存位图 | 左追踪次数 | 右追踪次数
        """
        c1 = Counter(self.get_raw_traces())
        c2 = Counter(other.get_raw_traces())
        keys = set(c1.keys()) | set(c2.keys())
        traces = sorted(keys, key=lambda x: (c1[x] << 10000) + c2[x], reverse=True)

        final_str = ""
        for t in traces:
            s = f"{t:064b}"
            s = s.replace("0", ".").replace("1", "^")
            s = r1_col + s[0:8] + r2_col + s[8:16] \
                + r1_col + s[16:24] + r2_col + s[24:32] \
                + r1_col + s[32:40] + r2_col + s[40:48] \
                + r1_col + s[48:56] + r2_col + s[56:64] \
                + res_col + s[64:]
            final_str += s + f" | {c1[t]:<6} | {c2[t]:<6}|\n"
        return final_str

    # ==============================================================================================
    # Public Methods
    # 公共方法

    def __eq__(self, other: object) -> bool:
        """
        通过哈希值比较两个硬件追踪是否相等。
        """
        if not isinstance(other, HTrace):
            raise NotImplementedError("Cannot compare HTrace with non-HTrace object")
        return self._hash == other._hash

    def __len__(self) -> int:
        """ 返回样本数量 """
        return len(self._raw)

    def __hash__(self) -> int:
        """ 返回哈希值 """
        return self._hash

    def merge(self, other: HTrace) -> HTrace:
        """
        Merge two HTrace objects into a single HTrace object
        :param other: HTrace object to merge with
        :return: A new HTrace object that contains all samples from both objects

        合并两个硬件追踪对象的所有样本。

        :param other: 待合并的HTrace对象
        :return: 包含所有样本的新HTrace对象
        """
        samples = np.concatenate([self._raw, other._raw])  # pylint: disable=protected-access
        return HTrace(samples, self.type_)

    def is_empty(self) -> bool:
        """
        Check if the trace was created from an empty sample or via `empty_trace()`

        检查追踪是否为空（无样本）。
        """
        return len(self) == 0

    def is_corrupted_or_ignored(self) -> None:
        """
        Check if the trace was created from a corrupted sample.
        A corrupted sample is a sample were all values are zero, which is a way that executor
        signals that the trace was not collected properly.

        检查追踪是否为损坏或被忽略的样本（所有trace值为0）。
        执行器用全零值信号追踪未正确收集。
        """
        return self._is_corrupted_or_ignored

    def get_raw_readings(self) -> ArrayOfSamples:
        """
        Get all raw readings used to construct the HTrace object (including both the trace and
        the performance counters)

        获取所有原始读数（包含追踪值和性能计数器）。
        """
        return self._raw

    def get_raw_traces(self) -> npt.NDArray[np.uint64]:
        """
        Get all raw traces in the HTrace object (does NOT include performance counters)

        获取所有原始追踪值（不含性能计数器）。
        """
        return self._raw['trace']

    def sample_size(self) -> int:
        """
        Get the number of htrace samples in the HTrace object

        获取样本数量。
        """
        return len(self._raw)

    def get_max_pfc(self) -> PFCTuple:
        """
        Get the maximum values of performance counters in the HTrace object

        获取所有样本中性能计数器的最大值。
        惰性计算，首次调用后缓存结果。
        """
        if self._max_pfc is None:
            new_max_pfc = (0, 0, 0, 0, 0)
            for sample in self._raw:
                # 找到任意计数器最大时的样本，取其所有计数器值
                if sample['pfc0'] > new_max_pfc[0]:
                    new_max_pfc = (int(sample['pfc0']), int(sample['pfc1']), int(sample['pfc2']),
                                   int(sample['pfc3']), int(sample['pfc4']))
            self._max_pfc = new_max_pfc
        return self._max_pfc


# ==================================================================================================
# Trace Containers
# 追踪容器
# ==================================================================================================
class TraceBundle(NamedTuple):
    """
    Container for a set of measurements produced by executing a test case with a given input on
    the model and on the executor. It contains the input, the input ID, the contract trace, the
    hardware trace.

    测量数据容器（命名元组）。
    包含单次测量的完整数据：输入ID、输入数据、合约追踪、硬件追踪。
    """
    input_id: InputID    # 输入标识符
    input_: InputData    # 输入数据对象
    ctrace: CTrace       # 合约追踪
    htrace: HTrace       # 硬件追踪


HWEquivalenceFunction = Callable[[HTrace, HTrace], bool]
# 硬件等价判断函数类型：接受两个HTrace，返回是否等价


def _default_eq_function(htrace1: HTrace, htrace2: HTrace) -> bool:
    """
    Default equivalence function that compares hardware traces for equality

    默认硬件等价判断函数：直接比较哈希值是否相等。
    """
    return htrace1 == htrace2


class HardwareEqClass:
    """
    Container for a set of TraceBundles that are hardware-equivalent;
    that is, all TraceBundles in the list have similar hardware trace.
    Note that the notion of similarity is configurable and defined by CONF.analyser

    硬件等价类容器。
    包含一组硬件追踪相似的TraceBundle。相似性的定义由配置决定，
    可使用默认哈希相等判断或自定义等价函数。

    核心属性：
    - htrace: 所有测量共享的硬件追踪（取第一个测量的htrace）
    - measurements: 硬件等价的TraceBundle列表
    """

    htrace: Final[HTrace]
    """ hardware trace that all measurements in the equivalence class share — 等价类共享的硬件追踪 """

    measurements: Final[List[TraceBundle]]
    """ a list of TraceBundles that are hardware-equivalent — 硬件等价的测量列表 """

    # ==============================================================================================
    # Constructors
    # 构造方法

    def __init__(self, measurements: List[TraceBundle]) -> None:
        """
        初始化硬件等价类。

        :param measurements: 硬件等价的测量列表
        """
        self.htrace = measurements[0].htrace
        self.measurements = measurements

    @classmethod
    def build_hw_classes(
        cls,
        measurements: List[TraceBundle],
        equivalence_function: HWEquivalenceFunction = _default_eq_function
    ) -> List[HardwareEqClass]:
        """
        Break down a list of measurements into hardware equivalence classes.
        :param measurements: a list of measurements
        :param equivalence_function: a function that compares two hardware traces and returns True
                if they are equivalent (i.e., they are similar enough to be considered the same)
        :return: List of hardware classes formed from the input measurements

        将测量列表分组为硬件等价类。
        遍历所有测量，对每个硬件追踪检查是否与已有等价类相似，
        相似则加入该类，否则创建新类。

        :param measurements: 测量列表
        :param equivalence_function: 硬件等价判断函数（默认为哈希相等）
        :return: 硬件等价类列表
        """
        # Collect lists of measurements with equivalent hardware traces
        # 收集硬件追踪等价的测量分组
        hw_groups: Dict[int, List[TraceBundle]] = {}
        diverging_htraces: List[HTrace] = []  # 已发现的不同的硬件追踪列表
        for measurement in measurements:
            htrace = measurement.htrace

            # First iteration: create a new hardware equivalence class
            # 首次迭代：创建第一个等价类
            if not diverging_htraces:
                diverging_htraces.append(htrace)
                hw_groups[hash(htrace)] = [measurement]
                continue

            # Subsequent iterations: check if the htrace is equivalent to any existing class
            # 后续迭代：检查是否与已有等价类相似
            for htrace_other in diverging_htraces:
                if equivalence_function(htrace, htrace_other):
                    hw_groups[hash(htrace_other)].append(measurement)
                    break
            else:
                # 不与任何已有类相似，创建新等价类
                diverging_htraces.append(htrace)
                hw_groups[hash(htrace)] = [measurement]

        # Create HardwareEqClass objects for each group
        # 为每个分组创建HardwareEqClass对象
        hw_classes: List[HardwareEqClass] = []
        for group in hw_groups.values():
            hw_classes.append(cls(group))
        return hw_classes

    # ==============================================================================================
    # Public Methods
    # 公共方法

    def __len__(self) -> int:
        """ 返回等价类中的测量数量 """
        return len(self.measurements)

    def __iter__(self) -> Generator[TraceBundle, None, None]:
        """ 迭代等价类中的测量 """
        yield from self.measurements

    def __getitem__(self, index: int) -> TraceBundle:
        """ 按索引获取测量 """
        return self.measurements[index]

    def __eq__(self, other: object) -> bool:
        """
        Compare two hardware equivalence classes for equality.
        Two classes are equal if they have the same hardware trace and the same measurements.

        比较两个硬件等价类是否相等：硬件追踪和测量列表都相同。
        """
        if not isinstance(other, HardwareEqClass):
            raise NotImplementedError("Cannot compare HardwareEqClass with object of another type")
        return self.htrace == other.htrace and self.measurements == other.measurements


class ContractEqClass:
    """
    ContractEqClass is a container for a set of TraceBundles that are contract-equivalent;
    that is, all TraceBundles in the list have the same contract trace.

    合约等价类容器。
    包含一组合约追踪相同的TraceBundle。同一合约等价类内的测量
    应产生相同的合约追踪，但硬件追踪可能不同（这正是违规检测的基础）。
    """

    ctrace: Final[CTrace]
    """ contract trace that all measurements in the equivalence class share — 等价类共享的合约追踪 """

    measurements: Final[List[TraceBundle]]
    """ list of TraceBundles that are contract-equivalent — 合约等价的测量列表 """

    _hw_classes: Optional[List[HardwareEqClass]] = None  # 硬件等价类列表（惰性设置）

    # ==============================================================================================
    # Constructors
    # 构造方法

    def __init__(self, measurements: List[TraceBundle]) -> None:
        """
        初始化合约等价类。

        :param measurements: 合约追踪相同的测量列表
        """
        self.ctrace = measurements[0].ctrace
        self.measurements = measurements

        # check that all measurements have the same contract trace
        # 验证所有测量的合约追踪相同
        for measurement in measurements:
            assert measurement.ctrace == self.ctrace, "All measurements must have the same ctrace"

    @classmethod
    def build_contract_classes(cls, measurements: List[TraceBundle]) -> List[ContractEqClass]:
        """
        Break down a list of measurements into contract equivalence classes
        :param measurements: a list of measurements
        :return: List of contract classes formed from the input measurements

        将测量列表分组为合约等价类。
        按合约追踪哈希值分组，哈希相同的测量归入同一类。

        :param measurements: 测量列表
        :return: 合约等价类列表
        """
        # Collect lists of measurements with equivalent contract traces
        # 按合约追踪哈希分组
        eq_groups: Dict[int, List[TraceBundle]] = {}
        for measurement in measurements:
            ctrace = measurement.ctrace
            hash_ = hash(ctrace)
            if hash_ not in eq_groups:
                eq_groups[hash_] = [measurement]
            else:
                eq_groups[hash_].append(measurement)

        # Create ContractEqClass objects for each group
        # 为每个分组创建ContractEqClass对象
        eq_classes: List[ContractEqClass] = []
        for group in eq_groups.values():
            eq_classes.append(cls(group))
        return eq_classes

    def __len__(self) -> int:
        """ 返回等价类中的测量数量 """
        return len(self.measurements)

    def set_hw_classes(self, hw_classes: List[HardwareEqClass]) -> None:
        """
        Set the hardware equivalence classes for this contract equivalence class.
        :param hw_classes: a dictionary of hardware equivalence classes indexed by htrace hash

        为此合约等价类设置硬件等价类。
        只能设置一次（第二次调用会报错）。

        :param hw_classes: 硬件等价类列表
        """
        assert self._hw_classes is None, "Attempting to set hardware equivalence classes twice"
        self._hw_classes = hw_classes

    def set_trivial_hw_classes(self) -> None:
        """
        Set the hardware equivalence classes for this contract equivalence class by directly
        comparing hardware traces for equality.

        使用默认哈希相等判断为此合约等价类构建硬件等价类。
        """
        assert self._hw_classes is None, "Attempting to set hardware equivalence classes twice"
        self._hw_classes = HardwareEqClass.build_hw_classes(self.measurements)

    def get_hw_classes(self) -> List[HardwareEqClass]:
        """
        Get a dictionary of all hardware equivalence classes
        in the contract equivalence class; indexed by htrace hash.

        获取此合约等价类中的所有硬件等价类。
        """
        assert self._hw_classes is not None, "Hardware equivalence classes not set"
        return self._hw_classes


class Violation(ContractEqClass):
    """
    Violation is a special type of equivalence class that represents a violation of a contract.
    It is a container for a list of measurements (TraceBundle) that triggered the violation
    as well as a complete sequence of inputs that triggered the violation and the test case program.

    违规类。
    表示检测到的合约违规——同一合约等价类中出现多个不同的硬件等价类。
    包含触发违规的测量列表、完整输入序列和测试用例代码。
    """

    input_sequence: List[InputData]
    """ complete sequence of inputs that triggered the violation — 触发违规的完整输入序列 """

    test_case_code: Final[TestCaseProgram]
    """ test case program that triggered the violation — 触发违规的测试用例程序 """

    # ==============================================================================================
    # Constructors
    # 构造方法

    def __init__(self, measurements: List[TraceBundle], input_sequence: List[InputData],
                 test_case_code: TestCaseProgram) -> None:
        """
        初始化违规对象。

        :param measurements: 触发违规的测量列表
        :param input_sequence: 完整输入序列
        :param test_case_code: 测试用例代码
        """
        super().__init__(measurements)
        self.input_sequence = input_sequence
        self.test_case_code = test_case_code

    @classmethod
    def from_contract_eq_class(cls, eq_class: ContractEqClass, input_sequence: List[InputData],
                               test_case_code: TestCaseProgram) -> Violation:
        """
        Create a Violation object from a ContractEqClass object
        :param eq_class: ContractEquivalenceClass object
        :param input_sequence: complete sequence of inputs that triggered the violation
        :return: Violation object

        从合约等价类创建违规对象，保留其硬件等价类信息。

        :param eq_class: 源合约等价类
        :param input_sequence: 触发违规的输入序列
        :param test_case_code: 测试用例代码
        :return: Violation对象
        """
        violation = cls(eq_class.measurements, input_sequence, test_case_code)
        violation.set_hw_classes(eq_class.get_hw_classes())
        return violation

    @classmethod
    def pseudo_violation_from_inputs(cls, input_sequence: List[InputData],
                                     test_case_code: TestCaseProgram) -> Violation:
        """
        Create a pseudo-violation object from a list of inputs.

        This interface is used by the variants of the fuzzer that rely on non-standard definition
        of violations (e.g., ArchFuzzer). Such fuzzers may not produce traces, yet they still
        have to return a violation object from the analyser.

        :param input_: input that triggered the pseudo-violation
        :return: Violation object

        从输入列表创建伪违规对象。
        用于不产生追踪的模糊测试变体（如ArchFuzzer），每个输入创建一个
        空追踪的TraceBundle和对应的硬件等价类。

        :param input_sequence: 输入序列
        :param test_case_code: 测试用例代码
        :return: 伪Violation对象
        """
        measurements = []
        hw_classes = []
        for i, input_ in enumerate(input_sequence):
            # 为每个输入创建空追踪的测量
            bundle = TraceBundle(InputID(i), input_, CTrace.empty_trace(), HTrace.empty_trace())
            measurements.append(bundle)
            # 每个测量单独构成一个硬件等价类
            hw_classes.append(HardwareEqClass([bundle]))
        violation = cls(measurements, input_sequence, test_case_code)
        violation.set_hw_classes(hw_classes)
        return violation

    # ==============================================================================================
    # Public Methods
    # 公共方法
    def full_str(self, region1_col: str = "", region2_col: str = "", reset_col: str = "") -> str:
        """
        Return a string representation of the violation, including the contract and hardware
        traces of all measurements in the violation

        返回违规的完整字符串表示，包含合约追踪和硬件追踪的对比信息。

        四种情况：
        1. 无硬件等价类：直接打印合约追踪和所有硬件追踪
        2. 单个硬件等价类（ArchFuzzer场景）：单输入违规
        3. 两个硬件等价类：并排对比显示
        4. 多个硬件等价类：逐类打印
        """
        # pylint: disable=too-many-locals  # justification: the method is clear enough as is

        s = "Violation Details:\n"

        # Four cases to consider:
        hw_classes = self._hw_classes

        # 1. No hardware equivalence classes (set_hw_classes() was never called)
        # 情况1：未设置硬件等价类
        if hw_classes is None or not hw_classes:
            s += f"  Contract trace: (hash {self.ctrace})\n"
            s += f"    {self.ctrace.full_str()} \n"
            s += "  Hardware traces:\n"
            for measurement in self.measurements:
                s += measurement.htrace.full_str("    ") + "\n"
            return s

        # 2. Only one measurement in the violation (normally the case for ArchFuzzer)
        # 情况2：单输入违规（ArchFuzzer场景）
        if len(hw_classes) == 1:
            s += "  Special Case: Single-input violation\n"
            s += f"  Input ID: {self.measurements[0].input_id}\n"
            s += f"  Contract trace: (hash {self.ctrace})\n"
            s += f"    {self.ctrace.full_str()} \n"
            s += "  Hardware traces:\n"
            s += f"    {hw_classes[0].htrace.full_str()} \n"
            return s

        # 3. If there are two HW classes, print them side by side for improved readability
        # 情况3：两个硬件等价类，并排对比显示
        hw_classes = self.get_hw_classes()
        if len(hw_classes) == 2:
            inputs1 = [m.input_id for m in hw_classes[0]]
            inputs2 = [m.input_id for m in hw_classes[1]]
            htrace1 = hw_classes[0][0].htrace
            htrace2 = hw_classes[1][0].htrace
            trace_table = htrace1.full_pair_str(htrace2, region1_col, region2_col, reset_col)

            line_width = max(len(line) for line in trace_table.splitlines())
            assert line_width > 19, "Invalid trace table"
            trace_width = line_width - 19

            # 构建对比表头部
            header = "\n" + "-" * line_width + "\n"
            header += f"{'HTrace':^{trace_width}} | ID:{inputs1[0]:<3} | ID:{inputs2[0]:<3}|\n"
            header += "-" * line_width + "\n"
            s += header + trace_table
            return s

        # 4. With more than two HW classes, print each HW class separately
        # 情况4：超过两个硬件等价类，逐类打印
        for hw_class in hw_classes:
            inputs = [measurement.input_id for measurement in hw_class]
            s += "  Inputs "
            s += f"{inputs}\n" if len(inputs) < 4 else f"{inputs[:4]} (+ {len(inputs) - 4} )\n"
            s += hw_class.htrace.full_str("    ", region1_col, region2_col, reset_col)
        s += "\n"
        return s

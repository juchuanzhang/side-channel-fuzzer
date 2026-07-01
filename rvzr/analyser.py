"""
文件：分析器（Analyser）模块
提供多种方式来比较收集到的合约迹（ctraces）与硬件迹（htraces），检测是否存在合约违例。
核心思路：将迹按合约等价类分组，在同一合约等价类内检查硬件迹是否一致；
若同一合约等价类中的硬件迹不一致，则报告为合约违例。

本模块包含以下分析器实现：
- MergedBitmapAnalyser：基于合并位图的分析器
- SetAnalyser：基于集合的分析器
- MWUAnalyser：基于Mann-Whitney U检验的分析器（实验性）
- ChiSquaredAnalyser：基于卡方检验的分析器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import Counter
from typing import List, Dict, TYPE_CHECKING, Union, Final
from abc import ABC, abstractmethod
from scipy import stats  # type: ignore

import numpy.typing as npt
import numpy as np

from .traces import HTrace, CTrace, TraceBundle, Violation, ContractEqClass, HardwareEqClass
from .config import CONF, ConfigException
from .stats import FuzzingStats
from .logs import warning, error

if TYPE_CHECKING:
    from .tc_components.test_case_data import InputData
    from .tc_components.test_case_code import TestCaseProgram

IntArrayLike = Union[List[int], npt.NDArray[np.uint64]]

STAT = FuzzingStats()


# ==================================================================================================
# 抽象分析器接口
# ==================================================================================================
class Analyser(ABC):
    """
    分析器抽象接口类：定义所有分析器必须实现的方法。
    所有分析器子类都需要实现违例检测和硬件迹等价性判断两个核心方法。
    """

    @abstractmethod
    def filter_violations(self,
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          test_case_code: TestCaseProgram,
                          inputs: List[InputData],
                          stats_: bool = False) -> List[Violation]:
        """
        比较合约迹和硬件迹，返回检测到的合约违例列表。
        :param ctraces: 待检查的合约迹列表
        :param htraces: 待检查的硬件迹列表
        :param test_case_code: 待测试的程序
        :param inputs: 待测试的输入列表（每条迹对应一个输入）
        :param stats_: 是否根据结果更新全局模糊测试统计
        :return: 检测到的违例列表，若无违例则返回空列表
        """

    @abstractmethod
    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """
        根据当前分析器的规则判断两条硬件迹是否等价。
        :param htrace1: 第一条硬件迹
        :param htrace2: 第二条硬件迹
        :return: 若两条迹等价返回True，否则返回False
        """


# ==================================================================================================
# 基于等价类的分析器
# ==================================================================================================
class EquivalenceAnalyserCommon(Analyser):
    """
    基于等价类的分析器抽象基类，实现核心的违例检测算法。

    算法原理：利用等价类概念比较合约迹和硬件迹。
    合约违例的定义如下：
      对于两对迹 (ctrace1, htrace1) 和 (ctrace2, htrace2)，
      其中 ctrace1 是 input1 的合约迹，htrace1 是 input1 的硬件迹（同理第二对），
      当以下条件满足时，迹违反合约：
           ctrace1 == ctrace2  （相同的合约迹）
           且 htrace1 与 htrace2 不等价（不同的硬件迹）

    "等价"的具体定义由子类实现（参见 htraces_are_equivalent 方法）。
    """

    def filter_violations(self,
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          test_case_code: TestCaseProgram,
                          inputs: List[InputData],
                          stats_: bool = False) -> List[Violation]:
        # --------
        # 注：这是所有基于等价类的分析器共用的违例检测算法。
        # 子类通过定义 htraces_are_equivalent 方法来调整实现。
        #
        # 算法步骤：
        # 1. 将测量结果按合约迹（ctrace）分组（构建合约等价类）
        # 2. 在每个合约等价类内检查所有硬件迹是否等价
        # 3. 若不等价，基于违反合约的迹创建 Violation 对象
        #
        # 算法还会过滤掉损坏/忽略的硬件迹，以避免假阳性
        # --------

        # 若无硬件迹，直接返回空列表
        if not htraces:
            return []

        # 将所有测量结果打包为 TraceBundle 对象
        # 并过滤掉损坏或被忽略的硬件迹
        measurements = []
        for i, htrace in enumerate(htraces):
            if htrace.is_empty() or htrace.is_corrupted_or_ignored():
                continue
            measurements.append(TraceBundle(i, inputs[i], ctraces[i], htrace))
        if not measurements:
            return []

        # 构建合约等价类列表
        all_classes = ContractEqClass.build_contract_classes(measurements)

        # 过滤掉无效的等价类（仅保留包含>=2个测量的等价类）
        effective_classes = [eq_cls for eq_cls in all_classes if len(eq_cls.measurements) >= 2]

        # 按合约迹排序
        effective_classes.sort(key=lambda x: x.ctrace)

        # 在每个有效等价类内计算硬件等价类
        for eq_cls in effective_classes:
            hw_classes = HardwareEqClass.build_hw_classes(
                eq_cls.measurements, equivalence_function=self.htraces_are_equivalent)
            eq_cls.set_hw_classes(hw_classes)

        # 检查是否存在合约反例（等价类内出现>=2个硬件等价类即为违例）
        violations: List[Violation] = []
        for eq_cls in effective_classes:
            hw_classes = eq_cls.get_hw_classes()
            if len(hw_classes) >= 2:
                v = Violation.from_contract_eq_class(eq_cls, inputs, test_case_code)
                violations.append(v)

        # 更新统计数据
        if stats_:
            STAT.eff_classes += len(effective_classes)
            STAT.single_entry_classes += len(all_classes) - len(effective_classes)
            STAT.analysed_test_cases += 1

        return violations


class MergedBitmapAnalyser(EquivalenceAnalyserCommon):
    """
    合并位图分析器：将硬件迹列表合并为位图后进行比较。
    具体做法：将每条硬件迹中的所有样本值按位合并（OR操作），形成位图，
    然后比较两个位图是否等价。
    
    还根据 CONF.analyser_outliers_threshold 过滤离群值（出现次数低于阈值的迹值）。
    
    位图等价性判断逻辑：
    - 若 analyser_subsets_is_violation 为 True：位图必须完全相等才算等价
    - 若为 False：位图不相交也算等价（即一个位图是另一个的子集或两者无重叠）
    """

    _bitmap_cache: Final[Dict[int, int]]   # 位图缓存：避免重复计算相同硬件迹的位图
    _MASK: Final[int]                       # 64位掩码，用于取反操作

    def __init__(self) -> None:
        super().__init__()
        self._bitmap_cache = {}
        self._MASK = pow(2, 64) - 1  # 全1的64位掩码

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """将两条硬件迹合并为位图并判断等价性"""
        bitmaps = [0, 0]

        sample_size = htrace1.sample_size()
        assert sample_size == htrace2.sample_size(), "htraces have different sizes"
        # 离群值阈值：出现次数低于此比例的迹值将被过滤掉
        threshold = CONF.analyser_outliers_threshold * sample_size

        for i, htrace in enumerate([htrace1, htrace2]):
            hash_ = hash(htrace)
            raw = htrace.get_raw_traces()

            # 检查缓存：若已计算过该硬件迹的位图，直接使用缓存结果
            if hash_ in self._bitmap_cache:
                bitmaps[i] = self._bitmap_cache[hash_]
                continue

            # 过滤离群值：仅保留出现次数 >= 阈值的迹值
            counter = Counter(raw)
            filtered = [x for x in raw if counter[x] >= threshold]

            # 合并为位图：将所有过滤后的迹值按位OR合并
            for t in filtered:
                bitmaps[i] |= int(t)

            # 缓存计算结果
            self._bitmap_cache[hash_] = bitmaps[i]

        if CONF.analyser_subsets_is_violation:
            # 严格模式：位图必须完全相等才算等价
            return bitmaps[0] == bitmaps[1]

        # 宽松模式：检查两个位图是否不相交
        # 若一个位图是另一个的子集，或两者无重叠位，则认为等价
        inverse = [~bitmaps[0] & self._MASK, ~bitmaps[1] & self._MASK]
        return bool(((bitmaps[0] & inverse[1]) == 0) or ((bitmaps[1] & inverse[0]) == 0))


class SetAnalyser(EquivalenceAnalyserCommon):
    """
    集合分析器：将硬件迹列表压缩为集合后进行比较。
    具体做法：将每条硬件迹中的所有样本值构成集合，然后比较两个集合是否等价。
    
    同样根据 CONF.analyser_outliers_threshold 过滤离群值。
    
    集合等价性判断逻辑：
    - 若 analyser_subsets_is_violation 为 True：集合必须完全相等才算等价
    - 若为 False：一个集合是另一个的子集也算等价
    """

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """将两条硬件迹压缩为集合并判断等价性"""
        sample_size = htrace1.sample_size()
        assert sample_size == htrace2.sample_size(), "htraces have different sizes"
        threshold = CONF.analyser_outliers_threshold * sample_size
        # 过滤离群值：仅保留出现次数 >= 阈值的迹值
        filtered1 = [x for x in htrace1.get_raw_traces() if x >= threshold]
        filtered2 = [x for x in htrace2.get_raw_traces() if x >= threshold]

        trace_set1 = set(filtered1)
        trace_set2 = set(filtered2)

        if CONF.analyser_subsets_is_violation:
            # 严格模式：集合必须完全相等才算等价
            return trace_set1 == trace_set2

        # 宽松模式：一个集合是另一个的子集也算等价
        return trace_set1.issubset(trace_set2) or trace_set2.issubset(trace_set1)


class MWUAnalyser(EquivalenceAnalyserCommon):
    """
    Mann-Whitney U检验分析器：使用Mann-Whitney U统计检验来比较两条硬件迹。
    
    Mann-Whitney U检验是一种非参数检验，用于判断两个独立样本是否来自同一分布。
    若p值大于统计阈值，则认为两条迹来自同一分布（等价）。
    
    注意：这是实验性分析器，可能不适用于所有场景。
    """

    def __init__(self) -> None:
        super().__init__()
        warning("analyser",
                "MWUAnalyser is an experimental analyser and may not work well for all cases. ")

        # 初始化时验证阈值配置是否合理
        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        _, p_value = stats.mannwhitneyu(a, b)
        if CONF.analyser_stat_threshold < p_value:
            raise ConfigException("analyser_stat_threshold is too high for the given sample size")

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """使用Mann-Whitney U检验判断两条硬件迹是否等价"""
        _, p_value = stats.mannwhitneyu(htrace1.get_raw_traces(), htrace2.get_raw_traces())
        # p值大于阈值说明两条迹来自同一分布，即等价
        return bool(p_value > CONF.analyser_stat_threshold)


class ChiSquaredAnalyser(EquivalenceAnalyserCommon):
    """
    卡方检验分析器：使用卡方同质性检验来比较两条硬件迹。
    
    卡方检验通过比较两条迹中各值的频率分布，判断是否来自同一分布。
    若检验统计量小于阈值，则认为两条迹等价。
    """

    def __init__(self) -> None:
        super().__init__()
        # 初始化时验证阈值配置是否合理
        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        stat = self.homogeneity_test(a, b)
        if CONF.analyser_stat_threshold > stat:
            error("analyser_stat_threshold is too low for the given sample size")

    def homogeneity_test(self, x: IntArrayLike, y: IntArrayLike) -> float:
        """
        执行卡方同质性检验，返回检验统计量。
        :param x: 第一组迹值
        :param y: 第二组迹值
        :return: 卡方检验统计量（已按样本总数归一化）
        """
        assert len(x) == len(y)
        counter1 = Counter(x)
        counter2 = Counter(y)
        # 合并两组数据的所有唯一值作为键
        keys = set(counter1.keys()) | set(counter2.keys())
        # 观测值：两组数据中每个键的计数
        observed = [counter1[k] for k in keys] + [counter2[k] for k in keys]
        # 期望值：两组数据中每个键的平均计数
        expected = [(counter1[k] + counter2[k]) / 2 for k in keys] * 2
        ddof = len(keys) - 1  # 自由度调整
        stat: float
        stat, _ = stats.chisquare(observed, expected, ddof=ddof)
        # 按样本总数归一化，使统计量不受样本大小影响
        stat /= len(x) + len(y)
        return stat

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """使用卡方同质性检验判断两条硬件迹是否等价"""
        stat = self.homogeneity_test(htrace1.get_raw_traces(), htrace2.get_raw_traces())
        # 统计量小于阈值说明两条迹分布相似，即等价
        return stat < CONF.analyser_stat_threshold

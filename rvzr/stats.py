"""
文件：全局统计类
用于记录和管理模糊测试过程中的统计数据，包括测试用例数、输入数、违例数、
各类假阳性过滤数等。采用 Borg 模式实现状态共享。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Any, Dict


class FuzzingStats:
    """
    模糊测试统计类：负责存储和管理模糊测试的统计数据。
    采用 Borg 模式（共享状态模式），使得所有实例共享同一状态，
    从而在不同模块中可以通过创建新实例来访问相同的统计数据。
    """
    _borg_shared_state: Dict[Any, Any] = {}

    test_cases: int = 0              # 已测试的测试用例总数
    num_inputs: int = 0              # 已生成的输入总数
    eff_classes: int = 0             # 有效等价类数量（包含>=2个测量的等价类）
    single_entry_classes: int = 0    # 单条目等价类数量（仅包含1个测量的等价类）
    violations: int = 0              # 检测到的违例总数
    analysed_test_cases: int = 0     # 已分析的测试用例总数
    executor_reruns: int = 0         # 执行器重复运行次数

    spec_filter: int = 0             # 被推测过滤器丢弃的测试用例数
    observ_filter: int = 0           # 被观测过滤器丢弃的测试用例数
    fast_path: int = 0               # 快速路径（无违例）通过的测试用例数
    fp_nesting: int = 0              # 因嵌套层级不足导致的假阳性数
    fp_taint_mistakes: int = 0       # 因污点追踪错误导致的假阳性数
    fp_early_priming: int = 0        # 因早期priming检查排除的假阳性数
    fp_large_sample: int = 0         # 因噪声（大样本检查）排除的假阳性数
    fp_priming: int = 0              # 因priming检查排除的假阳性数

    # Borg 模式的实现：所有实例共享同一个字典
    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state

    def __str__(self) -> str:
        """返回完整的统计报告字符串，包含各项统计指标的详细信息"""
        total_clss = self.eff_classes + self.single_entry_classes
        # 每个测试用例的平均等价类总数
        total_clss_per_test_case = total_clss / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        # 每个测试用例的平均有效等价类数
        effective_clss = self.eff_classes / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        # 每个测试用例的平均输入数
        iptc = self.num_inputs / self.test_cases if self.test_cases else 0

        s = ""
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {iptc:.1f}\n"
        s += f"Violations: {self.violations}\n"
        s += "Effectiveness: \n"
        s += f"  Total Cls: {total_clss_per_test_case:.1f}\n"
        s += f"  Effective Cls: {effective_clss:.1f}\n"
        s += "Discarded Test Cases:\n"
        s += f"  Speculation Filter: {self.spec_filter}\n"
        s += f"  Observation Filter: {self.observ_filter}\n"
        s += f"  Fast Path: {self.fast_path}\n"
        s += f"  Max Nesting Check: {self.fp_nesting}\n"
        s += f"  Tainting Check: {self.fp_taint_mistakes}\n"
        s += f"  Early Priming Check: {self.fp_early_priming}\n"
        s += f"  Large Sample Check: {self.fp_large_sample}\n"
        s += f"  Priming Check: {self.fp_priming}\n"
        return s

    def get_brief(self) -> str:
        """返回一行简短的统计摘要，用于实时显示模糊测试进度"""

        if self.test_cases == 0:
            return ""

        if self.analysed_test_cases:
            # 每个测试用例的等价类总数和有效等价类数
            all_cls = (self.eff_classes + self.single_entry_classes) // self.analysed_test_cases
            eff_cls = self.eff_classes // self.analysed_test_cases
        else:
            all_cls = 0
            eff_cls = 0
        # 每个输入的平均执行器重复运行次数
        executor_reruns = self.executor_reruns // self.num_inputs
        s = f"Cls:{eff_cls}/{all_cls},"     # 等价类统计：有效类/总类
        s += f"In:{self.num_inputs // self.test_cases},"  # 每个测试用例的平均输入数
        s += f"R:{executor_reruns},"          # 执行器平均重复运行次数
        s += f"SF:{self.spec_filter},"        # 推测过滤器丢弃数
        s += f"OF:{self.observ_filter},"      # 观测过滤器丢弃数
        s += f"Fst:{self.fast_path}," \
             f"CN:{self.fp_nesting}," \
             f"CT:{self.fp_taint_mistakes}," \
             f"P1:{self.fp_early_priming}," \
             f"CS:{self.fp_large_sample}," \
             f"P2:{self.fp_priming}," \
             f"V:{self.violations}"           # 违例总数
        return s

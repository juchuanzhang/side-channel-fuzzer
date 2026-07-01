"""
文件：模型接口（后端和ISA无关的抽象基类）。
模型是一个能够按照契约执行测试用例并收集契约轨迹的模块。
在微架构侧信道模糊测试框架中，模型用于模拟指令的执行效果并提取
与侧信道相关的契约轨迹信息。

File: Model Interface (Backend- and ISA-independent)
      A model is a module that can execute a test case according to a contract
      and collect contract traces.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, TYPE_CHECKING, Any

from .traces import CTrace
from .tc_components.test_case_data import InputData, InputTaint

if TYPE_CHECKING:
    from .sandbox import SandboxLayout, BaseAddrTuple
    from .tc_components.test_case_code import TestCaseProgram


class Model(ABC):
    """
    所有契约模型的抽象接口。
    具体实现取决于所选的后端（如Unicorn模拟器）和目标ISA（如x86-64、arm64）。
    模型负责：加载测试用例、执行测试用例、收集契约轨迹和污点信息。

    Abstract interface for all contract models.
    The specific implementation depends on the selected backend and the target ISA.
    """

    layout: SandboxLayout
    """ 最近加载的测试用例在模型中的内存布局 / The memory layout of the most-recently loaded test case within the model """

    is_speculative: bool
    """ 指示模型是否实现某种形式的投机执行 / Indicates whether the model implements any form of speculative execution """

    _enable_mismatch_check_mode: bool = False
    """
    不匹配检查模式：如果为True，模型将返回GPR值而非契约轨迹，
    用于检查模型与执行器之间的不一致。

    mismatch_check_mode: If True, the model will return GPR values instead of
    contract traces, which is used to check for mismatches between the model and the executor
    """

    @abstractmethod
    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        """
        初始化模型。
        参数:
            bases: 基地址元组，定义沙箱内存布局的基础地址
            enable_mismatch_check_mode: 是否启用不匹配检查模式，默认为False
        """
        pass

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        将测试用例加载到模型中，包括为代码和数据分配内存、
        初始化权限以及执行其他必要的设置。
        此方法必须在调用 trace_test_case 之前调用。

        Load a test case into the model, which implies allocating memory for the code
        and data, initializing permissions, and doing other necessary setup.

        This method *must* be called before calling `trace_test_case`.
        """

    @abstractmethod
    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        在模型中使用给定的输入执行已加载的测试用例，
        并为每次执行收集契约轨迹（每个输入对应一条轨迹）。

        参数:
            inputs: 输入数据列表
            nesting: 投机执行的嵌套深度
        返回:
            契约轨迹列表，每个输入对应一条轨迹

        Execute a previously loaded test case in the model with the given inputs,
        and collect the traces for each execution (i.e., one trace per input).
        """

    @abstractmethod
    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        在模型中使用给定的输入执行已加载的测试用例，
        收集契约轨迹的同时还收集每个输入的污点信息。
        污点信息用于追踪输入数据对执行路径的影响。

        参数:
            inputs: 输入数据列表
            nesting: 投机执行的嵌套深度
        返回:
            (契约轨迹列表, 污点列表) 的元组

        Execute a previously loaded test case in the model with the given inputs,
        and collect the traces for each execution (i.e., one trace per input).
        While collecting the traces, also collect the taints for each input.
        """

    @abstractmethod
    def report_coverage(self, path: str) -> None:
        """
        报告模糊测试活动的覆盖率并存储到指定文件路径。
        用于评估模型对契约 violations 的覆盖情况。

        参数:
            path: 覆盖率报告的存储文件路径

        Report the coverage of the fuzzing campaign w.r.t. the model, and store the report
        in the given file path.
        """


class DummyModel(Model):
    """
    模型接口的空实现，不执行任何操作。
    所有轨迹为空轨迹，因此所有输入形成相同的等价类。
    适用于测试目的或需要无模型运行模糊测试的场景（如独立硬件追踪）。

    Dummy implementation of the Model interface that does nothing. All traces produced by
    this model are empty, and thus all inputs form the same equivalence class.

    This model is useful for testing purposes or for cases where it's necessary to
    run the fuzzer without a model (e.g., for standalone hardware tracing).
    """
    is_speculative: bool = False  # 空模型不支持投机执行

    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        """空初始化，不做任何操作"""
        pass

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """空实现，不加载任何测试用例"""
        pass

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        为每个输入返回空轨迹。
        返回: 空契约轨迹列表，长度等于输入数量
        """
        return [CTrace.empty_trace() for _ in inputs]

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        为每个输入返回空轨迹和空污点。
        返回: (空轨迹列表, 空污点列表) 的元组
        """
        taints = [InputTaint() for _ in inputs]
        traces = [CTrace.empty_trace() for _ in inputs]
        return traces, taints

    def report_coverage(self, path: str) -> None:
        """空实现，不报告任何覆盖率"""
        pass

"""
文件：ARM64架构执行器的实现
本文件实现了ARM64架构上的测试用例执行器，继承通用Executor类，
在初始化时验证当前CPU是否为ARM架构，并在非ARM CPU上抛出配置异常。

File: Implementation of executor for arm64 architecture

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from rvzr.executor import Executor
from rvzr.config import ConfigException
from rvzr.target_desc import TargetDesc


class ARM64Executor(Executor):
    """
    ARM64架构特定的执行器实现。
    继承通用Executor类，在初始化时检查CPU供应商是否为ARM，
    若在非ARM CPU上运行则抛出ConfigException异常。
    目前无需额外的ARM64特定功能设置。

    ARM-specific implementation of the executor
    """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        """
        初始化ARM64执行器。

        参数:
            enable_mismatch_check_mode: 是否启用不匹配检查模式，
                用于检测模拟器与硬件执行结果的差异

        异常:
            ConfigException: 当在非ARM CPU上尝试运行ARM64执行器时抛出
        """
        super().__init__(enable_mismatch_check_mode)
        # 获取CPU供应商并验证是否为ARM架构
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "ARM":
            raise ConfigException(
                "Attempting to run ARM64Executor executor on a non-ARM CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        """
        设置ARM64供应商特定的执行器功能。
        目前无需设置任何ARM64特定功能，该方法为空实现。
        子类可在此添加ARM64特有的执行器配置。
        """
        pass
